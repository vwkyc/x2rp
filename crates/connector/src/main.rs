//! x2rp connector: publishes private services to an x2rp server over an outbound tunnel.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(not(target_os = "linux"))]
compile_error!(
    "x2rp-connector is Linux-only (targets: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl)"
);

mod session_manager;
mod transport;
mod transport_quic;
mod transport_wss;

use std::path::Path;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde::Deserialize;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};

use crate::transport::TransportConfig;

const SERVICE: &str = "x2rp-connector";
const CONFIG_FILE: &str = "/etc/x2rp-connector/config.json";
/// A session that lasted this long resets the reconnect backoff.
const STABLE_SESSION: Duration = Duration::from_secs(30);

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(name = "x2rp-connector")]
#[command(about = "x2rp connector (QUIC with WebSocket fallback)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the connector (used by systemd)
    Run,
    /// Show service status
    Status,
    /// Show connector logs (follows journald)
    Logs,
}

#[derive(Deserialize)]
struct Config {
    server: String,
    token: String,
}

/// Server settings response (auth check + QUIC obfuscation secret).
#[derive(Deserialize)]
struct ServerSettings {
    obfuscation_secret: String,
    force_wss: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let default_directive = if cfg!(debug_assertions) {
        "x2rp_connector=debug"
    } else {
        "x2rp_connector=info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(default_directive.parse().unwrap()),
        )
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install Rustls crypto provider");

    let result = match cli.command {
        Commands::Run => cmd_run().await,
        Commands::Status => x2rp_proto::cmd_status(SERVICE).map_err(Into::into),
        Commands::Logs => x2rp_proto::cmd_logs(SERVICE).map_err(Into::into),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn cmd_run() -> Result<()> {
    info!("x2rp connector starting");
    let config = load_config()?;
    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        result = reconnect_loop(&config) => result?,
        _ = sigterm.recv() => info!("Received SIGTERM"),
        _ = tokio::signal::ctrl_c() => info!("Received SIGINT"),
    }
    info!("Connector shutdown complete");
    Ok(())
}

/// Every reconnect re-polls settings, and its 401 is the one terminal signal:
/// returning `Ok` exits 0, so systemd (`Restart=on-failure`) leaves a deleted
/// connector stopped. Any transport failure just backs off into that check.
async fn reconnect_loop(config: &Config) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let settings_url = format!("{}/api/connector/settings", config.server);
    let mut transport_config = TransportConfig {
        server: config.server.clone(),
        token: config.token.clone(),
        obfuscation_secret: String::new(),
        force_wss: false,
    };
    let mut retry_count = 0u32;

    loop {
        match client
            .get(&settings_url)
            .bearer_auth(&config.token)
            .send()
            .await
        {
            Ok(resp) if resp.status() == reqwest::StatusCode::UNAUTHORIZED => {
                error!("Connector authorization rejected by server (deleted or token invalid)");
                error!("To reconnect, create a new connector in the admin UI and reinstall");
                return Ok(());
            }
            Ok(resp) if resp.status().is_success() => match resp.json::<ServerSettings>().await {
                Ok(settings) => {
                    if settings.force_wss != transport_config.force_wss {
                        let state = if settings.force_wss {
                            "enabled"
                        } else {
                            "disabled"
                        };
                        info!("Force WSS {state} by admin");
                    }
                    transport_config.obfuscation_secret = settings.obfuscation_secret;
                    transport_config.force_wss = settings.force_wss;
                }
                Err(e) => warn!("Failed to parse server settings: {e}"),
            },
            Ok(resp) => warn!("Server settings request failed: {}", resp.status()),
            Err(e) => warn!("Failed to fetch server settings: {e}"),
        }

        let started = tokio::time::Instant::now();
        match run_session(&transport_config).await {
            Ok(()) => info!("Session ended"),
            Err(e) => error!("Connection error: {e}"),
        }
        // Back off unless the session held. A QUIC close reads as a clean end, so a
        // server that drops us right after auth (session cap) would be redialed hot.
        if started.elapsed() >= STABLE_SESSION {
            retry_count = 0;
            continue;
        }
        retry_count = retry_count.saturating_add(1);
        let wait = reconnect_backoff_secs(retry_count);
        warn!("Reconnecting in {wait}s (attempt {retry_count})");
        tokio::time::sleep(Duration::from_secs(wait)).await;
    }
}

/// Prefer QUIC when the obfuscation secret is known; fall back to WSS otherwise.
/// `force_wss` (admin-set) skips the QUIC attempt entirely.
async fn run_session(config: &TransportConfig) -> std::io::Result<()> {
    if config.force_wss {
        info!("Force WSS enabled; skipping QUIC");
    } else if config.obfuscation_secret.is_empty() {
        warn!("Obfuscation secret unavailable; connecting via WSS only");
    } else {
        match transport_quic::connect(config).await {
            Ok(session) => {
                info!("Connected via QUIC");
                return session.run().await;
            }
            Err(e) => warn!("QUIC connect failed ({e}); trying WSS"),
        }
    }

    let session = transport_wss::connect(config).await?;
    info!("Connected via WSS");
    session.run().await
}

fn load_config() -> Result<Config> {
    let data = match x2rp_proto::read_secret_file(Path::new(CONFIG_FILE), 0o640) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err("Config not found. Run install-connector.sh first.".into());
        }
        data => data?,
    };
    let mut config: Config = serde_json::from_slice(&data)?;
    config.server = normalize_server_origin(&config.server)?;
    Ok(config)
}

/// `https://host[:port]` with no path, query or credentials.
fn normalize_server_origin(server: &str) -> Result<String> {
    let normalized = server.trim().trim_end_matches('/');
    match normalized.strip_prefix("https://") {
        Some(host) if !host.is_empty() && !host.contains(['/', '?', '#', '@']) => {
            Ok(normalized.to_string())
        }
        _ => Err("Config error: server must be a bare HTTPS origin (https://host[:port])".into()),
    }
}

/// Exp backoff for a failed reconnect: 1, 2, 4, 8, 16, 30s (capped at 30s).
fn reconnect_backoff_secs(attempt: u32) -> u64 {
    (1u64 << attempt.saturating_sub(1).min(5)).min(30)
}

#[cfg(test)]
mod tests {
    /// Reconnects follow this curve; it must cap rather than shift past 63 bits on a
    /// long outage.
    #[test]
    fn reconnect_backoff_doubles_then_caps() {
        let curve: Vec<u64> = (0..8).map(super::reconnect_backoff_secs).collect();
        assert_eq!(curve, [1, 1, 2, 4, 8, 16, 30, 30]);
        assert_eq!(super::reconnect_backoff_secs(u32::MAX), 30);
    }

    #[test]
    fn server_origin_must_be_bare_https() {
        assert!(super::normalize_server_origin("https://x2rp.example.com/").is_ok());
        for bad in ["http://h", "https://", "https://h/p", "https://u@h"] {
            assert!(super::normalize_server_origin(bad).is_err(), "{bad}");
        }
    }
}
