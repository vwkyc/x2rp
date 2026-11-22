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
use std::sync::Arc;
use std::time::Duration;

use rustls_platform_verifier::BuilderVerifierExt;
use serde::Deserialize;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::transport::{TransportConfig, https_get};

const SERVICE: &str = "x2rp-connector";
const CONFIG_FILE: &str = "/etc/x2rp-connector/config.json";
/// A session that lasted this long resets the reconnect backoff.
const STABLE_SESSION: Duration = Duration::from_secs(30);

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

enum Command {
    Run,
    Status,
    Logs,
}

fn usage() -> &'static str {
    "Usage: x2rp-connector <run|status|logs>\n\n\
     x2rp connector (QUIC with WebSocket fallback)\n\n\
     Commands:\n  \
       run     Run the connector (used by systemd)\n  \
       status  Show service status\n  \
       logs    Show connector logs (follows journald)\n"
}

fn parse_cli() -> Command {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        eprint!("{}", usage());
        std::process::exit(2);
    };
    if args.next().is_some() {
        eprintln!("Unexpected extra argument");
        eprint!("{}", usage());
        std::process::exit(2);
    }
    match cmd.as_str() {
        "run" => Command::Run,
        "status" => Command::Status,
        "logs" => Command::Logs,
        "help" | "-h" | "--help" => {
            print!("{}", usage());
            std::process::exit(0);
        }
        "-V" | "--version" => {
            println!("x2rp-connector {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        other => {
            eprintln!("Unknown command: {other}");
            eprint!("{}", usage());
            std::process::exit(2);
        }
    }
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

fn parse_log_filter(raw: Option<&str>) -> tracing_subscriber::filter::Targets {
    let default = if cfg!(debug_assertions) {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    let fallback =
        || tracing_subscriber::filter::Targets::new().with_target("x2rp_connector", default);
    raw.map(|raw| {
        raw.split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(",")
    })
    .filter(|s| !s.is_empty())
    .and_then(|s| s.parse().ok())
    .unwrap_or_else(fallback)
}

fn log_filter() -> tracing_subscriber::filter::Targets {
    parse_log_filter(std::env::var("RUST_LOG").ok().as_deref())
}

#[tokio::main]
async fn main() {
    let command = parse_cli();

    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    tracing_subscriber::registry()
        .with(log_filter())
        .with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_target(false),
        )
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install Rustls crypto provider");

    let result = match command {
        Command::Run => cmd_run().await,
        Command::Status => x2rp_proto::cmd_status(SERVICE).map_err(Into::into),
        Command::Logs => x2rp_proto::cmd_logs(SERVICE).map_err(Into::into),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn cmd_run() -> Result<()> {
    info!("x2rp connector starting");
    let config = load_config()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::spawn(async move {
        tokio::select! {
            _ = sigterm.recv() => info!("Received SIGTERM"),
            _ = tokio::signal::ctrl_c() => info!("Received SIGINT"),
        }
        let _ = shutdown_tx.send(true);
    });
    reconnect_loop(&config, shutdown_rx).await?;
    info!("Connector shutdown complete");
    Ok(())
}

/// Every reconnect re-polls settings, and its 401 is the one terminal signal:
/// returning `Ok` exits 0, so systemd (`Restart=on-failure`) leaves a deleted
/// connector stopped. Any transport failure just backs off into that check.
async fn reconnect_loop(config: &Config, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_platform_verifier()?
            .with_no_client_auth(),
    );
    let mut transport_config = TransportConfig {
        server: config.server.clone(),
        token: config.token.clone(),
        obfuscation_secret: String::new(),
        force_wss: false,
    };
    let mut retry_count = 0u32;

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let fetched = tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            res = https_get(&transport_config, "/api/connector/settings", &tls_config) => match res {
                Ok((401, _)) => {
                    error!("Connector authorization rejected by server (deleted or token invalid)");
                    error!("To reconnect, create a new connector in the admin UI and reinstall");
                    return Ok(());
                }
                Ok((200..=299, body)) => match serde_json::from_slice::<ServerSettings>(&body) {
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
                        true
                    }
                    Err(e) => {
                        warn!("Failed to parse server settings: {e}");
                        false
                    }
                },
                Ok((status, _)) => {
                    warn!("Server settings request failed: HTTP {status}");
                    false
                }
                Err(e) => {
                    warn!("Failed to fetch server settings: {e}");
                    false
                }
            },
        };

        // Measure only live session duration (never connect timeouts across multi-IP
        // blackholes) so repeated connect failures never reset the backoff.
        let mut session_duration = Duration::ZERO;
        if fetched {
            let connected = tokio::select! {
                _ = shutdown.changed() => return Ok(()),
                res = connect_session(&transport_config, &tls_config) => res,
            };
            match connected {
                Ok(session) => {
                    let started = tokio::time::Instant::now();
                    match session.run(shutdown.clone()).await {
                        Ok(()) => info!("Session ended"),
                        Err(e) => error!("Connection error: {e}"),
                    }
                    session_duration = started.elapsed();
                }
                Err(e) => error!("Connection error: {e}"),
            }
        }
        if *shutdown.borrow() {
            return Ok(());
        }
        // Back off unless the session held. A QUIC close reads as a clean end, so a
        // server that drops us right after auth (session cap) would be redialed hot.
        if session_duration >= STABLE_SESSION {
            retry_count = 0;
            continue;
        }
        retry_count = retry_count.saturating_add(1);
        let wait = reconnect_backoff_secs(retry_count);
        warn!("Reconnecting in {wait}s (attempt {retry_count})");
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            () = tokio::time::sleep(Duration::from_secs(wait)) => {}
        }
    }
}

enum ConnectedSession {
    Quic(transport_quic::QuicSession),
    Wss(transport_wss::WssSession),
}

impl ConnectedSession {
    async fn run(self, shutdown: watch::Receiver<bool>) -> std::io::Result<()> {
        match self {
            Self::Quic(s) => s.run(shutdown).await,
            Self::Wss(s) => s.run(shutdown).await,
        }
    }
}

/// Prefer QUIC when the obfuscation secret is known; fall back to WSS otherwise.
/// `force_wss` (admin-set) skips the QUIC attempt entirely.
async fn connect_session(
    config: &TransportConfig,
    tls_config: &Arc<rustls::ClientConfig>,
) -> std::io::Result<ConnectedSession> {
    if config.force_wss {
        info!("Force WSS enabled; skipping QUIC");
    } else if config.obfuscation_secret.is_empty() {
        warn!("Obfuscation secret unavailable; connecting via WSS only");
    } else {
        match transport_quic::connect(config, tls_config).await {
            Ok(session) => {
                info!("Connected via QUIC");
                return Ok(ConnectedSession::Quic(session));
            }
            Err(e) => warn!("QUIC connect failed ({e}); trying WSS"),
        }
    }

    let session = transport_wss::connect(config, tls_config).await?;
    info!("Connected via WSS");
    Ok(ConnectedSession::Wss(session))
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
    if config.token.trim().is_empty() {
        return Err("Config error: connector token is empty".into());
    }
    Ok(config)
}

/// `https://host[:port]` with no path, query or credentials.
fn normalize_server_origin(server: &str) -> Result<String> {
    let normalized = server.trim().trim_end_matches('/');
    match x2rp_proto::parse_http_origin(normalized) {
        Ok((_, _, true)) => {
            let rest = normalized.split_once("://").map_or(normalized, |(_, r)| r);
            Ok(format!("https://{rest}"))
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
        assert_eq!(
            super::normalize_server_origin("HTTPS://x2rp.example.com/").unwrap(),
            "https://x2rp.example.com"
        );
        for bad in ["http://h", "https://", "https://h/p", "https://u@h"] {
            assert!(super::normalize_server_origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parse_log_filter_scopes_directives_and_falls_back() {
        use tracing::Level;
        use tracing_subscriber::filter::LevelFilter;

        let scoped = super::parse_log_filter(Some(" x2rp_connector=debug , "));
        assert!(scoped.would_enable("x2rp_connector", &Level::DEBUG));
        assert!(!scoped.would_enable("quinn_proto", &Level::INFO));

        let multi = super::parse_log_filter(Some("warn, x2rp_connector=debug"));
        assert!(multi.would_enable("x2rp_connector", &Level::DEBUG));
        assert!(!multi.would_enable("quinn_proto", &Level::INFO));
        assert!(multi.would_enable("quinn_proto", &Level::WARN));

        assert_eq!(
            super::parse_log_filter(Some("off")).default_level(),
            Some(LevelFilter::OFF)
        );

        for raw in [None, Some(""), Some(" , "), Some("not_a_level=bogus")] {
            let fallback = super::parse_log_filter(raw);
            assert!(fallback.would_enable("x2rp_connector", &Level::INFO));
            assert!(!fallback.would_enable("quinn_proto", &Level::INFO));
        }
    }
}
