//! x2rp server

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::Request,
    middleware,
    response::{IntoResponse, Redirect},
    routing::{get, post, put},
};
use pingora_core::listeners::TcpSocketOptions;
use pingora_core::listeners::tls::TlsSettings;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use x2rp::api::{self, AppState, GlobalState};
use x2rp::connector_manager::ConnectorRegistry;
use x2rp::proxy::{Gateway, ProxyContext, ProxyResource, parse_host_header};
use x2rp::{http_middleware, security_headers, static_files, tls, transport};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const SERVICE: &str = "x2rp";

enum Command {
    Run,
    Status,
    Logs,
}

fn usage() -> &'static str {
    "Usage: x2rp [run|status|logs]\n\n\
     x2rp reverse proxy\n\n\
     Commands:\n  \
       run     Run the server (default)\n  \
       status  Show service status\n  \
       logs    Follow logs\n"
}

fn parse_cli() -> Command {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        return Command::Run;
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
            println!("x2rp {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        other => {
            eprintln!("Unknown command: {other}");
            eprint!("{}", usage());
            std::process::exit(2);
        }
    }
}

fn main() {
    let result = match parse_cli() {
        Command::Run => run_server(),
        Command::Status => x2rp_proto::cmd_status(SERVICE).map_err(Into::into),
        Command::Logs => x2rp_proto::cmd_logs(SERVICE).map_err(Into::into),
    };
    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[tokio::main]
async fn run_server() -> anyhow::Result<()> {
    let default_filter = if cfg!(debug_assertions) {
        "x2rp=debug"
    } else {
        "x2rp=info"
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| default_filter.into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_target(false),
        )
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install Rustls crypto provider");

    tracing::info!("Starting x2rp {}", env!("CARGO_PKG_VERSION"));
    // Hard-fail if a state file exists but cannot be loaded.
    let app_state = AppState::load()?;

    let proxy_ctx = Arc::new(ProxyContext::new(
        &app_state.domain,
        Arc::new(ConnectorRegistry::default()),
    ));
    let state = Arc::new(RwLock::new(app_state));
    let global_state = GlobalState {
        state: state.clone(),
        auth: Arc::default(),
        proxy_ctx: proxy_ctx.clone(),
    };

    {
        let (auth, proxy) = (global_state.auth.clone(), proxy_ctx.clone());
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                proxy.maintenance_tick();
                auth.cleanup_expired();
            }
        });
    }

    let api_routes = Router::new()
        .route("/setup", post(api::post_setup))
        .route(
            "/connectors",
            get(api::list_connectors).post(api::create_connector),
        )
        .route(
            "/connectors/{id}",
            put(api::update_connector).delete(api::delete_connector),
        )
        .route(
            "/connectors/{id}/token",
            post(api::regenerate_connector_token),
        )
        .route(
            "/resources",
            get(api::list_resources).post(api::create_resource),
        )
        .route(
            "/resources/{id}",
            put(api::update_resource).delete(api::delete_resource),
        )
        .route("/auth/login", post(api::auth_login))
        // No /auth/logout: admin sessions expire; operators clear cookies if needed.
        .route(
            "/connector/connect",
            get(transport::websocket::connector_connect),
        )
        .route("/connector/disconnect", post(api::connector_disconnect))
        .route("/connector/settings", get(api::connector_get_settings))
        .layer(middleware::from_fn_with_state(
            global_state.clone(),
            http_middleware::enforce_api_csrf,
        ))
        .layer(middleware::from_fn(
            security_headers::api_no_store_middleware,
        ));

    // Served on loopback; the public edge proxies x2rp.<domain> to it.
    let admin_app = Router::new()
        .nest("/api", api_routes)
        .fallback(
            |State(state): State<GlobalState>, req: Request<Body>| async move {
                let path = req.uri().path();
                if static_files::requires_auth(path)
                    && !api::verify_admin(&state, req.headers()).await
                {
                    return Redirect::temporary("/login.html").into_response();
                }
                static_files::serve_static(path)
            },
        )
        .with_state(global_state.clone())
        .layer(middleware::from_fn(
            security_headers::admin_security_headers_middleware,
        ));

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel::<Option<StopKind>>(None);
    tokio::spawn(async move {
        let kind = shutdown_signal().await;
        let _ = shutdown_tx.send(Some(kind));
    });

    let (admin_stop_tx, mut admin_stop_rx) = tokio::sync::watch::channel(false);
    let admin_addr = SocketAddr::from(([127, 0, 0, 1], x2rp::proxy::ADMIN_API_PORT));
    let admin_listener = tokio::net::TcpListener::bind(admin_addr).await?;
    tracing::info!("Admin API listening on {admin_addr}");
    let admin_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(admin_listener, admin_app)
            .with_graceful_shutdown(async move {
                let _ = admin_stop_rx.wait_for(|v| *v).await;
            })
            .await
        {
            tracing::error!("Admin server error: {e}");
        }
    });

    let s = state.read().await;
    if !s.initialized || s.domain.is_empty() {
        tracing::warn!("Not initialized: run install.sh");
        drop(s);
        let _ = shutdown_rx.wait_for(|v| v.is_some()).await;
        let _ = admin_stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), admin_handle).await;
        return Ok(());
    }
    let domain = s.domain.clone();
    let cf_api_token = s.server_config.cf_api_token.clone();
    let obfuscation_secret = s.server_config.obfuscation_secret.clone();
    for resource in s.resources.iter().filter(|r| r.enabled) {
        proxy_ctx.set_resource(ProxyResource::from_resource(resource));
        tracing::info!(
            "Resource {}.{} → {}",
            resource.subdomain,
            domain,
            resource.target
        );
    }
    drop(s);

    if cf_api_token.is_empty() {
        anyhow::bail!("A Cloudflare API token is required for TLS. Set cf_api_token and restart.");
    }
    tls::CertManager::new(domain.clone(), cf_api_token)
        .ensure_certs()
        .await
        .map_err(|e| e.context("TLS certificate provisioning failed"))?;
    // Shared by the HTTPS and QUIC listeners; a renewal swaps it in place.
    let certs = tls::CertStore::load(tls::CERT_FILE, tls::KEY_FILE, &domain)
        .map_err(|e| e.context("TLS certificate could not be loaded"))?;
    let tls_settings = || -> anyhow::Result<TlsSettings> {
        let mut settings = TlsSettings::intermediate(tls::CERT_FILE, tls::KEY_FILE)?;
        // With a resolver the paths go unused: every handshake asks the store.
        settings.set_cert_resolver(certs.clone());
        Ok(settings)
    };

    let conf = pingora_core::server::configuration::ServerConf {
        threads: std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
        // Default grace is 300s vs the unit's TimeoutStopSec=15, which makes every stop a SIGKILL.
        grace_period_seconds: Some(5),
        graceful_shutdown_timeout_seconds: Some(5),
        ..Default::default()
    };
    let mut server = pingora_core::server::Server::new_with_opt_and_conf(
        pingora_core::server::configuration::Opt::default(),
        conf,
    );
    server.bootstrap();
    let mut http_service =
        pingora_proxy::http_proxy_service(&server.configuration, Gateway::new(proxy_ctx));

    // Probe dual-stack first: Pingora binds later, and a host without IPv6 must fall back.
    match bind_dual_stack_tcp((Ipv6Addr::UNSPECIFIED, 443).into()) {
        Ok(_probe) => {
            let mut options = TcpSocketOptions::default();
            options.ipv6_only = Some(false);
            http_service.add_tls_with_settings("[::]:443", Some(options), tls_settings()?);
            tracing::info!("Proxy listening on [::]:443 (dual-stack)");
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            anyhow::bail!("TCP port 443 is already in use: {e}");
        }
        Err(e) => {
            tracing::warn!("Dual-stack bind failed ({e}), falling back to 0.0.0.0:443");
            http_service.add_tls_with_settings("0.0.0.0:443", None, tls_settings()?);
        }
    }
    let redirect_listener = match bind_dual_stack_tcp((Ipv6Addr::UNSPECIFIED, 80).into()) {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            anyhow::bail!("TCP port 80 is already in use: {e}");
        }
        Err(e) => {
            tracing::warn!("Dual-stack bind failed ({e}), falling back to 0.0.0.0:80");
            tokio::net::TcpListener::bind("0.0.0.0:80").await?
        }
    };
    server.add_service(http_service);
    tracing::info!("Admin UI: https://x2rp.{domain}");

    if shutdown_rx.borrow().is_some() {
        let _ = admin_stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), admin_handle).await;
        return Ok(());
    }

    // `Server::run` returns cleanly once Pingora's grace period and shutdown timeout finish.
    // Drive Pingora from our watch channel so a signal arriving during startup is never missed.
    let pingora_shutdown_rx = shutdown_rx.clone();
    let mut pingora_handle = tokio::task::spawn_blocking(move || {
        server.run(pingora_core::server::RunArgs {
            shutdown_signal: Box::new(WatchShutdown(pingora_shutdown_rx)),
        })
    });
    tokio::spawn(run_http_redirect(redirect_listener, domain));

    let secret = x2rp_proto::obfs::decode_secret_hex(&obfuscation_secret);
    let quic_endpoint =
        match secret.map(|secret| transport::quic::create_quic_endpoint(certs.clone(), secret)) {
            Some(Ok(endpoint)) => {
                tracing::info!("QUIC endpoint ready on UDP {}", transport::quic::QUIC_PORT);
                tokio::spawn(transport::quic::quic_accept_loop(
                    endpoint.clone(),
                    global_state,
                ));
                Some(endpoint)
            }
            Some(Err(e)) => {
                tracing::warn!(
                    "QUIC endpoint failed (UDP {}): {e}",
                    transport::quic::QUIC_PORT
                );
                None
            }
            None => {
                tracing::error!("Invalid obfuscation_secret; QUIC transport disabled");
                None
            }
        };

    // A renewed cert goes into service in place; a restart is the fallback only if it
    // cannot be loaded.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
        interval.tick().await;
        loop {
            interval.tick().await;
            let (domain, cf_token) = {
                let s = state.read().await;
                (s.domain.clone(), s.server_config.cf_api_token.clone())
            };
            match tls::CertManager::new(domain, cf_token).ensure_certs().await {
                Ok(true) => match certs.reload() {
                    Ok(()) => tracing::info!("Certificate renewed and in service"),
                    Err(e) => {
                        // systemd (`Restart=always`) brings us back on the new files.
                        tracing::error!("Renewed certificate did not load ({e:#}); restarting");
                        std::process::exit(1);
                    }
                },
                Ok(false) => {}
                Err(e) => tracing::error!("Certificate renewal failed: {e:#}. Retrying tomorrow."),
            }
        }
    });

    let mut unexpected_exit = false;
    tokio::select! {
        _ = shutdown_rx.wait_for(|v| v.is_some()) => {
            // Drain Pingora first so in-flight proxied/relayed requests finish before QUIC & admin stop.
            let _ = pingora_handle.await;
        }
        _ = &mut pingora_handle => {
            tracing::error!("Pingora proxy exited unexpectedly");
            unexpected_exit = true;
        }
    }
    if let Some(endpoint) = quic_endpoint {
        endpoint.close(0u32.into(), b"shutdown");
        let _ = tokio::time::timeout(Duration::from_millis(250), endpoint.wait_idle()).await;
    }
    let _ = admin_stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), admin_handle).await;
    if unexpected_exit {
        anyhow::bail!("Pingora proxy exited unexpectedly");
    }
    Ok(())
}

/// `[::]:port` accepting IPv4-mapped peers too.
fn bind_dual_stack_tcp(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    tokio::net::TcpListener::from_std(socket.into())
}

#[derive(Clone, Copy)]
enum StopKind {
    Graceful,
    Fast,
}

struct WatchShutdown(tokio::sync::watch::Receiver<Option<StopKind>>);

#[async_trait::async_trait]
impl pingora_core::server::ShutdownSignalWatch for WatchShutdown {
    async fn recv(&self) -> pingora_core::server::ShutdownSignal {
        let mut rx = self.0.clone();
        match rx.wait_for(|v| v.is_some()).await.ok().and_then(|v| *v) {
            Some(StopKind::Fast) => pingora_core::server::ShutdownSignal::FastShutdown,
            Some(StopKind::Graceful) | None => {
                pingora_core::server::ShutdownSignal::GracefulTerminate
            }
        }
    }
}

async fn shutdown_signal() -> StopKind {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate()).expect("register SIGTERM handler");
    let kind = tokio::select! {
        _ = tokio::signal::ctrl_c() => StopKind::Fast,
        _ = term.recv() => StopKind::Graceful,
    };
    tracing::info!("Shutdown signal received");
    kind
}

/// Where a :80 request for Host `raw` is redirected: the domain or a single-label
/// subdomain, spelled as a valid hostname, so malformed Host values or off-site
/// domains cannot turn the redirect into an open redirect.
fn redirect_host(raw: &str, domain: &str) -> Option<String> {
    let host = parse_host_header(raw)?.to_ascii_lowercase();
    let ours = host == domain
        || host
            .strip_suffix(domain)
            .and_then(|p| p.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.'));
    (ours && api::is_valid_domain(&host)).then_some(host)
}

/// Bounded HTTP/1.1 :80 → HTTPS :443 redirect server.
///
/// Enforces a strict header read timeout (5s), 8 KiB header cap, concurrency cap
/// (256), and `Connection: close` so Slowloris or header-flood attacks cannot hold
/// sockets or tasks open indefinitely.
async fn run_http_redirect(listener: tokio::net::TcpListener, domain: String) {
    const MAX_CONNS: usize = 256;
    const IO_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_HEADER_BYTES: usize = 8 * 1024;

    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNS));
    let domain = Arc::new(domain);

    loop {
        let (mut io, addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("HTTP redirect accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            tracing::debug!("HTTP :80 concurrency cap reached; dropping {}", addr.ip());
            continue;
        };
        let domain = Arc::clone(&domain);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _permit = permit;
            const READ_CHUNK: usize = 1024;
            let mut buf = Vec::with_capacity(READ_CHUNK);
            let read_res = tokio::time::timeout(IO_TIMEOUT, async {
                loop {
                    let old = buf.len();
                    let room = MAX_HEADER_BYTES.saturating_sub(old);
                    if room == 0 {
                        return Ok::<bool, std::io::Error>(false);
                    }
                    let cap = room.min(READ_CHUNK);
                    buf.resize(old + cap, 0);
                    let res = io.read(&mut buf[old..]).await;
                    buf.truncate(old + res.as_ref().copied().unwrap_or(0));
                    if res? == 0 {
                        return Ok(false);
                    }
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        return Ok(true);
                    }
                }
            })
            .await;

            let response = match read_res {
                Ok(Ok(true)) => build_http_redirect_response(&buf, &domain, addr.ip()),
                Ok(Ok(false)) if !buf.is_empty() => {
                    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        .to_vec()
                }
                _ => return,
            };
            let _ = tokio::time::timeout(IO_TIMEOUT, async {
                io.write_all(&response).await?;
                io.shutdown().await
            })
            .await;
        });
    }
}

fn build_http_redirect_response(raw: &[u8], domain: &str, peer_ip: std::net::IpAddr) -> Vec<u8> {
    const BAD_REQUEST: &[u8] =
        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

    let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return BAD_REQUEST.to_vec();
    };
    let Ok(head) = std::str::from_utf8(&raw[..header_end]) else {
        return BAD_REQUEST.to_vec();
    };
    let mut lines = head.split("\r\n");
    let Some(req_line) = lines.next() else {
        return BAD_REQUEST.to_vec();
    };
    // Reject bare CR or LF inside any line (request smuggling / log injection).
    if req_line.contains(['\r', '\n']) {
        return BAD_REQUEST.to_vec();
    }
    let mut req_parts = req_line.split(' ');
    let (Some(method), Some(target), Some(version), None) = (
        req_parts.next(),
        req_parts.next(),
        req_parts.next(),
        req_parts.next(),
    ) else {
        return BAD_REQUEST.to_vec();
    };
    if !(1..=16).contains(&method.len())
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || !matches!(version, "HTTP/1.1" | "HTTP/1.0")
        || !target.bytes().all(|b| b.is_ascii_graphic())
    {
        return BAD_REQUEST.to_vec();
    }

    let mut host: Option<&str> = None;
    for line in lines {
        if line.contains(['\r', '\n']) {
            return BAD_REQUEST.to_vec();
        }
        let Some((name, val)) = line.split_once(':') else {
            return BAD_REQUEST.to_vec();
        };
        if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return BAD_REQUEST.to_vec();
            }
            host = Some(val.trim_ascii());
        }
    }

    let Some(host) = host.and_then(|raw_host| redirect_host(raw_host, domain)) else {
        return BAD_REQUEST.to_vec();
    };
    let path = if target.starts_with('/') && !target.starts_with("//") {
        target
    } else {
        "/"
    };
    tracing::debug!("{peer_ip} {method} http://{host}{path} 308");
    format!(
        "HTTP/1.1 308 Permanent Redirect\r\nLocation: https://{host}{path}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn redirect_host_allows_apex_and_single_label_subdomains_only() {
        assert_eq!(
            redirect_host("example.com", "example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            redirect_host("APP.example.com:80", "example.com").as_deref(),
            Some("app.example.com")
        );
        for bad in [
            "a.b.example.com",
            "evil.com",
            "evil.com/.example.com",
            "notexample.com",
            "app.example.com ",
            "",
        ] {
            assert_eq!(redirect_host(bad, "example.com"), None, "{bad}");
        }
    }

    #[test]
    fn http_redirect_builds_308_or_400() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let ok = String::from_utf8(build_http_redirect_response(
            b"GET /hello?a=1 HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
            "example.com",
            ip,
        ))
        .unwrap();
        assert!(ok.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"));
        assert!(ok.contains("Location: https://app.example.com/hello?a=1\r\n"));
        assert!(ok.contains("Connection: close\r\n"));

        // Scheme-relative target must collapse to `/` rather than redirect off-site.
        let slash = String::from_utf8(build_http_redirect_response(
            b"GET //evil.com HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
            "example.com",
            ip,
        ))
        .unwrap();
        assert!(slash.contains("Location: https://app.example.com/\r\n"));

        // Duplicate Host, unknown Host, bare LF in method, or non-ASCII target gets 400.
        for bad in [
            b"GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: app.example.com\r\nHost: app.example.com\r\n\r\n",
            b"GET\nFAKE / HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
            "GET /café HTTP/1.1\r\nHost: app.example.com\r\n\r\n".as_bytes(),
        ] {
            let resp =
                String::from_utf8(build_http_redirect_response(bad, "example.com", ip)).unwrap();
            assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{resp}");
        }
    }
}
