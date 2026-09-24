//! x2rp server

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderValue, Request, StatusCode, header},
    middleware,
    response::{IntoResponse, Redirect},
    routing::{get, post, put},
};
use clap::{Parser, Subcommand};
use pingora_core::listeners::TcpSocketOptions;
use pingora_core::listeners::tls::TlsSettings;
use tokio::sync::RwLock;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use x2rp::api::{self, AppState, GlobalState};
use x2rp::connector_manager::ConnectorRegistry;
use x2rp::proxy::{Gateway, ProxyContext, ProxyResource, host_header_hostname};
use x2rp::{http_middleware, security_headers, static_files, tls, transport};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const SERVICE: &str = "x2rp";

#[derive(Parser)]
#[command(name = "x2rp", about = "x2rp reverse proxy")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the server (default)
    Run,
    /// Show service status
    Status,
    /// Follow logs
    Logs,
}

fn main() {
    let result = match Cli::parse().command.unwrap_or(Commands::Run) {
        Commands::Run => run_server(),
        Commands::Status => x2rp_proto::cmd_status(SERVICE).map_err(Into::into),
        Commands::Logs => x2rp_proto::cmd_logs(SERVICE).map_err(Into::into),
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
        // No /auth/logout: admin sessions expire; operators clear cookies if needed.
        .route("/auth/login", post(api::auth_login))
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
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ));

    // Served on loopback; the public edge proxies x2rp.<domain> to it.
    let mut admin_app = Router::new()
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
        // CSP is admin-app specific; the rest are the shared set the proxy path also applies.
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(security_headers::ADMIN_APP_CSP),
        ));
    for (name, value) in security_headers::STANDARD_RESPONSE_HEADERS {
        admin_app = admin_app.layer(SetResponseHeaderLayer::if_not_present(
            name,
            HeaderValue::from_static(value),
        ));
    }

    let admin_addr = SocketAddr::from(([127, 0, 0, 1], x2rp::proxy::ADMIN_API_PORT));
    let admin_listener = tokio::net::TcpListener::bind(admin_addr).await?;
    tracing::info!("Admin API listening on {admin_addr}");
    let admin_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(admin_listener, admin_app)
            .with_graceful_shutdown(shutdown_signal())
            .await
        {
            tracing::error!("Admin server error: {e}");
        }
    });

    let s = state.read().await;
    if !s.initialized || s.domain.is_empty() {
        tracing::warn!("Not initialized: run install.sh");
        drop(s);
        admin_handle.await?;
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
    let certs = tls::CertStore::load(tls::CERT_FILE, tls::KEY_FILE)
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
        Err(e) => {
            tracing::warn!("Dual-stack bind failed ({e}), falling back to 0.0.0.0:443");
            http_service.add_tls_with_settings("0.0.0.0:443", None, tls_settings()?);
        }
    }
    let redirect_listener = match bind_dual_stack_tcp((Ipv6Addr::UNSPECIFIED, 80).into()) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::warn!("Dual-stack bind failed ({e}), falling back to 0.0.0.0:80");
            tokio::net::TcpListener::bind("0.0.0.0:80").await?
        }
    };
    server.add_service(http_service);
    tracing::info!("Admin UI: https://x2rp.{domain}");

    // Server::run_forever is `-> !`: it ends in its own process::exit.
    tokio::task::spawn_blocking(move || server.run_forever());
    tokio::spawn(run_http_redirect(redirect_listener, domain));

    let secret = hex::decode(&obfuscation_secret)
        .ok()
        .and_then(|secret| <[u8; 32]>::try_from(secret).ok());
    match secret.map(|secret| transport::quic::create_quic_endpoint(certs.clone(), secret)) {
        Some(Ok(endpoint)) => {
            tracing::info!("QUIC endpoint ready on UDP {}", transport::quic::QUIC_PORT);
            tokio::spawn(transport::quic::quic_accept_loop(endpoint, global_state));
        }
        Some(Err(e)) => tracing::warn!(
            "QUIC endpoint failed (UDP {}): {e}",
            transport::quic::QUIC_PORT
        ),
        None => tracing::error!("Invalid obfuscation_secret; QUIC transport disabled"),
    }

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

    admin_handle.await?;
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

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate()).expect("register SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = term.recv() => {},
    }
    tracing::info!("Shutdown signal received");
}

/// HTTP :80 → HTTPS for the configured domain and its subdomains; anything else is a 400.
async fn run_http_redirect(listener: tokio::net::TcpListener, domain: String) {
    let app = Router::new().fallback(move |req: Request<Body>| {
        let suffix = format!(".{domain}");
        // A valid hostname only: `evil.com/.example.com` must not become a redirect.
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|raw| host_header_hostname(raw).to_ascii_lowercase())
            .filter(|host| {
                (*host == domain || host.ends_with(&suffix)) && api::is_valid_domain(host)
            });
        let path = req
            .uri()
            .path_and_query()
            .map_or("/", axum::http::uri::PathAndQuery::as_str);
        let response = match host {
            None => StatusCode::BAD_REQUEST.into_response(),
            Some(host) => Redirect::permanent(&format!("https://{host}{path}")).into_response(),
        };
        async move { response }
    });
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("HTTP redirect server error: {e}");
    }
}
