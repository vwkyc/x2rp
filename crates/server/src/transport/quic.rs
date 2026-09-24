//! Connector sessions over QUIC on UDP 443 (protocol: `x2rp_proto` docs). The
//! connector's first stream carries its token; after that the session is the
//! connection itself, and tunnels are streams the `ConnectorManager` opens.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use quinn::{Endpoint, ServerConfig, VarInt};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};
use x2rp_proto::obfs::ObfuscatedSocket;
use x2rp_proto::{ALPN, MAX_CONNECTOR_SESSIONS, Message, read_frame};

use crate::api::GlobalState;
use crate::connector_manager::{ConnectorManager, Link};
use crate::transport::set_last_seen;

const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Application close code for a rejected token (connector deleted or rotated).
const UNAUTHORIZED: VarInt = VarInt::from_u32(1);

pub const QUIC_PORT: u16 = 443;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The QUIC endpoint on UDP 443. Handshakes draw the certificate from `certs`, so a
/// renewal reaches QUIC without a restart.
pub fn create_quic_endpoint(
    certs: Arc<crate::tls::CertStore>,
    obfuscation_secret: [u8; 32],
) -> std::io::Result<Endpoint> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(certs);
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(std::io::Error::other)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(x2rp_proto::quic_transport_config()));

    let socket = ObfuscatedSocket::bind(
        (Ipv6Addr::UNSPECIFIED, QUIC_PORT).into(),
        obfuscation_secret,
    )
    .or_else(|e| {
        warn!("IPv6 QUIC bind unavailable ({e}), falling back to 0.0.0.0:{QUIC_PORT}");
        ObfuscatedSocket::bind(
            (Ipv4Addr::UNSPECIFIED, QUIC_PORT).into(),
            obfuscation_secret,
        )
    })?;
    Endpoint::new_with_abstract_socket(
        Default::default(),
        Some(server_config),
        Arc::new(socket),
        Arc::new(quinn::TokioRuntime),
    )
}

pub async fn quic_accept_loop(endpoint: Endpoint, state: GlobalState) {
    // Slots are taken only after token auth, so failed handshakes cost nothing.
    let sessions = Arc::new(Semaphore::new(MAX_CONNECTOR_SESSIONS));
    while let Some(incoming) = endpoint.accept().await {
        let (state, sessions) = (state.clone(), sessions.clone());
        tokio::spawn(async move {
            let remote = incoming.remote_address();
            match incoming.await {
                Ok(connection) => {
                    if let Err(e) = run_session(connection, state, sessions).await {
                        warn!("QUIC connector session from {remote}: {e}");
                    }
                }
                Err(e) => debug!("QUIC handshake from {remote} failed: {e}"),
            }
        });
    }
}

async fn run_session(
    connection: quinn::Connection,
    state: GlobalState,
    sessions: Arc<Semaphore>,
) -> Result<(), BoxError> {
    let auth = async {
        let (_, mut control) = connection.accept_bi().await?;
        match read_frame(&mut control).await? {
            Message::Auth { token } => Ok::<_, BoxError>(token),
            _ => Err("first frame was not Auth".into()),
        }
    };
    let token = tokio::time::timeout(AUTH_TIMEOUT, auth)
        .await
        .map_err(|_| "auth timed out")??;
    let connector_id =
        crate::api::connector_from_token(&*state.state.read().await, &token).map(|c| c.id.clone());
    let Some(connector_id) = connector_id else {
        connection.close(UNAUTHORIZED, b"unauthorized");
        return Err("invalid token".into());
    };
    let Ok(_permit) = sessions.try_acquire_owned() else {
        return Err(format!("connector {connector_id}: session limit reached").into());
    };

    let manager = Arc::new(ConnectorManager::new(
        connector_id.clone(),
        Link::Quic(connection.clone()),
    ));
    let registry = &state.proxy_ctx.connectors;
    registry.register(manager.clone());
    set_last_seen(&state, &connector_id).await;
    info!(
        "Connector {connector_id} connected via QUIC from {}",
        connection.remote_address()
    );

    let reason = connection.closed().await;
    registry.unregister_manager(&manager);
    set_last_seen(&state, &connector_id).await;
    info!("Connector {connector_id} disconnected: {reason}");
    Ok(())
}
