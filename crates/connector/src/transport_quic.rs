//! QUIC transport: `Auth` on the first stream, then one server-opened stream per
//! tunnel (protocol: `x2rp_proto` docs). Each tunnel is spliced to its backend with
//! `copy_bidirectional_with_sizes`, so QUIC's per-stream flow control is the only
//! backpressure and a slow tunnel never blocks another.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Connection, ConnectionError, Endpoint, RecvStream, SendStream};
use x2rp_proto::obfs::ObfuscatedSocket;
use x2rp_proto::{ALPN, Message, TUNNEL_READ_CHUNK, read_frame};

use crate::transport::{TransportConfig, connect_any, connect_backend};

/// Bound the `Connect` read and `Auth` write so a stalled stream cannot hold its task forever.
const CONNECT_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Server application close code for an unauthorized/rotated token.
const UNAUTHORIZED: quinn::VarInt = quinn::VarInt::from_u32(1);

pub(crate) struct QuicSession {
    endpoint: Endpoint,
    connection: Connection,
}

impl Drop for QuicSession {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"shutdown");
    }
}

impl QuicSession {
    /// Serve tunnels until the connection ends or `shutdown` signals; `Ok` on clean close.
    pub(crate) async fn run(
        self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> io::Result<()> {
        let mut tasks = tokio::task::JoinSet::new();
        let result = loop {
            if *shutdown.borrow() {
                break Ok(());
            }
            tokio::select! {
                _ = shutdown.changed() => break Ok(()),
                accepted = self.connection.accept_bi() => match accepted {
                    Ok((send, recv)) => {
                        tasks.spawn(splice_data_stream(send, recv));
                    }
                    Err(ConnectionError::ApplicationClosed(close))
                        if close.error_code == UNAUTHORIZED =>
                    {
                        break Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "QUIC authorization rejected by server",
                        ));
                    }
                    Err(ConnectionError::ApplicationClosed(_)) => break Ok(()),
                    Err(e) => break Err(io::Error::other(e)),
                },
                // Reap completed splice tasks so the JoinSet never grows unboundedly.
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        };
        // Abort any in-flight backend connects/splices immediately on session end.
        tasks.abort_all();
        // Flush CONNECTION_CLOSE on graceful shutdown so the server marks us offline right away.
        if *shutdown.borrow() {
            self.connection.close(0u32.into(), b"shutdown");
            let _ =
                tokio::time::timeout(Duration::from_millis(250), self.endpoint.wait_idle()).await;
        }
        result
    }
}

pub(crate) async fn connect(
    config: &TransportConfig,
    base_tls: &rustls::ClientConfig,
) -> io::Result<QuicSession> {
    connect_with(config, client_config(base_tls.clone())?).await
}

async fn connect_with(
    config: &TransportConfig,
    client_config: ClientConfig,
) -> io::Result<QuicSession> {
    let secret = x2rp_proto::obfs::decode_secret_hex(&config.obfuscation_secret)
        .ok_or_else(|| io::Error::other("invalid obfuscation secret"))?;
    let (server_name, _) = config.host_port()?;
    connect_any(config, |addr| {
        connect_to_addr(
            addr,
            &server_name,
            &config.token,
            secret,
            client_config.clone(),
        )
    })
    .await
}

async fn connect_to_addr(
    server_addr: SocketAddr,
    server_name: &str,
    token: &str,
    secret: [u8; 32],
    client_config: ClientConfig,
) -> io::Result<QuicSession> {
    let bind_addr: SocketAddr = if server_addr.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = ObfuscatedSocket::bind(bind_addr, secret)?;
    let mut endpoint = Endpoint::new_with_abstract_socket(
        Default::default(),
        None,
        Arc::new(socket),
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config);
    let connecting = endpoint
        .connect(server_addr, server_name)
        .map_err(io::Error::other)?;
    let connection = tokio::time::timeout(Duration::from_secs(10), connecting)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC handshake timed out"))?
        .map_err(io::Error::other)?;

    let auth_frame = Message::Auth {
        token: token.to_string(),
    }
    .frame()?;
    tokio::time::timeout(CONNECT_HEADER_TIMEOUT, async {
        let (mut control, _) = connection.open_bi().await.map_err(io::Error::other)?;
        control
            .write_all(&auth_frame)
            .await
            .map_err(io::Error::other)?;
        let _ = control.finish();
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC auth frame write timed out"))??;

    Ok(QuicSession {
        endpoint,
        connection,
    })
}

/// One tunnel: `Connect`, backend connect, `ConnectOk`/`ConnectErr`, then a bidi
/// splice (`copy_bidirectional` carries half-close both ways).
async fn splice_data_stream(mut send: SendStream, mut recv: RecvStream) {
    let (stream_id, target) =
        match tokio::time::timeout(CONNECT_HEADER_TIMEOUT, read_frame(&mut recv)).await {
            Ok(Ok(Message::Connect { stream_id, target })) => (stream_id, target),
            other => {
                tracing::warn!("QUIC stream {}: no valid Connect ({other:?})", send.id());
                return;
            }
        };

    // Abort backend dial immediately if the server resets/stops this stream.
    let backend = tokio::select! {
        biased;
        _ = send.stopped() => {
            tracing::debug!("QUIC tunnel {stream_id} cancelled before backend connect");
            return;
        }
        res = connect_backend(&target) => res,
    };
    let reply = match &backend {
        Ok(_) => Message::ConnectOk { stream_id },
        Err(e) => Message::ConnectErr {
            stream_id,
            error: e.to_string(),
        },
    };
    let Ok(reply) = reply.frame() else { return };
    if send.write_all(&reply).await.is_err() {
        return;
    }
    let Ok(mut backend) = backend else {
        let _ = send.finish();
        return;
    };
    // Same chunk as the server's end of the splice (see `connector_manager::quic_tunnel`).
    match tokio::io::copy_bidirectional_with_sizes(
        &mut backend,
        &mut tokio::io::join(recv, send),
        TUNNEL_READ_CHUNK,
        TUNNEL_READ_CHUNK,
    )
    .await
    {
        Ok((up, down)) => {
            tracing::debug!("QUIC tunnel {stream_id} closed (up {up} / down {down} bytes)")
        }
        Err(e) => tracing::debug!("QUIC tunnel {stream_id} ended: {e}"),
    }
}

fn client_config(mut tls: rustls::ClientConfig) -> io::Result<ClientConfig> {
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(io::Error::other)?,
    ));
    client_config.transport_config(Arc::new(x2rp_proto::quic_transport_config(
        x2rp_proto::MAX_ACTIVE_STREAMS as u32,
    )));
    Ok(client_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// End to end: a real TCP echo backend, a QUIC server that opens a tunnel to it,
    /// and bytes written on that tunnel must come back. Proves Auth, Connect,
    /// ConnectOk and the splice.
    #[tokio::test]
    async fn quic_stream_splices_to_backend() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("backend bind");
        let backend_addr = backend.local_addr().expect("backend addr");
        tokio::spawn(async move {
            let (mut sock, _) = backend.accept().await.expect("accept");
            let mut buf = [0u8; 1024];
            while let Ok(n @ 1..) = sock.read(&mut buf).await {
                if sock.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });

        let secret = [0x42; 32];
        let certified =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).expect("cert");
        let cert_der = certified.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der.into())
            .expect("tls");
        tls_config.alpn_protocols = vec![ALPN.to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).expect("crypto"),
        ));
        let socket =
            ObfuscatedSocket::bind("127.0.0.1:0".parse().expect("addr"), secret).expect("bind");
        let endpoint = Endpoint::new_with_abstract_socket(
            Default::default(),
            Some(server_config),
            Arc::new(socket),
            Arc::new(quinn::TokioRuntime),
        )
        .expect("endpoint");
        let server_addr = endpoint.local_addr().expect("local");

        let server = tokio::spawn(async move {
            let connection = endpoint
                .accept()
                .await
                .expect("accept")
                .await
                .expect("conn");
            let (_, mut control) = connection.accept_bi().await.expect("control");
            assert!(matches!(
                read_frame(&mut control).await.expect("auth"),
                Message::Auth { token } if token == "test-token"
            ));

            let (mut send, mut recv) = connection.open_bi().await.expect("data stream");
            let connect = Message::Connect {
                stream_id: 7,
                target: format!("http://{backend_addr}"),
            };
            send.write_all(&connect.frame().expect("frame"))
                .await
                .expect("connect");
            assert!(matches!(
                read_frame(&mut recv).await.expect("reply"),
                Message::ConnectOk { stream_id: 7 }
            ));

            send.write_all(b"hello").await.expect("write request");
            let mut echo = [0u8; 5];
            recv.read_exact(&mut echo).await.expect("read echo");
            assert_eq!(&echo, b"hello");
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).expect("trust cert");
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let config = TransportConfig {
            server: format!("https://127.0.0.1:{}", server_addr.port()),
            token: "test-token".to_string(),
            obfuscation_secret: x2rp_proto::encode_hex(&secret),
            force_wss: false,
        };
        let session = connect_with(&config, client_config(tls).expect("client config"))
            .await
            .expect("connect");
        let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let run = tokio::spawn(session.run(shutdown_rx));
        server.await.expect("server");
        run.abort();
    }
}
