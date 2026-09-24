//! QUIC transport: `Auth` on the first stream, then one server-opened stream per
//! tunnel (protocol: `x2rp_proto` docs). Each tunnel is spliced to its backend with
//! `copy_bidirectional`, so QUIC's per-stream flow control is the only
//! backpressure and a slow tunnel never blocks another.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Connection, ConnectionError, Endpoint, RecvStream, SendStream};
use x2rp_proto::obfs::ObfuscatedSocket;
use x2rp_proto::{ALPN, Message, read_frame};

use crate::transport::{TransportConfig, connect_any, connect_backend};

/// Bound the `Connect` read so a stalled stream cannot hold its task forever.
const CONNECT_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct QuicSession {
    _endpoint: Endpoint,
    connection: Connection,
}

impl QuicSession {
    /// Serve tunnels until the connection ends; `Ok` when the server closed it.
    pub(crate) async fn run(self) -> io::Result<()> {
        loop {
            match self.connection.accept_bi().await {
                Ok((send, recv)) => {
                    tokio::spawn(splice_data_stream(send, recv));
                }
                Err(ConnectionError::ApplicationClosed(_)) => return Ok(()),
                Err(e) => return Err(io::Error::other(e)),
            }
        }
    }
}

pub(crate) async fn connect(config: &TransportConfig) -> io::Result<QuicSession> {
    use rustls_platform_verifier::BuilderVerifierExt;
    let tls = rustls::ClientConfig::builder()
        .with_platform_verifier()
        .map_err(io::Error::other)?
        .with_no_client_auth();
    connect_with(config, client_config(tls)?).await
}

async fn connect_with(
    config: &TransportConfig,
    client_config: ClientConfig,
) -> io::Result<QuicSession> {
    let secret: [u8; 32] = hex::decode(&config.obfuscation_secret)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
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
    let connection = endpoint
        .connect(server_addr, server_name)
        .map_err(io::Error::other)?
        .await
        .map_err(io::Error::other)?;

    let (mut control, _) = connection.open_bi().await.map_err(io::Error::other)?;
    let auth = Message::Auth {
        token: token.to_string(),
    };
    control
        .write_all(&auth.frame()?)
        .await
        .map_err(io::Error::other)?;
    let _ = control.finish();

    Ok(QuicSession {
        _endpoint: endpoint,
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

    let backend = connect_backend(&target).await;
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
    match tokio::io::copy_bidirectional(&mut backend, &mut tokio::io::join(recv, send)).await {
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
    client_config.transport_config(Arc::new(x2rp_proto::quic_transport_config()));
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
            obfuscation_secret: hex::encode(secret),
            force_wss: false,
        };
        let session = connect_with(&config, client_config(tls).expect("client config"))
            .await
            .expect("connect");
        let run = tokio::spawn(session.run());
        server.await.expect("server");
        run.abort();
    }
}
