//! One connector session's tunnels. Each bridged client connection (a pipe end
//! from the proxy) becomes one tunnel: its own stream on QUIC, muxed as
//! `Message::Data` with per-stream `WindowUpdate` credit on WSS.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};
use x2rp_proto::{
    MAX_ACTIVE_STREAMS, Message, STREAM_RECV_WINDOW, SendCredit, TUNNEL_READ_CHUNK,
    WINDOW_UPDATE_THRESHOLD, read_frame,
};

/// Budget to open a tunnel: stream open, `Connect`, and the connector's backend
/// connect answered by `ConnectOk` / `ConnectErr`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How the session reaches its connector.
pub enum Link {
    Quic(quinn::Connection),
    /// Outbound queue drained by the WebSocket writer.
    Wss(mpsc::Sender<Message>),
}

/// Active WSS mux stream.
struct ActiveStream {
    /// Sends payloads to the downstream writer. Unbounded: the connector's
    /// download sender is credit-gated to [`STREAM_RECV_WINDOW`], enforced via
    /// `recv_outstanding`, so queued bytes stay within one window.
    to_socket: mpsc::UnboundedSender<Bytes>,
    /// Upload (client → connector) send credit; replenished by connector
    /// `WindowUpdate`s. Closed on teardown so the upload never leaks.
    send_credit: Arc<SendCredit>,
    /// Download bytes received but not yet written downstream. A connector that
    /// pushes past the window is violating flow control and gets Reset.
    recv_outstanding: Arc<AtomicUsize>,
}

pub struct ConnectorManager {
    connector_id: String,
    link: Link,
    active_streams: AtomicU32,
    shutdown_notify: Arc<tokio::sync::Notify>,
    // WSS mux state.
    next_stream_id: AtomicU32,
    /// Bridges waiting for ConnectOk / ConnectErr.
    pending: RwLock<HashMap<u32, oneshot::Sender<Result<(), String>>>>,
    streams: RwLock<HashMap<u32, ActiveStream>>,
}

impl ConnectorManager {
    pub fn new(connector_id: String, link: Link) -> Self {
        Self {
            connector_id,
            link,
            active_streams: AtomicU32::new(0),
            shutdown_notify: Arc::default(),
            next_stream_id: AtomicU32::new(1),
            pending: RwLock::default(),
            streams: RwLock::default(),
        }
    }

    pub fn shutdown_notify(&self) -> Arc<tokio::sync::Notify> {
        self.shutdown_notify.clone()
    }

    pub fn transport_label(&self) -> &'static str {
        match self.link {
            Link::Quic(_) => "QUIC",
            Link::Wss(_) => "WSS",
        }
    }

    /// End the session: QUIC closes the connection, the WSS writer watches the notify.
    pub fn shutdown(&self) {
        if let Link::Quic(connection) = &self.link {
            connection.close(0u32.into(), b"shutdown");
        }
        self.shutdown_notify.notify_waiters();
        for (_, pending) in self.pending.write().drain() {
            let _ = pending.send(Err("connector disconnected".to_string()));
        }
        // Close credits so uploads parked on acquire() exit instead of leaking.
        for (_, stream) in self.streams.write().drain() {
            stream.send_credit.close();
        }
        self.active_streams.store(0, Ordering::Release);
    }

    fn try_reserve_stream_slot(&self) -> bool {
        let limit = MAX_ACTIVE_STREAMS as u32;
        self.active_streams
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                (current < limit).then_some(current + 1)
            })
            .is_ok()
    }

    /// `checked_sub` saturates: shutdown may already have zeroed the counter.
    fn release_stream_slot(&self) {
        let _ = self
            .active_streams
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |c| c.checked_sub(1));
    }

    /// Idempotent teardown of one WSS stream: frees its slot, wakes its upload, and
    /// fails a still-pending connect so a late ConnectOk cannot start it.
    fn remove_stream(&self, stream_id: u32) {
        let Some(stream) = self.streams.write().remove(&stream_id) else {
            return;
        };
        stream.send_credit.close();
        self.release_stream_slot();
        if let Some(pending) = self.pending.write().remove(&stream_id) {
            let _ = pending.send(Err("stream closed".to_string()));
        }
    }

    /// Bridge a connection stream to the connector.
    pub fn bridge<S>(self: &Arc<Self>, target: &str, stream: S) -> Result<(), String>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        if !self.try_reserve_stream_slot() {
            return Err(format!(
                "connector overloaded: active stream cap ({MAX_ACTIVE_STREAMS}) reached"
            ));
        }
        let (this, target) = (self.clone(), target.to_string());
        tokio::spawn(async move {
            match &this.link {
                Link::Quic(connection) => {
                    if let Err(e) = quic_tunnel(connection, target, stream).await {
                        warn!("QUIC tunnel for {}: {e}", this.connector_id);
                    }
                    this.release_stream_slot();
                }
                Link::Wss(tx) => this.wss_tunnel(tx, stream, target).await,
            }
        });
        Ok(())
    }

    async fn wss_tunnel<S>(&self, tx: &mpsc::Sender<Message>, stream: S, target: String)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        // Skip ids still in use (the counter wraps after ~4 billion streams).
        let stream_id = loop {
            let id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
            if !self.streams.read().contains_key(&id) {
                break id;
            }
        };

        // Register the download channel before Connect: Data can race ahead of ConnectOk.
        let (response_tx, response_rx) = oneshot::channel();
        let (to_socket_tx, mut to_socket_rx) = mpsc::unbounded_channel();
        let send_credit = Arc::new(SendCredit::new(STREAM_RECV_WINDOW));
        let recv_outstanding = Arc::new(AtomicUsize::new(0));
        self.pending.write().insert(stream_id, response_tx);
        self.streams.write().insert(
            stream_id,
            ActiveStream {
                to_socket: to_socket_tx,
                send_credit: send_credit.clone(),
                recv_outstanding: recv_outstanding.clone(),
            },
        );

        // Bounded, so a full channel cannot park this bridge forever.
        let connect = Message::Connect { stream_id, target };
        let sent = tokio::time::timeout(Duration::from_secs(5), tx.send(connect));
        if !matches!(sent.await, Ok(Ok(()))) {
            warn!("Stream {stream_id} Connect not sent (connector channel full or closed)");
            self.remove_stream(stream_id);
            return;
        }

        let failure = match tokio::time::timeout(CONNECT_TIMEOUT, response_rx).await {
            Ok(Ok(Ok(()))) => None,
            Ok(Ok(Err(e))) => Some(format!("connection failed: {e}")),
            Ok(Err(_)) => Some("connection cancelled".to_string()),
            Err(_) => Some(format!(
                "connection timed out ({}s)",
                CONNECT_TIMEOUT.as_secs()
            )),
        };
        if let Some(reason) = failure {
            warn!("Stream {stream_id} {reason}");
            self.remove_stream(stream_id);
            // A connect that lands after we gave up must not leave a backend open.
            let _ = tx.send(Message::Reset { stream_id }).await;
            return;
        }

        let (mut rd, mut wr) = tokio::io::split(stream);
        // Upload: stream → connector. read_buf + freeze avoids a copy per chunk.
        let upload = async {
            let mut buf = BytesMut::with_capacity(TUNNEL_READ_CHUNK);
            loop {
                buf.reserve(TUNNEL_READ_CHUNK);
                match rd.read_buf(&mut buf).await {
                    // Request EOF: the connector half-closes the backend and still streams the response.
                    Ok(0) => {
                        let _ = tx.send(Message::Close { stream_id }).await;
                        return;
                    }
                    // Client/socket error: full abort, not request EOF.
                    Err(_) => {
                        let _ = tx.send(Message::Reset { stream_id }).await;
                        self.remove_stream(stream_id);
                        return;
                    }
                    Ok(_) => {
                        let payload = buf.split().freeze();
                        // Pause here when the backend is slower than the client;
                        // remove_stream closes the credit, so this cannot leak.
                        if !send_credit.acquire(payload.len()).await
                            || tx.send(Message::Data { stream_id, payload }).await.is_err()
                        {
                            return;
                        }
                    }
                }
            }
        };
        // Download: connector → stream, until the stream is removed or the client write fails.
        let download = async {
            let mut drained_since_grant = 0usize;
            let mut write_failed = false;
            while let Some(data) = to_socket_rx.recv().await {
                if wr.write_all(&data).await.is_err() {
                    write_failed = true;
                    break;
                }
                recv_outstanding.fetch_sub(data.len(), Ordering::AcqRel);
                // Grant drained bytes back so the connector's credit-gated backend read keeps going.
                drained_since_grant += data.len();
                if drained_since_grant >= WINDOW_UPDATE_THRESHOLD {
                    let bytes = drained_since_grant as u32;
                    drained_since_grant = 0;
                    if tx
                        .send(Message::WindowUpdate { stream_id, bytes })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
            let _ = wr.shutdown().await;
            // Client gone mid-response: full abort so the connector drops the backend.
            if write_failed {
                let _ = tx.send(Message::Reset { stream_id }).await;
            }
        };

        // The stream ends with the download; a finished upload only half-closes.
        tokio::pin!(download);
        tokio::select! {
            () = &mut download => {}
            () = upload => download.await,
        }
        self.remove_stream(stream_id);
    }

    /// Called by the WSS read loop; never blocks it.
    pub fn handle_message(&self, msg: Message) {
        match msg {
            Message::ConnectOk { stream_id } => {
                if let Some(pending) = self.pending.write().remove(&stream_id) {
                    let _ = pending.send(Ok(()));
                }
            }
            Message::ConnectErr { stream_id, error } => {
                if let Some(pending) = self.pending.write().remove(&stream_id) {
                    let _ = pending.send(Err(error));
                }
            }
            Message::Data { stream_id, payload } => {
                let entry = self
                    .streams
                    .read()
                    .get(&stream_id)
                    .map(|s| (s.to_socket.clone(), s.recv_outstanding.clone()));
                let Some((sender, outstanding)) = entry else {
                    return;
                };
                let len = payload.len();
                let after = outstanding.fetch_add(len, Ordering::AcqRel) + len;
                if after > STREAM_RECV_WINDOW {
                    warn!(
                        "Stream {stream_id} exceeded flow-control window ({after} > {STREAM_RECV_WINDOW}), resetting"
                    );
                    self.remove_stream(stream_id);
                    if let Link::Wss(tx) = &self.link {
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let _ = tx.send(Message::Reset { stream_id }).await;
                        });
                    }
                } else if sender.send(payload).is_err() {
                    self.remove_stream(stream_id);
                }
            }
            // Connector drained upload bytes: replenish that stream's send credit.
            Message::WindowUpdate { stream_id, bytes } => {
                if let Some(stream) = self.streams.read().get(&stream_id) {
                    stream.send_credit.add(bytes as usize);
                }
            }
            // Dropping the sender stops new data while preserving already-queued payloads.
            Message::Close { stream_id } | Message::Reset { stream_id } => {
                self.remove_stream(stream_id)
            }
            _ => {}
        }
    }
}

/// One QUIC tunnel: `Connect` out, `ConnectOk` / `ConnectErr` back, then a splice.
/// Dropping the streams on a failure closes the tunnel on the connector too.
async fn quic_tunnel<S>(
    connection: &quinn::Connection,
    target: String,
    mut stream: S,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let open = async {
        let (mut send, mut recv) = connection.open_bi().await.map_err(|e| e.to_string())?;
        let stream_id = send.id().index() as u32;
        let connect = Message::Connect { stream_id, target }.frame();
        send.write_all(&connect.map_err(|e| e.to_string())?)
            .await
            .map_err(|e| e.to_string())?;
        match read_frame(&mut recv).await.map_err(|e| e.to_string())? {
            Message::ConnectOk { .. } => Ok((send, recv)),
            Message::ConnectErr { error, .. } => Err(format!("connection failed: {error}")),
            other => Err(format!("unexpected {other:?}")),
        }
    };
    let (send, recv) = tokio::time::timeout(CONNECT_TIMEOUT, open)
        .await
        .map_err(|_| format!("connection timed out ({}s)", CONNECT_TIMEOUT.as_secs()))??;
    if let Err(e) =
        tokio::io::copy_bidirectional(&mut stream, &mut tokio::io::join(recv, send)).await
    {
        debug!("QUIC tunnel ended: {e}");
    }
    Ok(())
}

#[derive(Default)]
pub struct ConnectorRegistry {
    managers: RwLock<HashMap<String, Arc<ConnectorManager>>>,
}

impl ConnectorRegistry {
    pub fn register(&self, manager: Arc<ConnectorManager>) {
        let replaced = self
            .managers
            .write()
            .insert(manager.connector_id.clone(), manager.clone());
        if let Some(previous) = replaced
            && !Arc::ptr_eq(&previous, &manager)
        {
            previous.shutdown();
        }
    }

    /// Unregister on disconnect, only if it is still this instance and never a
    /// newly reconnected replacement.
    pub fn unregister_manager(&self, manager: &Arc<ConnectorManager>) {
        let mut map = self.managers.write();
        if map
            .get(&manager.connector_id)
            .is_some_and(|registered| Arc::ptr_eq(registered, manager))
        {
            map.remove(&manager.connector_id);
            manager.shutdown();
        }
    }

    /// Force-disconnect a connector by ID (used when deleting or reconfiguring)
    pub fn unregister(&self, connector_id: &str) {
        if let Some(manager) = self.managers.write().remove(connector_id) {
            manager.shutdown();
        }
    }

    pub fn get(&self, connector_id: &str) -> Option<Arc<ConnectorManager>> {
        self.managers.read().get(connector_id).cloned()
    }

    /// The transport the connector is currently connected over, if connected.
    pub fn transport_label(&self, connector_id: &str) -> Option<&'static str> {
        self.managers
            .read()
            .get(connector_id)
            .map(|m| m.transport_label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::duplex;

    /// Manager plus the channel end a transport would own: `to_rx` receives what
    /// the manager sends to the connector.
    fn test_manager(to_capacity: usize) -> (Arc<ConnectorManager>, mpsc::Receiver<Message>) {
        let (to_tx, to_rx) = mpsc::channel(to_capacity);
        let manager = Arc::new(ConnectorManager::new(
            "connector-a".to_string(),
            Link::Wss(to_tx),
        ));
        (manager, to_rx)
    }

    /// Next message the manager sent that matches `pick`, skipping the rest.
    async fn next_matching<T>(
        rx: &mut mpsc::Receiver<Message>,
        pick: impl Fn(Message) -> Option<T>,
    ) -> T {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(found) = pick(rx.recv().await.expect("channel open")) {
                    return found;
                }
            }
        })
        .await
        .expect("expected message should arrive")
    }

    /// Bridge a fresh duplex stream and return its id and the peer end.
    async fn bridged(
        manager: &Arc<ConnectorManager>,
        rx: &mut mpsc::Receiver<Message>,
        buf: usize,
    ) -> (u32, tokio::io::DuplexStream) {
        let (peer_end, stream) = duplex(buf);
        manager
            .bridge("http://example.internal", stream)
            .expect("bridge should start");
        let stream_id = next_matching(rx, |m| match m {
            Message::Connect { stream_id, .. } => Some(stream_id),
            _ => None,
        })
        .await;
        (stream_id, peer_end)
    }

    #[tokio::test]
    async fn shutdown_clears_pending_and_established_streams() {
        let (manager, mut rx) = test_manager(8);
        let (pending_id, _a) = bridged(&manager, &mut rx, 64).await;
        let (open_id, _b) = bridged(&manager, &mut rx, 64).await;
        manager.handle_message(Message::ConnectOk { stream_id: open_id });

        // Pending until ConnectOk; download map is registered early for reordered Data.
        assert!(manager.pending.read().contains_key(&pending_id));
        assert!(!manager.pending.read().contains_key(&open_id));
        assert_eq!(manager.streams.read().len(), 2);
        assert_eq!(manager.active_streams.load(Ordering::Acquire), 2);

        manager.shutdown();
        assert!(manager.pending.read().is_empty());
        assert!(manager.streams.read().is_empty());
        assert_eq!(manager.active_streams.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn early_data_before_connect_ok_is_delivered() {
        let (manager, mut rx) = test_manager(4);
        let (stream_id, mut peer_end) = bridged(&manager, &mut rx, 256).await;

        // Reordering: response Data before ConnectOk.
        manager.handle_message(Message::Data {
            stream_id,
            payload: Bytes::from_static(b"early-body"),
        });
        manager.handle_message(Message::ConnectOk { stream_id });

        let mut buf = [0u8; 32];
        let n = tokio::time::timeout(Duration::from_secs(1), peer_end.read(&mut buf))
            .await
            .expect("read should not time out")
            .expect("read should succeed");
        assert_eq!(&buf[..n], b"early-body");
    }

    #[tokio::test]
    async fn downstream_eof_notifies_connector_request_complete() {
        let (manager, mut rx) = test_manager(4);
        let (stream_id, mut peer_end) = bridged(&manager, &mut rx, 64).await;
        manager.handle_message(Message::ConnectOk { stream_id });

        peer_end.shutdown().await.expect("peer shutdown");
        let closed = next_matching(&mut rx, |m| match m {
            Message::Close { stream_id } => Some(stream_id),
            _ => None,
        })
        .await;
        assert_eq!(closed, stream_id);
    }

    /// QUIC frees the pre-opened data stream only on `Reset`, so a failed connect
    /// must still abort it.
    #[tokio::test]
    async fn connect_err_aborts_the_pre_splice_stream() {
        let (manager, mut rx) = test_manager(8);
        let (stream_id, _peer) = bridged(&manager, &mut rx, 64).await;
        manager.handle_message(Message::ConnectErr {
            stream_id,
            error: "backend refused".to_string(),
        });

        let reset = next_matching(&mut rx, |m| match m {
            Message::Reset { stream_id } => Some(stream_id),
            _ => None,
        })
        .await;
        assert_eq!(reset, stream_id);
        assert!(manager.streams.read().is_empty());
        assert_eq!(manager.active_streams.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn download_over_window_without_drain_is_reset_as_violation() {
        let (manager, mut rx) = test_manager(64);
        // Tiny downstream so the writer blocks and nothing meaningfully drains.
        let (stream_id, _peer) = bridged(&manager, &mut rx, 64).await;
        manager.handle_message(Message::ConnectOk { stream_id });

        // An honest connector never exceeds the window; push one byte past it.
        let chunk = Bytes::from(vec![0u8; 64 * 1024]);
        for _ in 0..(STREAM_RECV_WINDOW / chunk.len()) {
            manager.handle_message(Message::Data {
                stream_id,
                payload: chunk.clone(),
            });
        }
        assert!(manager.streams.read().contains_key(&stream_id));
        manager.handle_message(Message::Data {
            stream_id,
            payload: Bytes::from_static(b"x"),
        });
        assert!(!manager.streams.read().contains_key(&stream_id));

        let reset = next_matching(&mut rx, |m| match m {
            Message::Reset { stream_id } => Some(stream_id),
            _ => None,
        })
        .await;
        assert_eq!(reset, stream_id);
    }

    #[tokio::test]
    async fn upload_pauses_at_window_and_resumes_on_window_update() {
        let (manager, mut rx) = test_manager(256);
        let (stream_id, mut peer_end) = bridged(&manager, &mut rx, 2 * STREAM_RECV_WINDOW).await;
        manager.handle_message(Message::ConnectOk { stream_id });

        // More than one window of upload; the upload must stop at the boundary.
        peer_end
            .write_all(&vec![0u8; STREAM_RECV_WINDOW + 128 * 1024])
            .await
            .expect("client upload should be accepted");
        let mut sent = 0usize;
        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
        {
            if let Message::Data { payload, .. } = msg {
                sent += payload.len();
            }
        }
        assert!(
            sent <= STREAM_RECV_WINDOW,
            "upload exceeded the window (sent {sent})"
        );
        assert!(
            sent > STREAM_RECV_WINDOW - TUNNEL_READ_CHUNK,
            "used ~the whole window (sent {sent})"
        );

        manager.handle_message(Message::WindowUpdate {
            stream_id,
            bytes: 64 * 1024,
        });
        let resumed = next_matching(&mut rx, |m| match m {
            Message::Data { payload, .. } => Some(payload.len()),
            _ => None,
        })
        .await;
        assert!(resumed > 0);
    }

    #[tokio::test]
    async fn bridge_rejects_connections_past_stream_cap() {
        let (manager, _rx) = test_manager(MAX_ACTIVE_STREAMS + 1);
        for _ in 0..MAX_ACTIVE_STREAMS {
            let (_peer_end, stream) = duplex(1);
            assert!(manager.bridge("http://example.internal", stream).is_ok());
        }
        let (_peer_end, stream) = duplex(1);
        let err = manager
            .bridge("http://example.internal", stream)
            .expect_err("connector should reject streams beyond the cap");
        assert!(err.contains("active stream cap"));
    }

    #[test]
    fn unregister_manager_does_not_remove_newer_replacement() {
        let manager = || {
            let (to_tx, _to_rx) = mpsc::channel(4);
            Arc::new(ConnectorManager::new(
                "same-id".to_string(),
                Link::Wss(to_tx),
            ))
        };
        let registry = ConnectorRegistry::default();
        let (old_manager, new_manager) = (manager(), manager());

        registry.register(old_manager.clone());
        registry.register(new_manager.clone());
        registry.unregister_manager(&old_manager);
        let current = registry.get("same-id").expect("replacement should remain");
        assert!(Arc::ptr_eq(&current, &new_manager));

        registry.unregister_manager(&new_manager);
        assert!(registry.get("same-id").is_none());
        registry.register(old_manager);
        registry.unregister("same-id");
        assert!(registry.get("same-id").is_none());
    }

    /// Over QUIC a tunnel is `Connect`, `ConnectOk`, then raw bytes on its own stream.
    #[tokio::test]
    async fn quic_tunnel_splices_after_connect_ok() {
        let (server, connector, _endpoints) = quic_pair().await;
        let manager = Arc::new(ConnectorManager::new("c".to_string(), Link::Quic(server)));

        // Fake connector: answer the Connect, then echo. The outer handle keeps the
        // connection open until the echo is read.
        let fake = connector.clone();
        tokio::spawn(async move {
            let (mut send, mut recv) = fake.accept_bi().await.expect("tunnel stream");
            let Message::Connect { stream_id, target } =
                read_frame(&mut recv).await.expect("frame")
            else {
                panic!("expected Connect");
            };
            assert_eq!(target, "http://example.internal");
            let ok = Message::ConnectOk { stream_id }.frame().expect("frame");
            send.write_all(&ok).await.expect("reply");
            let mut buf = [0u8; 5];
            recv.read_exact(&mut buf).await.expect("request");
            send.write_all(&buf).await.expect("echo");
        });

        let (mut client, stream) = duplex(64);
        manager
            .bridge("http://example.internal", stream)
            .expect("bridge should start");
        client.write_all(b"hello").await.expect("write");
        let mut echo = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echo))
            .await
            .expect("echo should arrive")
            .expect("read");
        assert_eq!(&echo, b"hello");
        drop(connector);
    }

    /// A connected QUIC pair: (server side, connector side, endpoints to keep alive).
    async fn quic_pair() -> (
        quinn::Connection,
        quinn::Connection,
        (quinn::Endpoint, quinn::Endpoint),
    ) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
        let cert_der = cert.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_single_cert(vec![cert_der.clone()], key.into()).expect("tls"),
            "127.0.0.1:0".parse().expect("addr"),
        )
        .expect("server endpoint");
        let addr = server.local_addr().expect("local addr");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).expect("trust cert");
        let mut client =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("client");
        client.set_default_client_config(
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).expect("client tls"),
        );

        let accept = server.accept();
        let connecting = client.connect(addr, "localhost").expect("connect");
        let (server_conn, client_conn) = tokio::join!(
            async { accept.await.expect("incoming").await.expect("accept") },
            async { connecting.await.expect("handshake") }
        );
        (server_conn, client_conn, (server, client))
    }
}
