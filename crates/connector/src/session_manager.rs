//! WSS app mux: each `Connect` opens a backend TCP stream, bridged over `Message::Data`
//! with per-stream credit (`WindowUpdate`) flow control.

use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use x2rp_proto::{
    MAX_ACTIVE_STREAMS, Message, STREAM_RECV_WINDOW, SendCredit, TUNNEL_READ_CHUNK,
    WINDOW_UPDATE_THRESHOLD,
};

use crate::transport::connect_backend;

struct StreamState {
    /// Upload bytes for the backend. `None` after the server's request-side `Close`
    /// (the dropped sender is the EOF); the entry stays until `task` ends, so
    /// half-closed backends still count toward [`MAX_ACTIVE_STREAMS`].
    ///
    /// Unbounded: the server's upload sender is credit-gated to
    /// [`STREAM_RECV_WINDOW`], which is the real byte bound.
    request_tx: Option<mpsc::UnboundedSender<Bytes>>,
    /// Download send credit, replenished by the server's `WindowUpdate`s.
    send_credit: Arc<SendCredit>,
    task: JoinHandle<()>,
}

impl Drop for StreamState {
    /// The task owns the backend socket, so aborting it closes the backend.
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Manages all active streams for a connector connection.
pub(crate) struct SessionManager {
    streams: HashMap<u32, StreamState>,
    outbound: mpsc::Sender<Message>,
}

impl SessionManager {
    pub(crate) fn new(outbound: mpsc::Sender<Message>) -> Self {
        Self {
            streams: HashMap::new(),
            outbound,
        }
    }

    /// Handle an incoming message from the server. Never awaits: the mux loop
    /// must not park behind one stream.
    pub(crate) fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::Connect { stream_id, target } => self.handle_connect(stream_id, target),
            Message::Data { stream_id, payload } => {
                let delivered = self
                    .streams
                    .get(&stream_id)
                    .and_then(|state| state.request_tx.as_ref())
                    .is_none_or(|tx| tx.send(payload).is_ok());
                if !delivered {
                    self.streams.remove(&stream_id);
                }
            }
            // Server request-side EOF: half-close the backend write side, keep reading.
            Message::Close { stream_id } => {
                if let Some(state) = self.streams.get_mut(&stream_id) {
                    state.request_tx = None;
                }
            }
            // Force-close / client gone: drop the backend now (frees the slot).
            Message::Reset { stream_id } => {
                self.streams.remove(&stream_id);
            }
            Message::WindowUpdate { stream_id, bytes } => {
                if let Some(state) = self.streams.get(&stream_id) {
                    state.send_credit.add(bytes as usize);
                }
            }
            _ => {}
        }
    }

    fn handle_connect(&mut self, stream_id: u32, target: String) {
        // Finished handlers free their slot here.
        self.streams.retain(|_, state| !state.task.is_finished());
        if self.streams.remove(&stream_id).is_some() {
            warn!("Replacing duplicate stream {stream_id}");
        }

        let outbound = self.outbound.clone();
        if self.streams.len() >= MAX_ACTIVE_STREAMS {
            warn!("Refusing stream {stream_id}: active stream cap ({MAX_ACTIVE_STREAMS}) reached");
            // Spawned so the overload path cannot park the mux loop on a full queue.
            tokio::spawn(async move {
                let error = "connector overloaded".to_string();
                let _ = outbound
                    .send(Message::ConnectErr { stream_id, error })
                    .await;
            });
            return;
        }

        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let send_credit = Arc::new(SendCredit::new(STREAM_RECV_WINDOW));
        let task = tokio::spawn(stream_handler(
            stream_id,
            target,
            request_rx,
            send_credit.clone(),
            outbound,
        ));
        self.streams.insert(
            stream_id,
            StreamState {
                request_tx: Some(request_tx),
                send_credit,
                task,
            },
        );
    }
}

/// One backend stream. Both directions run inside this task, so aborting it
/// (Reset, session end) drops the backend socket.
async fn stream_handler(
    stream_id: u32,
    target: String,
    mut request_rx: mpsc::UnboundedReceiver<Bytes>,
    send_credit: Arc<SendCredit>,
    outbound: mpsc::Sender<Message>,
) {
    // Race DNS+TCP against the server abandoning the stream (Close drops the sender).
    let connect = connect_backend(&target);
    tokio::pin!(connect);
    let connected = loop {
        tokio::select! {
            biased;
            data = request_rx.recv() => match data {
                None => break Err(io::Error::other("stream abandoned")),
                Some(_) => debug!("Stream {stream_id} ignoring data before backend connect"),
            },
            result = &mut connect => break result,
        }
    };
    let mut backend = match connected {
        Ok(backend) => backend,
        Err(e) => {
            debug!("Stream {stream_id} connect failed: {e}");
            let error = e.to_string();
            let _ = outbound
                .send(Message::ConnectErr { stream_id, error })
                .await;
            return;
        }
    };
    debug!("Stream {stream_id} connected to {target}");
    if outbound
        .send(Message::ConnectOk { stream_id })
        .await
        .is_err()
    {
        return;
    }

    let (mut rd, mut wr) = backend.split();
    let download = async {
        let mut buf = BytesMut::with_capacity(TUNNEL_READ_CHUNK);
        loop {
            // Never hand read_buf zero capacity: that reads as EOF.
            buf.reserve(TUNNEL_READ_CHUNK);
            match rd.read_buf(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let payload = buf.split().freeze();
                    // Pause here (not at the server) when the client is slower than the backend.
                    if !send_credit.acquire(payload.len()).await
                        || outbound
                            .send(Message::Data { stream_id, payload })
                            .await
                            .is_err()
                    {
                        return;
                    }
                }
            }
        }
        let _ = outbound.send(Message::Close { stream_id }).await;
    };
    let upload = async {
        let mut drained_since_grant = 0usize;
        while let Some(data) = request_rx.recv().await {
            if wr.write_all(&data).await.is_err() {
                break;
            }
            // Grant drained bytes back so the server's credit-gated upload keeps going.
            drained_since_grant += data.len();
            if drained_since_grant >= WINDOW_UPDATE_THRESHOLD {
                let bytes = drained_since_grant as u32;
                drained_since_grant = 0;
                if outbound
                    .send(Message::WindowUpdate { stream_id, bytes })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
        // Request EOF: half-close so the backend can finish its response.
        let _ = wr.shutdown().await;
    };

    // The response ends the stream (WSS has no per-stream FIN for the upload).
    tokio::pin!(download);
    tokio::select! {
        () = &mut download => {}
        () = upload => download.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn idle_stream(request_tx: mpsc::UnboundedSender<Bytes>) -> StreamState {
        StreamState {
            request_tx: Some(request_tx),
            send_credit: Arc::new(SendCredit::new(STREAM_RECV_WINDOW)),
            task: tokio::spawn(std::future::pending()),
        }
    }

    async fn next(rx: &mut mpsc::Receiver<Message>) -> Message {
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("message should arrive")
            .expect("outbound should stay open")
    }

    /// A stream whose downstream stalls parks on send credit and resumes on
    /// WindowUpdate instead of being reset.
    #[tokio::test]
    async fn exhausted_send_credit_pauses_then_resumes_on_window_update() {
        let (outbound_tx, _outbound_rx) = mpsc::channel(4);
        let mut manager = SessionManager::new(outbound_tx);
        let (request_tx, _request_rx) = mpsc::unbounded_channel();
        let state = idle_stream(request_tx);
        let credit = state.send_credit.clone();
        manager.streams.insert(7, state);

        assert!(credit.acquire(STREAM_RECV_WINDOW).await);
        let waiter = {
            let credit = credit.clone();
            tokio::spawn(async move { credit.acquire(TUNNEL_READ_CHUNK).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "sender must park at zero credit");

        manager.handle_message(Message::WindowUpdate {
            stream_id: 7,
            bytes: TUNNEL_READ_CHUNK as u32,
        });
        assert!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("grant must wake the parked sender")
                .expect("waiter should join")
        );
        assert!(
            manager.streams.contains_key(&7),
            "stream survives backpressure"
        );

        manager.handle_message(Message::Reset { stream_id: 7 });
        assert!(!manager.streams.contains_key(&7), "Reset frees the slot");
    }

    /// `handle_connect` is sync, so "does not block on a full outbound queue" is a
    /// compile-time property; this pins that the refusal consumes no slot.
    #[tokio::test]
    async fn overloaded_connect_refuses_even_when_outbound_queue_is_full() {
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        outbound_tx
            .try_send(Message::Close { stream_id: 42 })
            .expect("prefill");
        let mut manager = SessionManager::new(outbound_tx);
        let mut receivers = Vec::new();
        for stream_id in 0..MAX_ACTIVE_STREAMS as u32 {
            let (request_tx, request_rx) = mpsc::unbounded_channel();
            receivers.push(request_rx);
            manager.streams.insert(stream_id, idle_stream(request_tx));
        }

        manager.handle_connect(999, "http://example.internal".to_string());
        assert!(!manager.streams.contains_key(&999));
        assert_eq!(manager.streams.len(), MAX_ACTIVE_STREAMS);
    }

    #[tokio::test]
    async fn stream_handler_abandons_quickly_when_request_side_closed() {
        let (tx, request_rx) = mpsc::unbounded_channel();
        drop(tx); // server already closed the stream
        let (outbound_tx, mut outbound_rx) = mpsc::channel(4);
        let credit = Arc::new(SendCredit::new(STREAM_RECV_WINDOW));

        tokio::time::timeout(
            Duration::from_millis(200),
            stream_handler(
                7,
                "http://192.0.2.1:9".into(),
                request_rx,
                credit,
                outbound_tx,
            ),
        )
        .await
        .expect("must not wait on backend connect");
        match outbound_rx
            .try_recv()
            .expect("abandon must notify transport")
        {
            Message::ConnectErr {
                stream_id: 7,
                error,
            } => assert!(error.contains("abandoned")),
            other => panic!("expected ConnectErr, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upload_drain_emits_window_update_grants() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 64 * 1024];
            while matches!(sock.read(&mut buf).await, Ok(1..)) {}
        });

        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let (outbound_tx, mut outbound_rx) = mpsc::channel(64);
        let credit = Arc::new(SendCredit::new(STREAM_RECV_WINDOW));
        let handler = tokio::spawn(stream_handler(
            9,
            format!("http://{addr}"),
            request_rx,
            credit,
            outbound_tx,
        ));
        assert!(matches!(
            next(&mut outbound_rx).await,
            Message::ConnectOk { stream_id: 9 }
        ));

        let chunk = Bytes::from(vec![0u8; TUNNEL_READ_CHUNK]);
        for _ in 0..(WINDOW_UPDATE_THRESHOLD / TUNNEL_READ_CHUNK) {
            request_tx.send(chunk.clone()).expect("request queue");
        }
        match next(&mut outbound_rx).await {
            Message::WindowUpdate {
                stream_id: 9,
                bytes,
            } => {
                assert_eq!(bytes as usize, WINDOW_UPDATE_THRESHOLD)
            }
            other => panic!("expected WindowUpdate, got {other:?}"),
        }
        drop(request_tx);
        handler.abort();
    }

    /// An idle backend whose stream is aborted (as a Reset or session end does)
    /// must have its socket closed, not left open.
    #[tokio::test]
    async fn abort_while_backend_idle_closes_backend_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            let _ = accepted_tx.send(sock);
        });

        let (_request_tx, request_rx) = mpsc::unbounded_channel();
        let (outbound_tx, mut outbound_rx) = mpsc::channel(64);
        let credit = Arc::new(SendCredit::new(STREAM_RECV_WINDOW));
        let task = tokio::spawn(stream_handler(
            5,
            format!("http://{addr}"),
            request_rx,
            credit,
            outbound_tx,
        ));
        assert!(matches!(
            next(&mut outbound_rx).await,
            Message::ConnectOk { stream_id: 5 }
        ));
        let mut backend_sock = accepted_rx.await.expect("backend should accept");

        task.abort();
        let _ = task.await;

        let mut buf = [0u8; 16];
        let result =
            tokio::time::timeout(Duration::from_secs(2), backend_sock.read(&mut buf)).await;
        assert!(
            matches!(result, Ok(Ok(0))),
            "backend connection must close after abort (got {result:?})"
        );
    }
}
