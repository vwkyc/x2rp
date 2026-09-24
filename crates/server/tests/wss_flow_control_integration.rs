//! End-to-end WSS mux flow control: a fast origin streaming through a real
//! WebSocket connector session to a slow downstream reader must be paced by
//! WindowUpdate credit, so the full payload arrives and the stream is never reset.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use axum::{Router, routing::get};
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message as WsMessage, client::IntoClientRequest},
};
use x2rp::transport::websocket::connector_connect;
use x2rp_proto::{
    Message, STREAM_RECV_WINDOW, SendCredit, TUNNEL_READ_CHUNK, WINDOW_UPDATE_THRESHOLD,
};

mod common;
use common::{make_transport_state, relay_connector};

/// Many windows' worth, so the transfer only completes if credit is granted
/// repeatedly rather than once.
const DOWNLOAD_TOTAL: usize = 4 * 1024 * 1024;

fn payload_byte(index: usize) -> u8 {
    (index % 251) as u8
}

fn encode_ws(msg: &Message) -> WsMessage {
    WsMessage::Binary(Bytes::from(msg.encode().expect("message should encode")))
}

#[tokio::test]
async fn slow_reader_download_completes_via_window_updates() {
    let token = "Zmxvdy1jb250cm9sLXRlc3QtdG9rZW4=";
    let connector = relay_connector("relay-fc", token);

    let (state, proxy_ctx) = make_transport_state(connector);
    let app = Router::new()
        .route("/api/connector/connect", get(connector_connect))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener should have addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test server should run");
    });

    let mut request = format!("ws://127.0.0.1:{}/api/connector/connect", addr.port())
        .into_client_request()
        .expect("request should build");
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", token)
            .parse()
            .expect("authorization header should parse"),
    );
    let (socket, _) = connect_async(request)
        .await
        .expect("websocket should connect");
    let (mut ws_sink, mut ws_read) = socket.split();

    // Fake connector: recv task handles Connect/WindowUpdate/Reset; a credit-gated sender streams DOWNLOAD_TOTAL bytes once Connect arrives.
    let send_credit = Arc::new(SendCredit::new(STREAM_RECV_WINDOW));
    let grants_seen = Arc::new(AtomicUsize::new(0));
    let got_reset = Arc::new(AtomicBool::new(false));
    let (connect_tx, mut connect_rx) = mpsc::unbounded_channel::<u32>();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();

    let recv_credit = send_credit.clone();
    let recv_grants = grants_seen.clone();
    let recv_reset = got_reset.clone();
    let recv_out = out_tx.clone();
    let recv_task = tokio::spawn(async move {
        while let Some(Ok(frame)) = ws_read.next().await {
            let WsMessage::Binary(data) = frame else {
                continue;
            };
            match Message::decode(data).expect("server frames should decode") {
                Message::Connect { stream_id, .. } => {
                    let _ = recv_out.send(Message::ConnectOk { stream_id });
                    let _ = connect_tx.send(stream_id);
                }
                Message::WindowUpdate { bytes, .. } => {
                    recv_grants.fetch_add(1, Ordering::Relaxed);
                    recv_credit.add(bytes as usize);
                }
                Message::Reset { .. } => {
                    recv_reset.store(true, Ordering::Release);
                    recv_credit.close();
                    return;
                }
                _ => {}
            }
        }
    });

    // Single writer owns the sink; both the recv task (ConnectOk) and the origin sender below feed it through out_rx.
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if ws_sink.send(encode_ws(&msg)).await.is_err() {
                break;
            }
        }
    });

    // Bridge a downstream socket once the session registers.
    for _ in 0..100 {
        if proxy_ctx.connectors.get("relay-fc").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let manager = proxy_ctx
        .connectors
        .get("relay-fc")
        .expect("connector session should be registered");

    let (mut peer_end, downstream) = tokio::io::duplex(64 * 1024);
    manager
        .bridge("http://origin.internal:80", downstream)
        .expect("bridge should start");

    let stream_id = tokio::time::timeout(Duration::from_secs(2), connect_rx.recv())
        .await
        .expect("Connect should reach the connector")
        .expect("connect channel should stay open");

    // Fast origin: emits the whole payload as quickly as credit allows.
    let origin_credit = send_credit.clone();
    let origin_out = out_tx;
    let origin_task = tokio::spawn(async move {
        let mut sent = 0usize;
        while sent < DOWNLOAD_TOTAL {
            let len = TUNNEL_READ_CHUNK.min(DOWNLOAD_TOTAL - sent);
            let mut chunk = BytesMut::with_capacity(len);
            for i in 0..len {
                chunk.extend_from_slice(&[payload_byte(sent + i)]);
            }
            if !origin_credit.acquire(len).await {
                return sent; // reset mid-transfer
            }
            if origin_out
                .send(Message::Data {
                    stream_id,
                    payload: chunk.freeze(),
                })
                .is_err()
            {
                return sent;
            }
            sent += len;
        }
        let _ = origin_out.send(Message::Close { stream_id });
        sent
    });

    // Slow downstream client: ~64 KiB per 15 ms (≈4 MiB/s). Without flow control the origin would run more than a window ahead and the stream would reset.
    let mut received = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    let read_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let n = tokio::time::timeout_at(read_deadline, peer_end.read(&mut buf))
            .await
            .expect("download should not stall")
            .expect("downstream read should succeed");
        if n == 0 {
            break;
        }
        for (i, byte) in buf[..n].iter().enumerate() {
            assert_eq!(
                *byte,
                payload_byte(received + i),
                "payload corrupted at offset {}",
                received + i
            );
        }
        received += n;
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    assert_eq!(
        received, DOWNLOAD_TOTAL,
        "slow reader must receive the full payload, not a truncated stream"
    );
    let sent = tokio::time::timeout(Duration::from_secs(5), origin_task)
        .await
        .expect("origin should finish")
        .expect("origin task should join");
    assert_eq!(sent, DOWNLOAD_TOTAL);
    assert!(
        !got_reset.load(Ordering::Acquire),
        "stream must be paced, never reset"
    );
    // Credit really cycled: ~TOTAL / threshold grants for a paced transfer.
    let grants = grants_seen.load(Ordering::Relaxed);
    assert!(
        grants >= (DOWNLOAD_TOTAL / WINDOW_UPDATE_THRESHOLD) / 2,
        "expected sustained WindowUpdate grants, saw {grants}"
    );

    recv_task.abort();
    writer_task.abort();
    server.abort();
}
