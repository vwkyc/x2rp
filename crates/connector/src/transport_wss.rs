//! WebSocket transport (TCP fallback when QUIC cannot connect): one TCP connection
//! carries every tunnel, so a slow tunnel can hold up the rest. Prefer QUIC.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Message as WsMessage, protocol::WebSocketConfig};
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream, client_async_tls_with_config};
use x2rp_proto::{
    CONNECTOR_CHANNEL_CAPACITY, HEARTBEAT_READ_TIMEOUT_SECS, MAX_MESSAGE_BODY_LEN, Message,
};

use crate::session_manager::SessionManager;
use crate::transport::{TransportConfig, connect_any};

const WSS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WSS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WSS_WRITE_TIMEOUT: Duration = Duration::from_secs(HEARTBEAT_READ_TIMEOUT_SECS);
const WSS_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub(crate) struct WssSession {
    ws_sink: SplitSink<WsStream, WsMessage>,
    ws_read: SplitStream<WsStream>,
}

fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("{what} timed out"))
}

pub(crate) async fn connect(
    config: &TransportConfig,
    tls_config: &Arc<rustls::ClientConfig>,
) -> io::Result<WssSession> {
    let url = config.server.replacen("https://", "wss://", 1) + "/api/connector/connect";
    let mut request = url.into_client_request().map_err(io::Error::other)?;
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", config.token)
            .parse()
            .map_err(io::Error::other)?,
    );

    let (ws_stream, _response) = connect_any(config, |addr| {
        let request = request.clone();
        let tls_config = Arc::clone(tls_config);
        async move {
            let stream = tokio::time::timeout(WSS_CONNECT_TIMEOUT, TcpStream::connect(addr))
                .await
                .map_err(|_| timed_out("WSS TCP connect"))??;
            stream.set_nodelay(true)?;
            let ws_config = WebSocketConfig::default()
                .max_write_buffer_size(MAX_MESSAGE_BODY_LEN * 2)
                .max_message_size(Some(MAX_MESSAGE_BODY_LEN))
                .max_frame_size(Some(MAX_MESSAGE_BODY_LEN));
            tokio::time::timeout(
                WSS_HANDSHAKE_TIMEOUT,
                client_async_tls_with_config(
                    request,
                    stream,
                    Some(ws_config),
                    Some(Connector::Rustls(tls_config)),
                ),
            )
            .await
            .map_err(|_| timed_out("WSS handshake"))?
            .map_err(io::Error::other)
        }
    })
    .await?;

    let (ws_sink, ws_read) = ws_stream.split();
    Ok(WssSession { ws_sink, ws_read })
}

/// Dedicated writer fed directly from `SessionManager`'s outbound queue, so slow
/// TCP writes never stall the read loop or reset its idle timeout.
async fn write_loop(
    mut sink: SplitSink<WsStream, WsMessage>,
    mut rx: mpsc::Receiver<Message>,
) -> io::Result<()> {
    let mut err = None;
    while let Some(msg) = rx.recv().await {
        let encoded = match msg.encode() {
            Ok(bytes) => bytes,
            Err(e) => {
                err = Some(e);
                break;
            }
        };
        match tokio::time::timeout(
            WSS_WRITE_TIMEOUT,
            sink.send(WsMessage::Binary(encoded.into())),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                err = Some(io::Error::other(e));
                break;
            }
            Err(_) => {
                err = Some(timed_out("WSS write"));
                break;
            }
        }
    }
    let _ = tokio::time::timeout(WSS_CLOSE_TIMEOUT, sink.close()).await;
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

impl WssSession {
    /// The app mux: frames in go to the `SessionManager`, its outbound queue goes
    /// directly to the writer task. `Ok` on a clean close by the server or shutdown.
    pub(crate) async fn run(
        mut self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> io::Result<()> {
        let (outbound_tx, outbound_rx) = mpsc::channel::<Message>(CONNECTOR_CHANNEL_CAPACITY);
        let mut write_task = tokio::spawn(write_loop(self.ws_sink, outbound_rx));
        let mut write_done = false;
        let mut manager = SessionManager::new(outbound_tx);
        let result = loop {
            if *shutdown.borrow() {
                break Ok(());
            }
            tokio::select! {
                _ = shutdown.changed() => break Ok(()),
                msg = recv_message(&mut self.ws_read) => match msg {
                    Ok(Some(msg)) => manager.handle_message(msg),
                    Ok(None) => break Ok(()),
                    Err(e) => break Err(e),
                },
                write_res = &mut write_task => {
                    write_done = true;
                    break match write_res {
                        Ok(Ok(())) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "WSS writer closed")),
                        Ok(Err(e)) => Err(e),
                        Err(e) => Err(io::Error::other(e)),
                    };
                }
            }
        };
        drop(manager);
        if !write_done {
            if *shutdown.borrow() {
                // Wait briefly for `write_loop` to send a WebSocket Close frame.
                let _ = tokio::time::timeout(WSS_CLOSE_TIMEOUT, &mut write_task).await;
            }
            write_task.abort();
        }
        result
    }
}

/// Next protocol message. Any valid frame, the server's pings included, resets the
/// idle timeout; tungstenite answers pings itself.
async fn recv_message(ws_read: &mut SplitStream<WsStream>) -> io::Result<Option<Message>> {
    loop {
        let frame = tokio::time::timeout(
            Duration::from_secs(HEARTBEAT_READ_TIMEOUT_SECS),
            ws_read.next(),
        )
        .await
        .map_err(|_| timed_out("WSS read waiting for ping or data"))?;

        match frame {
            Some(Ok(WsMessage::Binary(data))) => return Message::decode(data).map(Some),
            Some(Ok(WsMessage::Close(_))) | None => return Ok(None),
            Some(Ok(WsMessage::Text(_))) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected text WebSocket frame",
                ));
            }
            Some(Ok(_)) => {}
            Some(Err(e)) => return Err(io::Error::other(e)),
        }
    }
}
