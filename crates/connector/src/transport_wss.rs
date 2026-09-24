//! WebSocket transport (TCP fallback when QUIC cannot connect): one TCP connection
//! carries every tunnel, so a slow tunnel can hold up the rest. Prefer QUIC.

use std::io;
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Message as WsMessage, protocol::WebSocketConfig};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, client_async_tls_with_config};
use x2rp_proto::{
    CONNECTOR_CHANNEL_CAPACITY, HEARTBEAT_READ_TIMEOUT_SECS, MAX_MESSAGE_BODY_LEN, Message,
};

use crate::session_manager::SessionManager;
use crate::transport::{TransportConfig, connect_any};

const WSS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WSS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub(crate) struct WssSession {
    write_tx: mpsc::Sender<WsMessage>,
    ws_read: SplitStream<WsStream>,
}

fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("{what} timed out"))
}

pub(crate) async fn connect(config: &TransportConfig) -> io::Result<WssSession> {
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
        async move {
            let stream = tokio::time::timeout(WSS_CONNECT_TIMEOUT, TcpStream::connect(addr))
                .await
                .map_err(|_| timed_out("WSS TCP connect"))??;
            stream.set_nodelay(true)?;
            let ws_config = WebSocketConfig::default()
                .max_message_size(Some(MAX_MESSAGE_BODY_LEN))
                .max_frame_size(Some(MAX_MESSAGE_BODY_LEN));
            tokio::time::timeout(
                WSS_HANDSHAKE_TIMEOUT,
                client_async_tls_with_config(request, stream, Some(ws_config), None),
            )
            .await
            .map_err(|_| timed_out("WSS handshake"))?
            .map_err(io::Error::other)
        }
    })
    .await?;

    let (sink, ws_read) = ws_stream.split();
    let (write_tx, write_rx) = mpsc::channel(CONNECTOR_CHANNEL_CAPACITY);
    tokio::spawn(write_loop(sink, write_rx));
    Ok(WssSession { write_tx, ws_read })
}

/// A dedicated writer, so a slow send never stalls reading. Ends with the session.
async fn write_loop(mut sink: SplitSink<WsStream, WsMessage>, mut rx: mpsc::Receiver<WsMessage>) {
    while let Some(msg) = rx.recv().await {
        if sink.send(msg).await.is_err() {
            break;
        }
    }
    let _ = sink.close().await;
}

impl WssSession {
    /// The app mux: frames in go to the `SessionManager`, its outbound queue goes
    /// to the writer. `Ok` on a clean close by the server.
    pub(crate) async fn run(mut self) -> io::Result<()> {
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Message>(CONNECTOR_CHANNEL_CAPACITY);
        let mut manager = SessionManager::new(outbound_tx);
        loop {
            tokio::select! {
                msg = self.recv() => match msg? {
                    Some(msg) => manager.handle_message(msg),
                    None => return Ok(()),
                },
                Some(msg) = outbound_rx.recv() => {
                    // Awaits queue capacity only, never the WS sink.
                    self.write_tx
                        .send(WsMessage::Binary(msg.encode()?.into()))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WSS writer closed"))?;
                }
            }
        }
    }

    /// Next protocol message. Any frame, the server's pings included, resets the
    /// idle timeout; tungstenite answers the pings itself.
    async fn recv(&mut self) -> io::Result<Option<Message>> {
        loop {
            let frame = tokio::time::timeout(
                Duration::from_secs(HEARTBEAT_READ_TIMEOUT_SECS),
                self.ws_read.next(),
            )
            .await
            .map_err(|_| timed_out("WSS read waiting for ping or data"))?;

            match frame {
                Some(Ok(WsMessage::Binary(data))) => return Message::decode(data).map(Some),
                Some(Ok(WsMessage::Close(_))) | None => return Ok(None),
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(io::Error::other(e)),
            }
        }
    }
}
