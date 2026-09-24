//! Connector sessions over WebSocket: one TCP connection carries every tunnel, so
//! a slow tunnel can hold up the rest. The fallback; QUIC is preferred.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::{
    extract::{
        State,
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Semaphore, mpsc};
use tracing::{info, warn};
use x2rp_proto::{
    CONNECTOR_CHANNEL_CAPACITY, HEARTBEAT_INTERVAL_SECS, HEARTBEAT_READ_TIMEOUT_SECS,
    MAX_CONNECTOR_SESSIONS, MAX_MESSAGE_BODY_LEN, Message,
};

use crate::api::GlobalState;
use crate::connector_manager::{ConnectorManager, Link};
use crate::transport::set_last_seen;

static WSS_SESSIONS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONNECTOR_SESSIONS)));

/// WebSocket upgrade for a connector, authenticated by its bearer token.
pub async fn connector_connect(
    State(state): State<GlobalState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let connector_id = match crate::api::bearer_token(&headers) {
        Some(token) => crate::api::connector_from_token(&*state.state.read().await, token)
            .map(|c| c.id.clone()),
        None => None,
    };
    let Some(connector_id) = connector_id else {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    };
    let Ok(permit) = WSS_SESSIONS.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many connector connections",
        )
            .into_response();
    };
    ws.max_write_buffer_size(MAX_MESSAGE_BODY_LEN * 2)
        .max_message_size(MAX_MESSAGE_BODY_LEN)
        .max_frame_size(MAX_MESSAGE_BODY_LEN)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            run_session(socket, connector_id, state).await;
        })
}

async fn run_session(socket: WebSocket, connector_id: String, state: GlobalState) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel(CONNECTOR_CHANNEL_CAPACITY);
    let manager = Arc::new(ConnectorManager::new(connector_id.clone(), Link::Wss(tx)));
    // Armed before `register`: a kick landing before the writer polls is not lost.
    let shutdown = manager.shutdown_notify().notified_owned();
    let registry = &state.proxy_ctx.connectors;
    registry.register(manager.clone());
    set_last_seen(&state, &connector_id).await;
    info!("Connector {connector_id} connected via WebSocket");

    // Any frame, the Pong to our Ping included, proves the connector alive.
    let read = async {
        loop {
            let frame = tokio::time::timeout(
                Duration::from_secs(HEARTBEAT_READ_TIMEOUT_SECS),
                stream.next(),
            )
            .await;
            let problem = match frame {
                Ok(Some(Ok(WsMessage::Binary(data)))) => match Message::decode(data) {
                    Ok(msg) => {
                        manager.handle_message(msg);
                        continue;
                    }
                    Err(e) => format!("bad message: {e}"),
                },
                Ok(Some(Ok(WsMessage::Close(_))) | None) => return,
                Ok(Some(Ok(_))) => continue,
                Ok(Some(Err(e))) => e.to_string(),
                Err(_) => "idle timeout".to_string(),
            };
            warn!("WebSocket session for connector {connector_id} ended: {problem}");
            return;
        }
    };
    let write = async {
        let mut ping = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
        tokio::pin!(shutdown);
        loop {
            let frame = tokio::select! {
                msg = rx.recv() => match msg.map(|msg| msg.encode()) {
                    Some(Ok(body)) => WsMessage::Binary(body.into()),
                    _ => break,
                },
                _ = ping.tick() => WsMessage::Ping(Default::default()),
                _ = &mut shutdown => break,
            };
            if sink.send(frame).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    };
    // Either direction ending ends the session.
    tokio::select! {
        () = read => {}
        () = write => {}
    }

    registry.unregister_manager(&manager);
    set_last_seen(&state, &connector_id).await;
    info!("Connector {connector_id} disconnected");
}
