//! Connector sessions over WebSocket: one TCP connection carries every tunnel, so
//! a slow tunnel can hold up the rest. The fallback; QUIC is preferred.

use std::sync::Arc;
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
use tokio::sync::mpsc;
use tracing::{info, warn};
use x2rp_proto::{
    CONNECTOR_CHANNEL_CAPACITY, HEARTBEAT_INTERVAL_SECS, HEARTBEAT_READ_TIMEOUT_SECS,
    MAX_CONNECTOR_SESSIONS, MAX_MESSAGE_BODY_LEN, Message,
};

use crate::api::GlobalState;
use crate::connector_manager::{ConnectorManager, Link};
use crate::transport::set_last_seen;

/// WebSocket upgrade for a connector, authenticated by its bearer token.
pub async fn connector_connect(
    State(state): State<GlobalState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let connector_id = match crate::api::bearer_token(&headers) {
        Some(token) => {
            let s = state.state.read().await;
            if !s.initialized {
                return (StatusCode::SERVICE_UNAVAILABLE, "Not initialized").into_response();
            }
            crate::api::connector_from_token(&s, token).map(|c| c.id.clone())
        }
        None => None,
    };
    let Some(connector_id) = connector_id else {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    };
    if !state
        .proxy_ctx
        .connectors
        .can_register(&connector_id, MAX_CONNECTOR_SESSIONS)
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many connector connections",
        )
            .into_response();
    }
    ws.max_write_buffer_size(MAX_MESSAGE_BODY_LEN * 2)
        .max_message_size(MAX_MESSAGE_BODY_LEN)
        .max_frame_size(MAX_MESSAGE_BODY_LEN)
        .on_upgrade(move |socket| async move {
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
    if !registry.try_register(manager.clone(), MAX_CONNECTOR_SESSIONS) {
        warn!("WebSocket connector {connector_id} rejected: session limit reached");
        let _ = sink.close().await;
        return;
    }
    set_last_seen(&state, &connector_id).await;
    info!("Connector {connector_id} connected via WebSocket");

    // Valid binary/control frames prove the connector alive; unexpected text frames close the session.
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
                Ok(Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_)))) => continue,
                Ok(Some(Ok(WsMessage::Text(_)))) => "unexpected text frame".to_string(),
                Ok(Some(Err(e))) => e.to_string(),
                Err(_) => "idle timeout".to_string(),
            };
            warn!("WebSocket session for connector {connector_id} ended: {problem}");
            return;
        }
    };
    let write = async {
        const WRITE_TIMEOUT: Duration = Duration::from_secs(HEARTBEAT_READ_TIMEOUT_SECS);
        const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
        let mut ping = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let frame = tokio::select! {
                msg = rx.recv() => match msg.map(|msg| msg.encode()) {
                    Some(Ok(body)) => WsMessage::Binary(body.into()),
                    _ => break,
                },
                _ = ping.tick() => WsMessage::Ping(Default::default()),
            };
            if !matches!(
                tokio::time::timeout(WRITE_TIMEOUT, sink.send(frame)).await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, sink.close()).await;
    };
    // Race shutdown at the top level so kicking a connector whose TCP write buffer
    // is stalled still tears down the session immediately.
    tokio::select! {
        () = shutdown => {}
        () = read => {}
        () = write => {}
    }

    registry.unregister_manager(&manager);
    set_last_seen(&state, &connector_id).await;
    info!("Connector {connector_id} disconnected");
}
