use chrono::Utc;

use crate::api::GlobalState;

pub mod quic;
pub mod websocket;

/// Stamped on connect and disconnect; while connected the API reports "now".
pub(crate) async fn set_last_seen(state: &GlobalState, connector_id: &str) {
    if let Some(connector) = state.state.write().await.connectors.get_mut(connector_id) {
        connector.last_seen = Some(Utc::now());
    }
}
