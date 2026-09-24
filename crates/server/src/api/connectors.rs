use axum::{
    Json,
    extract::{Path, State},
};
use chrono::{DateTime, Utc};
use http::HeaderMap;
use serde::{Deserialize, Serialize};

use super::{Connector, GlobalState, bearer_token, hash_token, random_hex, verify_admin};

/// The one-shot install command the admin UI shows with a new token. A release
/// build knows the repository it was published from (`X2RP_REPO`, set by the
/// release workflow), so its command fetches the connector of the same version.
/// A source build points at a local `install-connector.sh`.
fn build_install_command(domain: &str, token: &str) -> String {
    let args = format!("--server https://x2rp.{domain} --token '{token}'");
    match option_env!("X2RP_REPO") {
        Some(repo) => format!(
            "curl -fsSL https://github.com/{repo}/releases/download/v{}/install-connector.sh | sudo bash -s -- {args}",
            env!("CARGO_PKG_VERSION")
        ),
        None => format!("sudo ./install-connector.sh {args}"),
    }
}

pub async fn list_connectors(
    State(state): State<GlobalState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ConnectorDetail>>, http::StatusCode> {
    if !verify_admin(&state, &headers).await {
        return Err(http::StatusCode::UNAUTHORIZED);
    }
    let s = state.state.read().await;
    Ok(Json(
        s.connectors
            .values()
            .map(|connector| connector_detail(connector, &state))
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateConnectorRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct CreateConnectorResponse {
    pub install_command: String,
}

pub async fn create_connector(
    State(state): State<GlobalState>,
    headers: HeaderMap,
    Json(req): Json<CreateConnectorRequest>,
) -> Result<Json<CreateConnectorResponse>, http::StatusCode> {
    if !verify_admin(&state, &headers).await {
        return Err(http::StatusCode::UNAUTHORIZED);
    }
    let name = req.name;
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(http::StatusCode::BAD_REQUEST);
    }

    let mut s = state.state.write().await;
    if s.connectors.values().any(|c| c.name == name) {
        return Err(http::StatusCode::CONFLICT);
    }

    let id = random_hex::<16>();
    let token = random_hex::<32>();
    let install_command = build_install_command(&s.domain, &token);
    s.connectors.insert(
        id.clone(),
        Connector {
            id: id.clone(),
            name,
            token_hash: hash_token(&token),
            force_wss: false,
            last_seen: None,
        },
    );
    if let Err(e) = s.save() {
        // Roll back, so no phantom connector holds a token nobody was shown.
        s.connectors.remove(&id);
        tracing::error!("Failed to save connector creation {}: {}", id, e);
        return Err(http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(CreateConnectorResponse { install_command }))
}

#[derive(Serialize)]
pub struct ConnectorDetail {
    pub id: String,
    pub name: String,
    pub last_seen: Option<DateTime<Utc>>,
    /// QUIC is skipped and the connector uses WebSocket exclusively.
    pub force_wss: bool,
    /// `QUIC` or `WSS` while connected; `null` when offline.
    pub transport: Option<&'static str>,
}

fn connector_detail(connector: &Connector, state: &GlobalState) -> ConnectorDetail {
    let transport = state.proxy_ctx.connectors.transport_label(&connector.id);
    ConnectorDetail {
        id: connector.id.clone(),
        name: connector.name.clone(),
        last_seen: transport.map_or(connector.last_seen, |_| Some(Utc::now())),
        force_wss: connector.force_wss,
        transport,
    }
}

#[derive(Deserialize)]
pub struct UpdateConnectorRequest {
    pub force_wss: bool,
}

/// PUT /api/connectors/{id}: toggle WebSocket-only mode.
///
/// Kicks the live session on change so the connector re-polls settings and
/// reconnects immediately. A save failure warns rather than fails the request:
/// it's a preference, and the in-memory value applies until restart.
pub async fn update_connector(
    State(state): State<GlobalState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpdateConnectorRequest>,
) -> Result<Json<ConnectorDetail>, http::StatusCode> {
    if !verify_admin(&state, &headers).await {
        return Err(http::StatusCode::UNAUTHORIZED);
    }
    let mut s = state.state.write().await;
    let connector = s
        .connectors
        .get_mut(&id)
        .ok_or(http::StatusCode::NOT_FOUND)?;
    let changed = connector.force_wss != req.force_wss;
    connector.force_wss = req.force_wss;

    if changed {
        if let Err(e) = s.save() {
            tracing::warn!("Failed to persist force_wss for {id}: {e}; applies until restart");
        }
        tracing::info!("Connector {} force_wss set to {}", id, req.force_wss);
        state.proxy_ctx.connectors.unregister(&id);
    }

    // Built from the still-held write guard, so a concurrent delete can't turn a
    // successful update into a misleading 404.
    Ok(Json(connector_detail(&s.connectors[&id], &state)))
}

/// POST /api/connector/disconnect: a connector ending its own session.
pub async fn connector_disconnect(
    State(state): State<GlobalState>,
    headers: HeaderMap,
) -> Result<http::StatusCode, http::StatusCode> {
    let token = bearer_token(&headers).ok_or(http::StatusCode::UNAUTHORIZED)?;
    let connector = {
        let s = state.state.read().await;
        if !s.initialized {
            return Err(http::StatusCode::SERVICE_UNAVAILABLE);
        }
        super::connector_from_token(&s, token)
            .cloned()
            .ok_or(http::StatusCode::UNAUTHORIZED)?
    };
    tracing::info!(
        "Connector {} ({}) disconnected itself",
        connector.name,
        connector.id
    );
    state.proxy_ctx.connectors.unregister(&connector.id);
    Ok(http::StatusCode::NO_CONTENT)
}

pub async fn delete_connector(
    State(state): State<GlobalState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<http::StatusCode, http::StatusCode> {
    if !verify_admin(&state, &headers).await {
        return Err(http::StatusCode::UNAUTHORIZED);
    }
    let mut s = state.state.write().await;
    let linked: Vec<&String> = s
        .resources
        .iter()
        .filter(|r| r.connector_id.as_ref() == Some(&id))
        .map(|r| &r.subdomain)
        .collect();
    if !linked.is_empty() {
        tracing::warn!("Cannot delete connector {id}: resources still use it: {linked:?}");
        return Err(http::StatusCode::CONFLICT);
    }

    let connector = s
        .connectors
        .remove(&id)
        .ok_or(http::StatusCode::NOT_FOUND)?;
    if let Err(e) = s.save() {
        // Restore, so disk and memory stay aligned for a retry.
        s.connectors.insert(id.clone(), connector);
        tracing::error!("Failed to save connector deletion {}: {}", id, e);
        return Err(http::StatusCode::INTERNAL_SERVER_ERROR);
    }
    // Only after the save: a failed delete must not leave the connector cut off.
    state.proxy_ctx.connectors.unregister(&id);
    Ok(http::StatusCode::NO_CONTENT)
}

pub async fn regenerate_connector_token(
    State(state): State<GlobalState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<CreateConnectorResponse>, http::StatusCode> {
    if !verify_admin(&state, &headers).await {
        return Err(http::StatusCode::UNAUTHORIZED);
    }
    let mut s = state.state.write().await;
    let token = random_hex::<32>();
    let connector = s
        .connectors
        .get_mut(&id)
        .ok_or(http::StatusCode::NOT_FOUND)?;
    let old_hash = std::mem::replace(&mut connector.token_hash, hash_token(&token));

    if let Err(e) = s.save() {
        // Roll back, so the live connector is not locked out by an unsaved token.
        if let Some(connector) = s.connectors.get_mut(&id) {
            connector.token_hash = old_hash;
        }
        tracing::error!("Failed to save token regenerate for {}: {}", id, e);
        return Err(http::StatusCode::INTERNAL_SERVER_ERROR);
    }
    let install_command = build_install_command(&s.domain, &token);
    drop(s);

    // The old token's session must not outlive it.
    state.proxy_ctx.connectors.unregister(&id);
    Ok(Json(CreateConnectorResponse { install_command }))
}

/// Response for connector settings (auth check + QUIC obfuscation secret).
#[derive(Serialize)]
pub struct ConnectorSettingsResponse {
    pub obfuscation_secret: String,
    /// Skip QUIC entirely and connect over WebSocket (restricted-network mode).
    pub force_wss: bool,
}

/// GET /api/connector/settings: auth check and QUIC obfuscation secret.
///
/// The secret is server-global, shared by all connectors by design: it is DPI
/// camouflage, not authentication (see `x2rp_proto::obfs`).
pub async fn connector_get_settings(
    State(state): State<GlobalState>,
    headers: HeaderMap,
) -> Result<Json<ConnectorSettingsResponse>, http::StatusCode> {
    let s = state.state.read().await;
    if !s.initialized {
        return Err(http::StatusCode::SERVICE_UNAVAILABLE);
    }
    let token = bearer_token(&headers).ok_or(http::StatusCode::UNAUTHORIZED)?;
    let connector = super::connector_from_token(&s, token).ok_or_else(|| {
        tracing::warn!("Connector settings request with invalid token");
        http::StatusCode::UNAUTHORIZED
    })?;
    let obfuscation_secret = s.server_config.obfuscation_secret.clone();
    if obfuscation_secret.is_empty() {
        tracing::error!("Connector settings requested but the obfuscation secret is missing");
        return Err(http::StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok(Json(ConnectorSettingsResponse {
        obfuscation_secret,
        force_wss: connector.force_wss,
    }))
}

#[cfg(test)]
mod tests {
    use super::build_install_command;

    /// Release and source builds word the command differently, but both must end in
    /// the arguments `install-connector.sh` parses, with the token single-quoted.
    #[test]
    fn install_command_ends_with_the_installer_arguments() {
        let cmd = build_install_command("example.com", "0af1");
        assert!(cmd.contains("install-connector.sh"), "{cmd}");
        assert!(
            cmd.ends_with(" --server https://x2rp.example.com --token '0af1'"),
            "{cmd}"
        );
    }
}
