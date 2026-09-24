use axum::{Json, extract::State};
use http::StatusCode;
use serde::Deserialize;

use super::{GlobalState, ServerConfig, is_valid_domain, normalize_domain, random_hex};

#[derive(Deserialize)]
pub struct SetupRequest {
    pub domain: String,
    pub admin_password: String,
    /// Cloudflare API token for wildcard TLS certificates (DNS-01).
    pub cf_api_token: Option<String>,
}

/// POST /api/setup: one-time initialization, refused once set up. Until then only
/// loopback reaches the admin API: the public edge starts once initialized.
pub async fn post_setup(
    State(state): State<GlobalState>,
    Json(req): Json<SetupRequest>,
) -> Result<StatusCode, StatusCode> {
    if state.state.read().await.initialized {
        return Err(StatusCode::CONFLICT);
    }
    let domain = normalize_domain(&req.domain);
    if !is_valid_domain(&domain) {
        tracing::warn!("Invalid domain provided during setup: {}", req.domain);
        return Err(StatusCode::BAD_REQUEST);
    }
    let pw_len = req.admin_password.len();
    if !(crate::auth::ADMIN_PASSWORD_MIN_LEN..=crate::auth::ADMIN_PASSWORD_MAX_LEN)
        .contains(&pw_len)
    {
        tracing::warn!(
            "Admin password invalid (must be {}-{} chars)",
            crate::auth::ADMIN_PASSWORD_MIN_LEN,
            crate::auth::ADMIN_PASSWORD_MAX_LEN
        );
        return Err(StatusCode::BAD_REQUEST);
    }
    let password_hash = crate::auth::hash_password_async(req.admin_password)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut s = state.state.write().await;
    if s.initialized {
        return Err(StatusCode::CONFLICT);
    }
    s.domain = domain;
    s.admin_password_hash = Some(password_hash);
    s.server_config = ServerConfig {
        cf_api_token: req.cf_api_token.unwrap_or_default(),
        obfuscation_secret: random_hex::<32>(),
    };
    s.initialized = true;
    s.save().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tracing::info!("Setup complete for domain: {}", s.domain);
    Ok(StatusCode::OK)
}
