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
            "Admin password invalid (must be {}-{} bytes)",
            crate::auth::ADMIN_PASSWORD_MIN_LEN,
            crate::auth::ADMIN_PASSWORD_MAX_LEN
        );
        return Err(StatusCode::BAD_REQUEST);
    }
    let cf_api_token = req
        .cf_api_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            tracing::warn!("Cloudflare API token is required during setup");
            StatusCode::BAD_REQUEST
        })?
        .to_string();
    let password_hash = crate::auth::hash_password_async(req.admin_password)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut s = state.state.write().await;
    if s.initialized {
        return Err(StatusCode::CONFLICT);
    }
    let prev_domain = std::mem::replace(&mut s.domain, domain);
    let prev_hash = s.admin_password_hash.replace(password_hash);
    let prev_config = std::mem::replace(
        &mut s.server_config,
        ServerConfig {
            cf_api_token,
            obfuscation_secret: random_hex::<32>(),
        },
    );
    s.initialized = true;
    if let Err(e) = s.save() {
        // Roll back so a transient disk failure does not leave setup wedged at 409.
        s.domain = prev_domain;
        s.admin_password_hash = prev_hash;
        s.server_config = prev_config;
        s.initialized = false;
        tracing::error!("Failed to save initial setup: {e}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    tracing::info!("Setup complete for domain: {}", s.domain);
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::AppState;
    use crate::proxy::ProxyContext;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn uninitialized_state(state_file: PathBuf) -> GlobalState {
        GlobalState {
            state: Arc::new(RwLock::new(AppState {
                state_file: Some(state_file),
                ..Default::default()
            })),
            auth: Arc::default(),
            proxy_ctx: Arc::new(ProxyContext::new("", Arc::default())),
        }
    }

    #[tokio::test]
    async fn post_setup_requires_cf_token_and_rolls_back_on_save_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = uninitialized_state(dir.path().join("state.json"));
        let empty_token = post_setup(
            State(state.clone()),
            Json(SetupRequest {
                domain: "example.com".into(),
                admin_password: "a-very-strong-password".into(),
                cf_api_token: Some("   ".into()),
            }),
        )
        .await;
        assert_eq!(empty_token, Err(StatusCode::BAD_REQUEST));

        // Point state_file at a directory so `save()` fails cleanly and must roll back.
        let unwritable = uninitialized_state(dir.path().to_path_buf());
        let failed = post_setup(
            State(unwritable.clone()),
            Json(SetupRequest {
                domain: "example.com".into(),
                admin_password: "a-very-strong-password".into(),
                cf_api_token: Some("cf-token".into()),
            }),
        )
        .await;
        assert_eq!(failed, Err(StatusCode::INTERNAL_SERVER_ERROR));
        let s = unwritable.state.read().await;
        assert!(!s.initialized);
        assert!(s.domain.is_empty());
        assert!(s.admin_password_hash.is_none());
        assert!(s.server_config.cf_api_token.is_empty());
    }
}
