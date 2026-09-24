use axum::response::IntoResponse;
use axum::{Json, extract::State};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Deserialize;

use super::GlobalState;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

/// Admin login: password only. Sets the HttpOnly session cookie and the CSRF cookie.
///
/// Guessing is bounded by the edge's login rate limit, the response-time floor below,
/// and the Argon2 semaphore (two verifies at once, server-wide).
pub async fn auth_login(
    State(state): State<GlobalState>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let password_hash = {
        let s = state.state.read().await;
        if !s.initialized {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        s.admin_password_hash
            .clone()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
    };

    // Reject oversized passwords before Argon2 (CPU DoS). Length is not secret.
    if req.password.len() > crate::auth::ADMIN_PASSWORD_MAX_LEN {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // A floor delay, so success and failure cannot be told apart by response time.
    const LOGIN_MIN_DURATION: std::time::Duration = std::time::Duration::from_millis(500);
    let started = std::time::Instant::now();
    let valid = crate::auth::verify_password_async(req.password, password_hash).await;
    if let Some(remaining) = LOGIN_MIN_DURATION.checked_sub(started.elapsed()) {
        tokio::time::sleep(remaining).await;
    }
    if !valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let (session_id, csrf_token) = state.auth.create_admin_session();
    tracing::info!("Admin logged in");

    // Max-Age tracks the server-side absolute TTL; a cookie outliving the session
    // only yields a redirect to login, but the two should not drift.
    let max_age = crate::auth::SESSION_ABSOLUTE_TTL_SECS;
    let cookies = [
        format!(
            "{}={session_id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}",
            crate::api::ADMIN_SESSION_COOKIE
        ),
        format!(
            "{}={csrf_token}; Path=/; Secure; SameSite=Strict; Max-Age={max_age}",
            crate::api::ADMIN_CSRF_COOKIE
        ),
    ];
    let mut headers = HeaderMap::new();
    for cookie in cookies {
        let value =
            HeaderValue::from_str(&cookie).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        headers.append(header::SET_COOKIE, value);
    }
    Ok((headers, StatusCode::NO_CONTENT))
}
