use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode, header},
    middleware::Next,
    response::IntoResponse,
};

use crate::api::{ADMIN_SESSION_COOKIE, GlobalState, extract_cookie};

/// Mutating API requests must carry, in `X-CSRF-Token`, the token minted for the
/// caller's admin session (the admin UI reads it from its CSRF cookie).
pub async fn enforce_api_csrf(
    State(state): State<GlobalState>,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let exempt = matches!(
        req.uri().path(),
        "/auth/login" | "/setup" | "/connector/disconnect"
    );
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe && !exempt {
        let headers = req.headers();
        let token = headers.get("x-csrf-token").and_then(|v| v.to_str().ok());
        let session = headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|cookies| extract_cookie(cookies, ADMIN_SESSION_COOKIE));
        let ok = matches!((token, session), (Some(token), Some(sid)) if state.auth.validate_admin_csrf(sid, token));
        if !ok {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    next.run(req).await
}
