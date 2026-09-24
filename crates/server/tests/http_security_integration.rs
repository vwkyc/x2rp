use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    middleware,
    routing::post,
};
use std::sync::Arc;
use tower::ServiceExt;
use x2rp::api::{AppState, GlobalState};
use x2rp::auth::AuthService;
use x2rp::http_middleware::enforce_api_csrf;

mod common;
use common::make_state_with_auth;

fn test_auth() -> Arc<AuthService> {
    Arc::default()
}

fn test_state(auth: Arc<AuthService>) -> GlobalState {
    make_state_with_auth(
        AppState {
            initialized: true,
            ..Default::default()
        },
        auth,
    )
}

/// One always-200 route behind the CSRF layer, so each test asserts only what the
/// middleware did.
fn csrf_app(state: GlobalState, path: &str) -> Router {
    Router::new()
        .route(path, post(|| async { StatusCode::OK }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_api_csrf,
        ))
        .with_state(state)
}

#[tokio::test]
async fn csrf_blocks_mutating_request_without_matching_token() {
    let app = csrf_app(test_state(test_auth()), "/resource");

    let req = Request::builder()
        .method("POST")
        .uri("/resource")
        .body(Body::empty())
        .expect("request should build");

    let resp = app.oneshot(req).await.expect("middleware should respond");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn csrf_allows_mutating_request_with_session_bound_token() {
    let auth = test_auth();
    let (session_id, csrf) = auth.create_admin_session();
    let app = csrf_app(test_state(auth), "/resource");

    let cookie = format!("__Host-x2rp_session={session_id}; __Host-x2rp_csrf={csrf}");
    let req = Request::builder()
        .method("POST")
        .uri("/resource")
        .header(header::COOKIE, cookie)
        .header("x-csrf-token", csrf)
        .body(Body::empty())
        .expect("request should build");

    let resp = app.oneshot(req).await.expect("middleware should forward");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn csrf_rejects_cookie_header_match_without_session_binding() {
    let app = csrf_app(test_state(test_auth()), "/resource");

    // Classic double-submit without a valid admin session must fail.
    let req = Request::builder()
        .method("POST")
        .uri("/resource")
        .header(header::COOKIE, "__Host-x2rp_csrf=forged-token")
        .header("x-csrf-token", "forged-token")
        .body(Body::empty())
        .expect("request should build");

    let resp = app.oneshot(req).await.expect("middleware should respond");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Header and cookie agree, and the session is real, but the token was minted for
/// another session: exactly what "session-bound" has to reject.
#[tokio::test]
async fn csrf_rejects_token_minted_for_another_session() {
    let auth = test_auth();
    let (session_id, _) = auth.create_admin_session();
    let (_, other_csrf) = auth.create_admin_session();
    let app = csrf_app(test_state(auth), "/resource");

    let req = Request::builder()
        .method("POST")
        .uri("/resource")
        .header(
            header::COOKIE,
            format!("__Host-x2rp_session={session_id}; __Host-x2rp_csrf={other_csrf}"),
        )
        .header("x-csrf-token", other_csrf)
        .body(Body::empty())
        .expect("request should build");

    let resp = app.oneshot(req).await.expect("middleware should respond");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn csrf_exempts_auth_login_path() {
    let app = csrf_app(test_state(test_auth()), "/auth/login");

    let req = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .body(Body::empty())
        .expect("request should build");

    let resp = app.oneshot(req).await.expect("middleware should forward");
    assert_eq!(resp.status(), StatusCode::OK);
}
