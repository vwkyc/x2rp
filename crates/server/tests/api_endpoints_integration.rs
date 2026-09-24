use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use tokio::sync::mpsc;
use x2rp::{
    api::{
        self, AppState, CreateResourceRequest, GlobalState, ServerConfig, UpdateConnectorRequest,
        auth_login, connector_get_settings, create_resource, delete_connector,
        regenerate_connector_token, update_connector,
    },
    auth::{ADMIN_PASSWORD_MAX_LEN, hash_password},
    connector_manager::{ConnectorManager, Link},
};

mod common;
use common::{admin_session_headers, make_state, relay_connector};

fn base_app_state() -> AppState {
    AppState {
        initialized: true,
        server_config: ServerConfig {
            obfuscation_secret: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .to_string(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// State plus an admin session, which every admin-gated endpoint below needs.
fn admin_state(app: AppState) -> (GlobalState, HeaderMap) {
    let state = make_state(app);
    let headers = admin_session_headers(&state);
    (state, headers)
}

fn create_request(subdomain: &str, target: &str, allowlist: &[&str]) -> CreateResourceRequest {
    CreateResourceRequest {
        subdomain: subdomain.to_string(),
        target: target.to_string(),
        connector_id: None,
        allowed_client_cidrs: allowlist.iter().map(ToString::to_string).collect(),
    }
}

#[tokio::test]
async fn auth_login_sets_session_and_csrf_cookies() {
    let password = "very-strong-password";
    let mut app = base_app_state();
    app.admin_password_hash = Some(hash_password(password).expect("password hash should build"));

    let state = make_state(app);
    let resp = auth_login(
        State(state),
        Json(api::auth_api::LoginRequest {
            password: password.to_string(),
        }),
    )
    .await
    .expect("login should succeed")
    .into_response();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let set_cookies: Vec<String> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(ToString::to_string)
        .collect();

    assert!(
        set_cookies
            .iter()
            .any(|c| c.contains("__Host-x2rp_session="))
    );
    assert!(set_cookies.iter().any(|c| c.contains("__Host-x2rp_csrf=")));
}

#[tokio::test]
async fn auth_login_rejects_invalid_password() {
    let mut app = base_app_state();
    app.admin_password_hash =
        Some(hash_password("another-strong-password").expect("password hash should build"));

    let state = make_state(app);
    let result = auth_login(
        State(state),
        Json(api::auth_api::LoginRequest {
            password: "wrong-password".to_string(),
        }),
    )
    .await;

    assert_eq!(result.err(), Some(StatusCode::UNAUTHORIZED));
}

#[tokio::test]
async fn auth_login_rejects_oversized_password_without_hashing() {
    let mut app = base_app_state();
    app.admin_password_hash =
        Some(hash_password("another-strong-password").expect("password hash should build"));

    let state = make_state(app);
    let result = auth_login(
        State(state),
        Json(api::auth_api::LoginRequest {
            password: "x".repeat(ADMIN_PASSWORD_MAX_LEN + 1),
        }),
    )
    .await;

    assert_eq!(result.err(), Some(StatusCode::UNAUTHORIZED));
}

#[tokio::test]
async fn connector_settings_accepts_case_insensitive_bearer_prefix() {
    let token = "dGVzdC10b2tlbg==";
    let connector = relay_connector("relay-1", token);

    let mut app = base_app_state();
    app.connectors.insert(connector.id.clone(), connector);

    let state = make_state(app);

    let mut bad_headers = HeaderMap::new();
    bad_headers.insert("authorization", token.parse().expect("header should parse"));
    let bad = connector_get_settings(State(state.clone()), bad_headers).await;
    assert_eq!(bad.err(), Some(StatusCode::UNAUTHORIZED));

    let mut ok_headers = HeaderMap::new();
    ok_headers.insert(
        "authorization",
        format!("bearer {}", token)
            .parse()
            .expect("header should parse"),
    );
    let ok = connector_get_settings(State(state), ok_headers)
        .await
        .expect("valid bearer auth should succeed");

    assert_eq!(
        ok.0.obfuscation_secret,
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    );
}

#[tokio::test]
async fn create_resource_rejects_target_with_path_or_query() {
    let (state, headers) = admin_state(base_app_state());

    let result = create_resource(
        State(state),
        headers,
        Json(create_request(
            "app",
            "http://127.0.0.1:8080/index.html?x=1",
            &[],
        )),
    )
    .await;

    assert_eq!(result.err(), Some(StatusCode::BAD_REQUEST));
}

#[tokio::test]
async fn create_resource_validates_the_allowlist() {
    let (state, headers) = admin_state(base_app_state());

    let bad = create_resource(
        State(state.clone()),
        headers.clone(),
        Json(create_request(
            "app",
            "http://127.0.0.1:8080",
            &["not-an-ip"],
        )),
    )
    .await;
    assert_eq!(bad.err(), Some(StatusCode::BAD_REQUEST));
    assert!(state.state.read().await.resources.is_empty());

    let created = create_resource(
        State(state),
        headers,
        Json(create_request(
            "app",
            "http://127.0.0.1:8080",
            &["203.0.113.7", "198.51.100.0/24"],
        )),
    )
    .await
    .expect("valid allowlist should be accepted")
    .0;
    assert_eq!(created.allowed_client_cidrs.len(), 2);
}

#[tokio::test]
async fn update_connector_toggles_and_persists_force_wss() {
    let mut app = base_app_state();
    app.connectors
        .insert("relay-1".to_string(), relay_connector("relay-1", "tok"));
    let (state, headers) = admin_state(app);

    let detail = update_connector(
        State(state.clone()),
        headers,
        Path("relay-1".to_string()),
        Json(UpdateConnectorRequest { force_wss: true }),
    )
    .await
    .expect("toggle should succeed")
    .0;
    assert!(detail.force_wss);
    assert!(state.state.read().await.connectors["relay-1"].force_wss);
}

#[tokio::test]
async fn update_connector_kicks_session_only_on_actual_change() {
    let mut app = base_app_state();
    app.connectors
        .insert("relay-1".to_string(), relay_connector("relay-1", "tok"));

    let (state, headers) = admin_state(app);
    let registry = state.proxy_ctx.connectors.clone();
    let (to_connector_tx, _to_connector_rx) = mpsc::channel(4);
    registry.register(Arc::new(ConnectorManager::new(
        "relay-1".to_string(),
        Link::Wss(to_connector_tx),
    )));

    let _ = update_connector(
        State(state.clone()),
        headers.clone(),
        Path("relay-1".to_string()),
        Json(UpdateConnectorRequest { force_wss: false }),
    )
    .await
    .expect("no-op toggle should still succeed");
    assert!(
        registry.get("relay-1").is_some(),
        "unchanged value must not kick a live session"
    );

    let _ = update_connector(
        State(state),
        headers,
        Path("relay-1".to_string()),
        Json(UpdateConnectorRequest { force_wss: true }),
    )
    .await
    .expect("toggle should succeed");
    assert!(
        registry.get("relay-1").is_none(),
        "changed value must drop the live session so the connector re-polls settings"
    );
}

/// A rotated or deleted relay token must not keep a live session: both paths go
/// through one revoke, so each is pinned at the endpoint.
#[tokio::test]
async fn rotating_or_deleting_a_relay_connector_drops_its_live_session() {
    let mut app = base_app_state();
    for id in ["relay-rotate", "relay-delete"] {
        app.connectors
            .insert(id.to_string(), relay_connector(id, &format!("{id}-token")));
    }

    let (state, headers) = admin_state(app);
    let registry = state.proxy_ctx.connectors.clone();
    let mut queues = Vec::new();
    for id in ["relay-rotate", "relay-delete"] {
        let (to_connector_tx, to_connector_rx) = mpsc::channel(4);
        queues.push(to_connector_rx);
        registry.register(Arc::new(ConnectorManager::new(
            id.to_string(),
            Link::Wss(to_connector_tx),
        )));
    }

    let _ = regenerate_connector_token(
        State(state.clone()),
        headers.clone(),
        Path("relay-rotate".to_string()),
    )
    .await
    .expect("rotation should succeed");
    assert!(
        registry.get("relay-rotate").is_none(),
        "the old token's session must be dropped on rotation"
    );

    let status = delete_connector(State(state), headers, Path("relay-delete".to_string()))
        .await
        .expect("delete should succeed");
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        registry.get("relay-delete").is_none(),
        "a deleted connector's session must be dropped"
    );
}
