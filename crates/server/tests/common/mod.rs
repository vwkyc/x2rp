//! Fixtures shared by the integration test binaries.
//!
//! Every binary compiles its own copy of this module, so only the helpers a given
//! test file uses are live there.
#![allow(dead_code)]

use std::sync::Arc;

use http::{HeaderMap, header};
use tokio::sync::RwLock;
use x2rp::{
    api::{self, AppState, Connector, GlobalState},
    auth::AuthService,
    proxy::ProxyContext,
};

/// The one `GlobalState` literal for every test binary, so a new field on the struct
/// is a single edit here rather than one per test file.
pub fn make_state_with_auth(mut app: AppState, auth: Arc<AuthService>) -> GlobalState {
    // Never the real /var/lib/x2rp/state.json, even when run as root.
    static STATE_DIR: std::sync::LazyLock<tempfile::TempDir> =
        std::sync::LazyLock::new(|| tempfile::tempdir().expect("tempdir should create"));
    app.state_file = Some(
        STATE_DIR
            .path()
            .join(format!("state-{}.json", api::random_hex::<8>())),
    );
    GlobalState {
        state: Arc::new(RwLock::new(app)),
        auth,
        proxy_ctx: Arc::new(ProxyContext::new("example.com", Arc::default())),
    }
}

pub fn make_state(app: AppState) -> GlobalState {
    make_state_with_auth(app, Arc::default())
}

/// State for a registered relay connector; its transport registers into
/// `state.proxy_ctx.connectors`.
pub fn make_transport_state(connector: Connector) -> (GlobalState, Arc<ProxyContext>) {
    let mut app = AppState {
        initialized: true,
        ..Default::default()
    };
    app.connectors.insert(connector.id.clone(), connector);
    let state = make_state(app);
    let proxy_ctx = state.proxy_ctx.clone();
    (state, proxy_ctx)
}

pub fn relay_connector(id: &str, token: &str) -> Connector {
    Connector {
        id: id.to_string(),
        name: id.to_string(),
        token_hash: api::hash_token(token),
        force_wss: false,
        last_seen: None,
    }
}

/// Cookie header carrying a fresh admin session minted on `state`.
pub fn admin_session_headers(state: &GlobalState) -> HeaderMap {
    let (session_id, _csrf) = state.auth.create_admin_session();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("__Host-x2rp_session={session_id}")
            .parse()
            .expect("cookie should parse"),
    );
    headers
}
