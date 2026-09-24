use std::sync::Arc;
use std::time::Duration;

use axum::{Router, routing::get};
use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest};
use x2rp::transport::websocket::connector_connect;

mod common;
use common::{make_transport_state, relay_connector};

async fn wait_for_condition(label: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..100 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    panic!("timed out waiting for {}", label);
}

#[tokio::test]
async fn websocket_connector_can_reconnect_without_losing_new_session() {
    let token = "d2Vic29ja2V0LXRlc3QtdG9rZW4=";
    let connector = relay_connector("relay-1", token);

    let (state, proxy_ctx) = make_transport_state(connector);
    let app = Router::new()
        .route("/api/connector/connect", get(connector_connect))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener should have addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test server should run");
    });

    let mut request = format!("ws://127.0.0.1:{}/api/connector/connect", addr.port())
        .into_client_request()
        .expect("request should build");
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", token)
            .parse()
            .expect("authorization header should parse"),
    );
    let (mut first_socket, _) = connect_async(request.clone())
        .await
        .expect("first websocket should connect");

    wait_for_condition("first websocket registration", || {
        proxy_ctx.connectors.get("relay-1").is_some()
    })
    .await;
    let first = proxy_ctx.connectors.get("relay-1").expect("first manager");

    let (mut second_socket, _) = connect_async(request)
        .await
        .expect("second websocket should connect");

    // A lookup already succeeds from the first session; only identity proves
    // the second one registered.
    wait_for_condition("second websocket to replace the first", || {
        proxy_ctx
            .connectors
            .get("relay-1")
            .is_some_and(|manager| !Arc::ptr_eq(&manager, &first))
    })
    .await;

    // Replacing shut the first session down; its teardown must not unregister the
    // replacement. Checked over a window, not at the first poll, so the teardown
    // has actually run.
    let _ = first_socket.close(None).await;
    for _ in 0..25 {
        assert!(
            proxy_ctx.connectors.get("relay-1").is_some(),
            "old session's teardown unregistered its replacement"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    second_socket
        .close(None)
        .await
        .expect("second socket should close cleanly");

    wait_for_condition("all websocket sessions to close", || {
        proxy_ctx.connectors.get("relay-1").is_none()
    })
    .await;

    server.abort();
}
