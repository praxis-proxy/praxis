// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the `WebSocket` proxy example configuration.

use std::collections::HashMap;

use futures::{SinkExt as _, StreamExt as _};
use praxis_test_utils::{free_port, start_websocket_echo_backend};
use tokio_tungstenite::{connect_async, tungstenite::Message};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_example_config_proxies_upgrade() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let config = super::load_example_config(
        "protocols/websocket.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", ws_backend.port())]),
    );
    let _proxy = praxis_test_utils::start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, resp) = connect_async(&url)
        .await
        .expect("WebSocket handshake failed through example config");

    assert_eq!(resp.status(), 101, "example config should proxy WebSocket upgrade");

    ws.send(Message::Text("example-test".into())).await.unwrap();
    let echo = ws.next().await.unwrap().unwrap();
    assert_eq!(
        echo,
        Message::Text("example-test".into()),
        "example config should echo messages bidirectionally"
    );

    ws.close(None).await.unwrap();
}
