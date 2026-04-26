// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Integration tests for WebSocket upgrade proxying.

use futures::{SinkExt, StreamExt};
use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, parse_body, parse_status, simple_proxy_yaml, start_header_echo_backend_with_shutdown,
    start_proxy, start_websocket_echo_backend,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        Message,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_upgrade_succeeds() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, resp) = connect_async(&url).await.expect("WebSocket handshake failed");

    assert_eq!(resp.status(), 101, "proxy should forward 101 Switching Protocols");

    ws.send(Message::Text("hello".into())).await.unwrap();
    let echo = ws.next().await.unwrap().unwrap();
    assert_eq!(
        echo,
        Message::Text("hello".into()),
        "echo backend should reflect the message"
    );

    ws.send(Message::Text("world".into())).await.unwrap();
    let echo = ws.next().await.unwrap().unwrap();
    assert_eq!(echo, Message::Text("world".into()), "multiple messages should work");

    ws.close(None).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_binary_messages() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let payload: bytes::Bytes = vec![0xDE, 0xAD, 0xBE, 0xEF].into();
    ws.send(Message::Binary(payload.clone())).await.unwrap();
    let echo = ws.next().await.unwrap().unwrap();
    assert_eq!(
        echo,
        Message::Binary(payload),
        "binary messages should be echoed correctly"
    );

    ws.close(None).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_message_ordering_preserved() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, _) = connect_async(&url).await.unwrap();

    for i in 0..50 {
        ws.send(Message::Text(format!("msg-{i}").into())).await.unwrap();
    }

    for i in 0..50 {
        let echo = ws.next().await.unwrap().unwrap();
        assert_eq!(
            echo,
            Message::Text(format!("msg-{i}").into()),
            "message {i} should echo in order"
        );
    }

    ws.close(None).await.ok();
}

#[test]
fn non_upgrade_request_strips_all_hop_by_hop() {
    let backend_guard = start_header_echo_backend_with_shutdown();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Keep-Alive: 300\r\n\
         X-Normal: keep\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(
        !body_lower.contains("keep-alive"),
        "Keep-Alive should be stripped: {body}"
    );
    assert!(
        body_lower.contains("x-normal"),
        "Normal headers should be preserved: {body}"
    );
}

#[test]
fn upgrade_request_preserves_upgrade_headers() {
    let backend_guard = start_header_echo_backend_with_shutdown();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Keep-Alive: 300\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(
        body_lower.contains("upgrade"),
        "Upgrade should be preserved for upgrade requests: {body}"
    );
    assert!(
        body_lower.contains("sec-websocket-key"),
        "WebSocket headers should be preserved: {body}"
    );
    assert!(
        !body_lower.contains("keep-alive"),
        "Other hop-by-hop headers should still be stripped: {body}"
    );
}

#[test]
fn upgrade_rejected_by_upstream_returns_normal_response() {
    let backend_guard = start_header_echo_backend_with_shutdown();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let status = parse_status(&raw);

    assert_eq!(status, 200, "non-websocket backend should return normal 200, not 101");
}

#[test]
fn h2c_upgrade_headers_stripped() {
    let backend_guard = start_header_echo_backend_with_shutdown();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: h2c\r\n\
         Connection: Upgrade, HTTP2-Settings\r\n\
         HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(
        !body_lower.contains("upgrade"),
        "h2c Upgrade header must be stripped to prevent smuggling: {body}"
    );
    assert!(
        !body_lower.contains("http2-settings"),
        "HTTP2-Settings must be stripped for h2c requests: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_ping_pong_frames() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, _) = connect_async(&url).await.unwrap();

    ws.send(Message::Ping(vec![1, 2, 3].into())).await.unwrap();
    let reply = ws.next().await.unwrap().unwrap();
    assert!(
        reply.is_pong() || reply.is_ping(),
        "proxy should forward ping/pong frames, got {reply:?}"
    );

    ws.close(None).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_large_message() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let payload: bytes::Bytes = vec![0xAB; 128 * 1024].into();
    ws.send(Message::Binary(payload.clone())).await.unwrap();
    let echo = ws.next().await.unwrap().unwrap();
    assert_eq!(
        echo,
        Message::Binary(payload),
        "128KB binary message should echo correctly"
    );

    ws.close(None).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_multiple_simultaneous_connections() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws1, _) = connect_async(&url).await.unwrap();
    let (mut ws2, _) = connect_async(&url).await.unwrap();
    let (mut ws3, _) = connect_async(&url).await.unwrap();

    ws1.send(Message::Text("from-1".into())).await.unwrap();
    ws2.send(Message::Text("from-2".into())).await.unwrap();
    ws3.send(Message::Text("from-3".into())).await.unwrap();

    let echo1 = ws1.next().await.unwrap().unwrap();
    let echo2 = ws2.next().await.unwrap().unwrap();
    let echo3 = ws3.next().await.unwrap().unwrap();

    assert_eq!(
        echo1,
        Message::Text("from-1".into()),
        "connection 1 should echo independently"
    );
    assert_eq!(
        echo2,
        Message::Text("from-2".into()),
        "connection 2 should echo independently"
    );
    assert_eq!(
        echo3,
        Message::Text("from-3".into()),
        "connection 3 should echo independently"
    );

    ws1.close(None).await.ok();
    ws2.close(None).await.ok();
    ws3.close(None).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_close_with_status_code() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, _) = connect_async(&url).await.unwrap();

    ws.send(Message::Text("before-close".into())).await.unwrap();
    let echo = ws.next().await.unwrap().unwrap();
    assert_eq!(
        echo,
        Message::Text("before-close".into()),
        "message before close should echo"
    );

    let close_frame = CloseFrame {
        code: CloseCode::Normal,
        reason: "done".into(),
    };
    ws.send(Message::Close(Some(close_frame))).await.unwrap();

    let close_result = ws.next().await;
    let got_close = match close_result {
        Some(Ok(msg)) => msg.is_close(),
        Some(Err(_)) | None => true,
    };
    assert!(got_close, "connection should close after close frame");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_via_header_on_upgrade_response() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, resp) = connect_async(&url).await.expect("WebSocket handshake failed");

    assert_eq!(resp.status(), 101, "should get 101 Switching Protocols");

    let via = resp.headers().get("via");
    assert!(via.is_some(), "101 upgrade response should include Via header");
    let via_str = via.unwrap().to_str().unwrap();
    assert!(
        via_str.contains("praxis"),
        "Via header should contain proxy pseudonym 'praxis', got: {via_str}"
    );

    ws.close(None).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_rate_limit_applies_to_upgrade() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let backend_port = ws_backend.port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: rate_limit
        mode: global
        rate: 1.0
        burst: 2
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, resp) = connect_async(&url).await.expect("first upgrade should succeed");
    assert_eq!(resp.status(), 101, "first upgrade should get 101");
    ws.close(None).await.ok();

    let request = "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n";
    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), request);
    let status = parse_status(&raw);

    assert_eq!(
        status, 429,
        "upgrade request past rate limit burst should be rejected with 429"
    );
}
