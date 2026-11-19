// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for cookie-based sticky sessions.

use std::collections::HashMap;

use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext, TerminalResponse};
use praxis_test_utils::{
    free_port, http_send, parse_body, parse_header_all, parse_status, registry_with, start_backend_with_shutdown,
    start_proxy, start_proxy_with_registry, start_request_counting_backend,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn sticky_sessions_cookie_pins_to_same_backend() {
    let port_a_guard = start_backend_with_shutdown("ss-a");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("ss-b");
    let port_b = port_b_guard.port();
    let port_c_guard = start_backend_with_shutdown("ss-c");
    let port_c = port_c_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/sticky-sessions.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
            // The example config declares three listeners; remap the two this
            // test does not exercise to free ports so the proxy does not bind
            // the literal 8081/8082 (an EADDRINUSE flake under concurrency).
            ("127.0.0.1:8081", free_port()),
            ("127.0.0.1:8082", free_port()),
        ]),
    );
    let proxy = start_proxy(&config);

    // First request — should get a Set-Cookie header.
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let first_body = parse_body(&raw);
    let set_cookies = parse_header_all(&raw, "set-cookie");
    let set_cookie = set_cookies
        .first()
        .expect("first response should contain Set-Cookie header");
    assert!(
        set_cookie.contains("_praxis_sticky="),
        "Set-Cookie should contain the configured cookie name, got: {set_cookie}"
    );

    // Extract cookie value for subsequent requests.
    let cookie_val = set_cookie.split(';').next().unwrap_or_default().trim();

    // Subsequent requests with the cookie should always reach the same backend.
    for _ in 0..5 {
        let raw = http_send(
            proxy.addr(),
            &format!(
                "GET / HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Cookie: {cookie_val}\r\n\
                 Connection: close\r\n\r\n"
            ),
        );
        let body = parse_body(&raw);
        assert_eq!(
            body, first_body,
            "cookie-pinned requests must always route to the same backend"
        );
    }
}

#[test]
fn sticky_sessions_header_pins_to_same_backend() {
    let port_a_guard = start_backend_with_shutdown("hdr-a");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("hdr-b");
    let port_b = port_b_guard.port();
    let proxy_port = free_port();
    let header_port = free_port();
    // learn-app lists two distinct endpoints (3021, 3022); this test does not
    // exercise them but they must still map to distinct addresses, since a
    // duplicate endpoint address is rejected by config validation.
    let learn_a = free_port();
    let learn_b = free_port();
    let config = super::load_example_config(
        "traffic-management/sticky-sessions.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:8081", header_port),
            ("127.0.0.1:8082", free_port()),
            ("127.0.0.1:3011", port_a),
            ("127.0.0.1:3012", port_b),
            ("127.0.0.1:3021", learn_a),
            ("127.0.0.1:3022", learn_b),
        ]),
    );
    let proxy = start_proxy(&config);
    let header_addr = format!("127.0.0.1:{header_port}");

    // First request with a session header establishes the binding.
    let raw = http_send(
        &header_addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Session-Id: user-42\r\n\
         Connection: close\r\n\r\n",
    );
    let first_body = parse_body(&raw);
    assert!(
        first_body == "hdr-a" || first_body == "hdr-b",
        "request should reach a backend, got: {first_body}"
    );

    for _ in 0..5 {
        let raw = http_send(
            &header_addr,
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             X-Session-Id: user-42\r\n\
             Connection: close\r\n\r\n",
        );
        assert_eq!(
            parse_body(&raw),
            first_body,
            "header-keyed requests must always route to the same backend"
        );
    }

    drop(proxy);
}

#[test]
fn header_connect_failure_does_not_create_binding_end_to_end() {
    let refused_port = free_port();
    let healthy = start_backend_with_shutdown("healthy");
    let proxy_port = free_port();
    let healthy_port = healthy.port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/session"
            cluster: backend
      - filter: sticky_sessions
        clusters:
          - name: backend
            type: header
            header_name: X-Session-Id
            ttl_secs: 3600
            failover: true
            max_entries: 1000
            eviction: lru
            storage: local
      - filter: load_balancer
        clusters:
          - name: backend
            load_balancer_strategy: round_robin
            retry_policy:
              max_retries: 0
            endpoints: ["127.0.0.1:{refused_port}", "127.0.0.1:{healthy_port}"]
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = praxis_core::config::Config::from_yaml(&yaml).expect("header affinity fixture must validate");
    let proxy = start_proxy(&config);
    let request =
        "GET /session HTTP/1.1\r\nHost: localhost\r\nX-Session-Id: failed-then-healthy\r\nConnection: close\r\n\r\n";

    let failed = http_send(proxy.addr(), request);
    assert_eq!(
        parse_status(&failed),
        502,
        "first round-robin endpoint must refuse connection: {failed}"
    );
    let recovered = http_send(proxy.addr(), request);
    assert_eq!(
        parse_status(&recovered),
        200,
        "failed dial must leave the key unbound: {recovered}"
    );
    assert_eq!(parse_body(&recovered), "healthy");
    let pinned = http_send(proxy.addr(), request);
    assert_eq!(
        parse_status(&pinned),
        200,
        "successful exchange must pin the healthy endpoint: {pinned}"
    );
    assert_eq!(parse_body(&pinned), "healthy");
}

/// Return a local response only after the load balancer has selected a peer.
struct ConditionalTerminalFilter;

#[async_trait::async_trait]
impl HttpFilter for ConditionalTerminalFilter {
    fn name(&self) -> &'static str {
        "test_local_terminal"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if ctx.request.headers.contains_key("x-local-terminal") {
            assert!(
                ctx.upstream.is_some(),
                "terminal fixture must run after endpoint selection"
            );
            let mut headers = http::HeaderMap::new();
            headers.insert("x-fixture-terminal", http::HeaderValue::from_static("local"));
            return Ok(FilterAction::TerminalResponse(Box::new(
                TerminalResponse::new(202)
                    .with_headers(headers)
                    .with_body("local-terminal"),
            )));
        }
        Ok(FilterAction::Continue)
    }
}

#[test]
fn header_local_terminal_response_does_not_bind_end_to_end() {
    use std::sync::atomic::Ordering;

    let (first, first_hits) = start_request_counting_backend("terminal-first");
    let (second, second_hits) = start_request_counting_backend("terminal-second");
    let proxy_port = free_port();
    let first_port = first.port();
    let second_port = second.port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/session"
            cluster: backend
      - filter: sticky_sessions
        clusters:
          - name: backend
            type: header
            header_name: X-Session-Id
            ttl_secs: 3600
            max_entries: 1000
            storage: local
      - filter: load_balancer
        clusters:
          - name: backend
            load_balancer_strategy: round_robin
            endpoints: ["127.0.0.1:{first_port}", "127.0.0.1:{second_port}"]
      - filter: test_local_terminal
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("test_local_terminal", || Box::new(ConditionalTerminalFilter));
    let proxy = start_proxy_with_registry(&config, &registry);
    assert_eq!(
        first_hits.load(Ordering::SeqCst),
        0,
        "readiness must not reach backend A"
    );
    assert_eq!(
        second_hits.load(Ordering::SeqCst),
        0,
        "readiness must not reach backend B"
    );

    let local = http_send(
        proxy.addr(),
        "GET /session HTTP/1.1\r\nHost: localhost\r\nX-Session-Id: terminal-key\r\nX-Local-Terminal: 1\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&local), 202, "terminal status must be delivered: {local}");
    assert_eq!(parse_header_all(&local, "x-fixture-terminal"), vec!["local".to_owned()]);
    assert_eq!(parse_body(&local), "local-terminal");
    assert_eq!(first_hits.load(Ordering::SeqCst), 0, "local response cannot reach A");
    assert_eq!(second_hits.load(Ordering::SeqCst), 0, "local response cannot reach B");

    let normal = "GET /session HTTP/1.1\r\nHost: localhost\r\nX-Session-Id: terminal-key\r\nConnection: close\r\n\r\n";
    let first_forwarded = http_send(proxy.addr(), normal);
    assert_eq!(parse_status(&first_forwarded), 200);
    assert_eq!(parse_body(&first_forwarded), "terminal-second");
    assert_eq!(first_hits.load(Ordering::SeqCst), 0, "local A must remain unbound");
    assert_eq!(second_hits.load(Ordering::SeqCst), 1, "unbound request must select B");

    let pinned = http_send(proxy.addr(), normal);
    assert_eq!(parse_status(&pinned), 200);
    assert_eq!(parse_body(&pinned), "terminal-second");
    assert_eq!(first_hits.load(Ordering::SeqCst), 0, "positive affinity must bypass A");
    assert_eq!(second_hits.load(Ordering::SeqCst), 2, "real forwarding must bind B");
}

/// Header-mode fixture with a visible reload marker and deterministic
/// round-robin order, so a missing binding routes to the second backend.
fn header_reload_yaml(proxy_port: u16, first_port: u16, second_port: u16, marker: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/session"
            cluster: backend
      - filter: sticky_sessions
        clusters:
          - name: backend
            type: header
            header_name: X-Session-Id
            ttl_secs: 3600
            max_entries: 1000
            storage: local
      - filter: load_balancer
        clusters:
          - name: backend
            load_balancer_strategy: round_robin
            endpoints: ["127.0.0.1:{first_port}", "127.0.0.1:{second_port}"]
      - filter: headers
        response_set:
          - name: X-Reload-Marker
            value: "{marker}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

#[test]
fn unchanged_reload_retains_header_binding_without_old_request() {
    let first = start_backend_with_shutdown("reload-first");
    let second = start_backend_with_shutdown("reload-second");
    let proxy_port = free_port();
    let initial = header_reload_yaml(proxy_port, first.port(), second.port(), "v1");
    let reloaded = header_reload_yaml(proxy_port, first.port(), second.port(), "v2");
    let proxy = praxis_test_utils::start_reloadable_proxy(&initial);
    let pinned_request =
        "GET /session HTTP/1.1\r\nHost: localhost\r\nX-Session-Id: retained\r\nConnection: close\r\n\r\n";
    let unbound_request = "GET /session HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    let original = http_send(proxy.addr(), pinned_request);
    assert_eq!(
        parse_body(&original),
        "reload-first",
        "fixture must first bind the first endpoint"
    );
    let probe = proxy.reload_until(
        &reloaded,
        || http_send(proxy.addr(), unbound_request),
        |raw| {
            parse_header_all(raw, "x-reload-marker")
                .iter()
                .any(|value| value == "v2")
        },
    );
    assert!(
        parse_header_all(&probe, "x-reload-marker")
            .iter()
            .any(|value| value == "v2"),
        "new pipeline must serve the probe"
    );
    assert_eq!(
        parse_body(&probe),
        "reload-first",
        "new round robin starts on the first endpoint"
    );

    let retained = http_send(proxy.addr(), pinned_request);
    assert_eq!(
        parse_body(&retained),
        "reload-first",
        "zero-overlap reload must retain the preexisting binding"
    );
}

/// Minimal backend that tags responses with `body` and sets a session cookie,
/// as an application server with server-side sessions would.
fn start_cookie_setting_backend(body: &'static str, session_id: &'static str) -> u16 {
    use std::io::{Read as _, Write as _};

    let (listener, port) = praxis_test_utils::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut buf = [0_u8; 4096];
            let _read = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Length: {}\r\n\
                 Set-Cookie: JSESSIONID={session_id}; Path=/\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _sent = stream.write_all(response.as_bytes());
        }
    });
    port
}

#[test]
fn sticky_sessions_learn_mode_adopts_backend_cookie() {
    let port_a = start_cookie_setting_backend("learn-a", "sess-from-a");
    let port_b = start_cookie_setting_backend("learn-b", "sess-from-b");
    let proxy_port = free_port();
    let learn_port = free_port();
    let config = super::load_example_config(
        "traffic-management/sticky-sessions.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:8081", free_port()),
            ("127.0.0.1:8082", learn_port),
            ("127.0.0.1:3011", port_a),
            ("127.0.0.1:3012", port_b),
            ("127.0.0.1:3021", port_a),
            ("127.0.0.1:3022", port_b),
        ]),
    );
    let proxy = start_proxy(&config);
    let learn_addr = format!("127.0.0.1:{learn_port}");

    // First request: backend issues its session cookie and the proxy learns
    // the binding.
    let raw = http_send(
        &learn_addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let first_body = parse_body(&raw);
    let set_cookie = parse_header_all(&raw, "set-cookie")
        .into_iter()
        .find(|v| v.contains("JSESSIONID="))
        .expect("backend Set-Cookie should pass through");
    let cookie_val = set_cookie.split(';').next().unwrap_or_default().trim().to_owned();

    // Replaying the learned cookie must keep hitting the same backend.
    for _ in 0..5 {
        let raw = http_send(
            &learn_addr,
            &format!(
                "GET / HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Cookie: {cookie_val}\r\n\
                 Connection: close\r\n\r\n"
            ),
        );
        assert_eq!(
            parse_body(&raw),
            first_body,
            "learned session must pin to the backend that issued the cookie"
        );
    }

    drop(proxy);
}
