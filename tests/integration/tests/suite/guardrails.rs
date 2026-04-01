//! Integration tests for the `guardrails` filter.

use praxis_core::config::Config;

use crate::common::{free_port, http_get, http_send, parse_body, parse_status, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn header_contains_blocks_matching_request() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = guardrails_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: bad-bot/1.0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 401, "bad-bot User-Agent should be blocked");
    assert_eq!(
        parse_body(&raw),
        "Unauthorized",
        "rejection body should be 'Unauthorized'"
    );
}

#[test]
fn clean_request_passes_through() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = guardrails_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "clean request should pass through");
    assert_eq!(body, "ok", "clean request should return backend response");
}

#[test]
fn body_contains_blocks_matching_content() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = guardrails_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let payload = "SELECT 1; DROP TABLE users;";
    let raw = http_send(
        &addr,
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(parse_status(&raw), 401, "body containing DROP TABLE should be blocked");
}

#[test]
fn body_without_match_passes_through() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = guardrails_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let payload = "SELECT 1 FROM users";
    let raw = http_send(
        &addr,
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(parse_status(&raw), 200, "clean body should pass through");
}

#[test]
fn header_pattern_blocks_regex_match() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = header_pattern_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Script: <script>alert(1)</script>\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 401, "script tag pattern should be blocked");
}

#[test]
fn header_only_rules_skip_body_inspection() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();

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
      - filter: guardrails
        rules:
          - target: header
            name: "X-Bad"
            contains: "evil"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let payload = "this body contains evil content but header-only rules won't catch it";
    let raw = http_send(
        &addr,
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(parse_status(&raw), 200, "header-only rules should not inspect body");
}

#[test]
fn multiple_rules_any_match_rejects() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = guardrails_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Evil: evilmonkey-value\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        401,
        "X-Evil header with 'evilmonkey' should be blocked"
    );
}

#[test]
fn negated_header_rejects_missing_header() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = negate_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, _) = http_get(&addr, "/", None);
    assert_eq!(
        status, 401,
        "missing X-Authorized header should be rejected by negated rule"
    );
}

#[test]
fn negated_header_rejects_non_matching_value() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = negate_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Authorized: stranger\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        401,
        "X-Authorized without 'trusted' should be rejected by negated rule"
    );
}

#[test]
fn negated_header_allows_matching_value() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = negate_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Authorized: trusted-client\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "X-Authorized with 'trusted' should pass negated rule"
    );
    assert_eq!(
        parse_body(&raw),
        "ok",
        "matching negated rule should forward to backend"
    );
}

#[test]
fn negated_body_rejects_non_matching_content() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = negate_body_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let payload = "not json at all";
    let raw = http_send(
        &addr,
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(
        parse_status(&raw),
        401,
        "body not matching JSON pattern should be rejected by negated rule"
    );
}

#[test]
fn negated_body_allows_matching_content() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = negate_body_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let payload = r#"{"key":"value"}"#;
    let raw = http_send(
        &addr,
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "JSON-shaped body should pass negated pattern rule"
    );
}

#[test]
fn mixed_positive_and_negated_rules() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = mixed_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let payload = r#"{"query":"SELECT 1"}"#;
    let raw = http_send(
        &addr,
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nX-Authorized: trusted-app\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "clean request with trusted header and JSON body should pass"
    );

    let raw = http_send(
        &addr,
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nX-Authorized: trusted-app\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            "evilmonkey payload".len(),
            "evilmonkey payload"
        ),
    );
    assert_eq!(
        parse_status(&raw),
        401,
        "positive body rule should still reject even with valid header"
    );

    let payload = r#"{"safe":"data"}"#;
    let raw = http_send(
        &addr,
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(
        parse_status(&raw),
        401,
        "missing X-Authorized header should be rejected even with clean body"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// YAML config with header contains, body contains, and header pattern rules.
fn guardrails_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: guardrails
        rules:
          - target: header
            name: "User-Agent"
            pattern: "bad-bot.*"
          - target: body
            contains: "DROP TABLE"
          - target: header
            name: "X-Evil"
            contains: "evilmonkey"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}

/// YAML config with a regex pattern rule for header inspection.
fn header_pattern_yaml(proxy_port: u16, backend_port: u16) -> String {
    guardrails_pipeline(
        proxy_port,
        backend_port,
        r#"
          - target: header
            name: "X-Script"
            pattern: "<script>.*</script>""#,
    )
}

/// YAML config with a negated header rule.
fn negate_yaml(proxy_port: u16, backend_port: u16) -> String {
    guardrails_pipeline(
        proxy_port,
        backend_port,
        r#"
          - target: header
            name: "X-Authorized"
            contains: "trusted"
            negate: true"#,
    )
}

/// YAML config with a negated body pattern rule.
fn negate_body_yaml(proxy_port: u16, backend_port: u16) -> String {
    guardrails_pipeline(
        proxy_port,
        backend_port,
        r#"
          - target: body
            pattern: ^\{.*\}$
            negate: true"#,
    )
}

/// YAML config mixing positive and negated rules.
fn mixed_yaml(proxy_port: u16, backend_port: u16) -> String {
    guardrails_pipeline(
        proxy_port,
        backend_port,
        r#"
          - target: header
            name: "X-Authorized"
            contains: "trusted"
            negate: true
          - target: body
            contains: "evilmonkey""#,
    )
}

/// Build a guardrails pipeline YAML from inline rules.
fn guardrails_pipeline(proxy_port: u16, backend_port: u16, rules: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: guardrails
        rules:{rules}
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}
