// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Fetch Standard CORS conformance tests.
//!
//! Verifies proxy behavior against the Fetch Standard
//! (WHATWG) CORS protocol sections.
//!
//! - [Fetch Standard Section 3.2.3]: CORS-preflight request
//! - [Fetch Standard Section 3.2.4]: CORS-preflight cache
//! - [Fetch Standard Section 3.2.5]: Main fetch CORS protocol steps
//!
//! [Fetch Standard Section 3.2.3]: https://fetch.spec.whatwg.org/#cors-preflight-request
//! [Fetch Standard Section 3.2.4]: https://fetch.spec.whatwg.org/#cors-preflight-cache
//! [Fetch Standard Section 3.2.5]: https://fetch.spec.whatwg.org/#main-fetch

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_send, parse_header, parse_status, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// [Fetch Standard Section 3.2.3]: a preflight request must
/// include `Origin`, `Access-Control-Request-Method`, and
/// optionally `Access-Control-Request-Headers`. The server
/// must respond with CORS headers on success.
///
/// [Fetch Standard Section 3.2.3]: https://fetch.spec.whatwg.org/#cors-preflight-request
#[test]
fn fetch_3_2_3_preflight_success_includes_required_headers() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nAccess-Control-Request-Method: PUT\r\nAccess-Control-Request-Headers: Content-Type\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 204, "successful preflight must return 204");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("https://app.example.com".to_owned()),
        "preflight must reflect allowed origin"
    );
    assert!(
        parse_header(&raw, "access-control-allow-methods").is_some(),
        "preflight must include Access-Control-Allow-Methods"
    );
    assert!(
        parse_header(&raw, "access-control-allow-headers").is_some(),
        "preflight must include Access-Control-Allow-Headers when requested"
    );
    assert!(
        parse_header(&raw, "vary").is_some(),
        "preflight must include Vary header"
    );
}

/// [Fetch Standard Section 3.2.3]: a preflight with a
/// disallowed method must not include `Access-Control-Allow-Origin`.
///
/// [Fetch Standard Section 3.2.3]: https://fetch.spec.whatwg.org/#cors-preflight-request
#[test]
fn fetch_3_2_3_preflight_disallowed_method_omits_acao() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nAccess-Control-Request-Method: PATCH\r\nConnection: close\r\n\r\n",
    );
    assert!(
        parse_header(&raw, "access-control-allow-origin").is_none(),
        "disallowed method preflight must not include ACAO"
    );
}

/// [Fetch Standard Section 3.2.4]: a successful preflight
/// must include `Access-Control-Max-Age` for cache control.
///
/// [Fetch Standard Section 3.2.4]: https://fetch.spec.whatwg.org/#cors-preflight-cache
#[test]
fn fetch_3_2_4_preflight_includes_max_age() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nAccess-Control-Request-Method: GET\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 204, "successful preflight must return 204");
    assert!(
        parse_header(&raw, "access-control-max-age").is_some(),
        "successful preflight must include Access-Control-Max-Age for caching"
    );
}

/// [Fetch Standard Section 3.2.5]: on a simple GET with an
/// allowed origin, the response must include
/// `Access-Control-Allow-Origin` reflecting the origin.
///
/// [Fetch Standard Section 3.2.5]: https://fetch.spec.whatwg.org/#main-fetch
#[test]
fn fetch_3_2_5_simple_request_reflects_allowed_origin() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "simple request should return 200");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("https://app.example.com".to_owned()),
        "simple request must reflect allowed origin in ACAO"
    );
}

/// [Fetch Standard Section 3.2.5]: on a simple GET with
/// a disallowed origin, the response must NOT include
/// `Access-Control-Allow-Origin`.
///
/// [Fetch Standard Section 3.2.5]: https://fetch.spec.whatwg.org/#main-fetch
#[test]
fn fetch_3_2_5_simple_request_omits_acao_for_disallowed_origin() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.com\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "disallowed origin still proxies upstream");
    assert!(
        parse_header(&raw, "access-control-allow-origin").is_none(),
        "disallowed origin must not receive ACAO header"
    );
}

/// [Fetch Standard Section 3.2.5]: when the origin list is
/// dynamic (not `*`), `Vary: Origin` must appear even on
/// non-CORS responses to prevent shared-cache poisoning.
///
/// [Fetch Standard Section 3.2.5]: https://fetch.spec.whatwg.org/#main-fetch
#[test]
fn fetch_3_2_5_vary_origin_on_non_cors_responses() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "non-CORS request should return 200");
    assert_eq!(
        parse_header(&raw, "vary"),
        Some("Origin".to_owned()),
        "dynamic origin list must include Vary: Origin on all responses"
    );
}

/// [Fetch Standard Section 3.2.5]: when credentials are
/// configured, a simple request with an allowed origin must
/// return both `Access-Control-Allow-Origin: <origin>` and
/// `Access-Control-Allow-Credentials: true`.
///
/// [Fetch Standard Section 3.2.5]: https://fetch.spec.whatwg.org/#main-fetch
#[test]
fn fetch_3_2_5_credentials_on_simple_request() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_credentials_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "credentialed simple request should return 200");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("https://app.example.com".to_owned()),
        "credentials mode must reflect exact origin, not wildcard"
    );
    assert_eq!(
        parse_header(&raw, "access-control-allow-credentials"),
        Some("true".to_owned()),
        "credentials mode must include Access-Control-Allow-Credentials: true"
    );
}

/// [Fetch Standard Section 3.2.5]: when `expose_headers` is
/// configured, the response must include
/// `Access-Control-Expose-Headers` on actual (non-preflight)
/// requests with an allowed origin.
///
/// [Fetch Standard Section 3.2.5]: https://fetch.spec.whatwg.org/#main-fetch
#[test]
fn fetch_3_2_5_expose_headers_on_actual_request() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_expose_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "request with expose-headers config should return 200"
    );
    let aceh = parse_header(&raw, "access-control-expose-headers");
    assert!(
        aceh.is_some_and(|v| v.contains("X-Request-ID")),
        "Access-Control-Expose-Headers must include configured headers"
    );
}

/// [Fetch Standard Section 3.2.5]: wildcard `allow_origins: ["*"]`
/// must produce `Access-Control-Allow-Origin: *` for any origin.
///
/// [Fetch Standard Section 3.2.5]: https://fetch.spec.whatwg.org/#main-fetch
#[test]
fn fetch_3_2_5_wildcard_origin_returns_star() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_wildcard_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://random-site.org\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "wildcard origin request should return 200");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("*".to_owned()),
        "wildcard config must produce ACAO: * for any origin"
    );
}

/// [Fetch Standard Section 3.2.3]: Private Network Access
/// preflight with `Access-Control-Request-Private-Network: true`
/// must include `Access-Control-Allow-Private-Network: true` in
/// the response when PNA is enabled.
///
/// [Fetch Standard Section 3.2.3]: https://fetch.spec.whatwg.org/#cors-preflight-request
#[test]
fn fetch_3_2_3_private_network_access_preflight() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_pna_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /api HTTP/1.1\r\n\
         Host: localhost\r\n\
         Origin: https://app.example.com\r\n\
         Access-Control-Request-Method: GET\r\n\
         Access-Control-Request-Private-Network: true\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 204, "PNA preflight should return 204");
    assert_eq!(
        parse_header(&raw, "access-control-allow-private-network"),
        Some("true".to_owned()),
        "PNA preflight must include Access-Control-Allow-Private-Network: true"
    );
}

/// [Fetch Standard Section 3.2.3]: in reject mode, a preflight
/// with a disallowed origin must return 403.
///
/// [Fetch Standard Section 3.2.3]: https://fetch.spec.whatwg.org/#cors-preflight-request
#[test]
fn fetch_3_2_3_reject_mode_disallowed_origin_returns_403() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_reject_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /api HTTP/1.1\r\n\
         Host: localhost\r\n\
         Origin: https://evil.com\r\n\
         Access-Control-Request-Method: GET\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "reject mode must return 403 for disallowed origin preflight"
    );
}

/// [Fetch Standard Section 3.2.3]: a successful preflight must
/// include a `Vary` header containing `Origin` to prevent
/// shared-cache poisoning.
///
/// [Fetch Standard Section 3.2.3]: https://fetch.spec.whatwg.org/#cors-preflight-request
#[test]
fn cors_successful_preflight_includes_vary_headers() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /api HTTP/1.1\r\n\
         Host: localhost\r\n\
         Origin: https://app.example.com\r\n\
         Access-Control-Request-Method: GET\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let vary = parse_header(&raw, "vary");

    assert_eq!(status, 204, "successful preflight must return 204 (got {status})");
    assert!(vary.is_some(), "successful preflight must include Vary header");
    assert!(
        vary.as_deref().is_some_and(|v| v.contains("Origin")),
        "Vary header on preflight must contain 'Origin'; got: {vary:?}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a CORS config with credentials enabled.
fn cors_credentials_yaml(proxy_port: u16, backend_port: u16) -> String {
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
      - filter: cors
        allow_origins:
          - "https://app.example.com"
        allow_methods:
          - GET
          - POST
        allow_credentials: true
        max_age: 3600
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

/// Build a CORS config with expose_headers configured.
fn cors_expose_yaml(proxy_port: u16, backend_port: u16) -> String {
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
      - filter: cors
        allow_origins:
          - "https://app.example.com"
        allow_methods:
          - GET
          - POST
        expose_headers:
          - X-Request-ID
          - X-RateLimit-Remaining
        max_age: 3600
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

/// Build a CORS config with wildcard origin.
fn cors_wildcard_yaml(proxy_port: u16, backend_port: u16) -> String {
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
      - filter: cors
        allow_origins:
          - "*"
        allow_methods:
          - GET
          - POST
        max_age: 3600
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

/// Build a CORS config with Private Network Access enabled.
fn cors_pna_yaml(proxy_port: u16, backend_port: u16) -> String {
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
      - filter: cors
        allow_origins:
          - "https://app.example.com"
        allow_methods:
          - GET
          - POST
        allow_private_network: true
        max_age: 3600
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

/// Build a CORS config with reject mode for disallowed origins.
fn cors_reject_yaml(proxy_port: u16, backend_port: u16) -> String {
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
      - filter: cors
        allow_origins:
          - "https://app.example.com"
        allow_methods:
          - GET
        disallowed_origin_mode: "reject"
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

/// Build a full proxy YAML config with a standard CORS filter for conformance tests.
fn cors_yaml(proxy_port: u16, backend_port: u16) -> String {
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
      - filter: cors
        allow_origins:
          - "https://app.example.com"
          - "https://*.example.com"
        allow_methods:
          - GET
          - POST
          - PUT
          - DELETE
        allow_headers:
          - Content-Type
          - Authorization
        max_age: 3600
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
