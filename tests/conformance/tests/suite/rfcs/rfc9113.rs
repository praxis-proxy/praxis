// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! [RFC 9113] HTTP/2 conformance tests.
//!
//! [RFC 9113]: https://datatracker.ietf.org/doc/html/rfc9113

use praxis_core::config::Config;
use praxis_test_utils::{free_port, simple_proxy_yaml, start_proxy, wait_for_http2};

use super::test_utils::{
    h2c_get, start_417_backend, start_custom_response_header_backend, start_hop_by_hop_backend, start_redirect_backend,
    start_request_line_echo_backend, start_te_backend, start_uppercase_header_backend,
};

// -----------------------------------------------------------------------------
// RFC 9113 Section 8.2.2 - H2 Connection-Specific Header Rejection
// -----------------------------------------------------------------------------

/// [RFC 9113 Section 8.2.2]: Connection header from an H1
/// upstream MUST NOT appear in an H2 response. Praxis strips
/// hop-by-hop headers unconditionally in `response_filter`.
///
/// [RFC 9113 Section 8.2.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.2.2
#[test]
fn rfc9113_h2_connection_header_stripped() {
    let backend_port = start_hop_by_hop_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http2(proxy.addr());

    let (response, _body) = h2c_get(proxy.addr(), "/");
    assert!(
        response.headers().get("connection").is_none(),
        "H2 response must not contain Connection header"
    );
}

/// [RFC 9113 Section 8.2.2]: Keep-Alive header from an H1
/// upstream MUST NOT appear in an H2 response.
///
/// [RFC 9113 Section 8.2.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.2.2
#[test]
fn rfc9113_h2_keep_alive_header_stripped() {
    let backend_port = start_hop_by_hop_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http2(proxy.addr());

    let (response, _body) = h2c_get(proxy.addr(), "/");
    assert!(
        response.headers().get("keep-alive").is_none(),
        "H2 response must not contain Keep-Alive header"
    );
}

/// [RFC 9113 Section 8.2.2]: Transfer-Encoding header from an
/// H1 upstream MUST NOT appear in an H2 response.
///
/// [RFC 9113 Section 8.2.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.2.2
#[test]
fn rfc9113_h2_transfer_encoding_header_stripped() {
    let backend_port = start_te_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http2(proxy.addr());

    let (response, _body) = h2c_get(proxy.addr(), "/");
    assert!(
        response.headers().get("transfer-encoding").is_none(),
        "H2 response must not contain Transfer-Encoding header"
    );
}

/// [RFC 9113 Section 8.2.2]: Upgrade header from an H1
/// upstream MUST NOT appear in an H2 response.
///
/// [RFC 9113 Section 8.2.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.2.2
#[test]
fn rfc9113_h2_upgrade_header_stripped() {
    let backend_port = start_hop_by_hop_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http2(proxy.addr());

    let (response, _body) = h2c_get(proxy.addr(), "/");
    assert!(
        response.headers().get("upgrade").is_none(),
        "H2 response must not contain Upgrade header"
    );
}

// -----------------------------------------------------------------------------
// RFC 9113 Section 8.3.1 - Request Pseudo-Header Fields
// -----------------------------------------------------------------------------

/// [RFC 9113 Section 8.3.1]: the `:method` and `:path` request
/// pseudo-header fields MUST be correctly translated into the
/// HTTP/1.1 request line when proxying an H2 client to an H1
/// upstream.
///
/// [RFC 9113 Section 8.3.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.3.1
#[test]
fn rfc9113_h2_pseudo_header_method_and_path_forwarded() {
    let backend_port = start_request_line_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http2(proxy.addr());

    let (_response, body) = h2c_get(proxy.addr(), "/api/v1/resource");
    assert_eq!(
        body, "GET /api/v1/resource HTTP/1.1",
        ":method and :path pseudo-headers must translate to the correct H1 request line"
    );
}

/// [RFC 9113 Section 8.3.1]: the `:path` request pseudo-header
/// field MUST preserve query string components through
/// H2-to-H1 translation.
///
/// [RFC 9113 Section 8.3.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.3.1
#[test]
fn rfc9113_h2_pseudo_header_path_query_preserved() {
    let backend_port = start_request_line_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http2(proxy.addr());

    let (_response, body) = h2c_get(proxy.addr(), "/search?q=hello&page=2");
    assert_eq!(
        body, "GET /search?q=hello&page=2 HTTP/1.1",
        ":path pseudo-header must preserve query parameters through H2-to-H1 translation"
    );
}

// -----------------------------------------------------------------------------
// RFC 9113 Section 8.3.2 - Response Pseudo-Header Fields
// -----------------------------------------------------------------------------

/// [RFC 9113 Section 8.3.2]: the `:status` response pseudo-header
/// field MUST correctly convey redirect status codes from an H1
/// upstream to the H2 client, along with associated headers.
///
/// [RFC 9113 Section 8.3.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.3.2
#[test]
fn rfc9113_h2_status_pseudo_header_redirect() {
    let backend_port = start_redirect_backend(301);
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http2(proxy.addr());

    let (response, _body) = h2c_get(proxy.addr(), "/old-path");
    assert_eq!(
        response.status(),
        http::StatusCode::MOVED_PERMANENTLY,
        ":status pseudo-header must convey 301 redirect from H1 upstream"
    );
    assert_eq!(
        response.headers().get("location").map(|v| v.to_str().unwrap()),
        Some("https://example.com/new"),
        "Location header must be forwarded alongside :status redirect"
    );
}

/// [RFC 9113 Section 8.3.2]: the `:status` response pseudo-header
/// field MUST correctly convey error status codes from an H1
/// upstream to the H2 client.
///
/// [RFC 9113 Section 8.3.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.3.2
#[test]
fn rfc9113_h2_status_pseudo_header_error() {
    let backend_port = start_417_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http2(proxy.addr());

    let (response, body) = h2c_get(proxy.addr(), "/");
    assert_eq!(
        response.status(),
        http::StatusCode::EXPECTATION_FAILED,
        ":status pseudo-header must convey 417 error from H1 upstream"
    );
    assert_eq!(
        body, "expectation failed",
        "error response body must be forwarded through H2-to-H1 path"
    );
}

// -----------------------------------------------------------------------------
// RFC 9113 Section 8.2.1 - Field Validity
// -----------------------------------------------------------------------------

/// [RFC 9113 Section 8.2.1]: HTTP/2 field names MUST NOT include
/// uppercase characters. When proxying H1 upstream responses to
/// an H2 client, the intermediary MUST lowercase all field names
/// to produce a valid H2 message.
///
/// [RFC 9113 Section 8.2.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.2.1
#[test]
fn rfc9113_h2_response_header_names_lowercased() {
    let backend_port = start_uppercase_header_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http2(proxy.addr());

    let (response, _body) = h2c_get(proxy.addr(), "/");
    assert_eq!(
        response.headers().get("x-allcaps-header").map(|v| v.to_str().unwrap()),
        Some("allcaps-value"),
        "uppercase H1 header name must be lowercased and value preserved in H2 response"
    );
    assert_eq!(
        response
            .headers()
            .get("x-mixedcase-header")
            .map(|v| v.to_str().unwrap()),
        Some("mixed-value"),
        "mixed-case H1 header name must be lowercased and value preserved in H2 response"
    );
}

// -----------------------------------------------------------------------------
// RFC 9113 Section 8.3.1 - H2-to-H1 Header Translation
// -----------------------------------------------------------------------------

/// [RFC 9113 Section 8.3.1]: when proxying from an H2 client to
/// an H1 upstream, response headers from the upstream must be
/// correctly forwarded. Custom response headers must survive
/// the H2-to-H1 translation path.
///
/// [RFC 9113 Section 8.3.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.3.1
#[test]
fn rfc9113_h2_client_receives_upstream_custom_headers() {
    let backend_port = start_custom_response_header_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http2(proxy.addr());

    let (response, body) = h2c_get(proxy.addr(), "/");
    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "H2 client should receive 200 from H1 upstream"
    );
    assert_eq!(
        response.headers().get("x-custom-response").map(|v| v.to_str().unwrap()),
        Some("backend-value-99"),
        "custom response header must survive H2-to-H1 translation"
    );
    assert_eq!(body, "ok", "body must be forwarded correctly through H2-to-H1 path");
}
