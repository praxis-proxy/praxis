// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the URL rewriting example configuration.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_proxy, start_uri_echo_backend};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn url_rewriting_regex_replace() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "transformation/url-rewriting.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/v1/users", None);
    assert_eq!(status, 200, "rewritten request should succeed");
    assert!(
        body.starts_with("/v2/users"),
        "upstream should see rewritten path /v2/users, got: {body}"
    );
    assert!(
        body.contains("source=gateway"),
        "upstream should see added query param source=gateway, got: {body}"
    );
}

#[test]
fn url_rewriting_preserve_drops_unlisted_params() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "transformation/url-rewriting.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(
        proxy.addr(),
        "/v1/users?api-version=2024-01&user=alice&debug=true&extra=stuff",
        None,
    );
    assert_eq!(status, 200, "rewritten request with query params should succeed");
    assert!(
        body.contains("/v2/users"),
        "upstream path should be rewritten to /v2/users, got: {body}"
    );
    assert!(
        body.contains("api-version=2024-01"),
        "api-version should be retained by preserve allowlist, got: {body}"
    );
    assert!(
        body.contains("user=alice"),
        "user should be retained by preserve allowlist, got: {body}"
    );
    assert!(
        !body.contains("debug"),
        "debug should be dropped by preserve allowlist, got: {body}"
    );
    assert!(
        !body.contains("extra"),
        "extra should be dropped by preserve allowlist, got: {body}"
    );
    assert!(
        body.contains("source=gateway"),
        "source=gateway should be added, got: {body}"
    );
}

#[test]
fn url_rewriting_no_match_preserves_path() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "transformation/url-rewriting.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/other", None);
    assert_eq!(status, 200, "non-matching path should still succeed");
    assert!(
        body.starts_with("/other"),
        "upstream should see original path /other, got: {body}"
    );
    assert!(
        body.contains("source=gateway"),
        "source=gateway should be added even without path match, got: {body}"
    );
}

#[test]
fn url_rewriting_preserve_only() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "transformation/url-rewriting-preserve.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(
        proxy.addr(),
        "/api?api-version=2024-01&user=alice&debug=1&trace=yes",
        None,
    );
    assert_eq!(
        status, 200,
        "preserve_query_params_only example should proxy successfully"
    );
    assert!(
        body.contains("api-version=2024-01"),
        "api-version should be retained: {body}"
    );
    assert!(body.contains("user=alice"), "user should be retained: {body}");
    assert!(!body.contains("debug"), "debug should be dropped: {body}");
    assert!(!body.contains("trace"), "trace should be dropped: {body}");
}
