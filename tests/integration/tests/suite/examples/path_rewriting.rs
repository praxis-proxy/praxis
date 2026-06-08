// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Tests for the path rewriting example configuration.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_proxy, start_uri_echo_backend};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn path_rewriting_strip_prefix() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "transformation/path-rewriting.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/api/v1/users", None);
    assert_eq!(status, 200, "request should succeed");
    assert_eq!(body, "/users", "upstream should see path with prefix stripped");
}

#[test]
fn path_rewriting_regex_replace() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "transformation/path-rewriting.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/old/resource", None);
    assert_eq!(status, 200, "request should succeed");
    assert_eq!(body, "/new/resource", "upstream should see regex-rewritten path");
}

#[test]
fn path_rewriting_no_match_passes_through() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "transformation/path-rewriting.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/other", None);
    assert_eq!(status, 200, "request should succeed");
    assert_eq!(
        body, "/other",
        "upstream should see original path when no rewrite matches"
    );
}
