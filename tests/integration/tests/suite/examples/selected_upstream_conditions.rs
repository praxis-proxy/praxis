// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the selected-upstream conditions example configuration.
//!
//! The example gates a `path_rewrite` on `selected_upstream`, so the URI the
//! upstream echoes back proves whether the condition fired: the rewrite adds a
//! `/selected` prefix only when the load balancer picked the `vllm` provider.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_proxy, start_uri_echo_backend};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// The matching upstream (provider `vllm`) triggers the gated rewrite.
#[test]
fn selected_upstream_match_triggers_rewrite() {
    let vllm_backend = start_uri_echo_backend();
    let openai_backend = start_uri_echo_backend();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "pipeline/selected-upstream-conditions.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", vllm_backend.port()),
            ("127.0.0.1:3002", openai_backend.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/vllm/chat", None);
    assert_eq!(status, 200, "request routed to the vllm upstream should succeed");
    assert_eq!(
        body, "/selected/vllm/chat",
        "the selected_upstream condition should match provider=vllm and apply the rewrite"
    );
}

/// The non-matching upstream (provider `openai`) leaves the path untouched,
/// proving the condition reads typed selection metadata and fails closed on a
/// mismatch rather than firing unconditionally.
#[test]
fn selected_upstream_mismatch_skips_rewrite() {
    let vllm_backend = start_uri_echo_backend();
    let openai_backend = start_uri_echo_backend();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "pipeline/selected-upstream-conditions.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", vllm_backend.port()),
            ("127.0.0.1:3002", openai_backend.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/openai/chat", None);
    assert_eq!(status, 200, "request routed to the openai upstream should succeed");
    assert_eq!(
        body, "/openai/chat",
        "provider=openai must not satisfy the provider=vllm predicate, so the rewrite is skipped"
    );
}
