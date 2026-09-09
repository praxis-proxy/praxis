// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the hostname upstream example configuration.

use praxis_core::config::Config;
use praxis_test_utils::{example_config_path, free_port, http_get, start_backend_with_shutdown};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn hostname_upstream_routes_to_backend() {
    let backend_port_guard = start_backend_with_shutdown("hostname-backend");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    // The shared example loader rewrites endpoints to `127.0.0.1:<port>`,
    // which would turn this example's whole subject, a DNS hostname
    // upstream, into a literal address and skip both the resolver and the
    // runtime private-address check the example's insecure_options opt out
    // of. Patch the ports by hand so `localhost` survives.
    let path = example_config_path("traffic-management/hostname-upstream.yaml");
    let yaml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .replace("0.0.0.0:8080", &format!("127.0.0.1:{proxy_port}"))
        .replace("localhost:9000", &format!("localhost:{backend_port}"));
    let config = Config::from_yaml(&yaml).expect("hostname upstream example should parse");

    let proxy = praxis_test_utils::start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "hostname upstream example should return 200");
    assert_eq!(body, "hostname-backend", "proxy should forward to hostname upstream");
}
