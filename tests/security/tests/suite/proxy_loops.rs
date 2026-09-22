// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Proxy-loop / Via-chain attack-vector tests.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_send, parse_header, parse_status, simple_proxy_yaml, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn long_via_header_chain_handled_safely() {
    let backend_port = start_backend("via-ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    // Simulate a request that has already bounced through many proxies.
    let via_values = (0..64)
        .map(|i| format!("1.1 hop{i}.example"))
        .collect::<Vec<_>>()
        .join(", ");
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Via: {via_values}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400 || status == 502 || status == 0,
        "long Via chain must complete safely (got {status})"
    );
    assert_ne!(status, 500, "must not crash with 500");

    // Response must be finite — no unbounded Via growth visible as multi-MB header.
    if let Some(via) = parse_header(&raw, "via") {
        assert!(
            via.len() < 16_384,
            "Via header must not grow unboundedly (len={})",
            via.len()
        );
    }
    assert!(
        raw.len() < 1_048_576,
        "response must remain bounded for Via-loop safety"
    );
}
