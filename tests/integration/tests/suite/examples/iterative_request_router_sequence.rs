// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the iterative request router sequence example.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn sequential_steps_returns_final_response() {
    let service_a = start_backend_with_shutdown("from-a");
    let service_b = start_backend_with_shutdown("from-b");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "pipeline/iterative-request-router-sequence.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3000", service_a.port()),
            ("127.0.0.1:3001", service_b.port()),
        ]),
    );
    let proxy = praxis_test_utils::start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "sequential steps should return 200");
    assert_eq!(body, "from-b", "should get step-b's response (the final step)");
}
