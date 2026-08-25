// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Schema test: sticky-sessions.yaml parses and validates.

use std::collections::HashMap;

use praxis_test_utils::{free_port, start_backend, start_proxy};

#[test]
fn sticky_sessions_config_parses() {
    let port_a = start_backend("ss-a");
    let port_b = start_backend("ss-b");
    let port_c = start_backend("ss-c");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "traffic-management/sticky-sessions.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
            // Remap the other two declared listeners to free ports so the proxy
            // does not bind the literal 8081/8082 (an EADDRINUSE flake).
            ("127.0.0.1:8081", free_port()),
            ("127.0.0.1:8082", free_port()),
        ]),
    );
    let _proxy = start_proxy(&config);
}
