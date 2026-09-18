// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! CloudEvents publisher example schema tests.

use std::collections::HashMap;

use praxis_test_utils::{free_port, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn cloud_events_example_parses() {
    let backend_port = start_backend("cloud-events");
    let proxy_port = free_port();
    let receiver_port = free_port();
    let config = crate::example_utils::load_example_config(
        "observability/cloud-events.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", receiver_port)]),
    );
    let _proxy = start_proxy(&config);
}
