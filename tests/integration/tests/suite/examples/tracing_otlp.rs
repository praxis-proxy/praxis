// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional test for the OTLP tracing example config.
//!
//! Verifies the proxy starts and serves traffic with the `otel` feature
//! enabled and an OTLP endpoint configured. The batch exporter buffers
//! spans internally when no collector is reachable, so no external
//! service is needed for this test.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn tracing_otlp() {
    let proxy_port = free_port();
    let config = super::load_example_config("observability/tracing-otlp.yaml", proxy_port, HashMap::new());
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "proxy with OTLP tracing config should serve requests");
}
