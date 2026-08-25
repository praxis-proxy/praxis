// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the OTLP tracing example config.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_proxy};

#[test]
fn tracing_otlp() {
    let proxy_port = free_port();
    let config = super::load_example_config("observability/tracing-otlp.yaml", proxy_port, HashMap::new());
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "proxy with OTLP tracing config should serve requests");
}

// The span-export test (`otlp_exporter_delivers_spans`) installs a process-
// global tracing subscriber, so it lives in its own test binary
// (`tests/otlp_exporter.rs`) rather than in this shared `suite` process.
