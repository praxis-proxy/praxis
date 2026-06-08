// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Cross-chain flat pipeline example config tests.

use std::collections::HashMap;

use praxis_test_utils::{
    build_pipeline, free_port, http_send, parse_body, parse_status, start_header_echo_backend, start_proxy,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn cross_chain_flat_pipeline_builds() {
    let config = crate::example_utils::load_example_config(
        "branching/cross-chain-flat.yaml",
        8080,
        HashMap::from([("127.0.0.1:3000", 3000)]),
    );
    let pipeline = build_pipeline(&config);
    assert_eq!(
        pipeline.len(),
        5,
        "cross-chain flat pipeline: headers + request_id + cors + router + load_balancer"
    );
}

#[test]
fn cross_chain_flat_preprocessing_adds_header() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "branching/cross-chain-flat.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 200, "cross-chain flat request should succeed");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-preprocess: true"),
        "preprocessing chain should inject X-Preprocess header; got body:\n{body}"
    );
}
