// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the head classifier example configuration.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, parse_body, start_backend_with_shutdown, start_proxy};

#[test]
fn head_class_drives_routing() {
    let api = start_backend_with_shutdown("api-backend");
    let assets = start_backend_with_shutdown("assets-backend");
    let other = start_backend_with_shutdown("other-backend");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/head-classifier.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", api.port()),
            ("127.0.0.1:3002", assets.port()),
            ("127.0.0.1:3003", other.port()),
        ]),
    );
    let proxy = start_proxy(&config);
    let get = |path: &str| {
        parse_body(&http_send(
            proxy.addr(),
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        ))
    };
    assert_eq!(get("/api/users"), "api-backend", "/api/* classifies as api");
    assert_eq!(
        get("/assets/app.js"),
        "assets-backend",
        "/assets/* classifies as assets"
    );
    assert_eq!(get("/home"), "other-backend", "unmatched path uses the default class");
}
