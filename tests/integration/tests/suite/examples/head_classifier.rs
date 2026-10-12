// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the head classifier example configuration.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, parse_body, parse_status, start_backend_with_shutdown, start_proxy};

/// Start the head-classifier example proxy wired to three backends.
fn proxy_for(api: u16, assets: u16, other: u16, proxy_port: u16) -> praxis_test_utils::ProxyGuard {
    let config = super::load_example_config(
        "traffic-management/head-classifier.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", api),
            ("127.0.0.1:3002", assets),
            ("127.0.0.1:3003", other),
        ]),
    );
    start_proxy(&config)
}

/// Send a POST with a plain-text body over a closing connection.
fn post(addr: &str, path: &str, body: &str) -> String {
    http_send(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

#[test]
fn head_class_drives_routing() {
    let api = start_backend_with_shutdown("api-backend");
    let assets = start_backend_with_shutdown("assets-backend");
    let other = start_backend_with_shutdown("other-backend");
    let proxy_port = free_port();
    let proxy = proxy_for(api.port(), assets.port(), other.port(), proxy_port);
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

#[test]
fn head_class_gates_body_guardrails_before_pre_read() {
    let api = start_backend_with_shutdown("api-backend");
    let assets = start_backend_with_shutdown("assets-backend");
    let other = start_backend_with_shutdown("other-backend");
    let proxy_port = free_port();
    let proxy = proxy_for(api.port(), assets.port(), other.port(), proxy_port);

    // A forbidden body on /api/* is blocked: the head phase promoted class `api`
    // before the body pre-read, so the body guardrails gate matched. If the head
    // phase ran after pre-read, the gate would be unset and this would not block.
    assert_eq!(
        parse_status(&post(proxy.addr(), "/api/users", "forbidden")),
        403,
        "class api must block a forbidden body, proving head ran before pre-read"
    );

    // The same forbidden body on /home is not blocked: class `other` does not
    // match the gate, so guardrails is skipped and the body reaches the backend.
    assert_eq!(
        parse_status(&post(proxy.addr(), "/home", "forbidden")),
        200,
        "class other must skip guardrails even with a forbidden body"
    );
}
