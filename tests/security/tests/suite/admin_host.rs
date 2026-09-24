// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! DNS rebinding tests for the admin listener `Host` check.

use praxis_core::config::Config;
use praxis_test_utils::{
    ProxyGuard, free_port, http_send, parse_body, parse_status, simple_proxy_yaml, start_backend, start_full_proxy,
    wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn loopback_admin_rejects_rebound_host_on_read_routes() {
    let (_proxy, admin) = start_admin("127.0.0.1", false);
    for path in [
        "/healthy",
        "/ready",
        "/metrics",
        "/api/pipelines",
        "/api/stats",
        "/api/kv/store",
    ] {
        let (status, body) = admin_request(&admin, "GET", path, Some("attacker.example"));
        assert_eq!(status, 421, "GET {path} with a rebound Host must be 421: {body}");
        assert_eq!(
            body, r#"{"error":"misdirected request"}"#,
            "GET {path} must not leak admin data to a rebound page"
        );
    }
}

#[test]
fn loopback_admin_rejects_rebound_host_on_mutating_routes() {
    let (_proxy, admin) = start_admin("127.0.0.1", false);
    for (method, path) in [
        ("PUT", "/api/kv/store/key"),
        ("DELETE", "/api/kv/store/key"),
        ("PUT", "/api/log-level"),
        ("DELETE", "/api/log-level"),
    ] {
        let (status, body) = admin_request(&admin, method, path, Some("attacker.example:9901"));
        assert_eq!(status, 421, "{method} {path} with a rebound Host must be 421: {body}");
    }
}

#[test]
fn loopback_admin_serves_loopback_hosts() {
    let (_proxy, admin) = start_admin("127.0.0.1", false);
    let port = admin.rsplit_once(':').map(|(_, port)| port).unwrap();
    for host in [
        "localhost".to_owned(),
        "LocalHost.".to_owned(),
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
    ] {
        let (status, body) = admin_request(&admin, "GET", "/api/stats", Some(&host));
        assert_eq!(status, 200, "Host {host} must be served: {body}");
    }

    let (status, body) = admin_request(&admin, "PUT", "/api/kv/store/key", Some("localhost"));
    assert_eq!(
        (status, body.as_str()),
        (404, r#"{"error":"store not found"}"#),
        "a loopback PUT must reach the KV handler"
    );

    let (status, body) = admin_request(&admin, "GET", "/healthy", None);
    assert_eq!(
        (status, body.as_str()),
        (200, r#"{"status":"ok"}"#),
        "a Host-less HTTP/1.0 probe must be served"
    );
}

#[test]
fn public_admin_bind_accepts_dns_name_hosts() {
    let (_proxy, admin) = start_admin("0.0.0.0", true);
    for path in ["/healthy", "/api/stats"] {
        let (status, body) = admin_request(&admin, "GET", path, Some("admin.internal.example"));
        assert_eq!(
            status, 200,
            "a non-loopback bind must serve DNS-name Hosts on {path}: {body}"
        );
    }

    let (status, body) = admin_request(&admin, "PUT", "/api/kv/store/key", Some("admin.internal.example"));
    assert_eq!(status, 404, "a non-loopback bind must route KV writes: {body}");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Start a full proxy whose admin listener binds `admin_ip`; returns the guard
/// and a loopback address that reaches the admin listener.
fn start_admin(admin_ip: &str, allow_public_admin: bool) -> (ProxyGuard, String) {
    let backend_port = start_backend("ok");
    let admin_port = free_port();
    let yaml = format!(
        "{}  allow_public_admin: {allow_public_admin}\nadmin:\n  address: \"{admin_ip}:{admin_port}\"\n",
        simple_proxy_yaml(free_port(), backend_port)
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_full_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);
    (proxy, admin)
}

/// Send one admin request with an optional `Host`; `None` sends HTTP/1.0
/// without `Host`.
fn admin_request(admin: &str, method: &str, path: &str, host: Option<&str>) -> (u16, String) {
    let raw = match host {
        Some(host) => http_send(
            admin,
            &format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        ),
        None => http_send(admin, &format!("{method} {path} HTTP/1.0\r\n\r\n")),
    };
    (parse_status(&raw), parse_body(&raw))
}
