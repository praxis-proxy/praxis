// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the forward-proxy example configurations.
//!
//! Each test starts the example's listener against loopback backends and
//! drives it the way an `HTTP_PROXY`/`HTTPS_PROXY` client does: a real
//! `CONNECT` tunnel carrying bytes both ways, and absolute-form plain
//! requests (`GET http://host/path`).
//!
//! The examples allowlist public hostnames; the tests swap those for
//! `localhost` on the backends' ports, and turn on
//! `insecure_options.allow_private_upstreams` because `localhost` resolves
//! to loopback, which the runtime's private-address guard refuses otherwise.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{
    ProxyGuard, example_config_path, free_port, patch_yaml, start_proxy, start_tcp_echo_backend, start_uri_echo_backend,
};

// -----------------------------------------------------------------------------
// Tests: security/forward-proxy.yaml (destination allowlist)
// -----------------------------------------------------------------------------

#[test]
fn allowlist_example_tunnels_connect_to_allowed_destination() {
    let echo_port = start_tcp_echo_backend();
    let (proxy, _http_backend) = start_allowlist_example(echo_port);

    let mut tunnel = connect_tunnel(proxy.addr(), &format!("localhost:{echo_port}"));
    assert_eq!(tunnel.status, 200, "allowlisted CONNECT should open a tunnel");

    for payload in [&b"first message"[..], &b"second, after a round trip"[..]] {
        tunnel.stream.write_all(payload).unwrap();
        assert_eq!(
            read_exact_len(&mut tunnel.stream, payload.len()),
            payload,
            "tunnel should relay bytes to the destination and back"
        );
    }
}

#[test]
fn allowlist_example_rejects_connect_outside_the_allowlist() {
    let echo_port = start_tcp_echo_backend();
    let (proxy, _http_backend) = start_allowlist_example(echo_port);

    for (target, why) in [
        (
            format!("localhost:{}", free_port()),
            "a port the localhost rules do not list",
        ),
        ("other.example.org:443".to_owned(), "a host no rule matches"),
        (
            "example.com:443".to_owned(),
            "the apex of an allowlisted wildcard domain",
        ),
        (
            format!("127.0.0.1:{echo_port}"),
            "an IP literal, which no host pattern matches",
        ),
    ] {
        let tunnel = connect_tunnel(proxy.addr(), &target);
        assert_eq!(tunnel.status, 403, "CONNECT to {why} ({target}) must be denied");
    }
}

#[test]
fn allowlist_example_forwards_absolute_form_to_allowed_origin() {
    let echo_port = start_tcp_echo_backend();
    let (proxy, http_backend) = start_allowlist_example(echo_port);
    let origin = format!("localhost:{}", http_backend.port());

    let (status, body) = send_request(
        proxy.addr(),
        &format!("GET http://{origin}/search?q=praxis HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"),
    );

    assert_eq!(status, 200, "allowlisted absolute-form request should be forwarded");
    assert_eq!(
        body, "/search?q=praxis",
        "the origin should receive the origin-form path and query"
    );
}

#[test]
fn allowlist_example_rejects_absolute_form_outside_the_allowlist() {
    let echo_port = start_tcp_echo_backend();
    let (proxy, _http_backend) = start_allowlist_example(echo_port);

    let (status, _) = send_request(
        proxy.addr(),
        "GET http://other.example.org/ HTTP/1.1\r\nHost: other.example.org\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(status, 403, "absolute-form request to an unlisted host must be denied");
}

#[test]
fn allowlist_example_rejects_origin_form_requests_with_400() {
    let echo_port = start_tcp_echo_backend();
    let (proxy, _http_backend) = start_allowlist_example(echo_port);

    let (status, _) = send_request(
        proxy.addr(),
        "GET /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(
        status, 400,
        "an origin-form request names no destination and the example routes none"
    );
}

#[test]
fn allowlist_example_with_router_keeps_reverse_proxying_origin_form() {
    let echo_port = start_tcp_echo_backend();
    let reverse_backend = start_uri_echo_backend();
    let (proxy, http_backend) = start_allowlist_example_with(echo_port, &reverse_route(reverse_backend.port()));

    let (status, body) = send_request(
        proxy.addr(),
        "GET /app/page HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        status, 200,
        "a routed origin-form request must be reverse-proxied, not refused"
    );
    assert_eq!(body, "/app/page", "the reverse-proxy backend should serve it");

    let origin = format!("localhost:{}", http_backend.port());
    let (status, body) = send_request(
        proxy.addr(),
        &format!("GET http://{origin}/fwd HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"),
    );
    assert_eq!(
        status, 200,
        "absolute-form requests are still forwarded on the same port"
    );
    assert_eq!(body, "/fwd", "the forward origin should serve it");
}

// -----------------------------------------------------------------------------
// Tests: security/forward-proxy-ip-acl.yaml (client ACL, no allowlist)
// -----------------------------------------------------------------------------

#[test]
fn ip_acl_example_rejects_origin_form_requests_with_400() {
    let proxy = start_ip_acl_example("127.0.0.0/8", true);

    let (status, _) = send_request(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(
        status, 400,
        "an admitted client's origin-form request is a client error"
    );
}

#[test]
fn ip_acl_example_denies_unlisted_clients_before_the_400() {
    let proxy = start_ip_acl_example("10.0.0.0/8", true);

    let (status, _) = send_request(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(status, 403, "the ACL decides first; a denied client never sees the 400");
}

#[test]
fn ip_acl_example_tunnels_for_allowed_clients() {
    let echo_port = start_tcp_echo_backend();
    let proxy = start_ip_acl_example("127.0.0.0/8", true);

    let mut tunnel = connect_tunnel(proxy.addr(), &format!("localhost:{echo_port}"));
    assert_eq!(
        tunnel.status, 200,
        "with no allowlist, a client the ACL admits may tunnel to any destination"
    );
    tunnel.stream.write_all(b"via acl").unwrap();
    assert_eq!(
        read_exact_len(&mut tunnel.stream, 7),
        b"via acl",
        "tunnel should relay bytes"
    );
}

#[test]
fn ip_acl_example_rejects_clients_outside_the_acl() {
    let echo_port = start_tcp_echo_backend();
    // The test client connects from loopback; an ACL without loopback stands
    // in for a client from an unlisted network.
    let proxy = start_ip_acl_example("10.0.0.0/8", true);

    let tunnel = connect_tunnel(proxy.addr(), &format!("localhost:{echo_port}"));
    assert_eq!(tunnel.status, 403, "a client outside the ACL must not open a tunnel");
}

#[test]
fn ip_acl_example_refuses_private_destinations_by_default() {
    let echo_port = start_tcp_echo_backend();
    // As shipped: no allow_private_upstreams, so loopback is unreachable.
    let proxy = start_ip_acl_example("127.0.0.0/8", false);

    let tunnel = connect_tunnel(proxy.addr(), &format!("localhost:{echo_port}"));
    assert_eq!(
        tunnel.status, 502,
        "a destination resolving to a private address must not be dialed"
    );
}

#[test]
fn ip_acl_example_refuses_private_literal_destinations_by_default() {
    let echo_port = start_tcp_echo_backend();
    let http_backend = start_uri_echo_backend();
    // As shipped: no allowlist and no allow_private_upstreams. With no
    // allowlist an IP literal is not denied by a pattern, so the
    // private-address guard alone keeps loopback (and 169.254.169.254, RFC
    // 1918, ...) unreachable, for literals as for resolved names.
    let proxy = start_ip_acl_example("127.0.0.0/8", false);

    let tunnel = connect_tunnel(proxy.addr(), &format!("127.0.0.1:{echo_port}"));
    assert_eq!(tunnel.status, 502, "CONNECT to a private IP literal must not be dialed");

    let origin = format!("127.0.0.1:{}", http_backend.port());
    let (status, body) = send_request(
        proxy.addr(),
        &format!("GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"),
    );
    assert_eq!(
        status, 502,
        "absolute-form request to a private IP literal must not be forwarded, got body: {body:?}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Start `security/forward-proxy.yaml` with its `api.example.com:443` and
/// `docs.example.com` rules pointed at `localhost` on the echo and HTTP
/// backends, returning the proxy and the HTTP backend guard.
fn start_allowlist_example(echo_port: u16) -> (ProxyGuard, praxis_test_utils::BackendGuard) {
    start_allowlist_example_with(echo_port, "")
}

/// [`start_allowlist_example`] with `extra_filters` (YAML list items,
/// indented for the chain) appended to the example's filter chain.
fn start_allowlist_example_with(echo_port: u16, extra_filters: &str) -> (ProxyGuard, praxis_test_utils::BackendGuard) {
    let http_backend = start_uri_echo_backend();
    let proxy_port = free_port();
    let example = read_example("security/forward-proxy.yaml", proxy_port);
    assert!(
        example.ends_with("      - filter: access_log\n"),
        "the example's chain should end the file"
    );
    let yaml = format!("{example}{extra_filters}")
        .replacen(
            "- host: api.example.com\n          port: 443",
            &format!("- host: localhost\n          port: {echo_port}"),
            1,
        )
        .replacen(
            "- host: docs.example.com",
            &format!("- host: localhost\n          port: {}", http_backend.port()),
            1,
        );
    assert!(
        !yaml.contains("- host: api.example.com") && !yaml.contains("- host: docs.example.com"),
        "example destinations should be patched to the test backends"
    );
    (start_example(&with_private_upstreams(&yaml)), http_backend)
}

/// Start `security/forward-proxy-ip-acl.yaml` with its client ACL replaced by
/// `allow_cidr`, optionally allowing private destinations.
fn start_ip_acl_example(allow_cidr: &str, allow_private_upstreams: bool) -> ProxyGuard {
    let proxy_port = free_port();
    let example = read_example("security/forward-proxy-ip-acl.yaml", proxy_port);
    let (before_acl, acl_and_rest) = example
        .split_once("        allow:\n")
        .expect("example has an ip_acl allow list");
    let (_example_acl, after_acl) = acl_and_rest
        .split_once("      - filter: access_log")
        .expect("access_log follows the ip_acl filter");
    let yaml =
        format!("{before_acl}        allow:\n          - \"{allow_cidr}\"\n      - filter: access_log{after_acl}");
    if allow_private_upstreams {
        start_example(&with_private_upstreams(&yaml))
    } else {
        start_example(&yaml)
    }
}

/// Read an example config with its listener moved to `proxy_port`.
fn read_example(filename: &str, proxy_port: u16) -> String {
    let path = example_config_path(filename);
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    patch_yaml(&yaml, proxy_port, &HashMap::new())
}

/// A `router` and `load_balancer` sending every origin-form request to the
/// loopback backend on `port`, as chain list items.
fn reverse_route(port: u16) -> String {
    format!(
        "      - filter: router\n        routes:\n          - path_prefix: \"/\"\n            cluster: app\n      \
         - filter: load_balancer\n        clusters:\n          - name: app\n            endpoints:\n              - \
         \"127.0.0.1:{port}\"\n"
    )
}

/// Append the insecure options loopback test backends need: dialing
/// `localhost` destinations, and loopback endpoints for added routes.
fn with_private_upstreams(yaml: &str) -> String {
    assert!(
        !yaml.contains("insecure_options:"),
        "example should not set insecure_options"
    );
    format!("{yaml}\ninsecure_options:\n  allow_private_upstreams: true\n  allow_private_endpoints: true\n")
}

/// Parse and start a patched example.
fn start_example(yaml: &str) -> ProxyGuard {
    let config = Config::from_yaml(yaml).unwrap_or_else(|e| panic!("patched example should parse: {e}"));
    start_proxy(&config)
}

/// An answered CONNECT: the response status and, after a 2xx, the stream
/// carrying the tunnel.
struct Tunnel {
    /// CONNECT response status code.
    status: u16,

    /// The client connection, positioned after the response head.
    stream: TcpStream,
}

/// Send `CONNECT target` and read the response head.
fn connect_tunnel(proxy: &str, target: &str) -> Tunnel {
    let mut stream = TcpStream::connect(proxy).expect("connect to proxy");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(stream, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").unwrap();
    let status = parse_status(&read_head(&mut stream));
    Tunnel { status, stream }
}

/// Send a raw request and return its status and body.
fn send_request(proxy: &str, request: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(proxy).expect("connect to proxy");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    drop(stream.read_to_string(&mut response));
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((&response, ""));
    (parse_status(head), body.to_owned())
}

/// Read up to and including the blank line ending a response head, one byte
/// at a time so no tunnel bytes are consumed.
fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Read exactly `len` bytes from the tunnel.
fn read_exact_len(stream: &mut TcpStream, len: usize) -> Vec<u8> {
    let mut buf = vec![0_u8; len];
    stream
        .read_exact(&mut buf)
        .expect("tunnel should deliver the echoed bytes");
    buf
}

/// Status code from a response status line.
fn parse_status(head: &str) -> u16 {
    head.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("malformed response head: {head:?}"))
}
