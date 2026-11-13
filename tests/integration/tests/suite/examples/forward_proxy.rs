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
    net::{Shutdown, TcpListener, TcpStream},
    time::Duration,
};

use praxis_core::config::Config;
use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext, Rejection};
use praxis_test_utils::{
    BackendGuard, ProxyGuard, example_config_path, free_port, patch_yaml, registry_with, start_proxy,
    start_proxy_with_registry, start_tcp_echo_backend, start_uri_echo_backend,
};

// -----------------------------------------------------------------------------
// Tests: security/forward-proxy.yaml (destination allowlist)
// -----------------------------------------------------------------------------

#[test]
fn allowlist_example_tunnels_connect_to_allowed_destination() {
    let echo_port = start_tcp_echo_backend();
    let proxy = start_allowlist_example(echo_port);

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
    let proxy = start_allowlist_example(echo_port);

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
fn allowlist_example_relays_simultaneous_sends_in_both_directions() {
    // The client sends everything before it reads, while the destination
    // sends and reads at once. Both directions must keep moving: a direct
    // connection completes this, so the tunnel must too. The volume is far
    // beyond what socket buffers absorb.
    within(TRANSFER_DEADLINE, || {
        let (destination, port) = praxis_test_utils::bind_unique_port();
        let destination = std::thread::spawn(move || {
            let (stream, _peer) = destination.accept().unwrap();
            send_while_receiving(stream, b'd')
        });
        let proxy = start_allowlist_example(port);
        let tunnel = connect_tunnel(proxy.addr(), &format!("localhost:{port}"));
        assert_eq!(tunnel.status, 200);

        let mut client = bounded(tunnel.stream);
        client
            .write_all(&vec![b'c'; SIMULTANEOUS_BYTES])
            .expect("the client's send must not stall");
        let from_destination = read_exact_len(&mut client, SIMULTANEOUS_BYTES);
        assert!(
            from_destination.iter().all(|&byte| byte == b'd'),
            "every destination byte reaches the client"
        );
        let from_client = destination.join().unwrap();
        assert!(
            from_client.iter().all(|&byte| byte == b'c'),
            "every client byte reaches the destination"
        );
    });
}

#[test]
fn allowlist_example_keeps_the_upload_after_the_destination_half_closes() {
    // The destination answers and shuts down its write side, then keeps
    // reading. The client sees the end of the answer, and the rest of its
    // upload still reaches the destination.
    within(TRANSFER_DEADLINE, || {
        let (destination, port) = praxis_test_utils::bind_unique_port();
        let destination = std::thread::spawn(move || {
            let (stream, _peer) = destination.accept().unwrap();
            let mut stream = bounded(stream);
            stream.write_all(b"answer").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            let mut upload = Vec::new();
            stream.read_to_end(&mut upload).unwrap();
            upload
        });
        let proxy = start_allowlist_example(port);
        let tunnel = connect_tunnel(proxy.addr(), &format!("localhost:{port}"));
        assert_eq!(tunnel.status, 200);

        let mut client = bounded(tunnel.stream);
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).unwrap();
        assert_eq!(answer, b"answer", "the client sees the destination's half-close");
        let upload = vec![b'u'; 1_048_576]; // 1 MiB
        client.write_all(&upload).expect("the upload must not stall");
        client.shutdown(Shutdown::Write).unwrap();
        let received = destination.join().unwrap();
        assert_eq!(received.len(), upload.len(), "no upload byte is dropped");
    });
}

#[test]
fn allowlist_example_forwards_absolute_form_to_allowed_origin() {
    let echo_port = start_tcp_echo_backend();
    let (proxy, http_backend) = start_allowlist_example_with_origin(echo_port, "");
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
    let proxy = start_allowlist_example(echo_port);

    let (status, _) = send_request(
        proxy.addr(),
        "GET http://other.example.org/ HTTP/1.1\r\nHost: other.example.org\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(status, 403, "absolute-form request to an unlisted host must be denied");
}

#[test]
fn allowlist_example_refuses_absolute_form_hosts_in_another_spelling() {
    // Filters judge the request by `Host`, equal to the target authority;
    // the gate checks the canonical host. A spelling where the two differ
    // is refused before any filter or dial, never forwarded.
    let echo_port = start_tcp_echo_backend();
    let (proxy, http_backend) = start_allowlist_example_with_origin(echo_port, "");
    let port = http_backend.port();
    for authority in [
        format!("[localhost]:{port}"),
        format!("LOCALHOST:{port}"),
        format!("localhost.:{port}"),
        format!("[::FFFF:7F00:1]:{port}"),
        format!("[0:0:0:0:0:0:0:1]:{port}"),
    ] {
        let (status, body) = send_request(
            proxy.addr(),
            &format!("GET http://{authority}/ HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"),
        );
        assert_eq!(status, 400, "{authority} must not be forwarded, got body: {body:?}");
    }
}

#[test]
fn allowlist_example_host_conditions_hold_for_absolute_form() {
    // A condition on `Host` sees the canonical authority: the fork holds
    // `Host` equal to it, and any other spelling is refused before the
    // pipeline. No spelling forwards past the condition.
    let echo_port = start_tcp_echo_backend();
    let http_backend = start_uri_echo_backend();
    let port = http_backend.port();
    let gate = format!(
        "      - filter: static_response\n        status: 451\n        conditions:\n          - when:\n              \
         headers:\n                host: \"localhost:{port}\"\n"
    );
    let yaml = allowlist_example_yaml(echo_port, &gate).replacen(
        "- host: docs.example.com",
        &format!("- host: localhost\n          port: {port}"),
        1,
    );
    let proxy = start_example(&yaml);
    for (authority, expected) in [
        (format!("localhost:{port}"), 451),
        (format!("LOCALHOST:{port}"), 400),
        (format!("localhost.:{port}"), 400),
        (format!("Localhost.:{port}"), 400),
    ] {
        let (status, body) = send_request(
            proxy.addr(),
            &format!("GET http://{authority}/ HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"),
        );
        assert_eq!(
            status, expected,
            "{authority} must not reach the origin, got body: {body:?}"
        );
    }
}

#[test]
fn allowlist_example_rejects_origin_form_requests_with_400() {
    let echo_port = start_tcp_echo_backend();
    let proxy = start_allowlist_example(echo_port);

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
    let (proxy, http_backend) = start_allowlist_example_with_origin(echo_port, &reverse_route(reverse_backend.port()));

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
    // As shipped: no allowlist and no allow_private_upstreams. With no
    // allowlist an IP literal is not denied by a pattern, so the
    // private-address guard alone keeps loopback (and 169.254.169.254, RFC
    // 1918, ...) unreachable, for literals as for resolved names.
    let proxy = start_ip_acl_example("127.0.0.0/8", false);

    for target in [
        format!("127.0.0.1:{echo_port}"),
        format!("[::ffff:127.0.0.1]:{echo_port}"),
        format!("[::FFFF:7F00:1]:{echo_port}"),
    ] {
        let tunnel = connect_tunnel(proxy.addr(), &target);
        assert_eq!(
            tunnel.status, 502,
            "CONNECT to a private IP literal ({target}) must not be dialed"
        );
    }

    let http_backend = start_uri_echo_backend();
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
// Tests: listener gating
// -----------------------------------------------------------------------------

#[test]
fn disabled_forward_proxy_answers_connect_with_405() {
    // `enabled: false` must keep CONNECT off at the proxy layer, which
    // decides on its own whether CONNECT reaches the handler; it must not
    // fall through to the reverse-proxy pipeline.
    let echo_port = start_tcp_echo_backend();
    let yaml = allowlist_example_yaml(echo_port, "").replacen("      enabled: true\n", "      enabled: false\n", 1);
    assert!(
        yaml.contains("      enabled: false\n"),
        "the example's block should be disabled"
    );
    let proxy = start_example(&yaml);

    let tunnel = connect_tunnel(proxy.addr(), &format!("localhost:{echo_port}"));
    assert_eq!(tunnel.status, 405, "a disabled forward proxy must not accept CONNECT");
}

#[test]
fn http2_connect_is_answered_with_501() {
    // HTTP/2 CONNECT (RFC 9113 Section 8.5) is out of scope; the listener
    // speaks h2c, so the request reaches the handler and is refused there.
    let echo_port = start_tcp_echo_backend();
    let proxy = start_allowlist_example(echo_port);

    let status = h2c_connect(proxy.addr(), &format!("localhost:{echo_port}"));
    assert_eq!(status, 501, "an HTTP/2 CONNECT must not open a tunnel");
}

// -----------------------------------------------------------------------------
// Tests: request-head and response phases on the CONNECT
// -----------------------------------------------------------------------------

#[test]
fn head_hook_rejection_refuses_the_connect() {
    // Without the head phase, the destination gate's 403 would answer.
    let echo_port = start_tcp_echo_backend();
    let proxy = start_allowlist_example_with_registry(
        echo_port,
        "      - filter: test_hook\n",
        &registry_with("test_hook", || Box::new(RejectingHook::Head)),
    );

    let tunnel = connect_tunnel(proxy.addr(), "other.example.org:443");
    assert_eq!(tunnel.status, 418, "the head hook decides before the destination gate");
}

#[test]
fn response_hook_rejection_refuses_the_tunnel() {
    let destination = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = destination.local_addr().unwrap().port();
    let proxy = start_allowlist_example_with_registry(
        port,
        "      - filter: test_hook\n",
        &registry_with("test_hook", || Box::new(RejectingHook::Response)),
    );

    let mut tunnel = connect_tunnel(proxy.addr(), &format!("localhost:{port}"));
    assert_eq!(tunnel.status, 418, "the response hook's refusal answers the CONNECT");
    // A refused CONNECT closes the connection; no tunnel follows.
    let mut rest = Vec::new();
    tunnel.stream.read_to_end(&mut rest).unwrap();
    // The proxy dialed and then dropped the destination: its read ends.
    let (mut dialed, _peer) = destination.accept().unwrap();
    dialed.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut byte = [0_u8; 1];
    assert_eq!(dialed.read(&mut byte).unwrap_or(0), 0, "the refused dial is closed");
}

#[test]
fn response_header_edits_reach_the_tunnel_200() {
    let echo_port = start_tcp_echo_backend();
    let proxy = start_allowlist_example_with(
        echo_port,
        "      - filter: headers\n        response_set:\n          - name: x-egress\n            value: gateway\n",
    );

    let mut tunnel = connect_tunnel(proxy.addr(), &format!("localhost:{echo_port}"));
    assert_eq!(tunnel.status, 200);
    assert!(
        tunnel.head.to_ascii_lowercase().contains("x-egress: gateway"),
        "the response filter's header is on the 200: {}",
        tunnel.head
    );
    tunnel.stream.write_all(b"after edits").unwrap();
    assert_eq!(
        read_exact_len(&mut tunnel.stream, 11),
        b"after edits",
        "the tunnel still relays"
    );
    tunnel.stream.shutdown(Shutdown::Both).unwrap();
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Bytes each peer sends in the simultaneous-send test: far more than the
/// loopback socket buffers hold between the peers and the proxy.
const SIMULTANEOUS_BYTES: usize = 33_554_432; // 32 MiB

/// Send [`SIMULTANEOUS_BYTES`] of `fill` while receiving as many, and
/// return what arrived.
fn send_while_receiving(stream: TcpStream, fill: u8) -> Vec<u8> {
    let stream = bounded(stream);
    let mut writer = stream.try_clone().unwrap();
    let sender = std::thread::spawn(move || writer.write_all(&vec![fill; SIMULTANEOUS_BYTES]));
    let mut reader = stream;
    let received = read_exact_len(&mut reader, SIMULTANEOUS_BYTES);
    sender.join().unwrap().expect("the destination's send must not stall");
    received
}

/// How long one large-transfer test may run end to end. Loopback moves
/// these volumes in well under a second; the margin is for slow CI.
const TRANSFER_DEADLINE: Duration = Duration::from_secs(60);

/// How long any one socket read or write may block in a transfer test.
const IO_STALL_LIMIT: Duration = Duration::from_secs(20);

/// `stream` with read and write timeouts, so a relay that stops moving
/// bytes fails the blocked call instead of hanging the test.
fn bounded(stream: TcpStream) -> TcpStream {
    stream.set_read_timeout(Some(IO_STALL_LIMIT)).unwrap();
    stream.set_write_timeout(Some(IO_STALL_LIMIT)).unwrap();
    stream
}

/// Run `test` on its own thread and fail if it does not finish within
/// `deadline`.
///
/// Socket timeouts bound each blocked call; this bounds the whole test,
/// so a relay that trickles bytes slowly enough to dodge them still fails.
/// A test that times out leaves its thread running until the process exits.
fn within(deadline: Duration, test: impl FnOnce() + Send + 'static) {
    let (done, finished) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        test();
        let _sent = done.send(());
    });
    match finished.recv_timeout(deadline) {
        Ok(()) => worker.join().unwrap(),
        // The sender dropped without a send: the test panicked. Re-raise it.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => std::panic::resume_unwind(worker.join().unwrap_err()),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("transfer test did not finish within {deadline:?}: the relay stalled")
        },
    }
}

/// A filter that rejects the CONNECT with 418 in one phase.
enum RejectingHook {
    /// Reject in the request-head phase.
    Head,

    /// Reject the tunnel's response.
    Response,
}

#[async_trait::async_trait]
impl HttpFilter for RejectingHook {
    fn name(&self) -> &'static str {
        "test_hook"
    }

    fn runs_request_head(&self) -> bool {
        matches!(self, Self::Head)
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_head(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Reject(Rejection::status(418)))
    }

    async fn on_response(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(match self {
            Self::Head => FilterAction::Continue,
            Self::Response => FilterAction::Reject(Rejection::status(418)),
        })
    }
}

/// Start `security/forward-proxy.yaml` with its `api.example.com:443` rule
/// pointed at `localhost` on `echo_port`.
fn start_allowlist_example(echo_port: u16) -> ProxyGuard {
    start_allowlist_example_with(echo_port, "")
}

/// [`start_allowlist_example`] with `extra_filters` (YAML list items,
/// indented for the chain) appended to the example's filter chain.
fn start_allowlist_example_with(echo_port: u16, extra_filters: &str) -> ProxyGuard {
    start_example(&allowlist_example_yaml(echo_port, extra_filters))
}

/// [`start_allowlist_example_with`] on a custom filter registry.
fn start_allowlist_example_with_registry(
    echo_port: u16,
    extra_filters: &str,
    registry: &praxis_filter::FilterRegistry,
) -> ProxyGuard {
    let yaml = allowlist_example_yaml(echo_port, extra_filters);
    let config = Config::from_yaml(&yaml).unwrap_or_else(|e| panic!("patched example should parse: {e}"));
    start_proxy_with_registry(&config, registry)
}

/// [`start_allowlist_example_with`] with the `docs.example.com` rule also
/// pointed at a loopback HTTP origin, returned alongside the proxy.
fn start_allowlist_example_with_origin(echo_port: u16, extra_filters: &str) -> (ProxyGuard, BackendGuard) {
    let http_backend = start_uri_echo_backend();
    let yaml = allowlist_example_yaml(echo_port, extra_filters).replacen(
        "- host: docs.example.com",
        &format!("- host: localhost\n          port: {}", http_backend.port()),
        1,
    );
    assert!(
        !yaml.contains("- host: docs.example.com"),
        "the docs.example.com rule should be patched to the HTTP origin"
    );
    (start_example(&yaml), http_backend)
}

/// `security/forward-proxy.yaml` patched for loopback destinations, with
/// `extra_filters` appended to its chain.
fn allowlist_example_yaml(echo_port: u16, extra_filters: &str) -> String {
    let proxy_port = free_port();
    let example = read_example("security/forward-proxy.yaml", proxy_port);
    assert!(
        example.ends_with("      - filter: access_log\n"),
        "the example's chain should end the file"
    );
    let yaml = format!("{example}{extra_filters}").replacen(
        "- host: api.example.com\n          port: 443",
        &format!("- host: localhost\n          port: {echo_port}"),
        1,
    );
    assert!(
        !yaml.contains("- host: api.example.com"),
        "example destinations should be patched to the test backends"
    );
    with_private_upstreams(&yaml)
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

/// An answered CONNECT: the response head and status and, after a 2xx, the
/// stream carrying the tunnel.
struct Tunnel {
    /// CONNECT response status code.
    status: u16,

    /// The response head, through its blank line.
    head: String,

    /// The client connection, positioned after the response head.
    stream: TcpStream,
}

/// Send `CONNECT target` and read the response head.
fn connect_tunnel(proxy: &str, target: &str) -> Tunnel {
    let mut stream = TcpStream::connect(proxy).expect("connect to proxy");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(stream, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").unwrap();
    let head = read_head(&mut stream);
    Tunnel {
        status: parse_status(&head),
        head,
        stream,
    }
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

/// Send an HTTP/2 `CONNECT target` (h2c, prior knowledge) and return the
/// response status.
///
/// A classic CONNECT: only `:method` and `:authority` (RFC 9113 Section
/// 8.5). Bounded, so a server that never answers fails the test.
fn h2c_connect(proxy: &str, target: &str) -> u16 {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for h2c");
    runtime.block_on(async {
        let exchange = async {
            let tcp = tokio::net::TcpStream::connect(proxy).await.expect("connect to proxy");
            let (mut client, connection) = h2::client::handshake(tcp).await.expect("h2c handshake");
            drop(tokio::spawn(connection));
            let request = http::Request::connect(target).body(()).expect("build CONNECT");
            let (response, _send) = client.send_request(request, false).expect("send CONNECT");
            response.await.expect("CONNECT response").status().as_u16()
        };
        tokio::time::timeout(Duration::from_secs(5), exchange)
            .await
            .expect("the proxy must answer an HTTP/2 CONNECT")
    })
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
