// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the forward-proxy example configurations.
//!
//! Each test starts the example's listener against loopback backends and
//! drives it the way an `HTTPS_PROXY` client does: a real `CONNECT` tunnel
//! carrying bytes both ways.
//!
//! The examples allowlist public hostnames; the tests swap those for
//! `localhost` on the backends' ports, and turn on
//! `insecure_options.allow_private_upstreams` because `localhost` resolves
//! to loopback, which the runtime's private-address guard refuses otherwise.
//! The local-service example lists a loopback address itself, so its tests
//! only move that address to a backend's port and leave the guard on.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::{Shutdown, TcpListener, TcpStream},
    time::Duration,
};

use praxis_core::config::Config;
use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext, Rejection};
use praxis_test_utils::{
    ProxyGuard, example_config_path, free_port, patch_yaml, registry_with, start_proxy, start_proxy_with_registry,
    start_tcp_echo_backend,
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

// -----------------------------------------------------------------------------
// Tests: security/forward-proxy-ip-acl.yaml (client ACL, no allowlist)
// -----------------------------------------------------------------------------

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
}

// -----------------------------------------------------------------------------
// Tests: security/forward-proxy-local-service.yaml (listed local address)
// -----------------------------------------------------------------------------

#[test]
fn local_service_example_tunnels_connect_to_the_listed_address() {
    let echo_port = start_tcp_echo_backend();
    let proxy = start_example(&local_service_example_yaml(echo_port, ""));

    let mut tunnel = connect_tunnel(proxy.addr(), &format!("127.0.0.1:{echo_port}"));
    assert_eq!(
        tunnel.status, 200,
        "a listed loopback address opens a tunnel without allow_private_upstreams"
    );
    tunnel.stream.write_all(b"to the local service").unwrap();
    assert_eq!(
        read_exact_len(&mut tunnel.stream, 20),
        b"to the local service",
        "tunnel should relay bytes"
    );
}

#[test]
fn local_service_example_forwards_plain_requests_to_the_listed_address() {
    let backend_port = praxis_test_utils::start_backend("local service says hi");
    let proxy = start_example(&local_service_example_yaml(backend_port, ""));

    let response = praxis_test_utils::http_send(
        proxy.addr(),
        &format!(
            "GET http://127.0.0.1:{backend_port}/api/tags HTTP/1.1\r\n\
             Host: 127.0.0.1:{backend_port}\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(
        parse_status(&response),
        200,
        "an absolute-form request to the listed address is forwarded: {response}"
    );
    assert_eq!(praxis_test_utils::parse_body(&response), "local service says hi");
}

#[test]
fn local_service_example_keeps_the_guard_for_other_destinations() {
    let echo_port = start_tcp_echo_backend();
    // A name rule beside the listed address: the name resolves to the same
    // loopback address, but the client chose it, so the guard refuses it.
    let proxy = start_example(&local_service_example_yaml(echo_port, "        - host: localhost\n"));

    for (target, status, why) in [
        (
            format!("127.0.0.1:{}", free_port()),
            403,
            "another port of the listed address",
        ),
        (format!("127.0.0.2:{echo_port}"), 403, "an unlisted loopback address"),
        (
            format!("localhost:{echo_port}"),
            502,
            "a name resolving to the listed address",
        ),
    ] {
        let tunnel = connect_tunnel(proxy.addr(), &target);
        assert_eq!(tunnel.status, status, "CONNECT to {why} ({target})");
    }
    let unlisted = free_port();
    let response = praxis_test_utils::http_send(
        proxy.addr(),
        &format!(
            "GET http://127.0.0.1:{unlisted}/ HTTP/1.1\r\nHost: 127.0.0.1:{unlisted}\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(
        parse_status(&response),
        403,
        "an absolute-form request to an unlisted port is denied: {response}"
    );
}

#[test]
fn local_service_example_needs_allow_private_endpoints() {
    let yaml = local_service_example_yaml(free_port(), "");
    let (without_flag, _insecure) = yaml
        .split_once("insecure_options:")
        .expect("the example sets insecure_options");
    let err = Config::from_yaml(without_flag).expect_err("listing loopback must be opted in to");
    assert!(err.to_string().contains("allow_private_endpoints"), "{err}");
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

/// `security/forward-proxy-local-service.yaml` with its listed address moved
/// to `port`, and `extra_rules` (YAML list items, indented for
/// `allow_destinations`) appended to its destination rules.
fn local_service_example_yaml(port: u16, extra_rules: &str) -> String {
    let example = read_example("security/forward-proxy-local-service.yaml", free_port());
    let listed = "        - host: 127.0.0.1\n          port: 11434\n";
    assert!(example.contains(listed), "the example lists 127.0.0.1:11434");
    let yaml = example.replacen(
        listed,
        &format!("        - host: 127.0.0.1\n          port: {port}\n{extra_rules}"),
        1,
    );
    assert!(
        !yaml.contains("allow_private_upstreams: true"),
        "the listed address must work with the runtime guard on"
    );
    yaml
}

/// Read an example config with its listener moved to `proxy_port`.
fn read_example(filename: &str, proxy_port: u16) -> String {
    let path = example_config_path(filename);
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    patch_yaml(&yaml, proxy_port, &HashMap::new())
}

/// Append the insecure option loopback test destinations need.
fn with_private_upstreams(yaml: &str) -> String {
    assert!(
        !yaml.contains("insecure_options:"),
        "example should not set insecure_options"
    );
    format!("{yaml}\ninsecure_options:\n  allow_private_upstreams: true\n")
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
