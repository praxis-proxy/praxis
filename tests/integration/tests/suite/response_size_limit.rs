// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Declared response sizes are rejected before the final head reaches clients.

#[cfg(feature = "pingora")]
use std::net::Shutdown;
use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, mpsc},
    thread,
    thread::JoinHandle,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
    Rejection,
};
use praxis_test_utils::{
    H1Completion, H1Response, H2Response, custom_filter_yaml, free_port, h2c_grpc_call, http_get, read_h1_response,
    read_http_request, spawn_raw_http_backend, start_full_proxy, start_full_proxy_with_registry,
    start_recording_backend, wait_for_tcp,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Registry name of the response header mutation test filter.
const HEADER_MUTATION_FILTER: &str = "response_size_header_mutation";

/// Registry name of the response rejection test filter.
const RESPONSE_REJECT_FILTER: &str = "response_size_reject";

/// Registry name of the response body-shrinking test filter.
const RESPONSE_BODY_SHRINK_FILTER: &str = "response_size_body_shrink";

/// Return a proxy configuration with the selected response ceiling.
fn config(proxy_port: u16, backend_port: u16) -> Config {
    config_with_limit(proxy_port, backend_port, "4", false)
}

/// Return a proxy configuration with `response_limit` and the unbounded opt-in.
fn config_with_limit(proxy_port: u16, backend_port: u16, response_limit: &str, allow_unbounded: bool) -> Config {
    Config::from_yaml(&format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:{backend_port}"]
            retry_policy:
              max_retries: 1
              retriable_status_codes: [502]
body_limits:
  max_response_bytes: {response_limit}
insecure_options:
  allow_private_endpoints: true
  allow_unbounded_body: {allow_unbounded}
"#
    ))
    .unwrap()
}

/// Configure a retryable pair of upstream statuses and the response ceiling.
fn retry_config(proxy_port: u16, first_backend_port: u16, retry_backend_port: u16) -> Config {
    Config::from_yaml(&format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{first_backend_port}"
              - "127.0.0.1:{retry_backend_port}"
            load_balancer_strategy: round_robin
            retry_policy:
              max_retries: 1
              retriable_status_codes: [502, 503]
body_limits:
  max_response_bytes: 4
insecure_options:
  allow_private_endpoints: true
"#
    ))
    .unwrap()
}

/// Configure the upload-cancellation test's one-slot listener and fresh probe.
fn partial_upload_config(proxy_port: u16, backend_port: u16) -> Config {
    Config::from_yaml(&format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    max_connections: 1
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        conditions:
          - when:
              path: /probe
        status: 200
        body: probe
      - filter: router
        routes:
          - path_prefix: "/oversized"
            cluster: oversized
      - filter: load_balancer
        clusters:
          - name: oversized
            endpoints: ["127.0.0.1:{backend_port}"]
body_limits:
  max_request_bytes: 1024
  max_response_bytes: 4
insecure_options:
  allow_private_endpoints: true
"#
    ))
    .unwrap()
}

/// Hold one upstream response body until the test explicitly releases it.
fn held_backend(
    head: &'static [u8],
    body: &'static [u8],
) -> (u16, mpsc::Receiver<()>, mpsc::Sender<()>, JoinHandle<()>) {
    let (head_sent, head_received) = mpsc::channel();
    let (release_body, body_release) = mpsc::channel();
    let (port, backend) = spawn_raw_http_backend(move |mut stream| {
        read_http_request(&mut stream);
        stream.write_all(head).unwrap();
        stream.flush().unwrap();
        head_sent.send(()).unwrap();
        let _released = body_release.recv_timeout(Duration::from_secs(10));
        let _sent = stream.write_all(body);
    });
    (port, head_received, release_body, backend)
}

/// Read one held response, then release its body after a bounded wait.
fn response_before_release(
    config: &Config,
    registry: &FilterRegistry,
    head_received: &mpsc::Receiver<()>,
    release_body: &mpsc::Sender<()>,
) -> (bool, H1Response, Vec<u8>) {
    let proxy = start_full_proxy_with_registry(config, registry);
    wait_for_tcp(proxy.addr());
    let mut client = TcpStream::connect(proxy.addr()).unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    head_received.recv_timeout(Duration::from_secs(5)).unwrap();

    let (response_sent, response_received) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut body = Vec::new();
        let response = read_h1_response(&mut BufReader::new(client), false, 1024, |chunk| {
            body.extend_from_slice(chunk);
            Ok(())
        });
        let _sent = response_sent.send((response, body));
    });
    let before_release = response_received.recv_timeout(Duration::from_secs(3));
    let received_before_release = before_release.is_ok();
    release_body.send(()).unwrap();
    let (response, body) =
        before_release.unwrap_or_else(|_| response_received.recv_timeout(Duration::from_secs(5)).unwrap());
    reader.join().unwrap();
    (received_before_release, response, body)
}

#[test]
fn declared_oversize_h1_returns_complete_502_before_body_release() {
    let registry = FilterRegistry::with_builtins();
    let (backend_port, head_received, release_body, backend) = held_backend(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        b"leak!",
    );
    let (received_before_release, response, body) = response_before_release(
        &config(free_port(), backend_port),
        &registry,
        &head_received,
        &release_body,
    );
    backend.join().unwrap();

    assert!(
        received_before_release,
        "502 must complete before body release: {response:?}"
    );
    assert_eq!(response.status, Some(502), "{response:?}");
    assert_eq!(response.completion, Some(H1Completion::ContentLength), "{response:?}");
    assert_eq!(response.abort, None, "{response:?}");
    assert!(
        String::from_utf8_lossy(&body).contains("Upstream response body exceeds the configured size limit"),
        "the local size-limit cause must survive retry policy: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(
        !body.windows(b"leak!".len()).any(|window| window == b"leak!"),
        "the withheld upstream body must not reach the client"
    );
}

#[test]
fn retriable_upstream_status_wins_over_declared_response_size_limit() {
    let (first_backend, first_requests) = start_recording_backend(|_| {
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret".to_vec()
    });
    let (retry_backend, retry_requests) = start_recording_backend(|_| {
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Response-Source: retry\r\nConnection: close\r\n\r\ngood".to_vec()
    });
    let config = retry_config(free_port(), first_backend.port(), retry_backend.port());
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());

    let (status, body) = http_get(proxy.addr(), "/", None);

    assert_eq!(status, 200, "the configured 503 retry must beat local size admission");
    assert_eq!(
        body, "good",
        "the independent second upstream response must be selected"
    );
    assert!(
        !body.contains("configured size limit"),
        "no local size error may replace the retry"
    );
    assert_eq!(
        (
            first_requests.lock().unwrap().len(),
            retry_requests.lock().unwrap().len()
        ),
        (1, 1),
        "the safe GET makes one initial request and exactly one retry"
    );
}

#[test]
fn exhausted_status_retry_then_oversized_response_returns_one_local_502() {
    let (first_backend, first_requests) = start_recording_backend(|_| {
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
    });
    let (retry_backend, retry_requests) = start_recording_backend(|_| {
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret".to_vec()
    });
    let config = retry_config(free_port(), first_backend.port(), retry_backend.port());
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());

    let (status, body) = http_get(proxy.addr(), "/", None);

    assert_eq!(
        status, 502,
        "the final declared-size policy replaces the upstream response"
    );
    assert!(
        body.contains("Upstream response body exceeds the configured size limit"),
        "the local policy cause reaches the client: {body}"
    );
    assert!(!body.contains("secret"), "no upstream body bytes reach the client");
    assert_eq!(
        (
            first_requests.lock().unwrap().len(),
            retry_requests.lock().unwrap().len()
        ),
        (1, 1),
        "one retriable status consumes the budget; the local 502 starts no third attempt"
    );
}

#[test]
fn response_header_replacement_and_removal_cannot_hide_original_length() {
    for mutation in [HeaderMutation::Replace, HeaderMutation::Remove] {
        let (backend_port, head_received, release_body, backend) = held_backend(
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\n",
            b"secret",
        );
        let registry = header_mutation_registry(mutation);
        let yaml = custom_filter_yaml(free_port(), backend_port, HEADER_MUTATION_FILTER);
        let config = Config::from_yaml(&format!("{yaml}\nbody_limits:\n  max_response_bytes: 4\n")).unwrap();
        let (before_release, response, body) =
            response_before_release(&config, &registry, &head_received, &release_body);
        backend.join().unwrap();
        assert!(before_release, "{mutation:?}: {response:?}");
        assert_eq!(response.status, Some(502), "{mutation:?}: {response:?}");
        assert_eq!(
            response.completion,
            Some(H1Completion::ContentLength),
            "{mutation:?}: {response:?}"
        );
        assert!(
            !body.windows(b"secret".len()).any(|window| window == b"secret"),
            "upstream body bytes are not exposed"
        );
    }
}

#[test]
fn source_length_preflight_precedes_body_shrinking_writer_and_status_rewrite() {
    let (backend_port, head_received, release_body, backend) = held_backend(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        b"leak!",
    );
    let yaml = custom_filter_yaml(free_port(), backend_port, RESPONSE_BODY_SHRINK_FILTER);
    let config = Config::from_yaml(&format!("{yaml}\nbody_limits:\n  max_response_bytes: 4\n")).unwrap();
    let registry = body_shrinking_registry();

    let (before_release, response, body) = response_before_release(&config, &registry, &head_received, &release_body);
    backend.join().unwrap();

    assert!(
        before_release,
        "the source size wins before the writer reads the body: {response:?}"
    );
    assert_eq!(
        response.status,
        Some(502),
        "a rewritten 201 still carries the source body"
    );
    assert_eq!(response.completion, Some(H1Completion::ContentLength), "{response:?}");
    assert!(
        String::from_utf8_lossy(&body).contains("configured size limit"),
        "the local size-limit cause reaches the client"
    );
    assert!(
        !body.windows(b"leak!".len()).any(|window| window == b"leak!"),
        "the source response body is not exposed"
    );
}

#[test]
fn ambiguous_origin_framing_stays_with_existing_http_validation() {
    // Both adapters currently return a complete 500 for TE+CL and 502 for
    // conflicting Content-Length fields; the assertions below keep the
    // contract on safe framing and classification rather than parser internals.
    for (label, response) in [
        (
            "Transfer-Encoding with Content-Length",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\nConnection: close\r\n\r\n6\r\nsecret\r\n0\r\n\r\n"
                .as_slice(),
        ),
        (
            "conflicting Content-Length fields",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret".as_slice(),
        ),
    ] {
        let response = response.to_vec();
        let (backend_port, backend) = spawn_raw_http_backend(move |mut stream| {
            read_http_request(&mut stream);
            stream.write_all(&response).unwrap();
        });
        let proxy = start_full_proxy(&config(free_port(), backend_port));
        wait_for_tcp(proxy.addr());
        let mut client = TcpStream::connect(proxy.addr()).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();

        let mut reader = BufReader::new(client);
        let mut body = Vec::new();
        let observed = read_h1_response(&mut reader, false, 1024, |chunk| {
            body.extend_from_slice(chunk);
            Ok(())
        });
        let mut trailing = Vec::new();
        reader.read_to_end(&mut trailing).unwrap();
        backend.join().unwrap();

        assert!(
            observed.status.is_some(),
            "{label}: the proxy must either reject the origin response or answer it: {observed:?}"
        );
        let has_transfer_encoding = observed.headers.iter().any(|(name, _)| name == "transfer-encoding");
        let has_content_length = observed.headers.iter().any(|(name, _)| name == "content-length");
        assert!(
            !(has_transfer_encoding && has_content_length),
            "{label}: ambiguous framing must not reach the downstream: {observed:?}"
        );
        assert!(
            !String::from_utf8_lossy(&body).contains("configured size limit"),
            "{label}: raw ambiguous framing is not a declared-size rejection"
        );
        assert!(
            observed.status != Some(200) || observed.body_bytes <= 4,
            "{label}: existing incremental enforcement still observes the global cap: {observed:?}"
        );
        assert!(
            observed
                .abort
                .as_ref()
                .is_none_or(|(kind, _)| !matches!(kind, std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)),
            "{label}: connection cleanup must not time out: {observed:?}"
        );
        assert!(
            trailing.is_empty(),
            "{label}: no unframed bytes may follow the one downstream response"
        );
    }
}

#[test]
fn response_filter_rejection_precedes_size_rejection() {
    let (backend_port, head_received, release_body, backend) = held_backend(
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\n",
        b"secret",
    );
    let yaml = custom_filter_yaml(free_port(), backend_port, RESPONSE_REJECT_FILTER);
    let config = Config::from_yaml(&format!("{yaml}\nbody_limits:\n  max_response_bytes: 4\n")).unwrap();
    let registry = response_rejection_registry();
    let (before_release, response, body) = response_before_release(&config, &registry, &head_received, &release_body);
    backend.join().unwrap();

    assert!(before_release, "{response:?}");
    assert_eq!(response.status, Some(403), "filter rejection wins: {response:?}");
    assert!(response.completion.is_some(), "{response:?}");
    assert!(!body.windows(b"secret".len()).any(|window| window == b"secret"));
}

#[tokio::test]
async fn h2_upstream_overlimit_head_is_rejected_before_body_release_for_h1_and_h2_clients() {
    for downstream_h2 in [false, true] {
        assert_h2_upstream_rejected_early(downstream_h2).await;
    }
}

#[tokio::test]
async fn h2_downstream_with_h1_upstream_gets_a_complete_502_before_body_release() {
    let (backend_port, head_received, release_body, backend) = held_backend(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        b"leak!",
    );
    let proxy = start_full_proxy(&config(free_port(), backend_port));
    wait_for_tcp(proxy.addr());
    let address = proxy.addr().parse::<SocketAddr>().unwrap();
    let mut request = tokio::spawn(async move { send_h2_at(address).await });
    tokio::task::spawn_blocking(move || head_received.recv_timeout(Duration::from_secs(5)).unwrap())
        .await
        .unwrap();

    let before_release = tokio::time::timeout(Duration::from_secs(3), &mut request).await;
    let received_before_release = before_release.is_ok();
    release_body.send(()).unwrap();
    let (response, body) = match before_release {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => panic!("downstream reader failed: {error}"),
        Err(_) => tokio::time::timeout(Duration::from_secs(5), &mut request)
            .await
            .expect("downstream response after releasing the upstream body")
            .unwrap(),
    };
    backend.join().unwrap();

    assert!(
        received_before_release,
        "the H2 error must precede upstream body release"
    );
    assert_eq!(response.status, Some(502), "{response:?}");
    assert!(response.end_stream, "the local H2 response must finish its stream");
    assert!(response.abort.is_none(), "{response:?}");
    assert!(
        String::from_utf8_lossy(&body).contains("Upstream response body exceeds the configured size limit"),
        "the H1 upstream length must produce the local error body"
    );
    assert!(
        !body.windows(5).any(|window| window == b"leak!"),
        "upstream body bytes are not exposed"
    );
}

#[test]
fn declared_oversize_response_maps_to_grpc_trailers_only() {
    let (backend_port, head_received, release_body, backend) = held_backend(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        b"leak!",
    );
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: grpc
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: grpc_status
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:{backend_port}"]
body_limits:
  max_response_bytes: 4
insecure_options:
  allow_private_endpoints: true
"#
    );
    let proxy = start_full_proxy(&Config::from_yaml(&yaml).unwrap());
    wait_for_tcp(proxy.addr());
    let address = proxy.addr().to_owned();
    let (response_sent, response_received) = mpsc::channel();
    let client = thread::spawn(move || {
        let response = h2c_grpc_call(&address, "/", &[]);
        let _sent = response_sent.send(response);
    });
    head_received.recv_timeout(Duration::from_secs(5)).unwrap();

    let before_release = response_received.recv_timeout(Duration::from_secs(3));
    let received_before_release = before_release.is_ok();
    release_body.send(()).unwrap();
    let response = before_release.unwrap_or_else(|_| response_received.recv_timeout(Duration::from_secs(5)).unwrap());
    client.join().unwrap();
    backend.join().unwrap();

    assert!(
        received_before_release,
        "the gRPC error must precede upstream body release"
    );
    assert_eq!(response.status, 200, "gRPC reports proxy errors as HTTP 200");
    assert_eq!(
        response.grpc_header("grpc-status").as_deref(),
        Some("14"),
        "a local 502 maps to UNAVAILABLE"
    );
    assert!(response.end_stream, "the error must be a Trailers-Only response");
    assert_eq!(
        response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc")
    );
    assert!(response.grpc_header("grpc-message").is_some());
}

#[cfg(feature = "pingora")]
#[test]
fn declared_response_limit_cleans_up_a_post_upload_after_the_local_502() {
    let (head_sent, head_received) = mpsc::channel();
    let (prefix_sent, prefix_received) = mpsc::channel();
    let (send_response, response_requested) = mpsc::channel();
    let (upstream_closed, upstream_closed_rx) = mpsc::channel();
    let (backend_port, backend) = spawn_raw_http_backend(move |stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut reader = BufReader::new(stream);
        read_h1_request_head(&mut reader);
        head_sent.send(()).unwrap();

        let mut prefix = [0; 3];
        reader.read_exact(&mut prefix).unwrap();
        prefix_sent.send(prefix).unwrap();
        response_requested.recv_timeout(Duration::from_secs(5)).unwrap();

        reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n")
            .unwrap();
        reader.get_mut().flush().unwrap();
        let mut tail = Vec::new();
        let closed = reader.read_to_end(&mut tail).is_ok();
        let _sent = upstream_closed.send((closed, tail));
    });
    let config = partial_upload_config(free_port(), backend_port);
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let mut client = TcpStream::connect(proxy.addr()).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    client.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut response_reader = BufReader::new(client.try_clone().unwrap());
    client
        .write_all(b"POST /oversized HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 8\r\n\r\n")
        .unwrap();
    head_received.recv_timeout(Duration::from_secs(5)).unwrap();
    client.write_all(b"abc").unwrap();
    assert_eq!(prefix_received.recv_timeout(Duration::from_secs(5)).unwrap(), *b"abc");
    send_response.send(()).unwrap();

    let mut response_body = Vec::new();
    let response = read_h1_response(&mut response_reader, false, 1024, |chunk| {
        response_body.extend_from_slice(chunk);
        Ok(())
    });
    assert_eq!(response.status, Some(502), "{response:?}");
    assert_eq!(response.completion, Some(H1Completion::ContentLength), "{response:?}");
    assert!(
        response
            .headers
            .iter()
            .any(|(name, value)| name == "connection" && value == "close"),
        "the rejected upload must not reuse its HTTP/1 connection: {response:?}"
    );
    assert!(
        String::from_utf8_lossy(&response_body).contains("configured size limit"),
        "the local error body must complete before upload cleanup"
    );
    assert_eq!(
        http_get(proxy.addr(), "/probe", None).0,
        503,
        "the active upload keeps its listener permit until cleanup finishes"
    );

    client.write_all(b"defgh").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let (closed, forwarded_tail) = upstream_closed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    backend.join().unwrap();
    assert!(closed, "the rejected upstream exchange must be released");
    assert!(
        forwarded_tail.is_empty(),
        "the unread request tail must not reach the upstream"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let (status, body) = http_get(proxy.addr(), "/probe", None);
        if status == 200 {
            break;
        }
        assert_eq!(status, 503, "only the in-flight cleanup should hold admission: {body}");
        assert!(
            std::time::Instant::now() < deadline,
            "upload cleanup must release the permit"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let mut extra = [0; 1];
    assert_eq!(
        response_reader.read(&mut extra).unwrap(),
        0,
        "the closed request connection must not parse unread bytes as another request"
    );
}

#[cfg(feature = "hyper")]
#[test]
fn hyper_size_limit_closes_a_partial_post_without_reusing_either_connection() {
    let (head_sent, head_received) = mpsc::channel();
    let (prefix_sent, prefix_received) = mpsc::channel();
    let (send_response, response_requested) = mpsc::channel();
    let (upstream_closed, upstream_closed_rx) = mpsc::channel();
    let (backend_port, backend) = spawn_raw_http_backend(move |stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut reader = BufReader::new(stream);
        read_h1_request_head(&mut reader);
        head_sent.send(()).unwrap();

        let mut prefix = [0; 3];
        reader.read_exact(&mut prefix).unwrap();
        prefix_sent.send(prefix).unwrap();
        response_requested.recv_timeout(Duration::from_secs(5)).unwrap();

        reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n")
            .unwrap();
        reader.get_mut().flush().unwrap();
        let mut tail = Vec::new();
        let closed = reader.read_to_end(&mut tail).is_ok();
        let _sent = upstream_closed.send((closed, tail));
    });
    let config = partial_upload_config(free_port(), backend_port);
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let mut client = TcpStream::connect(proxy.addr()).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    client.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    client
        .write_all(b"POST /oversized HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 8\r\n\r\n")
        .unwrap();
    head_received.recv_timeout(Duration::from_secs(5)).unwrap();
    client.write_all(b"abc").unwrap();
    assert_eq!(prefix_received.recv_timeout(Duration::from_secs(5)).unwrap(), *b"abc");
    send_response.send(()).unwrap();

    let mut response_reader = BufReader::new(client);
    let mut response_body = Vec::new();
    let response = read_h1_response(&mut response_reader, false, 1024, |chunk| {
        response_body.extend_from_slice(chunk);
        Ok(())
    });
    assert_eq!(response.status, Some(502), "{response:?}");
    assert_eq!(response.completion, Some(H1Completion::ContentLength), "{response:?}");
    assert!(
        response
            .headers
            .iter()
            .any(|(name, value)| name == "connection" && value == "close"),
        "the partial upload's HTTP/1 connection must close: {response:?}"
    );
    assert!(
        String::from_utf8_lossy(&response_body).contains("configured size limit"),
        "the local error body must complete"
    );
    let mut downstream_tail = Vec::new();
    response_reader.read_to_end(&mut downstream_tail).unwrap();
    assert!(
        downstream_tail.is_empty(),
        "unread request bytes cannot become another HTTP/1 request"
    );

    let (closed, forwarded_tail) = upstream_closed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    backend.join().unwrap();
    assert!(closed, "the rejected upstream exchange must be cancelled");
    assert!(forwarded_tail.is_empty(), "no request tail reaches the upstream");
    let (probe_status, probe_body) = http_get(proxy.addr(), "/probe", None);
    assert_eq!(probe_status, 200, "a fresh connection remains healthy: {probe_body}");
}

#[test]
fn declared_response_lengths_one_below_and_at_the_limit_succeed() {
    for length in [3_usize, 4] {
        let expected = vec![b'x'; length];
        let backend_body = expected.clone();
        let (backend_port, backend) = spawn_raw_http_backend(move |mut stream| {
            read_http_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            stream.write_all(&backend_body).unwrap();
        });
        let proxy = start_full_proxy(&config(free_port(), backend_port));
        wait_for_tcp(proxy.addr());
        let mut client = TcpStream::connect(proxy.addr()).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut body = Vec::new();
        let response = read_h1_response(&mut BufReader::new(client), false, 1024, |chunk| {
            body.extend_from_slice(chunk);
            Ok(())
        });
        backend.join().unwrap();

        assert_eq!(response.status, Some(200), "{length} bytes: {response:?}");
        assert_eq!(response.completion, Some(H1Completion::ContentLength), "{response:?}");
        assert_eq!(body, expected, "{length} bytes");
    }
}

#[test]
fn unbounded_declared_response_is_not_rejected() {
    let (backend_port, backend) = spawn_raw_http_backend(move |mut stream| {
        read_http_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret")
            .unwrap();
    });
    let proxy = start_full_proxy(&config_with_limit(free_port(), backend_port, "null", true));
    wait_for_tcp(proxy.addr());
    let mut client = TcpStream::connect(proxy.addr()).unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut body = Vec::new();
    let response = read_h1_response(&mut BufReader::new(client), false, 1024, |chunk| {
        body.extend_from_slice(chunk);
        Ok(())
    });
    backend.join().unwrap();

    assert_eq!(response.status, Some(200), "{response:?}");
    assert_eq!(response.completion, Some(H1Completion::ContentLength), "{response:?}");
    assert_eq!(body, b"secret");
}

#[test]
fn absent_length_keeps_incremental_response_limit_enforcement() {
    let (head_sent, head_received) = mpsc::channel();
    let (release_body, body_release) = mpsc::channel();
    let (backend_port, backend) = spawn_raw_http_backend(move |mut stream| {
        read_http_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .unwrap();
        stream.flush().unwrap();
        head_sent.send(()).unwrap();
        let _released = body_release.recv_timeout(Duration::from_secs(10));
        let _sent = stream.write_all(b"secret");
    });
    let proxy = start_full_proxy(&config(free_port(), backend_port));
    wait_for_tcp(proxy.addr());
    let mut client = TcpStream::connect(proxy.addr()).unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let (header_sent, header_received) = mpsc::channel();
    let (body_sent, body_received) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut reader = BufReader::new(client);
        let mut header = Vec::new();
        loop {
            let mut line = Vec::new();
            if reader.read_until(b'\n', &mut line).is_err() {
                break;
            }
            let end = line == b"\r\n";
            header.extend_from_slice(&line);
            if end {
                break;
            }
        }
        let _sent = header_sent.send(header);
        let mut body = Vec::new();
        let _read = reader.read_to_end(&mut body);
        let _sent = body_sent.send(body);
    });
    head_received.recv_timeout(Duration::from_secs(5)).unwrap();
    let before_release = header_received.recv_timeout(Duration::from_secs(3));
    let received_before_release = before_release.is_ok();
    release_body.send(()).unwrap();
    let header = before_release.unwrap_or_else(|_| header_received.recv_timeout(Duration::from_secs(5)).unwrap());
    let body = body_received.recv_timeout(Duration::from_secs(5)).unwrap();
    reader.join().unwrap();
    backend.join().unwrap();

    assert!(
        received_before_release,
        "unknown-length headers should commit before body enforcement: {}",
        String::from_utf8_lossy(&header)
    );
    assert!(
        header.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&header)
    );
    assert!(
        !body.windows(b"secret".len()).any(|window| window == b"secret"),
        "the incremental limit must stop the over-limit chunk"
    );
    assert!(
        !body.ends_with(b"0\r\n\r\n"),
        "the incremental overflow must not complete the chunked response"
    );
}

/// Which response-header edit the test filter makes.
#[derive(Clone, Copy, Debug)]
enum HeaderMutation {
    /// Replace the upstream length with a smaller value.
    Replace,
    /// Remove the upstream length.
    Remove,
}

/// Filter that changes the forwarded framing without changing the source size.
struct ResponseHeadMutation(HeaderMutation);

#[async_trait::async_trait]
impl HttpFilter for ResponseHeadMutation {
    fn name(&self) -> &'static str {
        HEADER_MUTATION_FILTER
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(response) = ctx.response_header.as_deref_mut() {
            match self.0 {
                HeaderMutation::Replace => {
                    response
                        .headers
                        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("1"));
                },
                HeaderMutation::Remove => {
                    let _removed = response.headers.remove(http::header::CONTENT_LENGTH);
                },
            }
        }
        Ok(FilterAction::Continue)
    }
}

/// A response writer that also rewrites the final status.
struct ShrinkResponseBody;

#[async_trait::async_trait]
impl HttpFilter for ShrinkResponseBody {
    fn name(&self) -> &'static str {
        RESPONSE_BODY_SHRINK_FILTER
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(response) = ctx.response_header.as_deref_mut() {
            response.status = http::StatusCode::CREATED;
        }
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite(praxis_filter::BodyRequirement::Optional)
    }

    fn response_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(16) }
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream && body.is_some() {
            *body = Some(bytes::Bytes::from_static(b"x"));
        }
        Ok(FilterAction::Continue)
    }
}

/// Filter that rejects the response head before the size policy is considered.
struct RejectResponse;

#[async_trait::async_trait]
impl HttpFilter for RejectResponse {
    fn name(&self) -> &'static str {
        RESPONSE_REJECT_FILTER
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Reject(Rejection::status(403)))
    }
}

/// Register the response length rewrite filter.
fn header_mutation_registry(mutation: HeaderMutation) -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            HEADER_MUTATION_FILTER,
            FilterFactory::Http(Arc::new(move |_| Ok(Box::new(ResponseHeadMutation(mutation))))),
        )
        .unwrap();
    registry
}

/// Register the response rejection filter.
fn response_rejection_registry() -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            RESPONSE_REJECT_FILTER,
            FilterFactory::Http(Arc::new(|_| Ok(Box::new(RejectResponse)))),
        )
        .unwrap();
    registry
}

/// Register the body-shrinking response filter.
fn body_shrinking_registry() -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            RESPONSE_BODY_SHRINK_FILTER,
            FilterFactory::Http(Arc::new(|_| Ok(Box::new(ShrinkResponseBody)))),
        )
        .unwrap();
    registry
}

/// Read an HTTP/1 request head without consuming an incomplete request body.
fn read_h1_request_head(reader: &mut BufReader<TcpStream>) {
    loop {
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line).unwrap();
        if line == b"\r\n" {
            return;
        }
    }
}

/// Serve one HTTP/2 response whose declared body waits for the test to release it.
fn held_h2_backend() -> (
    SocketAddr,
    mpsc::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (head_sent, head_received) = mpsc::channel();
    let (release_body, body_release) = tokio::sync::oneshot::channel();
    let backend = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(socket).await.unwrap();
            let Some(Ok((_request, mut respond))) = connection.accept().await else {
                return;
            };
            let response = http::Response::builder()
                .status(200)
                .header(http::header::CONTENT_LENGTH, "5")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            let driver = tokio::spawn(async move {
                while let Some(result) = connection.accept().await {
                    if result.is_err() {
                        break;
                    }
                }
            });
            head_sent.send(()).unwrap();
            let _released = body_release.await;
            let _sent = send.send_data(bytes::Bytes::from_static(b"leak!"), true);
            drop(send);
            let _finished = tokio::time::timeout(Duration::from_secs(2), driver).await;
        });
    });
    (address, head_received, release_body, backend)
}

/// Check an HTTP/2 upstream response against either downstream protocol.
async fn assert_h2_upstream_rejected_early(downstream_h2: bool) {
    let (backend_address, head_received, release_body, backend) = held_h2_backend();
    let config = h2_upstream_config(free_port(), backend_address);
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let address = proxy.addr().parse::<SocketAddr>().unwrap();
    let mut request = tokio::spawn(async move {
        if downstream_h2 {
            let (response, body) = send_h2_at(address).await;
            DownstreamResponse::Http2(Box::new(response), body)
        } else {
            DownstreamResponse::Http1(send_h1_at(address).await)
        }
    });
    tokio::task::spawn_blocking(move || head_received.recv_timeout(Duration::from_secs(5)).unwrap())
        .await
        .unwrap();
    let before_release = tokio::time::timeout(Duration::from_secs(3), &mut request).await;
    let response_received_before_release = before_release.is_ok();
    release_body.send(()).unwrap();
    let response = match before_release {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => panic!("downstream reader failed: {error}"),
        Err(_) => tokio::time::timeout(Duration::from_secs(5), &mut request)
            .await
            .expect("downstream response after releasing the upstream body")
            .unwrap(),
    };
    backend.join().unwrap();

    assert!(
        response_received_before_release,
        "a complete local 502 must precede body release, H2 client={downstream_h2}"
    );
    if downstream_h2 {
        let DownstreamResponse::Http2(response, body) = response else {
            panic!("expected an HTTP/2 response");
        };
        assert_eq!(response.status, Some(502), "{response:?}");
        assert!(response.end_stream, "{response:?}");
        assert!(response.abort.is_none(), "{response:?}");
        assert!(
            !body.windows(5).any(|window| window == b"leak!"),
            "upstream body bytes are not exposed"
        );
    } else {
        let DownstreamResponse::Http1(response) = response else {
            panic!("expected an HTTP/1 response");
        };
        assert!(
            response.starts_with(b"HTTP/1.1 502"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            !response.windows(5).any(|window| window == b"leak!"),
            "upstream body bytes are not exposed"
        );
    }
}

/// Send one HTTP/1 request to `address` and read its complete response.
async fn send_h1_at(address: SocketAddr) -> Vec<u8> {
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut raw))
        .await
        .expect("HTTP/1 response completes")
        .unwrap();
    raw
}

/// Send one HTTP/2 request to `address` and read its complete response.
#[expect(
    clippy::large_stack_frames,
    reason = "the real HTTP/2 client state is large in this test helper"
)]
async fn send_h2_at(address: SocketAddr) -> (H2Response, Vec<u8>) {
    Box::pin(async move {
        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
        let (mut client, connection) = h2::client::handshake(socket).await.unwrap();
        let driver = tokio::spawn(connection);
        let request = http::Request::get("/").header("host", "localhost").body(()).unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .expect("HTTP/2 response head arrives")
            .unwrap();
        let mut body = Vec::new();
        let observed = tokio::time::timeout(
            Duration::from_secs(5),
            praxis_test_utils::read_h2_response(Ok(response), 1024, |chunk| {
                body.extend_from_slice(chunk);
                Ok(())
            }),
        )
        .await
        .expect("HTTP/2 response completes");
        driver.abort();
        (observed, body)
    })
    .await
}

/// Configure a route whose upstream leg speaks HTTP/2.
fn h2_upstream_config(proxy_port: u16, backend_address: SocketAddr) -> Config {
    Config::from_yaml(&format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["{backend_address}"]
            http:
              version: h2
            retry_policy:
              max_retries: 1
              retriable_status_codes: [502]
body_limits:
  max_response_bytes: 4
insecure_options:
  allow_private_endpoints: true
"#
    ))
    .unwrap()
}

/// The response a client received over one downstream protocol.
enum DownstreamResponse {
    /// An HTTP/1 response collected from the wire.
    Http1(Vec<u8>),
    /// An HTTP/2 response, including stream completion.
    Http2(Box<H2Response>, Vec<u8>),
}
