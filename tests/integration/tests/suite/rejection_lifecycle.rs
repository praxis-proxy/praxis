// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Early rejection delivery, body-limit diagnostics, and bounded upload cleanup.

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext, TerminalResponse};
use praxis_test_utils::{
    PraxisProcess, TestCertificates, free_port, http_get, http_post, http_send, parse_body, parse_status,
    registry_with, simple_proxy_yaml, start_echo_backend, start_proxy, start_proxy_with_registry,
    start_tls_proxy_no_wait, wait_for_tls,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
#[cfg_attr(coverage, ignore = "spawns the proxy binary")]
fn oversized_expect_continue_is_rejected_before_upload_and_logged() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut proxy = PraxisProcess::spawn(&inspection_config(port, ""), &addr);
    let response = http_send(
        &addr,
        concat!(
            "POST / HTTP/1.1\r\nHost: localhost\r\n",
            "Content-Length: 16777216\r\nExpect: 100-continue\r\n\r\n"
        ),
    );

    assert_eq!(
        parse_status(&response),
        413,
        "a final rejection must arrive without sending the body"
    );
    assert!(
        !response.contains("100 Continue"),
        "an oversized declared body must not be invited"
    );
    assert!(
        parse_body(&response).contains("request body too large"),
        "the response must explain the rejection"
    );
    let _status = proxy.terminate();
    assert_warning(&proxy.logs(), "DeclaredLength");
    assert!(
        proxy.logs().contains("bytes_seen=0"),
        "header admission must not consume body data"
    );
}

#[test]
#[cfg_attr(coverage, ignore = "spawns the proxy binary")]
fn chunked_send_then_read_gets_413_and_one_body_limit_warning() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut proxy = PraxisProcess::spawn(&inspection_config(port, ""), &addr);
    let response = http_send(&addr, &chunked_upload());

    assert_eq!(
        parse_status(&response),
        413,
        "a blocking chunked uploader must receive the rejection"
    );
    let _status = proxy.terminate();
    let logs = proxy.logs();
    assert_warning(&logs, "PreRead");
    assert_eq!(
        logs.matches("request body exceeds configured limit").count(),
        1,
        "overflow must log once"
    );
}

#[test]
#[cfg_attr(coverage, ignore = "spawns the proxy binary")]
fn streaming_size_limit_rejection_drains_an_unknown_length_upload() {
    let backend = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let yaml = format!(
        "runtime:\n  threads: 2\nbody_limits:\n  max_request_bytes: 1024\n{}",
        simple_proxy_yaml(port, backend.port())
    );
    let mut proxy = PraxisProcess::spawn(&yaml, &addr);

    let response = http_send(&addr, &chunked_upload());

    assert_eq!(
        parse_status(&response),
        413,
        "the streaming body callback must use shared rejection cleanup"
    );
    let _status = proxy.terminate();
    assert_warning(&proxy.logs(), "SizeLimit");
}

#[test]
#[cfg_attr(coverage, ignore = "spawns the proxy binary")]
fn stalled_streaming_rejection_releases_upstream_before_cleanup() {
    let (backend, closed) = upstream_close_probe();
    let port = free_port();
    let admin = format!("127.0.0.1:{}", free_port());
    let addr = format!("127.0.0.1:{port}");
    let proxy = PraxisProcess::spawn_with_env(
        &stalled_upload_config(port, backend, &admin),
        &addr,
        &[("RUST_LOG", "info")],
    );
    let mut client = TcpStream::connect(&addr).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    client.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    client
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1000000\r\n")
        .unwrap();
    client.write_all(&vec![b'a'; 11_534_336]).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();

    assert_eq!(
        parse_status(&response),
        413,
        "the stalled upload must receive 413 and EOF"
    );
    let received = closed
        .recv_timeout(Duration::from_secs(2))
        .expect("the upstream must close while the downstream upload is still unfinished");
    assert!(
        received > 0,
        "the request must have reached the upstream before rejection"
    );
    let logs = wait_for_completion_log(&proxy);
    assert!(
        !logs.contains("Fail to proxy"),
        "an expected 413 must not also log an ERROR:\n{logs}"
    );
    assert_eq!(
        logs.matches("request body exceeds configured limit").count(),
        1,
        "overflow must log once"
    );
    let duration = logs
        .lines()
        .find_map(|line| line.split_once("lifecycle 413 "))
        .and_then(|(_, suffix)| suffix.split_whitespace().next())
        .and_then(|value| value.parse::<f64>().ok())
        .expect("access log duration");
    assert!(
        duration < 5_000.0,
        "access duration must exclude lingering cleanup: {duration} ms"
    );
    let (status, metrics) = http_get(&admin, "/metrics", None);
    assert_eq!(status, 200, "the metrics endpoint must remain available during cleanup");
    assert!(
        (request_metric(&metrics, "count") - 1.0).abs() < f64::EPSILON,
        "completion must be counted before cleanup"
    );
    assert!(
        request_metric(&metrics, "sum") < 5.0,
        "request latency must exclude cleanup:\n{metrics}"
    );

    let mut overload = TcpStream::connect(&addr).unwrap();
    overload.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    overload
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 16777216\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    overload
        .read_to_string(&mut response)
        .expect("overload rejection must close promptly without entering upload cleanup");
    assert_eq!(
        parse_status(&response),
        503,
        "cleanup must still hold the first request's permit"
    );
}

#[tokio::test]
#[cfg_attr(coverage, ignore = "spawns the proxy binary")]
async fn streaming_body_limit_rejection_does_not_retry_upstream() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = listener.local_addr().unwrap().port();
    let (accepted, mut attempts) = tokio::sync::mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        let mut connections = Vec::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            connections.push(stream);
            if accepted.send(connections.len()).is_err() {
                break;
            }
        }
    });
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let yaml = simple_proxy_yaml(port, backend).replacen(
        "            endpoints:",
        "            retry_policy:\n              max_retries: 1\n              retriable_status_codes: [413]\n            endpoints:",
        1,
    );
    let config = format!("runtime:\n  threads: 2\nbody_limits:\n  max_request_bytes: 1024\n{yaml}");
    let proxy = PraxisProcess::spawn(&config, &addr);
    let mut client = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let request = format!(
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n800\r\n{}\r\n0\r\n\r\n",
        "a".repeat(2048)
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_string(&mut response))
        .await
        .expect("a local body rejection must be delivered promptly")
        .unwrap();
    assert_eq!(parse_status(&response), 413, "the local rejection must be preserved");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), attempts.recv())
            .await
            .expect("the initial attempt must reach the upstream")
            .expect("the upstream probe must stay alive"),
        1,
        "the upstream probe must observe the initial attempt"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), attempts.recv())
            .await
            .is_err(),
        "a local 413 must not open a second upstream attempt even when 413 is retriable"
    );
    server.abort();
    let _result = server.await;
    drop(proxy);
}

#[test]
fn successful_terminal_response_cleans_up_an_unfinished_upload() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let yaml = format!(
        "runtime:\n  threads: 2\n\
         listeners:\n  - name: web\n    address: '{addr}'\n    max_connections: 1\n    filter_chains: [main]\n\
         filter_chains:\n  - name: main\n    filters:\n      - filter: test_terminal\n"
    );
    let registry = registry_with("test_terminal", || Box::new(SuccessfulTerminalFilter));
    let proxy = start_proxy_with_registry(&Config::from_yaml(&yaml).unwrap(), &registry);
    let mut client = TcpStream::connect(&addr).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    client.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    client
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 8\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .expect("the complete terminal response and EOF must arrive before the upload finishes");
    assert_eq!(
        parse_status(&response),
        200,
        "the local response must retain its status"
    );
    assert_eq!(parse_body(&response), "ok", "the terminal body must be complete");
    assert_eq!(
        http_get(&addr, "/", None).0,
        503,
        "the unread upload must still hold its connection permit during cleanup"
    );

    client
        .write_all(b"finished")
        .expect("the response half-close must leave upload reads usable");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let (status, _) = http_get(&addr, "/", None);
        if status == 200 {
            break;
        }
        assert_eq!(status, 503, "only admission should reject the probe");
        assert!(
            Instant::now() < deadline,
            "finishing the upload must promptly release its connection permit"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(proxy);
}

#[test]
fn early_auth_and_rate_limit_rejections_drain_unread_uploads() {
    let body = "a".repeat(16_777_216);
    for status in [401, 403, 429] {
        let yaml = format!(
            "body_limits:\n  max_request_bytes: 67108864\n{}",
            terminal_config(free_port(), status)
        );
        let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());

        let (received, _) = http_post(proxy.addr(), "/", &body);

        assert_eq!(
            received, status,
            "a blocking uploader must receive the early {status} response"
        );
    }
}

#[test]
fn tls_chunked_upload_receives_complete_413_after_write_side_shutdown() {
    let certs = TestCertificates::generate();
    let tls = format!(
        "    tls:\n      certificates:\n        - cert_path: \"{}\"\n          key_path: \"{}\"\n",
        certs.cert_path.display(),
        certs.key_path.display()
    );
    let config = Config::from_yaml(&inspection_config(free_port(), &tls)).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    let client_config = certs.raw_tls_client_config();
    wait_for_tls(proxy.addr(), &client_config);
    let socket = TcpStream::connect(proxy.addr()).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let connection = rustls::ClientConnection::new(client_config, "localhost".try_into().unwrap()).unwrap();
    let mut stream = rustls::StreamOwned::new(connection, socket);

    stream
        .write_all(chunked_upload().as_bytes())
        .expect("TLS upload must finish without a broken pipe");
    stream.flush().unwrap();
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("TLS close_notify must follow the complete response");

    assert_eq!(
        parse_status(&response),
        413,
        "TLS clients must receive the rejection status"
    );
    let body: serde_json::Value = serde_json::from_str(&parse_body(&response)).unwrap();
    assert_eq!(
        body["error"], "request body too large",
        "TLS clients must receive the complete JSON body"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Return a real terminal response instead of the rejection used by static_response.
struct SuccessfulTerminalFilter;

#[async_trait::async_trait]
impl HttpFilter for SuccessfulTerminalFilter {
    fn name(&self) -> &'static str {
        "test_terminal"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::TerminalResponse(Box::new(
            TerminalResponse::new(200).with_body("ok"),
        )))
    }
}

/// Observe closure of the upstream's incomplete request without sending a response.
fn upstream_close_probe() -> (u16, mpsc::Receiver<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = mpsc::channel();
    drop(std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut received = Vec::new();
        let ended = match stream.read_to_end(&mut received) {
            Ok(_) => true,
            Err(error) => error.kind() == std::io::ErrorKind::ConnectionReset,
        };
        if ended {
            let _sent = sender.send(received.len());
        }
    }));
    (port, receiver)
}

/// Configure a streamed upload with access logging and an isolated metrics endpoint.
fn stalled_upload_config(port: u16, backend: u16, admin: &str) -> String {
    let yaml = simple_proxy_yaml(port, backend).replacen(
        "      - filter: router",
        "      - filter: access_log\n        template: 'lifecycle {status} {duration_ms}'\n      - filter: router",
        1,
    );
    format!("runtime:\n  threads: 2\n  max_connections: 1\nadmin:\n  metrics_address: '{admin}'\n{yaml}")
}

/// Wait for the access record while the rejected client keeps its upload open.
fn wait_for_completion_log(proxy: &PraxisProcess) -> String {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let logs = proxy.logs();
        if logs.contains("lifecycle 413 ") {
            return logs;
        }
        assert!(
            Instant::now() < deadline,
            "completion must be logged before cleanup ends:\n{logs}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Read the rejected POST's duration series from its isolated process recorder.
fn request_metric(metrics: &str, suffix: &str) -> f64 {
    let prefix = format!("praxis_http_request_duration_seconds_{suffix}{{");
    metrics
        .lines()
        .find(|line| {
            line.starts_with(&prefix) && line.contains("method=\"POST\"") && line.contains("status_class=\"4xx\"")
        })
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse().ok())
        .expect("rejected request duration metric")
}

/// A body much larger than the configured cap with no declared total length.
fn chunked_upload() -> String {
    let body = format!(r#"{{"model":"{}"}}"#, "a".repeat(16_777_216));
    format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{body}\r\n0\r\n\r\n",
        body.len()
    )
}

/// A body-inspection pipeline ending in a local success response.
fn inspection_config(port: u16, tls: &str) -> String {
    format!(
        r#"
runtime:
  threads: 2
listeners:
  - name: web
    address: "127.0.0.1:{port}"
    filter_chains: [main]
{tls}filter_chains:
  - name: main
    filters:
      - filter: json_body_field
        field: model
        header: X-Model
        max_body_bytes: 1024
      - filter: static_response
        status: 200
        body: ok
"#
    )
}

/// A terminal filter rejects a request without reading its body.
fn terminal_config(port: u16, status: u16) -> String {
    format!(
        r#"
listeners:
  - name: web
    address: "127.0.0.1:{port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: {status}
        body: denied
"#
    )
}

/// Assert that a real proxy process emitted structured body-limit diagnostics.
fn assert_warning(logs: &str, phase: &str) {
    assert!(
        logs.contains("WARN") && logs.contains("request body exceeds configured limit"),
        "missing warning:\n{logs}"
    );
    assert!(
        logs.contains("status=413") && logs.contains("limit=1024"),
        "missing limit fields:\n{logs}"
    );
    assert!(
        logs.contains(&format!("phase={phase}")),
        "missing rejection phase {phase}:\n{logs}"
    );
}
