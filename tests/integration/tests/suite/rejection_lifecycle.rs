// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Early rejection delivery, body-limit diagnostics, and bounded upload cleanup.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{
    PraxisProcess, TestCertificates, free_port, http_post, http_send, parse_body, parse_status, simple_proxy_yaml,
    start_echo_backend, start_proxy, start_tls_proxy_no_wait, wait_for_tls,
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
