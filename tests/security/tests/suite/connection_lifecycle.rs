// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Connection reuse, pipelined framing, and truncation after response commitment.

use std::{
    io::{Read as _, Write as _},
    sync::mpsc,
};

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, parse_body, parse_header, parse_status, read_http_request, simple_proxy_yaml, spawn_raw_http_backend,
    start_full_proxy, start_keepalive_poison_backend, start_proxy, start_uri_echo_backend, wait_for_tcp,
};

use super::test_utils::{IO_TIMEOUT, connect, read_closed, send_text, status_lines};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn keepalive_poisoning_does_not_leak_to_later_requests() {
    let (backend, log) = start_keepalive_poison_backend();
    let config = Config::from_yaml(&simple_proxy_yaml(free_port(), backend.port())).unwrap();
    let proxy = start_proxy(&config);
    for path in ["/first", "/later"] {
        let raw = send_text(
            proxy.addr(),
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        );
        assert_eq!(parse_status(&raw), 200, "each request must get a legitimate response");
        assert_eq!(
            parse_body(&raw),
            "safe",
            "later request must not consume forged response"
        );
        assert!(
            parse_header(&raw, "x-poisoned").is_none(),
            "forged header must not cross requests"
        );
        assert_eq!(status_lines(&raw), 1, "exactly one response belongs to each request");
    }
    let requests = log.lock().unwrap();
    let first = requests
        .iter()
        .find(|entry| entry.3 == "/first")
        .map(|entry| entry.0)
        .expect("backend must receive first request");
    let later = requests
        .iter()
        .find(|entry| entry.3 == "/later")
        .map(|entry| (entry.0, entry.1))
        .expect("backend must receive later request");
    drop(requests);
    assert_ne!(
        first, later.0,
        "poisoned upstream connection must not return to the pool"
    );
    assert_eq!(later.1, 1, "later request must start a fresh backend connection");
}

#[test]
fn http11_pipelining_drops_overread_without_mixing_responses() {
    let backend = start_uri_echo_backend();
    let config = Config::from_yaml(&simple_proxy_yaml(free_port(), backend.port())).unwrap();
    let proxy = start_proxy(&config);
    let raw = send_text(
        proxy.addr(),
        "GET /a HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\nGET /b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "first pipelined request must succeed");
    assert_eq!(parse_body(&raw), "/a", "disabled pipelining must not append or swap /b");
    assert_eq!(status_lines(&raw), 1, "overread must close after exactly one response");
}

#[test]
fn premature_backend_close_truncates_committed_body_and_does_not_poison_recovery() {
    let (release, released) = mpsc::channel();
    let (port, worker) = spawn_raw_http_backend(move |mut stream| {
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        read_http_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 131072\r\nConnection: keep-alive\r\n\r\n")
            .unwrap();
        stream.write_all(&vec![b'x'; 65_536]).unwrap();
        released
            .recv_timeout(IO_TIMEOUT)
            .expect("client must observe committed response before backend close");
    });
    let healthy = praxis_test_utils::start_backend_with_shutdown("recovered");
    let mut yaml = simple_proxy_yaml(free_port(), healthy.port());
    yaml = yaml.replace(
        "routes:\n",
        "routes:\n          - path_prefix: \"/truncated\"\n            cluster: broken\n",
    );
    yaml = yaml.replace(
        "clusters:\n",
        &format!("clusters:\n          - name: broken\n            endpoints: [\"127.0.0.1:{port}\"]\n"),
    );
    let proxy = start_full_proxy(&Config::from_yaml(&yaml).unwrap());
    wait_for_tcp(proxy.addr());
    let mut stream = connect(proxy.addr());
    stream
        .write_all(b"GET /truncated HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut observed = Vec::new();
    while observed
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .is_none_or(|end| observed.len() < end + 4 + 65_536)
    {
        let mut buffer = [0_u8; 512];
        let count = stream.read(&mut buffer).expect("committed response before timeout");
        assert_ne!(count, 0, "backend must remain open until body is observed");
        observed.extend_from_slice(&buffer[..count]);
        assert!(observed.len() < 131_072, "fixture response must remain small");
    }
    release.send(()).unwrap();
    observed.extend_from_slice(&read_closed(&mut stream));
    worker.join().expect("truncated backend must finish");
    let raw = String::from_utf8(observed).unwrap();
    assert_eq!(
        parse_status(&raw),
        200,
        "already committed status cannot be replaced with 502"
    );
    assert_eq!(
        parse_header(&raw, "content-length").as_deref(),
        Some("131072"),
        "declared size must exceed actual body"
    );
    assert_eq!(
        parse_body(&raw),
        "x".repeat(65_536),
        "upstream EOF must truncate rather than fabricate a complete body"
    );
    assert_eq!(
        status_lines(&raw),
        1,
        "no error status may be appended to the committed body"
    );
    let recovered = send_text(
        proxy.addr(),
        "GET /healthy HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&recovered),
        200,
        "independent request must recover after truncation"
    );
    assert_eq!(
        parse_body(&recovered),
        "recovered",
        "failed upstream must not contaminate healthy response"
    );
}
