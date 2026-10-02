// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for upstream TLS handshakes that cannot complete: a backend
//! that never answers the handshake, a backend that speaks plaintext,
//! and a backend whose certificate has expired.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    path::Path,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{TestCertificates, free_port, http_get, start_proxy, start_tls_backend};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn silent_tls_backend_hits_the_connection_timeout() {
    let backend_port = start_silent_backend();
    let proxy_port = free_port();
    let yaml = tls_cluster_yaml(proxy_port, backend_port, None, Some(500));
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let start = Instant::now();
    let (status, _) = http_get(proxy.addr(), "/", None);
    let elapsed = start.elapsed();
    assert_eq!(
        status, 504,
        "a backend that never answers the TLS handshake should hit total_connection_timeout_ms and get a 504 \
         (took {elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the connection timeout should bound the request, retries included; took {elapsed:?}"
    );
}

#[test]
fn plaintext_backend_behind_tls_cluster_returns_502() {
    let backend_port = start_plaintext_backend();
    let proxy_port = free_port();
    let yaml = tls_cluster_yaml(proxy_port, backend_port, None, None);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let start = Instant::now();
    let (status, body) = http_get(proxy.addr(), "/", None);
    let elapsed = start.elapsed();
    assert_eq!(
        status, 502,
        "a plaintext reply to the TLS ClientHello should fail the handshake with a 502: {body}"
    );
    assert!(
        !body.contains("bad request"),
        "the backend's plaintext reply must not reach the client: {body}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "a failed handshake should surface promptly; took {elapsed:?}"
    );
}

#[test]
fn expired_backend_certificate_returns_502() {
    let cases = [
        (
            TestCertificates::generate(),
            200,
            "an in-date certificate from the trusted CA should verify (the control for the expired case)",
        ),
        (
            TestCertificates::generate_expired(),
            502,
            "an expired certificate from the trusted CA must fail verification with a 502",
        ),
    ];
    for (certs, expected, why) in cases {
        let backend_port = start_tls_backend(&certs, "verified");
        let proxy_port = free_port();
        let yaml = tls_cluster_yaml(proxy_port, backend_port, Some(&certs.ca_cert_path), None);
        let config = Config::from_yaml(&yaml).unwrap();
        let proxy = start_proxy(&config);

        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, expected, "{why}: {body}");
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Start a backend that accepts connections and reads whatever arrives
/// but never sends a byte, so a TLS handshake against it never finishes.
fn start_silent_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                drop(stream.set_read_timeout(Some(Duration::from_secs(30))));
                let mut buf = [0_u8; 4096];
                while matches!(stream.read(&mut buf), Ok(len) if len > 0) {}
            });
        }
    });
    port
}

/// Start a plaintext HTTP backend that answers whatever arrives, a TLS
/// ClientHello included, with an HTTP 400 and then closes.
fn start_plaintext_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || reply_in_plaintext(stream));
        }
    });
    port
}

/// Read one chunk from `stream` and answer it with a plaintext 400.
fn reply_in_plaintext(mut stream: TcpStream) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    let _sent =
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbad request");
}

/// Proxy config routing everything to one TLS cluster that expects the
/// name `localhost`, trusting `ca` when given and bounding connection
/// setup (TCP plus TLS) to `connect_timeout_ms` when given.
fn tls_cluster_yaml(proxy_port: u16, backend_port: u16, ca: Option<&Path>, connect_timeout_ms: Option<u64>) -> String {
    let ca = ca.map_or_else(String::new, |path| {
        format!("\n              ca:\n                ca_path: \"{}\"", path.display())
    });
    let timeout = connect_timeout_ms.map_or_else(String::new, |millis| {
        format!("\n            total_connection_timeout_ms: {millis}")
    });
    format!(
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
            tls:
              sni: "localhost"{ca}
            endpoints:
              - "127.0.0.1:{backend_port}"{timeout}
insecure_options:
  allow_private_endpoints: true
"#
    )
}
