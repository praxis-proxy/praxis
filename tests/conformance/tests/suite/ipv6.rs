//! IPv6 conformance tests.
//!
//! Verify that the proxy correctly handles IPv6 listeners,
//! IPv6 upstream endpoints, IP ACL rules with IPv6 CIDR
//! ranges, and IPv6 client address logging.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

use praxis_core::{config::Config, connectivity::CidrRange};

use crate::common::{free_port, http_get, parse_body, parse_status, start_backend, start_proxy, wait_for_tcp};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn ipv6_listener_serves_http() {
    if !ipv6_available() {
        eprintln!("SKIPPED: IPv6 loopback not available");
        return;
    }

    let backend_port = start_backend("ipv6-listener-ok");
    let proxy_port = free_port_v6();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "[::1]:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get_v6(&addr, "/");
    assert_eq!(status, 200, "IPv6 listener should return 200");
    assert_eq!(body, "ipv6-listener-ok", "IPv6 listener should proxy to IPv4 backend");
}

#[test]
fn ipv6_upstream_endpoint() {
    if !ipv6_available() {
        eprintln!("SKIPPED: IPv6 loopback not available");
        return;
    }

    let backend_port = start_backend_v6("ipv6-upstream-ok");
    wait_for_tcp(&format!("[::1]:{backend_port}"));

    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "[::1]:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "proxy should reach IPv6 upstream and return 200");
    assert_eq!(body, "ipv6-upstream-ok", "response body should come from IPv6 backend");
}

#[test]
fn ipv6_ip_acl_allow() {
    if !ipv6_available() {
        eprintln!("SKIPPED: IPv6 loopback not available");
        return;
    }

    let backend_port = start_backend("ipv6-acl-ok");
    let proxy_port = free_port_v6();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "[::1]:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        allow:
          - "::1/128"
        deny:
          - "::/0"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get_v6(&addr, "/");
    assert_eq!(status, 200, "::1 should be allowed by ::1/128 ACL");
    assert_eq!(body, "ipv6-acl-ok", "allowed IPv6 request should return backend body");
}

#[test]
fn ipv6_ip_acl_deny() {
    if !ipv6_available() {
        eprintln!("SKIPPED: IPv6 loopback not available");
        return;
    }

    let backend_port = start_backend("should-not-reach");
    let proxy_port = free_port_v6();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "[::1]:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        deny:
          - "::1/128"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, _) = http_get_v6(&addr, "/");
    assert_eq!(status, 403, "::1 should be denied by ::1/128 deny rule");
}

#[test]
fn ipv6_access_log_records_client_address() {
    if !ipv6_available() {
        eprintln!("SKIPPED: IPv6 loopback not available");
        return;
    }

    let backend_port = start_backend("logged-v6");
    let proxy_port = free_port_v6();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "[::1]:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: access_log
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get_v6(&addr, "/");
    assert_eq!(status, 200, "IPv6 listener with access_log should return 200");
    assert_eq!(
        body, "logged-v6",
        "response body should be intact with access_log filter on IPv6"
    );
}

#[test]
fn cidr_v6_exact_match() {
    let range = CidrRange::parse("::1/128").expect("::1/128 should parse");
    let loopback: std::net::IpAddr = "::1".parse().unwrap();
    let other: std::net::IpAddr = "::2".parse().unwrap();

    assert!(range.contains(&loopback), "::1/128 should match ::1 exactly");
    assert!(!range.contains(&other), "::1/128 should not match ::2");
}

#[test]
fn cidr_v6_match_all() {
    let range = CidrRange::parse("::/0").expect("::/0 should parse");
    let addrs: Vec<std::net::IpAddr> = vec![
        "::1".parse().unwrap(),
        "fe80::1".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
    ];

    for addr in &addrs {
        assert!(
            range.contains(addr),
            "::/0 should match all IPv6 addresses, failed on {addr}"
        );
    }
}

#[test]
fn cidr_v6_ula_range() {
    let range = CidrRange::parse("fd00::/16").expect("fd00::/16 should parse");

    let inside: std::net::IpAddr = "fd00::abcd:1234".parse().unwrap();
    let also_inside: std::net::IpAddr = "fd00:1::1".parse().unwrap();
    let outside: std::net::IpAddr = "fe80::1".parse().unwrap();
    let outside_v4: std::net::IpAddr = "10.0.0.1".parse().unwrap();

    assert!(range.contains(&inside), "fd00::abcd:1234 should be within fd00::/16");
    assert!(range.contains(&also_inside), "fd00:1::1 should be within fd00::/16");
    assert!(!range.contains(&outside), "fe80::1 should be outside fd00::/16");
    assert!(
        !range.contains(&outside_v4),
        "IPv4 10.0.0.1 should not match IPv6 range fd00::/16"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Attempt to bind to `[::1]:0`. Returns `true` if IPv6
/// loopback is available in this environment.
fn ipv6_available() -> bool {
    TcpListener::bind("[::1]:0").is_ok()
}

/// Allocate a free port on the IPv6 loopback interface.
///
/// # Panics
///
/// Panics if binding to `[::1]:0` fails (caller must check
/// [`ipv6_available`] first).
fn free_port_v6() -> u16 {
    TcpListener::bind("[::1]:0").unwrap().local_addr().unwrap().port()
}

/// Spawn a raw TCP backend on `[::1]` that returns a fixed
/// HTTP response body. Returns the port.
///
/// # Panics
///
/// Panics if binding to `[::1]:0` fails.
fn start_backend_v6(body: &str) -> u16 {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = body.to_owned();

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let body = body.clone();
            std::thread::spawn(move || {
                handle_v6_connection(stream, &body);
            });
        }
    });

    port
}

/// Handle a single TCP connection: read request headers,
/// write a minimal HTTP 200 response.
fn handle_v6_connection(mut stream: TcpStream, body: &str) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut buf = [0u8; 4096];
    let _ = stream.read(&mut buf);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Connect to an IPv6 address, send a raw HTTP request,
/// and return the response.
fn http_send_v6(addr: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
}

/// Send an HTTP GET to an IPv6 address and return
/// `(status, body)`.
fn http_get_v6(addr: &str, path: &str) -> (u16, String) {
    let raw = http_send_v6(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    );
    (parse_status(&raw), parse_body(&raw))
}
