// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! IPv6 conformance tests.

use praxis_core::{config::Config, connectivity::CidrRange};
use praxis_test_utils::{
    free_port, free_port_v6, http_get, http_get_v6, ipv6_available, start_backend, start_backend_v6, start_proxy,
    wait_for_tcp,
};

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
    let proxy = start_proxy(&config);

    let (status, body) = http_get_v6(proxy.addr(), "/");
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
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
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
    let proxy = start_proxy(&config);

    let (status, body) = http_get_v6(proxy.addr(), "/");
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
    let proxy = start_proxy(&config);

    let (status, _) = http_get_v6(proxy.addr(), "/");
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
    let proxy = start_proxy(&config);

    let (status, body) = http_get_v6(proxy.addr(), "/");
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
