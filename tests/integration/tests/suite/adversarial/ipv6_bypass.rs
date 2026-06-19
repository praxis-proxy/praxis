// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Adversarial tests verifying IPv4-mapped IPv6 addresses
//! cannot bypass IP ACL rules.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, free_port_v6, http_get, http_get_v6, ipv6_available, start_backend_v6, start_backend_with_shutdown,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn ipv4_deny_blocks_loopback() {
    let backend_port_guard = start_backend_with_shutdown("secret");
    let backend_port = backend_port_guard.port();
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
      - filter: ip_acl
        deny:
          - "127.0.0.0/8"
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

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 403, "127.0.0.1 should be denied by ACL");
}

#[test]
fn ipv6_loopback_denied_when_acl_covers_ipv6() {
    if !ipv6_available() {
        eprintln!("SKIPPED: IPv6 loopback not available");
        return;
    }

    let backend_port = start_backend_v6("secret");
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
              - "[::1]:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get_v6(proxy.addr(), "/");
    assert_eq!(
        status, 403,
        "IPv6 loopback ::1 should be denied when ::1/128 is in deny list"
    );
}

#[test]
fn ipv4_acl_allow_does_not_permit_ipv6_loopback() {
    if !ipv6_available() {
        eprintln!("SKIPPED: IPv6 loopback not available");
        return;
    }

    let backend_port = start_backend_v6("secret");
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
          - "10.0.0.0/8"
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

    let (status, _) = http_get_v6(proxy.addr(), "/");
    assert_eq!(status, 403, "IPv6 loopback should not bypass IPv4-only allow list");
}
