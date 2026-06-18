// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! IPv4 and IPv6 ip_acl configuration parsing tests.

use std::collections::HashMap;

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn ip_acl_example_parses() {
    let proxy_port = praxis_test_utils::free_port();
    let _config = crate::example_utils::load_example_config("security/ip-acl.yaml", proxy_port, HashMap::new());
}

#[test]
fn ipv6_loopback_in_allow_list() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        allow:
          - "::1/128"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    let acl = &config.filter_chains[0].filters[0];
    assert_eq!(acl.filter_type, "ip_acl", "first filter should be ip_acl");
    let allow = acl
        .config
        .get("allow")
        .and_then(|v| v.as_sequence())
        .expect("allow list must exist");
    assert_eq!(allow.len(), 1, "allow list should have 1 entry");
    assert_eq!(
        allow[0].as_str().unwrap(),
        "::1/128",
        "allow entry should be IPv6 loopback"
    );
}

#[test]
fn ipv6_ula_in_allow_list() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        allow:
          - "fd00::/8"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    let acl = &config.filter_chains[0].filters[0];
    let allow = acl
        .config
        .get("allow")
        .and_then(|v| v.as_sequence())
        .expect("allow list must exist");
    assert_eq!(
        allow[0].as_str().unwrap(),
        "fd00::/8",
        "allow entry should be IPv6 ULA range"
    );
}

#[test]
fn ipv6_documentation_prefix_in_allow_list() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        allow:
          - "2001:db8::/32"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    let acl = &config.filter_chains[0].filters[0];
    let allow = acl
        .config
        .get("allow")
        .and_then(|v| v.as_sequence())
        .expect("allow list must exist");
    assert_eq!(
        allow[0].as_str().unwrap(),
        "2001:db8::/32",
        "allow entry should be IPv6 documentation prefix"
    );
}

#[test]
fn ipv6_catch_all_in_deny_list() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        deny:
          - "::/0"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    let acl = &config.filter_chains[0].filters[0];
    let deny = acl
        .config
        .get("deny")
        .and_then(|v| v.as_sequence())
        .expect("deny list must exist");
    assert_eq!(deny.len(), 1, "deny list should have 1 entry");
    assert_eq!(deny[0].as_str().unwrap(), "::/0", "deny entry should be IPv6 catch-all");
}

#[test]
fn mixed_ipv4_and_ipv6_rules() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        allow:
          - "127.0.0.0/8"
          - "10.0.0.0/8"
          - "::1/128"
          - "fd00::/8"
          - "2001:db8::/32"
        deny:
          - "0.0.0.0/0"
          - "::/0"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    let acl = &config.filter_chains[0].filters[0];
    let allow = acl
        .config
        .get("allow")
        .and_then(|v| v.as_sequence())
        .expect("allow list must exist");
    assert_eq!(allow.len(), 5, "allow list should have 5 entries (2 IPv4 + 3 IPv6)");
    let deny = acl
        .config
        .get("deny")
        .and_then(|v| v.as_sequence())
        .expect("deny list must exist");
    assert_eq!(deny.len(), 2, "deny list should have 2 entries (IPv4 + IPv6 catch-all)");
}

#[test]
fn ipv6_full_address_cidr() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        allow:
          - "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    let acl = &config.filter_chains[0].filters[0];
    let allow = acl
        .config
        .get("allow")
        .and_then(|v| v.as_sequence())
        .expect("allow list must exist");
    assert_eq!(
        allow[0].as_str().unwrap(),
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128",
        "should accept full IPv6 address with /128 prefix"
    );
}

#[test]
fn ipv6_link_local_in_deny_list() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        deny:
          - "fe80::/10"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    let acl = &config.filter_chains[0].filters[0];
    let deny = acl
        .config
        .get("deny")
        .and_then(|v| v.as_sequence())
        .expect("deny list must exist");
    assert_eq!(
        deny[0].as_str().unwrap(),
        "fe80::/10",
        "deny entry should be IPv6 link-local range"
    );
}
