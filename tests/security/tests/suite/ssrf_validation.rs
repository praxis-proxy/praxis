// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! SSRF endpoint validation security tests.
//!
//! Verifies that alternate IP representations (decimal, hex,
//! octal) are rejected in cluster endpoint addresses to prevent
//! SSRF attacks that bypass naive address matching.

use praxis_core::config::Config;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn decimal_loopback_ip_rejected_in_endpoint() {
    let yaml = cluster_yaml("2130706433:80");
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(
        err.to_string().contains("sensitive address"),
        "decimal 2130706433 (127.0.0.1) must be rejected: {err}"
    );
}

#[test]
fn hex_loopback_ip_rejected_in_endpoint() {
    let yaml = cluster_yaml("0x7f000001:80");
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(
        err.to_string().contains("sensitive address"),
        "hex 0x7f000001 (127.0.0.1) must be rejected: {err}"
    );
}

#[test]
fn octal_dotted_loopback_rejected_in_endpoint() {
    let yaml = cluster_yaml("0177.0.0.1:80");
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(
        err.to_string().contains("sensitive address"),
        "octal 0177.0.0.1 (127.0.0.1) must be rejected: {err}"
    );
}

#[test]
fn hex_dotted_loopback_rejected_in_endpoint() {
    let yaml = cluster_yaml("0x7f.0.0.1:80");
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(
        err.to_string().contains("sensitive address"),
        "hex dotted 0x7f.0.0.1 (127.0.0.1) must be rejected: {err}"
    );
}

#[test]
fn decimal_metadata_ip_rejected_in_endpoint() {
    let yaml = cluster_yaml("2852039166:80");
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(
        err.to_string().contains("sensitive address"),
        "decimal 2852039166 (169.254.169.254) must be rejected: {err}"
    );
}

#[test]
fn ipv4_mapped_ipv6_loopback_rejected_in_endpoint() {
    let yaml = cluster_yaml("[::ffff:127.0.0.1]:80");
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(
        err.to_string().contains("sensitive address"),
        "IPv4-mapped IPv6 loopback must be rejected: {err}"
    );
}

#[test]
fn localhost_hostname_rejected_in_endpoint() {
    let yaml = cluster_yaml("localhost:80");
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(
        err.to_string().contains("sensitive address"),
        "localhost hostname must be rejected: {err}"
    );
}

#[test]
fn metadata_hostname_rejected_in_endpoint() {
    let yaml = cluster_yaml("metadata.google.internal:80");
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(
        err.to_string().contains("sensitive address"),
        "metadata hostname must be rejected: {err}"
    );
}

#[test]
fn allow_private_endpoints_bypasses_ssrf_check() {
    let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: "backend"
    endpoints:
      - "2130706433:80"
insecure_options:
  allow_private_endpoints: true
"#;
    Config::from_yaml(yaml).expect("allow_private_endpoints should bypass SSRF check");
}

#[test]
fn public_decimal_ip_accepted_in_endpoint() {
    let yaml = cluster_yaml("134744072:80");
    Config::from_yaml(&yaml).expect("decimal 134744072 (8.8.8.8) should be accepted");
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Build a minimal config YAML with a single cluster endpoint.
fn cluster_yaml(endpoint: &str) -> String {
    format!(
        r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: "backend"
    endpoints:
      - "{endpoint}"
"#
    )
}
