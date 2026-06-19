// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Health check validation: constraints, thresholds, and SSRF prevention.

use std::net::IpAddr;

use tracing::warn;

use crate::{
    config::{Cluster, HealthCheckType, InsecureOptions},
    connectivity::normalize_mapped_ipv4,
    errors::ProxyError,
};

// -----------------------------------------------------------------------------
// Health Check Validation
// -----------------------------------------------------------------------------

/// Validates health check configuration constraints.
pub(super) fn validate_health_check(
    hc: &crate::config::HealthCheckConfig,
    cluster_name: &str,
) -> Result<(), ProxyError> {
    validate_health_check_type(hc, cluster_name)?;
    validate_health_check_timing(hc, cluster_name)?;
    validate_health_check_thresholds(hc, cluster_name)?;
    validate_expected_status(hc, cluster_name)?;
    validate_passive_thresholds(hc, cluster_name)
}

/// Reject `expected_status` values outside the valid HTTP range.
fn validate_expected_status(hc: &crate::config::HealthCheckConfig, cluster_name: &str) -> Result<(), ProxyError> {
    if !(100..=599).contains(&hc.expected_status) {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health check expected_status must be 100..=599, got {}",
            hc.expected_status
        )));
    }
    Ok(())
}

/// Reject unsupported health check types.
fn validate_health_check_type(hc: &crate::config::HealthCheckConfig, cluster_name: &str) -> Result<(), ProxyError> {
    match hc.check_type {
        HealthCheckType::Http | HealthCheckType::Tcp => Ok(()),
        HealthCheckType::Grpc => Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health check type 'grpc' is not yet supported"
        ))),
    }
}

/// Validate interval, timeout, and path constraints.
fn validate_health_check_timing(hc: &crate::config::HealthCheckConfig, cluster_name: &str) -> Result<(), ProxyError> {
    if hc.interval_ms == 0 {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health check interval_ms must be > 0"
        )));
    }
    if hc.timeout_ms == 0 {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health_check.timeout_ms must be greater than 0"
        )));
    }
    validate_health_check_path(&hc.path, cluster_name)?;
    if hc.timeout_ms >= hc.interval_ms {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health check timeout_ms ({}) must be \
             less than interval_ms ({})",
            hc.timeout_ms, hc.interval_ms
        )));
    }
    Ok(())
}

/// Validate healthy/unhealthy threshold values.
fn validate_health_check_thresholds(
    hc: &crate::config::HealthCheckConfig,
    cluster_name: &str,
) -> Result<(), ProxyError> {
    if hc.healthy_threshold == 0 {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health check healthy_threshold must be >= 1"
        )));
    }
    if hc.unhealthy_threshold == 0 {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health check unhealthy_threshold must be >= 1"
        )));
    }
    Ok(())
}

/// Validate health check path for injection-prone characters.
fn validate_health_check_path(path: &str, cluster_name: &str) -> Result<(), ProxyError> {
    if !path.starts_with('/') {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health check path must start with '/'"
        )));
    }
    if path.contains('\r') || path.contains('\n') {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health_check.path must not contain CR or LF characters"
        )));
    }
    if path.contains('?') || path.contains('#') {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health_check.path must not contain '?' or '#'"
        )));
    }
    if path.contains("%00") || contains_encoded_crlf(path) {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health_check.path must not contain percent-encoded control characters"
        )));
    }
    if path.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health_check.path must not contain non-printable characters"
        )));
    }
    Ok(())
}

/// Check for percent-encoded CR (%0d/%0D) or LF (%0a/%0A).
fn contains_encoded_crlf(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.contains("%0d") || lower.contains("%0a")
}

/// Validate passive health check thresholds.
fn validate_passive_thresholds(hc: &crate::config::HealthCheckConfig, cluster_name: &str) -> Result<(), ProxyError> {
    if hc.passive_unhealthy_threshold == Some(0) {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': passive_unhealthy_threshold must be >= 1"
        )));
    }
    if hc.passive_healthy_threshold == Some(0) {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': passive_healthy_threshold must be >= 1"
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Health Check SSRF Prevention Validation
// -----------------------------------------------------------------------------

/// Reject health check endpoints that resolve to SSRF-sensitive addresses.
pub(super) fn validate_health_check_ssrf(
    cluster: &Cluster,
    insecure_options: &InsecureOptions,
) -> Result<(), ProxyError> {
    if cluster.health_check.is_none() {
        return Ok(());
    };

    for ep in &cluster.endpoints {
        let addr_str = ep.address();
        let host = extract_host(addr_str);
        check_ssrf_host(
            host,
            &cluster.name,
            addr_str,
            insecure_options.allow_private_health_checks,
        )?;
    }

    Ok(())
}

/// Check a single host for SSRF sensitivity, emitting an error or
/// warning depending on the override flag.
fn check_ssrf_host(host: &str, cluster_name: &str, addr_str: &str, allowed: bool) -> Result<(), ProxyError> {
    let sensitive = match host.parse::<IpAddr>() {
        Ok(raw) => is_ssrf_sensitive(&normalize_mapped_ipv4(raw)),
        Err(_) => is_ssrf_sensitive_hostname(host),
    };
    if !sensitive {
        return Ok(());
    }
    if allowed {
        warn!(
            cluster = %cluster_name,
            endpoint = %addr_str,
            "health check endpoint resolves to a sensitive address; \
             allowed by insecure_options.allow_private_health_checks"
        );
        return Ok(());
    }
    Err(ProxyError::Config(format!(
        "cluster '{cluster_name}': health check endpoint '{addr_str}' resolves to a \
         sensitive address; set insecure_options.allow_private_health_checks: true to allow"
    )))
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Extract the host portion from an endpoint address string.
///
/// Handles bracketed IPv6 (`[::1]:80` -> `::1`) and plain
/// `host:port` (`127.0.0.1:80` -> `127.0.0.1`).
pub(super) fn extract_host(addr: &str) -> &str {
    if let Some(bracketed) = addr.strip_prefix('[') {
        bracketed.split_once(']').map_or(addr, |(host, _)| host)
    } else {
        addr.rsplit_once(':').map_or(addr, |(h, _)| h)
    }
}

/// Returns `true` for IP addresses that are SSRF-sensitive.
///
/// Covers loopback and link-local for both IPv4 and IPv6.
/// [RFC 1918] private ranges (10/8, 172.16/12, 192.168/16) are
/// intentionally not flagged.
///
/// [RFC 1918]: https://datatracker.ietf.org/doc/html/rfc1918
pub(super) fn is_ssrf_sensitive(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            v6.is_loopback() || (segs[0] & 0xFFC0) == 0xFE80
        },
    }
}

/// Returns `true` for hostnames that commonly resolve to
/// SSRF-sensitive addresses (loopback, cloud metadata).
pub(super) fn is_ssrf_sensitive_hostname(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    lower == "localhost" || lower.ends_with(".internal") || lower.ends_with(".local") || lower.starts_with("metadata.")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::super::validate_clusters;
    use crate::config::{Cluster, Config, InsecureOptions};

    #[test]
    fn accept_valid_http_health_check() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: http
      path: "/healthz"
      interval_ms: 5000
      timeout_ms: 2000
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn accept_valid_tcp_health_check() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: tcp
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_grpc_health_check() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: grpc
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("not yet supported"), "got: {err}");
    }

    #[test]
    fn reject_unknown_health_check_type() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: websocket
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("websocket") || err.to_string().contains("unknown variant"),
            "serde should reject unknown health check type, got: {err}"
        );
    }

    #[test]
    fn reject_zero_interval() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: http
      interval_ms: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("interval_ms must be > 0"), "got: {err}");
    }

    #[test]
    fn reject_timeout_gte_interval() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: http
      interval_ms: 2000
      timeout_ms: 2000
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("timeout_ms (2000) must be less than interval_ms (2000)"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_zero_healthy_threshold() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: http
      healthy_threshold: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("healthy_threshold must be >= 1"), "got: {err}");
    }

    #[test]
    fn reject_zero_unhealthy_threshold() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: http
      unhealthy_threshold: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("unhealthy_threshold must be >= 1"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_zero_timeout_ms() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: http
      interval_ms: 5000
      timeout_ms: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("timeout_ms must be greater than 0"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_health_check_path_with_cr() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/health\r\nEvil: header".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("must not contain CR or LF"), "got: {err}");
    }

    #[test]
    fn reject_health_check_path_with_lf() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/health\nEvil: header".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("must not contain CR or LF"), "got: {err}");
    }

    #[test]
    fn is_ssrf_sensitive_flags_loopback_v4() {
        assert!(
            super::is_ssrf_sensitive(&"127.0.0.1".parse().unwrap()),
            "127.0.0.1 should be flagged"
        );
        assert!(
            super::is_ssrf_sensitive(&"127.0.0.2".parse().unwrap()),
            "127.0.0.2 should be flagged"
        );
    }

    #[test]
    fn is_ssrf_sensitive_flags_loopback_v6() {
        assert!(
            super::is_ssrf_sensitive(&"::1".parse().unwrap()),
            "::1 should be flagged"
        );
    }

    #[test]
    fn is_ssrf_sensitive_flags_cloud_metadata() {
        assert!(
            super::is_ssrf_sensitive(&"169.254.169.254".parse().unwrap()),
            "cloud metadata address should be flagged"
        );
    }

    #[test]
    fn is_ssrf_sensitive_flags_link_local_range() {
        assert!(
            super::is_ssrf_sensitive(&"169.254.0.1".parse().unwrap()),
            "169.254.0.1 (link-local) should be flagged"
        );
        assert!(
            super::is_ssrf_sensitive(&"169.254.255.255".parse().unwrap()),
            "169.254.255.255 (link-local upper bound) should be flagged"
        );
    }

    #[test]
    fn is_ssrf_sensitive_allows_rfc1918() {
        assert!(
            !super::is_ssrf_sensitive(&"10.0.0.1".parse().unwrap()),
            "RFC 1918 addresses should NOT be flagged"
        );
        assert!(
            !super::is_ssrf_sensitive(&"192.168.1.1".parse().unwrap()),
            "RFC 1918 addresses should NOT be flagged"
        );
        assert!(
            !super::is_ssrf_sensitive(&"172.16.0.1".parse().unwrap()),
            "RFC 1918 addresses should NOT be flagged"
        );
    }

    #[test]
    fn is_ssrf_sensitive_allows_public() {
        assert!(
            !super::is_ssrf_sensitive(&"8.8.8.8".parse().unwrap()),
            "public addresses should NOT be flagged"
        );
    }

    #[test]
    fn reject_ssrf_health_check_loopback() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/health".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["127.0.0.1:80".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("sensitive address"),
            "should reject loopback health check: {err}"
        );
    }

    #[test]
    fn allow_ssrf_health_check_with_override() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/health".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["127.0.0.1:80".into()])
        }];
        let opts = InsecureOptions {
            allow_private_health_checks: true,
            ..InsecureOptions::default()
        };
        validate_clusters(&clusters, &opts).expect("allow_private_health_checks should demote error to warning");
    }

    #[test]
    fn ssrf_check_passes_for_rfc1918() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/health".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])
        }];
        validate_clusters(&clusters, &InsecureOptions::default()).expect("RFC 1918 addresses should not be flagged");
    }

    #[test]
    fn reject_zero_passive_unhealthy_threshold() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: Some(0),
                path: "/".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("passive_unhealthy_threshold must be >= 1"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_zero_passive_healthy_threshold() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: Some(0),
                passive_unhealthy_threshold: None,
                path: "/".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("passive_healthy_threshold must be >= 1"),
            "got: {err}"
        );
    }

    #[test]
    fn is_ssrf_sensitive_flags_ipv4_mapped_loopback() {
        let ip: std::net::IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let normalized = crate::connectivity::normalize_mapped_ipv4(ip);
        assert!(
            super::is_ssrf_sensitive(&normalized),
            "IPv4-mapped ::ffff:127.0.0.1 should be flagged after normalization"
        );
    }

    #[test]
    fn is_ssrf_sensitive_flags_ipv4_mapped_metadata() {
        let ip: std::net::IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        let normalized = crate::connectivity::normalize_mapped_ipv4(ip);
        assert!(
            super::is_ssrf_sensitive(&normalized),
            "IPv4-mapped ::ffff:169.254.169.254 should be flagged after normalization"
        );
    }

    #[test]
    fn reject_ssrf_ipv4_mapped_loopback_endpoint() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/health".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["::ffff:127.0.0.1:80".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("sensitive address"),
            "IPv4-mapped loopback should be rejected: {err}"
        );
    }

    #[test]
    fn reject_ssrf_bracketed_ipv6_loopback() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/health".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["[::1]:80".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("sensitive address"),
            "bracketed IPv6 loopback should be rejected: {err}"
        );
    }

    #[test]
    fn extract_host_plain_ipv4() {
        assert_eq!(super::extract_host("127.0.0.1:80"), "127.0.0.1");
    }

    #[test]
    fn extract_host_bracketed_ipv6() {
        assert_eq!(super::extract_host("[::1]:80"), "::1");
    }

    #[test]
    fn extract_host_bare_hostname() {
        assert_eq!(super::extract_host("example.com"), "example.com");
    }

    #[test]
    fn accept_expected_status_at_lower_bound() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: http
      expected_status: 100
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_expected_status_below_lower_bound() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: http
      expected_status: 99
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("expected_status must be 100..=599"),
            "got: {err}"
        );
    }

    #[test]
    fn accept_expected_status_at_upper_bound() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: http
      expected_status: 599
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_expected_status_above_upper_bound() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: http
      expected_status: 600
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("expected_status must be 100..=599"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_health_check_path_with_query() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/health?foo=bar".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("'?' or '#'"),
            "query string in path should be rejected: {err}"
        );
    }

    #[test]
    fn reject_health_check_path_with_fragment() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/health#frag".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("'?' or '#'"),
            "fragment in path should be rejected: {err}"
        );
    }

    #[test]
    fn reject_health_check_path_with_encoded_null() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/health%00z".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("percent-encoded control"),
            "encoded null byte should be rejected: {err}"
        );
    }

    #[test]
    fn reject_health_check_path_with_encoded_crlf() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/health%0D%0AEvil: header".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("percent-encoded control"),
            "encoded CRLF should be rejected: {err}"
        );
    }

    #[test]
    fn is_ssrf_sensitive_flags_ipv6_link_local() {
        assert!(
            super::is_ssrf_sensitive(&"fe80::1".parse().unwrap()),
            "fe80::1 (link-local) should be flagged"
        );
        assert!(
            super::is_ssrf_sensitive(&"fe80::abcd:1234".parse().unwrap()),
            "fe80::abcd:1234 (link-local) should be flagged"
        );
    }

    #[test]
    fn is_ssrf_sensitive_allows_global_ipv6() {
        assert!(
            !super::is_ssrf_sensitive(&"2001:db8::1".parse().unwrap()),
            "global IPv6 should NOT be flagged"
        );
    }

    #[test]
    fn is_ssrf_sensitive_hostname_flags_localhost() {
        assert!(
            super::is_ssrf_sensitive_hostname("localhost"),
            "localhost should be flagged"
        );
        assert!(
            super::is_ssrf_sensitive_hostname("LOCALHOST"),
            "LOCALHOST should be flagged (case-insensitive)"
        );
    }

    #[test]
    fn is_ssrf_sensitive_hostname_flags_internal() {
        assert!(
            super::is_ssrf_sensitive_hostname("metadata.google.internal"),
            "metadata.google.internal should be flagged"
        );
        assert!(
            super::is_ssrf_sensitive_hostname("foo.internal"),
            "foo.internal should be flagged"
        );
    }

    #[test]
    fn is_ssrf_sensitive_hostname_flags_local() {
        assert!(
            super::is_ssrf_sensitive_hostname("myhost.local"),
            "myhost.local should be flagged"
        );
    }

    #[test]
    fn is_ssrf_sensitive_hostname_flags_metadata_prefix() {
        assert!(
            super::is_ssrf_sensitive_hostname("metadata.example.com"),
            "metadata.* should be flagged"
        );
    }

    #[test]
    fn is_ssrf_sensitive_hostname_allows_normal() {
        assert!(
            !super::is_ssrf_sensitive_hostname("example.com"),
            "example.com should NOT be flagged"
        );
        assert!(
            !super::is_ssrf_sensitive_hostname("api.internal.example.com"),
            "internal as a subdomain should NOT be flagged"
        );
    }

    #[test]
    fn reject_ssrf_health_check_localhost_hostname() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/health".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["localhost:80".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("sensitive address"),
            "hostname 'localhost' should be rejected: {err}"
        );
    }

    #[test]
    fn reject_ssrf_health_check_ipv6_link_local() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/health".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["[fe80::1]:80".into()])
        }];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("sensitive address"),
            "IPv6 link-local should be rejected: {err}"
        );
    }

    #[test]
    fn accept_valid_passive_thresholds() {
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
    endpoints: ["10.0.0.1:80"]
    health_check:
      type: http
      passive_unhealthy_threshold: 5
      passive_healthy_threshold: 3
"#;
        Config::from_yaml(yaml).unwrap();
    }
}
