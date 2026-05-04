// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Health check validation: constraints, thresholds, and SSRF prevention.

use std::net::IpAddr;

use tracing::warn;

use crate::{
    config::{Cluster, HealthCheckType, InsecureOptions},
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
    validate_passive_thresholds(hc, cluster_name)
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
    if hc.path.contains('\r') || hc.path.contains('\n') {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health_check.path must not contain CR or LF characters"
        )));
    }
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
        let host = addr_str.rsplit_once(':').map_or(addr_str, |(h, _)| h);

        let Ok(ip) = host.parse::<IpAddr>() else {
            continue;
        };

        if is_ssrf_sensitive(&ip) {
            if insecure_options.allow_private_health_checks {
                warn!(
                    cluster = %cluster.name,
                    endpoint = %addr_str,
                    "health check endpoint resolves to a sensitive address \
                     (loopback or cloud metadata); allowed by insecure_options.allow_private_health_checks"
                );
            } else {
                return Err(ProxyError::Config(format!(
                    "cluster '{}': health check endpoint '{addr_str}' resolves to a \
                     sensitive address (loopback or cloud metadata); set \
                     insecure_options.allow_private_health_checks: true to allow",
                    cluster.name
                )));
            }
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Returns `true` for IP addresses that are SSRF-sensitive.
///
/// Note: [RFC 1918] private ranges (10/8, 172.16/12, 192.168/16)
/// are intentionally not flagged; only loopback and cloud metadata
/// addresses are considered sensitive.
///
/// [RFC 1918]: https://datatracker.ietf.org/doc/html/rfc1918
fn is_ssrf_sensitive(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || *v4 == std::net::Ipv4Addr::new(169, 254, 169, 254),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
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
