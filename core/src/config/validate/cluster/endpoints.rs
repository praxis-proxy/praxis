// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Endpoint count, weight, and SSRF validation for clusters.

use std::net::IpAddr;

use super::{
    MAX_ENDPOINTS,
    health_check::{extract_host, is_ssrf_sensitive, is_ssrf_sensitive_hostname},
};
use crate::{
    config::{Cluster, InsecureOptions},
    connectivity::normalize_mapped_ipv4,
    errors::ProxyError,
};

// -----------------------------------------------------------------------------
// Endpoint Validation
// -----------------------------------------------------------------------------

/// Validate endpoint count, per-endpoint weights, and SSRF safety.
pub(super) fn validate_endpoints(cluster: &Cluster, insecure_options: &InsecureOptions) -> Result<(), ProxyError> {
    if cluster.endpoints.is_empty() {
        return Err(ProxyError::Config(format!(
            "cluster '{}' has no endpoints",
            cluster.name
        )));
    }
    if cluster.endpoints.len() > MAX_ENDPOINTS {
        return Err(ProxyError::Config(format!(
            "cluster '{}' has too many endpoints ({}, max {MAX_ENDPOINTS})",
            cluster.name,
            cluster.endpoints.len()
        )));
    }
    for ep in &cluster.endpoints {
        validate_endpoint_address(ep.address(), &cluster.name)?;
        if ep.weight() == 0 {
            return Err(ProxyError::Config(format!(
                "cluster '{}': endpoint '{}' has weight 0 (must be >= 1)",
                cluster.name,
                ep.address()
            )));
        }
    }
    validate_endpoint_ssrf(cluster, insecure_options)
}

/// Validate an endpoint address is well-formed `host:port`.
///
/// Accepts `SocketAddr` (`1.2.3.4:80`), bracketed IPv6
/// (`[::1]:80`), or `hostname:port` with a valid `u16` port.
fn validate_endpoint_address(addr: &str, cluster_name: &str) -> Result<(), ProxyError> {
    if addr.is_empty() {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': endpoint address must not be empty"
        )));
    }
    if addr.parse::<std::net::SocketAddr>().is_ok() {
        return Ok(());
    }
    let port_str = addr.rsplit_once(':').map_or("", |(_, p)| p);
    if port_str.parse::<u16>().is_err() {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': endpoint '{addr}' must be 'host:port' with a valid port"
        )));
    }
    Ok(())
}

/// Reject endpoints that resolve to SSRF-sensitive addresses
/// when the cluster has no health check configured.
///
/// Clusters with health checks are covered by
/// [`validate_health_check_ssrf`], gated by `allow_private_health_checks`.
///
/// [`validate_health_check_ssrf`]: super::health_check::validate_health_check_ssrf
fn validate_endpoint_ssrf(cluster: &Cluster, insecure_options: &InsecureOptions) -> Result<(), ProxyError> {
    if cluster.health_check.is_some() || insecure_options.allow_private_endpoints {
        return Ok(());
    }
    for ep in &cluster.endpoints {
        let addr_str = ep.address();
        let host = extract_host(addr_str);
        reject_ssrf_host(host, &cluster.name, addr_str)?;
    }
    Ok(())
}

/// Return an error when a host resolves to an SSRF-sensitive address.
fn reject_ssrf_host(host: &str, cluster_name: &str, addr_str: &str) -> Result<(), ProxyError> {
    let sensitive = match host.parse::<IpAddr>() {
        Ok(raw) => is_ssrf_sensitive(&normalize_mapped_ipv4(raw)),
        Err(_) => is_ssrf_sensitive_hostname(host),
    };
    if sensitive {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': endpoint '{addr_str}' resolves to a sensitive \
             address; set insecure_options.allow_private_endpoints: true to allow"
        )));
    }
    Ok(())
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
    fn reject_empty_endpoints() {
        let clusters = vec![Cluster::with_defaults("empty", vec![])];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("cluster 'empty' has no endpoints"));
    }

    #[test]
    fn reject_too_many_endpoints() {
        let endpoints: Vec<_> = (0..10_001)
            .map(|i| format!("10.0.{}.{}:80", i / 256, i % 256).into())
            .collect();
        let clusters = vec![Cluster::with_defaults("big", endpoints)];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("too many endpoints"),
            "should reject cluster exceeding MAX_ENDPOINTS: {err}"
        );
    }

    #[test]
    fn accept_exactly_max_endpoints() {
        let endpoints: Vec<_> = (0..10_000)
            .map(|i| format!("10.{}.{}.{}:80", i / 65536, (i / 256) % 256, i % 256).into())
            .collect();
        let clusters = vec![Cluster::with_defaults("big", endpoints)];
        validate_clusters(&clusters, &InsecureOptions::default()).expect("exactly MAX_ENDPOINTS should be accepted");
    }

    #[test]
    fn reject_loopback_endpoint_without_health_check() {
        let clusters = vec![Cluster::with_defaults("web", vec!["127.0.0.1:80".into()])];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("sensitive address"), "got: {err}");
    }

    #[test]
    fn reject_localhost_hostname_endpoint() {
        let clusters = vec![Cluster::with_defaults("web", vec!["localhost:80".into()])];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("sensitive address"), "got: {err}");
    }

    #[test]
    fn reject_metadata_internal_hostname() {
        let clusters = vec![Cluster::with_defaults(
            "web",
            vec!["metadata.google.internal:80".into()],
        )];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("sensitive address"), "got: {err}");
    }

    #[test]
    fn reject_ipv6_link_local_endpoint() {
        let clusters = vec![Cluster::with_defaults("web", vec!["[fe80::1]:80".into()])];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("sensitive address"), "got: {err}");
    }

    #[test]
    fn allow_private_endpoint_with_override() {
        let clusters = vec![Cluster::with_defaults("web", vec!["127.0.0.1:80".into()])];
        let opts = InsecureOptions {
            allow_private_endpoints: true,
            ..InsecureOptions::default()
        };
        validate_clusters(&clusters, &opts).expect("allow_private_endpoints should allow loopback");
    }

    #[test]
    fn ssrf_skip_endpoint_check_when_health_check_present() {
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
        validate_clusters(&clusters, &opts)
            .expect("endpoint SSRF defers to health check SSRF when health check present");
    }

    #[test]
    fn accept_rfc1918_endpoint_without_override() {
        let clusters = vec![Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])];
        validate_clusters(&clusters, &InsecureOptions::default()).expect("RFC 1918 addresses should not be flagged");
    }

    #[test]
    fn accept_public_hostname_endpoint() {
        let clusters = vec![Cluster::with_defaults("web", vec!["api.example.com:443".into()])];
        validate_clusters(&clusters, &InsecureOptions::default()).expect("public hostnames should not be flagged");
    }

    #[test]
    fn reject_endpoint_missing_port() {
        let clusters = vec![Cluster::with_defaults("web", vec!["10.0.0.1".into()])];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("host:port"),
            "endpoint without port should be rejected: {err}"
        );
    }

    #[test]
    fn reject_endpoint_invalid_port() {
        let clusters = vec![Cluster::with_defaults("web", vec!["10.0.0.1:99999".into()])];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("host:port"),
            "endpoint with invalid port should be rejected: {err}"
        );
    }

    #[test]
    fn reject_empty_endpoint_address() {
        let clusters = vec![Cluster::with_defaults("web", vec!["".into()])];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "empty endpoint address should be rejected: {err}"
        );
    }

    #[test]
    fn accept_ipv4_endpoint() {
        let clusters = vec![Cluster::with_defaults("web", vec!["10.0.0.1:8080".into()])];
        validate_clusters(&clusters, &InsecureOptions::default()).expect("valid IPv4:port should be accepted");
    }

    #[test]
    fn accept_bracketed_ipv6_endpoint() {
        let clusters = vec![Cluster::with_defaults("web", vec!["[2001:db8::1]:80".into()])];
        validate_clusters(&clusters, &InsecureOptions::default()).expect("bracketed IPv6 should be accepted");
    }

    #[test]
    fn accept_hostname_endpoint() {
        let clusters = vec![Cluster::with_defaults("web", vec!["api.example.com:443".into()])];
        validate_clusters(&clusters, &InsecureOptions::default()).expect("hostname:port should be accepted");
    }

    #[test]
    fn reject_ipv4_mapped_ipv6_loopback_endpoint() {
        let clusters = vec![Cluster::with_defaults("web", vec!["[::ffff:127.0.0.1]:80".into()])];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("sensitive address"),
            "IPv4-mapped IPv6 loopback should be flagged: {err}"
        );
    }

    #[test]
    fn reject_zero_weight_endpoint() {
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
      - address: "10.0.0.1:80"
        weight: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("weight 0"), "got: {err}");
    }
}
