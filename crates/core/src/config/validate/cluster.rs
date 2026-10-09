// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Cluster validation: endpoints, weights, SNI hostnames, timeouts, and health check addresses.

mod application;
pub(in crate::config) mod authority;
mod endpoints;
mod health_check;
mod load_balancer;
mod timeouts;
mod tls;

pub use health_check::is_ssrf_sensitive;

use crate::{config::InsecureOptions, errors::ProxyError};

// -----------------------------------------------------------------------------
// Cluster Validation Constants
// -----------------------------------------------------------------------------

/// Maximum number of clusters allowed in the configuration.
const MAX_CLUSTERS: usize = 10_000;

/// Maximum allowed timeout value in milliseconds (1 hour).
pub(crate) const MAX_TIMEOUT_MS: u64 = 3_600_000;

/// Maximum number of endpoints allowed per cluster.
pub(crate) const MAX_ENDPOINTS: usize = 10_000;

/// Maximum relative weight for a single endpoint.
///
/// Weighted load balancers (Maglev, consistent hashing) expand each
/// endpoint into `weight` replicas at build time, so an unbounded weight
/// is an out-of-memory vector — a `weight` typo would allocate billions
/// of replicas during a live reload. A ratio of 1000:1 is far beyond any
/// real hardware-capacity spread.
pub(crate) const MAX_ENDPOINT_WEIGHT: u32 = 1_000;

// -----------------------------------------------------------------------------
// Cluster Validation
// -----------------------------------------------------------------------------

/// Validate endpoint counts, weights, SNI hostnames, and timeout consistency.
pub(in crate::config::validate) fn validate_clusters(
    clusters: &[crate::config::Cluster],
    insecure_options: &InsecureOptions,
) -> Result<(), ProxyError> {
    if clusters.len() > MAX_CLUSTERS {
        return Err(ProxyError::Config(format!(
            "too many clusters ({}, max {MAX_CLUSTERS})",
            clusters.len()
        )));
    }
    for cluster in clusters {
        if cluster.name.is_empty() {
            return Err(ProxyError::Config("cluster name must not be empty".into()));
        }
        super::validate_name_chars(&cluster.name, "cluster")?;
        cluster.validate_authority()?;
        validate_base_path(cluster)?;
        application::validate_application_metadata(cluster)?;
        endpoints::validate_endpoints(cluster, insecure_options)?;
        validate_endpoint_hosts(cluster)?;
        tls::validate_tls_settings(cluster, insecure_options)?;
        timeouts::validate_timeouts(cluster)?;
        validate_cluster_max_connections(cluster)?;
        load_balancer::validate_lb_strategy(cluster)?;
        if let Some(hc) = &cluster.health_check {
            health_check::validate_health_check(hc, &cluster.name)?;
        }
        health_check::validate_grpc_probe_transport(cluster)?;
        health_check::validate_health_check_ssrf(cluster, insecure_options)?;
        health_check::warn_tls_http_probe_mismatch(cluster);
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Base Path Validation
// -----------------------------------------------------------------------------

/// Longest accepted upstream base path.
const MAX_BASE_PATH_LEN: usize = 1024;

/// Validate the optional upstream base path.
///
/// Rejected rather than normalized, because every rejected form means the
/// author intended something the prefix cannot express: a relative path, a
/// path that escapes the prefix, or a query the upstream leg would drop.
fn validate_base_path(cluster: &crate::config::Cluster) -> Result<(), ProxyError> {
    let Some(raw) = cluster.http.base_path.as_deref() else {
        return Ok(());
    };
    let context = format!("cluster '{}': http.base_path", cluster.name);
    let fault = if raw.len() > MAX_BASE_PATH_LEN {
        format!("is longer than {MAX_BASE_PATH_LEN} bytes")
    } else if !raw.starts_with('/') {
        "must start with '/'".to_owned()
    } else if raw.starts_with("//") {
        "must not start with '//'".to_owned()
    } else if raw.contains("//") {
        "must not contain an empty segment".to_owned()
    } else if raw.split('/').any(|seg| seg == ".." || seg == ".") {
        "must not contain a '.' or '..' segment".to_owned()
    } else if raw.contains('?') || raw.contains('#') {
        "must not contain a query or fragment".to_owned()
    } else if raw.contains('%') {
        // Allowing it would admit the encoded traversal the path check rejects.
        "must not be percent-encoded".to_owned()
    } else if !raw.bytes().all(|byte| byte.is_ascii_graphic()) {
        "must be printable ASCII with no whitespace".to_owned()
    } else if raw.parse::<http::uri::PathAndQuery>().is_err() {
        // Caught here, or every request for the cluster fails in production.
        "is not a valid URI path".to_owned()
    } else {
        return Ok(());
    };
    Err(ProxyError::Config(format!("{context} {raw:?} {fault}")))
}

// -----------------------------------------------------------------------------
// Trusted Private Endpoints Validation
// -----------------------------------------------------------------------------

/// Each entry must be a hostname naming one of the cluster's endpoints.
fn validate_endpoint_hosts(cluster: &crate::config::Cluster) -> Result<(), ProxyError> {
    if cluster.trusted_private_endpoints.is_empty() {
        return Ok(());
    }
    let context = format!("cluster '{}'", cluster.name);
    crate::connectivity::validate_host_entries(&context, &cluster.trusted_private_endpoints)
        .map_err(ProxyError::Config)?;
    for entry in &cluster.trusted_private_endpoints {
        let unbracketed = entry
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(entry);
        let host = crate::connectivity::strip_root_dot(entry);
        let fault = if unbracketed.parse::<std::net::IpAddr>().is_ok() {
            // Literal endpoints are never resolved, so the entry could not match.
            "is an IP address"
        } else if host.is_empty() || host.ends_with('.') {
            "is not a hostname"
        } else if !cluster.endpoints.iter().any(|ep| {
            crate::connectivity::strip_root_dot(health_check::extract_host(ep.address())).eq_ignore_ascii_case(host)
        }) {
            "matches no endpoint host"
        } else {
            continue;
        };
        return Err(ProxyError::Config(format!(
            "{context}: trusted_private_endpoints entry {entry:?} {fault}"
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Max Connections Validation
// -----------------------------------------------------------------------------

/// Validate `max_connections` is at least 1 and within the allowed ceiling.
fn validate_cluster_max_connections(cluster: &crate::config::Cluster) -> Result<(), ProxyError> {
    let Some(max_connections) = cluster.max_connections else {
        return Ok(());
    };
    let name = &cluster.name;
    if max_connections == 0 {
        return Err(ProxyError::Config(format!(
            "cluster '{name}': max_connections must be >= 1"
        )));
    }
    if max_connections > super::MAX_CONNECTIONS {
        return Err(ProxyError::Config(format!(
            "cluster '{name}': max_connections ({max_connections}) exceeds maximum ({})",
            super::MAX_CONNECTIONS,
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
    use super::validate_clusters;
    use crate::config::{Cluster, Config, InsecureOptions};

    #[test]
    fn reject_too_many_clusters() {
        let clusters: Vec<Cluster> = (0..10_001)
            .map(|i| Cluster::with_defaults(&format!("c{i}"), vec!["10.0.0.1:80".into()]))
            .collect();
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("too many clusters"), "got: {err}");
    }

    #[test]
    fn no_tls_skips_tls_validation() {
        let clusters = vec![Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])];
        validate_clusters(&clusters, &InsecureOptions::default()).expect("no TLS should skip TLS validation");
    }

    #[test]
    fn reject_cluster_zero_max_connections() {
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
  - name: backend
    endpoints: ["10.0.0.1:80"]
    max_connections: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("max_connections must be >= 1"),
            "should reject zero cluster max_connections: {err}"
        );
    }

    #[test]
    fn reject_cluster_max_connections_exceeding_maximum() {
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
  - name: backend
    endpoints: ["10.0.0.1:80"]
    max_connections: 1000001
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "should reject cluster max_connections > 1M: {err}"
        );
    }

    #[test]
    fn accept_cluster_with_authority() {
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
  - name: api
    endpoints: ["10.0.0.1:443"]
    http:
      authority: "api.example.com"
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn accept_cluster_with_authority_and_port() {
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
  - name: api
    endpoints: ["10.0.0.1:8443"]
    http:
      authority: "api.example.com:8443"
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn accept_cluster_with_endpoint_authority() {
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
  - name: api
    endpoints: ["api-a.example.com:443", "api-b.example.com:443"]
    http:
      authority: { from: endpoint }
    tls: {}
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert!(
            config.clusters[0]
                .http
                .authority
                .as_ref()
                .is_some_and(crate::config::UpstreamAuthority::follows_endpoint),
            "authority should parse as the endpoint-derived form"
        );
    }

    #[test]
    fn reject_cluster_with_unknown_authority_source() {
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
  - name: api
    endpoints: ["10.0.0.1:80"]
    http:
      authority: { from: upstream }
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("upstream"),
            "the unknown authority source should be named: {err}"
        );
    }

    #[test]
    fn accept_cluster_without_authority() {
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
  - name: backend
    endpoints: ["10.0.0.1:80"]
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_cluster_with_empty_authority() {
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
  - name: backend
    endpoints: ["10.0.0.1:80"]
    http:
      authority: ""
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "should reject empty authority: {err}"
        );
    }

    #[test]
    fn reject_cluster_with_scheme_in_authority() {
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
  - name: backend
    endpoints: ["10.0.0.1:443"]
    http:
      authority: "https://api.example.com"
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("not a valid HTTP authority"),
            "should reject authority with scheme: {err}"
        );
    }

    #[test]
    fn reject_cluster_with_path_in_authority() {
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
  - name: backend
    endpoints: ["10.0.0.1:443"]
    http:
      authority: "api.example.com/v1"
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("not a valid HTTP authority"),
            "should reject authority with path: {err}"
        );
    }

    #[test]
    fn accept_cluster_max_connections_at_maximum() {
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
  - name: backend
    endpoints: ["10.0.0.1:80"]
    max_connections: 1000000
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn accept_cluster_application_metadata() {
        config_with_http_block("      application_protocol: openai_chat_completions\n      application_provider: vllm")
            .expect("valid application metadata should be accepted");
    }

    #[test]
    fn accept_cluster_application_protocol_alone() {
        config_with_http_block("      application_protocol: openai_responses")
            .expect("application_protocol without provider should be accepted");
    }

    #[test]
    fn accept_cluster_application_provider_alone() {
        config_with_http_block("      application_provider: vllm")
            .expect("application_provider without protocol should be accepted");
    }

    #[test]
    fn reject_cluster_invalid_application_protocol() {
        let err = config_with_http_block("      application_protocol: OpenAI").unwrap_err();
        assert!(
            err.to_string().contains("application_protocol"),
            "should reject invalid application_protocol: {err}"
        );
    }

    #[test]
    fn reject_cluster_invalid_application_provider() {
        let err = config_with_http_block("      application_provider: \"vllm!\"").unwrap_err();
        assert!(
            err.to_string().contains("application_provider"),
            "should reject invalid application_provider: {err}"
        );
    }

    #[test]
    fn reject_cluster_empty_application_protocol() {
        let err = config_with_http_block("      application_protocol: \"\"").unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "should reject empty application_protocol: {err}"
        );
    }

    #[test]
    fn reject_inline_load_balancer_cluster_invalid_application_protocol() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: load_balancer
        clusters:
          - name: api
            endpoints: ["10.0.0.1:443"]
            http:
              application_protocol: OpenAI
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("application_protocol"),
            "inline load-balancer cluster must reject an invalid application_protocol \
             (same validation as top-level clusters): {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    #[test]
    fn accept_valid_base_paths() {
        for raw in ["/grid-models/model-a", "/v1", "/a/b/c", "/models/a/", "/"] {
            let failure = config_with_http_block(&format!("      base_path: {raw:?}")).err();
            assert!(
                failure.is_none(),
                "base_path {raw:?} should be accepted, got: {failure:?}"
            );
        }
    }

    #[test]
    fn reject_malformed_base_paths() {
        let cases = [
            ("models/a", "must start with '/'"),
            ("//models/a", "must not start with '//'"),
            ("/models//a", "must not contain an empty segment"),
            ("/models/../a", "must not contain a '.' or '..' segment"),
            ("/models/./a", "must not contain a '.' or '..' segment"),
            ("/models/a?x=1", "must not contain a query or fragment"),
            ("/models/a#frag", "must not contain a query or fragment"),
            ("/models/ a", "must be printable ASCII with no whitespace"),
            ("/models/\u{e9}", "must be printable ASCII with no whitespace"),
            ("/models/%2e%2e/a", "must not be percent-encoded"),
            ("/models/a%2fb", "must not be percent-encoded"),
            ("/models/<a>", "is not a valid URI path"),
        ];
        for (raw, want) in cases {
            let err = config_with_http_block(&format!("      base_path: {raw:?}"))
                .expect_err(&format!("base_path {raw:?} should be rejected"));
            let text = err.to_string();
            assert!(
                text.contains(want),
                "base_path {raw:?} should be rejected for {want:?}, got: {text}"
            );
        }
    }

    #[test]
    fn reject_overlong_base_path() {
        let raw = format!("/{}", "a".repeat(super::MAX_BASE_PATH_LEN));
        let err = config_with_http_block(&format!("      base_path: {raw:?}")).expect_err("should be rejected");
        assert!(err.to_string().contains("is longer than"), "got: {err}");
    }

    // Build a config with one cluster carrying the given `http:` block.
    fn config_with_http_block(http_block: &str) -> Result<Config, crate::errors::ProxyError> {
        let yaml = format!(
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
  - name: api
    endpoints: ["10.0.0.1:443"]
    http:
{http_block}
"#
        );
        Config::from_yaml(&yaml)
    }
}
