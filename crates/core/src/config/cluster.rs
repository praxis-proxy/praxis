// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Upstream cluster definitions: endpoints, load-balancing strategies, and timeouts.

mod endpoint;
mod health_check;
mod load_balancer_strategy;
mod retry_policy;
mod upstream_authority;

use std::{fmt, sync::Arc};

pub use endpoint::Endpoint;
pub use health_check::{HealthCheckConfig, HealthCheckType};
pub use load_balancer_strategy::{
    ConsistentHashOpts, HashFunction, LoadBalancerStrategy, MaglevOpts, ParameterisedStrategy, PriorityOpts,
    RingHashOpts, SimpleStrategy, SubsetFallbackPolicy, SubsetOpts, ZoneAwareOpts,
};
pub use retry_policy::{
    BackoffConfig, BudgetPercent, DEFAULT_MAX_RETRIES, DEFAULT_RETRY_BODY_LIMIT_BYTES, HttpStatusCode,
    MAX_EFFECTIVE_RETRIES, MAX_RETRY_BODY_LIMIT_BYTES, RetriableCondition, RetryBodyLimit, RetryBudgetConfig,
    RetryPolicy,
};
use serde::{Deserialize, Serialize};
pub use upstream_authority::{AuthoritySource, UpstreamAuthority};

use crate::errors::ProxyError;

// -----------------------------------------------------------------------------
// Cluster
// -----------------------------------------------------------------------------

/// The HTTP version Praxis speaks to a cluster's endpoints.
///
/// Praxis proxies to upstreams over HTTP/1.1 unless a cluster opts
/// out. HTTP/2 is required for gRPC upstreams: response trailers —
/// which carry `grpc-status` — exist only on an HTTP/2 leg.
///
/// ```
/// use praxis_core::config::UpstreamHttpVersion;
///
/// let v: UpstreamHttpVersion = serde_yaml::from_str("h2").unwrap();
/// assert_eq!(v, UpstreamHttpVersion::H2);
/// assert_eq!(UpstreamHttpVersion::default(), UpstreamHttpVersion::H1);
///
/// let bad: Result<UpstreamHttpVersion, _> = serde_yaml::from_str("http3");
/// assert!(bad.is_err());
/// ```
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamHttpVersion {
    /// HTTP/1.1 only (the default, and Praxis's historical behaviour).
    #[default]
    H1,

    /// HTTP/2 only: ALPN `h2` over TLS, prior-knowledge h2c over
    /// plaintext. A plaintext endpoint that does not speak h2c fails
    /// to connect — there is no negotiation to fall back on.
    H2,

    /// Prefer HTTP/2, fall back to HTTP/1.1.
    ///
    /// Over TLS this advertises `h2,http/1.1` and honours the server's
    /// choice. Over plaintext there is no negotiation mechanism, so
    /// Pingora connects over HTTP/1.1.
    Auto,
}

impl fmt::Display for UpstreamHttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::H1 => f.write_str("h1"),
            Self::H2 => f.write_str("h2"),
            Self::Auto => f.write_str("auto"),
        }
    }
}

/// HTTP-specific options for a cluster.
///
/// These apply only when the cluster serves HTTP listeners; TCP load
/// balancers do not process HTTP headers and ignore this block.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterHttpOptions {
    /// Override the upstream HTTP `Host` header.
    ///
    /// When set, the proxy rewrites the `Host` header sent to the
    /// upstream instead of forwarding the downstream value. The
    /// downstream HTTP/2 `:authority` pseudo-header is never forwarded
    /// upstream; on an HTTP/2 upstream leg Pingora rebuilds
    /// `:authority` from this `Host` value.
    ///
    /// A plain string is a fixed authority sent on every request. It
    /// must be a valid HTTP authority: a hostname with an optional
    /// port, or a bracketed IPv6 address with an optional port. URI
    /// schemes, paths, userinfo, and fragments are rejected. When
    /// `tls.sni` is unset, the upstream TLS SNI defaults to this host
    /// (port stripped) rather than the client `Host` header.
    ///
    /// `{ from: endpoint }` sends the address of the endpoint selected
    /// for each attempt instead, so one cluster can front endpoints
    /// with different hostnames. The port is left out when it is the
    /// scheme default (80, or 443 with `tls`), and a retry to another
    /// endpoint sends that endpoint's address. Without `tls.sni`, the
    /// TLS SNI follows the endpoint too rather than copying the
    /// downstream `Host`; an IP endpoint gets no SNI.
    ///
    /// ```
    /// # use praxis_core::config::Cluster;
    /// let yaml = r#"
    /// name: "mixed"
    /// endpoints: ["api-a.example.com:443", "api-b.example.com:443"]
    /// http:
    ///   authority: { from: endpoint }
    /// tls: {}
    /// "#;
    /// let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
    /// assert!(cluster.http.authority.unwrap().follows_endpoint());
    /// ```
    #[serde(default)]
    pub authority: Option<UpstreamAuthority>,

    /// Opaque application protocol the upstream cluster expects.
    ///
    /// Declares the wire representation of the request body (for
    /// example `openai_chat_completions` or `openai_responses`). The
    /// value stays opaque to Praxis core — consuming filters interpret
    /// it; Praxis defines no enum of known protocols. Validated as a
    /// bounded, canonical identifier: 1–64 bytes of lowercase ASCII
    /// letters, digits, `.`, `_`, or `-`, starting and ending with a
    /// letter or digit.
    ///
    /// The open string type is deliberate: the protocol set is
    /// open-ended and owned by consuming filters, so keep this a string
    /// — do not convert it to an enum.
    #[serde(default)]
    pub application_protocol: Option<Arc<str>>,

    /// Opaque application provider refining `application_protocol`.
    ///
    /// Distinguishes provider-specific semantics (for example `openai`
    /// or `vllm`) independent of the deployed cluster, whose identity
    /// is already the cluster name. Stays opaque to Praxis core and
    /// follows the same identifier rules — and the same enum-free
    /// rationale — as `application_protocol`.
    #[serde(default)]
    pub application_provider: Option<Arc<str>>,

    /// HTTP version used for upstream connections to this cluster.
    ///
    /// Defaults to [`H1`]. Set `h2` for gRPC upstreams: response
    /// trailers, and therefore `grpc-status`, only exist on an
    /// HTTP/2 leg.
    ///
    /// ```
    /// # use praxis_core::config::{Cluster, UpstreamHttpVersion};
    /// let yaml = r#"
    /// name: "grpc"
    /// endpoints: ["10.0.0.1:50051"]
    /// http:
    ///   version: h2
    /// "#;
    /// let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
    /// assert_eq!(cluster.http.version, UpstreamHttpVersion::H2);
    /// ```
    ///
    /// [`H1`]: UpstreamHttpVersion::H1
    #[serde(default)]
    pub version: UpstreamHttpVersion,
}

/// A named group of upstream endpoints.
///
/// ```
/// # use praxis_core::config::Cluster;
/// let yaml = r#"
/// name: "backend"
/// endpoints: ["10.0.0.1:8080"]
/// connection_timeout_ms: 5000
/// idle_timeout_ms: 30000
/// "#;
/// let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
/// assert_eq!(cluster.connection_timeout_ms, Some(5000));
/// assert_eq!(cluster.idle_timeout_ms, Some(30000));
/// assert!(cluster.read_timeout_ms.is_none());
/// assert!(cluster.tls.is_none());
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cluster {
    /// Unique name for the cluster.
    pub name: Arc<str>,

    /// HTTP-specific cluster options.
    ///
    /// Grouped under `http:` so the shared cluster/upstream transport
    /// types stay protocol-agnostic; TCP load balancers ignore this
    /// block entirely.
    ///
    /// ```
    /// # use praxis_core::config::{Cluster, UpstreamAuthority};
    /// let yaml = r#"
    /// name: "api"
    /// endpoints: ["10.0.0.1:443"]
    /// http:
    ///   authority: "api.example.com"
    /// tls:
    ///   sni: "api.example.com"
    /// "#;
    /// let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
    /// assert_eq!(
    ///     cluster.http.authority,
    ///     Some(UpstreamAuthority::from("api.example.com"))
    /// );
    /// ```
    #[serde(default)]
    pub http: ClusterHttpOptions,

    /// TCP connection timeout in milliseconds.
    ///
    /// Applies to the TCP handshake only (before TLS). When
    /// exceeded, the connection attempt fails and the load
    /// balancer may retry on the next endpoint. `None` (the
    /// default) uses Pingora's built-in timeout.
    #[serde(default)]
    pub connection_timeout_ms: Option<u64>,

    /// List of endpoints for the cluster. Each entry is either a plain
    /// `"host:port"` string or a `{ address, weight }` object.
    pub endpoints: Vec<Endpoint>,

    /// Active health check configuration for this cluster.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,

    /// Idle connection timeout in milliseconds.
    ///
    /// Closes pooled upstream connections that have been idle
    /// longer than this duration. `None` uses Pingora's default.
    #[serde(default)]
    pub idle_timeout_ms: Option<u64>,

    /// Load-balancing algorithm for this cluster. Defaults to `round_robin`.
    #[serde(default)]
    pub load_balancer_strategy: LoadBalancerStrategy,

    /// Maximum concurrent in-flight requests to this cluster.
    ///
    /// When set, excess requests receive 503. Prevents a single
    /// slow upstream from consuming all available capacity.
    ///
    /// ```
    /// # use praxis_core::config::Cluster;
    /// let yaml = r#"
    /// name: backend
    /// endpoints: ["10.0.0.1:80"]
    /// max_connections: 100
    /// "#;
    /// let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
    /// assert_eq!(cluster.max_connections, Some(100));
    /// ```
    #[serde(default)]
    pub max_connections: Option<u32>,

    /// Per-read timeout in milliseconds.
    ///
    /// Applies to each individual read operation on an
    /// established upstream connection. For HTTP, a timeout
    /// before the response starts gets the client a 504; once
    /// the response is streaming, the client connection is
    /// closed with the body cut short.
    #[serde(default)]
    pub read_timeout_ms: Option<u64>,

    /// TLS settings for upstream connections.
    ///
    /// Presence implies TLS is enabled. Omit for plaintext HTTP.
    #[serde(default)]
    pub tls: Option<praxis_tls::ClusterTls>,

    /// Total connection timeout in milliseconds (TCP + TLS).
    ///
    /// Bounds the combined TCP handshake and TLS negotiation.
    /// When exceeded, the connection attempt fails; for HTTP, the
    /// client gets a 504 once any retries are used up. Prefer
    /// this over [`connection_timeout_ms`] for TLS-enabled
    /// clusters where the handshake dominates latency.
    ///
    /// [`connection_timeout_ms`]: Cluster::connection_timeout_ms
    #[serde(default)]
    pub total_connection_timeout_ms: Option<u64>,

    /// Endpoint hostnames allowed to resolve to RFC 1918 or IPv6 unique-local
    /// addresses. Loopback, link-local, and cloud metadata stay refused.
    /// Hostnames only, HTTP clusters only.
    #[serde(default)]
    pub trusted_private_endpoints: Vec<String>,

    /// Per-write timeout in milliseconds.
    ///
    /// Applies to each individual write operation on an
    /// established upstream connection. For HTTP, a timed-out
    /// request body write stops the upload; the proxy then waits
    /// for whatever response the upstream sends and answers 504
    /// if none arrives. Pair it with [`read_timeout_ms`] so that
    /// wait is bounded.
    ///
    /// [`read_timeout_ms`]: Cluster::read_timeout_ms
    #[serde(default)]
    pub write_timeout_ms: Option<u64>,

    /// Optional retry policy for this cluster.
    ///
    /// When unset, the proxy retains the legacy connect-failure
    /// retry behavior (3 attempts, idempotent methods, 64 `KiB` body).
    #[serde(default)]
    pub retry_policy: Option<RetryPolicy>,
}

impl Cluster {
    /// Validate the optional upstream HTTP authority override.
    ///
    /// Only a fixed authority is checked here; `{ from: endpoint }`
    /// sends endpoint addresses, which endpoint validation covers.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] when a fixed authority is not a
    /// supported hostname with an optional port or a bracketed IPv6
    /// address with an optional port.
    pub fn validate_authority(&self) -> Result<(), ProxyError> {
        match &self.http.authority {
            Some(UpstreamAuthority::Literal(authority)) => {
                super::validate::cluster::authority::validate_authority(authority, &self.name)
            },
            Some(UpstreamAuthority::Derived { .. }) | None => Ok(()),
        }
    }

    /// Build a cluster with only a name and endpoints; all other
    /// fields use their defaults (no timeouts, no TLS, no health
    /// check, `round_robin` strategy).
    ///
    /// ```
    /// use praxis_core::config::Cluster;
    /// use praxis_tls::ClusterTls;
    ///
    /// let c = Cluster {
    ///     tls: Some(ClusterTls::default()),
    ///     ..Cluster::with_defaults("backend", vec!["10.0.0.1:443".into()])
    /// };
    /// assert_eq!(&*c.name, "backend");
    /// assert!(c.tls.is_some());
    /// assert!(c.tls.as_ref().unwrap().verify);
    /// ```
    pub fn with_defaults(name: &str, endpoints: Vec<Endpoint>) -> Self {
        Self {
            name: Arc::from(name),
            http: ClusterHttpOptions::default(),
            connection_timeout_ms: None,
            endpoints,
            health_check: None,
            idle_timeout_ms: None,
            load_balancer_strategy: LoadBalancerStrategy::default(),
            max_connections: None,
            read_timeout_ms: None,
            tls: None,
            total_connection_timeout_ms: None,
            trusted_private_endpoints: Vec::new(),
            write_timeout_ms: None,
            retry_policy: None,
        }
    }
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
    use super::*;

    #[test]
    fn parse_cluster_minimal() {
        let yaml = r#"
name: "backend"
endpoints: ["10.0.0.1:8080"]
"#;
        let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(&*cluster.name, "backend", "cluster name mismatch");
        assert_eq!(
            cluster.endpoints[0].address(),
            "10.0.0.1:8080",
            "endpoint address mismatch"
        );
        assert_eq!(cluster.endpoints[0].weight(), 1, "default weight should be 1");
        assert_eq!(
            cluster.load_balancer_strategy,
            LoadBalancerStrategy::default(),
            "strategy should default"
        );
        assert!(
            cluster.connection_timeout_ms.is_none(),
            "connection_timeout should default to None"
        );
    }

    #[test]
    fn parse_cluster_with_weights() {
        let yaml = r#"
name: "backend"
endpoints:
  - "10.0.0.1:8080"
  - address: "10.0.0.2:8080"
    weight: 3
"#;
        let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cluster.endpoints.len(), 2, "should parse two endpoints");
        assert_eq!(cluster.endpoints[0].weight(), 1, "simple endpoint weight should be 1");
        assert_eq!(cluster.endpoints[1].weight(), 3, "weighted endpoint weight should be 3");
    }

    #[test]
    fn parse_cluster_with_timeouts() {
        let yaml = r#"
name: "backend"
endpoints: ["10.0.0.1:8080"]
connection_timeout_ms: 5000
idle_timeout_ms: 30000
read_timeout_ms: 10000
write_timeout_ms: 10000
"#;
        let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            cluster.connection_timeout_ms,
            Some(5000),
            "connection_timeout_ms mismatch"
        );
        assert_eq!(cluster.idle_timeout_ms, Some(30000), "idle_timeout_ms mismatch");
        assert_eq!(cluster.read_timeout_ms, Some(10000), "read_timeout_ms mismatch");
        assert_eq!(cluster.write_timeout_ms, Some(10000), "write_timeout_ms mismatch");
    }

    #[test]
    fn cluster_roundtrips_via_serde() {
        let cluster = Cluster {
            connection_timeout_ms: Some(1000),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])
        };
        let value = serde_yaml::to_value(&cluster).unwrap();
        let back: Cluster = serde_yaml::from_value(value).unwrap();
        assert_eq!(back.name, cluster.name, "name should roundtrip");
        assert_eq!(back.endpoints, cluster.endpoints, "endpoints should roundtrip");
        assert_eq!(
            back.connection_timeout_ms, cluster.connection_timeout_ms,
            "timeout should roundtrip"
        );
    }

    #[test]
    fn endpoint_authority_roundtrips_via_serde() {
        let cluster = Cluster {
            http: ClusterHttpOptions {
                authority: Some(UpstreamAuthority::Derived {
                    from: AuthoritySource::Endpoint,
                }),
                ..ClusterHttpOptions::default()
            },
            ..Cluster::with_defaults("web", vec!["api.example.com:443".into()])
        };
        let value = serde_yaml::to_value(&cluster).unwrap();
        let back: Cluster = serde_yaml::from_value(value).unwrap();
        assert_eq!(back.http, cluster.http, "endpoint-derived authority should roundtrip");
    }

    #[test]
    fn validate_authority_skips_endpoint_authority() {
        let cluster: Cluster = serde_yaml::from_str(
            r#"
name: "web"
endpoints: ["api.example.com:443"]
http:
  authority: { from: endpoint }
"#,
        )
        .unwrap();
        cluster
            .validate_authority()
            .expect("an endpoint-derived authority has no fixed value to validate");
    }

    #[test]
    fn validate_authority_still_checks_a_fixed_authority() {
        let cluster = Cluster {
            http: ClusterHttpOptions {
                authority: Some("api.example.com/v1".into()),
                ..ClusterHttpOptions::default()
            },
            ..Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])
        };
        let err = cluster.validate_authority().unwrap_err();
        assert!(
            err.to_string().contains("not a valid HTTP authority"),
            "a fixed authority must still be validated: {err}"
        );
    }

    #[test]
    fn tls_and_sni_parse_correctly() {
        let yaml = r#"
name: "backend"
endpoints: ["10.0.0.1:443"]
tls:
  sni: "api.example.com"
"#;
        let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
        assert!(cluster.tls.is_some(), "tls should be present");
        assert_eq!(
            cluster.tls.as_ref().unwrap().sni.as_deref(),
            Some("api.example.com"),
            "sni mismatch"
        );
    }

    #[test]
    fn tls_verify_defaults_to_true() {
        let yaml = r#"
name: "backend"
endpoints: ["10.0.0.1:443"]
tls: {}
"#;
        let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
        assert!(cluster.tls.as_ref().unwrap().verify, "verify should default to true");
    }

    #[test]
    fn tls_verify_can_be_disabled() {
        let yaml = r#"
name: "backend"
endpoints: ["10.0.0.1:443"]
tls:
  verify: false
"#;
        let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
        assert!(
            !cluster.tls.as_ref().unwrap().verify,
            "verify should be false when explicitly set"
        );
    }

    #[test]
    fn no_tls_by_default() {
        let cluster = Cluster::with_defaults("web", vec!["10.0.0.1:80".into()]);
        assert!(cluster.tls.is_none(), "tls should be None by default");
    }

    #[test]
    fn parse_cluster_application_metadata() {
        let yaml = r#"
name: "backend"
endpoints: ["10.0.0.1:8080"]
http:
  application_protocol: openai_chat_completions
  application_provider: vllm
"#;
        let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            cluster.http.application_protocol.as_deref(),
            Some("openai_chat_completions"),
            "application_protocol mismatch"
        );
        assert_eq!(
            cluster.http.application_provider.as_deref(),
            Some("vllm"),
            "application_provider mismatch"
        );
    }

    #[test]
    fn application_metadata_defaults_to_none() {
        let cluster = Cluster::with_defaults("web", vec!["10.0.0.1:80".into()]);
        assert!(
            cluster.http.application_protocol.is_none(),
            "application_protocol should default to None"
        );
        assert!(
            cluster.http.application_provider.is_none(),
            "application_provider should default to None"
        );
    }
}
