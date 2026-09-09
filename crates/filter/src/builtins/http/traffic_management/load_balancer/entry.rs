// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Resolved cluster entry: strategy, connection options, and TLS config.

use std::sync::Arc;

use arc_swap::ArcSwap;
use http::header::HeaderValue;
use praxis_core::{
    config::{CachedClusterTls, Cluster, RetryPolicy},
    connectivity::{ConnectionOptions, Upstream},
    retry::ClusterRetryState,
};
use tracing::debug;

use super::{
    reselector::EndpointReselector,
    strategy::{Strategy, build_strategy},
};
use crate::{FilterError, filter::HttpFilterContext, load_balancing::endpoint::build_weighted_endpoints};

// -----------------------------------------------------------------------------
// ClusterEntry
// -----------------------------------------------------------------------------

/// Memo slot pairing a route override policy (the cache key, compared by
/// [`Arc`] identity) with the merged policy computed from it.
type RetryMemoSlot = Option<(Arc<RetryPolicy>, Arc<RetryPolicy>)>;

/// Resolved state for a single cluster.
pub(super) struct ClusterEntry {
    /// Pre-parsed upstream authority override as a [`HeaderValue`].
    /// `None` means forward the downstream `Host` header unchanged.
    /// Parsed at config load time to avoid per-request conversion.
    pub(super) authority: Option<HeaderValue>,

    /// Connection options derived from the cluster config, [`Arc`]-wrapped
    /// to avoid per-request cloning.
    pub(super) opts: Arc<ConnectionOptions>,

    /// The load-balancing strategy for this cluster.
    pub(super) strategy: Arc<Strategy>,

    /// Pre-cached TLS material. `None` means plain TCP.
    pub(super) tls: Option<CachedClusterTls>,

    /// Resolved retry policy (legacy default when unset).
    pub(super) retry_policy: Arc<RetryPolicy>,

    /// Shared active-request counter and retry budget.
    pub(super) retry_state: Arc<ClusterRetryState>,

    /// One-slot memo of the last route-override retry merge, keyed by
    /// the route policy's [`Arc`] identity. Route policies are
    /// config-stable [`Arc`]s cloned per request from router config, so
    /// requests flowing through one route hit the memo instead of
    /// re-allocating the merged policy each time; holding the route
    /// [`Arc`] both keys the cache and pins its address against reuse.
    merged_retry_memo: ArcSwap<RetryMemoSlot>,

    /// Lazily built reselector for the common case — no hash key, no
    /// route retry override. The reselector is stateless config data,
    /// so one shared instance serves every such request instead of a
    /// fresh allocation per request.
    default_reselector: std::sync::OnceLock<Arc<EndpointReselector>>,
}

impl ClusterEntry {
    /// Resolve this cluster's TLS material for one request.
    ///
    /// When TLS is configured and no explicit SNI is set, falls back
    /// to the `Host` header from the request. The port is stripped
    /// from the host value because SNI must be a bare hostname
    /// per [RFC 6066].
    ///
    /// [RFC 6066]: https://datatracker.ietf.org/doc/html/rfc6066
    pub(super) fn request_tls(&self, ctx: &HttpFilterContext<'_>) -> Option<CachedClusterTls> {
        self.tls.clone().map(|mut t| {
            if t.sni().is_none()
                && let Some(host) = ctx
                    .request
                    .headers
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
            {
                t.set_sni(strip_host_port(host));
            }
            t
        })
    }

    /// Whether this cluster's TLS material depends on the per-request
    /// `Host`-derived SNI fallback.
    ///
    /// Such a cluster has no single cluster-wide TLS value, so state
    /// cached across requests, the shared [`Self::default_reselector`],
    /// cannot carry its TLS material.
    pub(super) fn tls_needs_request_sni(&self) -> bool {
        self.tls.as_ref().is_some_and(|t| t.sni().is_none())
    }

    /// Build an [`Upstream`] from a selected address and request context.
    pub(super) fn build_upstream(&self, addr: Arc<str>, ctx: &HttpFilterContext<'_>) -> Upstream {
        self.upstream_with_tls(addr, self.request_tls(ctx))
    }

    /// Build an [`Upstream`] from a selected address and already-resolved
    /// per-request TLS material.
    pub(super) fn upstream_with_tls(&self, addr: Arc<str>, tls: Option<CachedClusterTls>) -> Upstream {
        Upstream {
            address: addr,
            authority: self.authority.clone(),
            connection: Arc::clone(&self.opts),
            tls,
        }
    }

    /// Merge the route-level retry override onto this cluster's policy,
    /// memoizing the last merge by the route policy's [`Arc`] identity.
    ///
    /// A memo hit costs one lock-free load and a refcount bump; a miss
    /// (first request, or the route's policy changed) re-runs
    /// [`RetryPolicy::merge_override`] and replaces the slot.
    pub(super) fn merged_retry_policy(&self, route: &Arc<RetryPolicy>) -> Arc<RetryPolicy> {
        let cached = self.merged_retry_memo.load();
        if let Some((cached_route, merged)) = cached.as_ref()
            && Arc::ptr_eq(cached_route, route)
        {
            return Arc::clone(merged);
        }
        let merged = Arc::new(self.retry_policy.merge_override(route));
        self.merged_retry_memo
            .store(Arc::new(Some((Arc::clone(route), Arc::clone(&merged)))));
        merged
    }

    /// The shared reselector for requests with no hash key, the cluster's
    /// own retry policy, and cluster-wide TLS material (the dominant case).
    ///
    /// Only valid when [`Self::tls_needs_request_sni`] is `false`: a
    /// cluster whose SNI comes from the request `Host` header needs a
    /// per-request reselector so a retry offers the same SNI the initial
    /// attempt did.
    pub(super) fn default_reselector(&self) -> &Arc<EndpointReselector> {
        self.default_reselector.get_or_init(|| {
            Arc::new(self.reselector_with_policy(None, Arc::clone(&self.retry_policy), self.tls.clone()))
        })
    }

    /// Capture a reselector with an already-merged retry policy and the
    /// TLS material resolved for this request.
    ///
    /// The reselector builds the upstream for an alternate-host retry, so
    /// it must carry the same material the initial attempt used, including
    /// the `Host`-derived SNI fallback, which is not part of the cluster's
    /// cached TLS.
    pub(super) fn reselector_with_policy(
        &self,
        hash_key: Option<Arc<str>>,
        retry_policy: Arc<RetryPolicy>,
        tls: Option<CachedClusterTls>,
    ) -> EndpointReselector {
        EndpointReselector::new(
            Arc::clone(&self.strategy),
            Arc::clone(&self.opts),
            tls,
            self.authority.clone(),
            hash_key,
            retry_policy,
            Arc::clone(&self.retry_state),
        )
    }
}

/// Extract the hostname from a `Host` header value, stripping the port.
///
/// Handles both plain hosts (`example.com:8443` -> `example.com`)
/// and IPv6 bracket notation (`[::1]:8443` -> `[::1]`).
fn strip_host_port(host: &str) -> &str {
    if let Some(bracket_end) = host.find(']') {
        host.get(..=bracket_end).unwrap_or(host)
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    }
}

/// Build a [`ClusterEntry`] from a cluster definition.
///
/// # Errors
///
/// Returns [`FilterError`] if the authority override cannot be parsed
/// as a valid HTTP header value.
pub(super) fn build_cluster_entry(cluster: &Cluster) -> Result<ClusterEntry, FilterError> {
    let endpoints = build_weighted_endpoints(cluster);
    let total_weight: u32 = endpoints.iter().map(|ep| ep.weight).sum();
    debug!(
        cluster = %cluster.name,
        endpoints = endpoints.len(),
        total_weight,
        "cluster registered"
    );

    let tls = build_cached_tls(cluster)?;
    let authority = build_authority(cluster)?;
    let strategy = Arc::new(build_strategy(&cluster.load_balancer_strategy, endpoints));
    let retry_policy = Arc::new(cluster.retry_policy.clone().unwrap_or_else(RetryPolicy::legacy_default));
    let retry_state = Arc::new(ClusterRetryState::new(retry_policy.retry_budget.as_ref()));
    Ok(ClusterEntry {
        authority,
        opts: Arc::new(ConnectionOptions::from(cluster)),
        strategy,
        tls,
        retry_policy,
        retry_state,
        merged_retry_memo: ArcSwap::from_pointee(None),
        default_reselector: std::sync::OnceLock::new(),
    })
}

/// Pre-cache TLS material for a cluster, failing closed on unreadable material.
///
/// Returns an error instead of silently disabling TLS, so a misconfigured or
/// unreadable certificate cannot cause traffic to fall back to plaintext.
fn build_cached_tls(cluster: &Cluster) -> Result<Option<CachedClusterTls>, FilterError> {
    let Some(t) = cluster.tls.as_ref() else {
        return Ok(None);
    };
    CachedClusterTls::try_from_config(t).map(Some).map_err(|e| {
        format!(
            "cluster '{}': TLS material is unreadable, refusing to fall back to plaintext: {e}",
            cluster.name,
        )
        .into()
    })
}

/// Pre-parse the authority override as a [`HeaderValue`].
///
/// Returns an error instead of silently disabling the override, so
/// that programmatic callers of `LoadBalancerFilter::new` cannot
/// accidentally forward the caller's original `Host` header.
fn build_authority(cluster: &Cluster) -> Result<Option<HeaderValue>, FilterError> {
    let Some(a) = cluster.http.authority.as_deref() else {
        return Ok(None);
    };
    cluster.validate_authority().map_err(|e| e.to_string())?;
    HeaderValue::from_str(a).map(Some).map_err(|e| {
        format!(
            "cluster '{}': authority '{}' is not a valid HTTP header value: {e}",
            cluster.name, a,
        )
        .into()
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn strip_host_port_with_port() {
        assert_eq!(
            strip_host_port("example.com:8443"),
            "example.com",
            "should strip port from host"
        );
    }

    #[test]
    fn strip_host_port_without_port() {
        assert_eq!(
            strip_host_port("example.com"),
            "example.com",
            "host without port should be unchanged"
        );
    }

    #[test]
    fn strip_host_port_ipv6_with_port() {
        assert_eq!(
            strip_host_port("[::1]:8443"),
            "[::1]",
            "should strip port from IPv6 bracket notation"
        );
    }

    #[test]
    fn strip_host_port_ipv6_without_port() {
        assert_eq!(
            strip_host_port("[::1]"),
            "[::1]",
            "IPv6 without port should be unchanged"
        );
    }

    #[test]
    fn strip_host_port_standard_https() {
        assert_eq!(
            strip_host_port("example.com:443"),
            "example.com",
            "should strip default HTTPS port"
        );
    }

    #[test]
    fn merged_retry_policy_memoizes_by_route_identity() {
        let cluster: Cluster =
            serde_yaml::from_str("name: memo\nendpoints:\n  - \"203.0.113.1:80\"\nretry_policy:\n  max_retries: 2\n")
                .expect("cluster yaml");
        let entry = build_cluster_entry(&cluster).expect("entry");

        let route = Arc::new(RetryPolicy {
            max_retries: Some(5),
            ..RetryPolicy::default()
        });

        let first = entry.merged_retry_policy(&route);
        let second = entry.merged_retry_policy(&route);
        assert!(
            Arc::ptr_eq(&first, &second),
            "the same route policy must hit the memo, not re-allocate"
        );
        assert_eq!(first.max_retries, Some(5), "route override must win");

        let other_route = Arc::new(RetryPolicy {
            max_retries: Some(7),
            ..RetryPolicy::default()
        });
        let third = entry.merged_retry_policy(&other_route);
        assert!(
            !Arc::ptr_eq(&first, &third),
            "a different route policy must recompute the merge"
        );
        assert_eq!(third.max_retries, Some(7), "recomputed merge must use the new route");
        assert_eq!(
            *third,
            entry.retry_policy.merge_override(&other_route),
            "the memoized merge must equal a direct merge_override"
        );
    }
}
