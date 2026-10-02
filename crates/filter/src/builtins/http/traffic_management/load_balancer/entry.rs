// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Resolved cluster entry: strategy, connection options, and TLS config.

use std::sync::Arc;

use arc_swap::ArcSwap;
use praxis_core::{
    config::{CachedClusterTls, Cluster, RetryPolicy},
    connectivity::{ConnectionOptions, Upstream},
    retry::ClusterRetryState,
};
use tracing::debug;

use super::{
    authority::AuthorityResolver,
    reselector::EndpointReselector,
    strategy::{Strategy, build_strategy},
};
use crate::{FilterError, filter::HttpFilterContext, load_balancing::endpoint::build_weighted_endpoints};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum route overrides memoized per cluster.
///
/// Sized to hold every route that overrides one cluster in practical
/// configs, so alternating routes do not thrash a single slot.
const MAX_RETRY_MEMO_ENTRIES: usize = 16;

// -----------------------------------------------------------------------------
// ClusterEntry
// -----------------------------------------------------------------------------

/// Memo entries pairing a route override policy (the cache key, compared by
/// [`Arc`] identity) with the merged policy computed from it.
type RetryMemo = Vec<(Arc<RetryPolicy>, Arc<RetryPolicy>)>;

/// Resolved state for a single cluster.
pub(super) struct ClusterEntry {
    /// Upstream `Host` for each attempt; forwards the downstream `Host`
    /// when the cluster sets no authority.
    pub(super) authority: AuthorityResolver,

    /// Connection options derived from the cluster config.
    pub(super) opts: Arc<ConnectionOptions>,

    /// The load-balancing strategy for this cluster.
    pub(super) strategy: Arc<Strategy>,

    /// Pre-cached TLS material. `None` means plain TCP.
    pub(super) tls: Option<CachedClusterTls>,

    /// Opaque application protocol tagged on the cluster, if any.
    pub(super) application_protocol: Option<Arc<str>>,

    /// Opaque application provider tagged on the cluster, if any.
    pub(super) application_provider: Option<Arc<str>>,

    /// Resolved retry policy (legacy default when unset).
    pub(super) retry_policy: Arc<RetryPolicy>,

    /// Shared active-request counter and retry budget.
    pub(super) retry_state: Arc<ClusterRetryState>,

    /// Bounded memo of route-override retry merges, keyed by the route
    /// policy's [`Arc`] identity, most recent first. Holding the route
    /// [`Arc`] both keys the cache and pins its address against reuse.
    merged_retry_memo: ArcSwap<RetryMemo>,

    /// Whether the panic-mode warning has been logged for the current
    /// all-unhealthy episode, so the warning fires once per transition
    /// instead of on every request.
    pub(super) panic_mode_logged: std::sync::atomic::AtomicBool,

    /// Lazily built reselector for the common case: no hash key and no
    /// route retry override. The reselector is stateless config data.
    default_reselector: std::sync::OnceLock<Arc<EndpointReselector>>,
}

impl ClusterEntry {
    /// Build an [`Upstream`] from a selected address and request context.
    ///
    /// When TLS is configured and no explicit SNI is set, the SNI is
    /// taken from the cluster's fixed `authority`, then the request
    /// `Host` header, then the request URI authority (HTTP/2
    /// `:authority`). The configured authority wins over `Host` so a
    /// client cannot steer the upstream TLS name. The chosen value
    /// goes through [`sni_candidate`]: SNI must be a bare DNS
    /// hostname per [RFC 6066], so ports and the root dot are
    /// stripped and IP literals produce no SNI. A cluster whose
    /// authority follows the endpoint skips all of this and leaves SNI
    /// unset, so the peer derives it from each attempt's own endpoint
    /// address.
    ///
    /// [RFC 6066]: https://datatracker.ietf.org/doc/html/rfc6066#section-3
    pub(super) fn build_upstream(&self, addr: Arc<str>, ctx: &HttpFilterContext<'_>) -> Upstream {
        let authority = self.authority.for_address(&addr);
        let tls = self.tls.clone().map(|mut t| {
            if t.sni().is_none()
                && !self.authority.follows_endpoint()
                && let Some(sni) = authority
                    .as_ref()
                    .and_then(|v| v.to_str().ok())
                    .or_else(|| {
                        ctx.request
                            .headers
                            .get(http::header::HOST)
                            .and_then(|v| v.to_str().ok())
                    })
                    .or_else(|| ctx.request.uri.authority().map(http::uri::Authority::as_str))
                    .and_then(sni_candidate)
            {
                t.set_sni(sni);
            }
            t
        });
        Upstream {
            address: addr,
            authority,
            connection: Arc::clone(&self.opts),
            tls,
        }
    }

    /// Merge the route-level retry override onto this cluster's policy,
    /// memoizing up to [`MAX_RETRY_MEMO_ENTRIES`] merges by the route
    /// policy's [`Arc`] identity.
    pub(super) fn merged_retry_policy(&self, route: &Arc<RetryPolicy>) -> Arc<RetryPolicy> {
        if let Some(merged) = lookup_memo(&self.merged_retry_memo.load(), route) {
            return merged;
        }
        let merged = Arc::new(self.retry_policy.merge_override(route));
        self.merged_retry_memo.rcu(|memo| {
            let mut next = RetryMemo::with_capacity(MAX_RETRY_MEMO_ENTRIES);
            next.push((Arc::clone(route), Arc::clone(&merged)));
            next.extend(
                memo.iter()
                    .filter(|(cached_route, _)| !Arc::ptr_eq(cached_route, route))
                    .take(MAX_RETRY_MEMO_ENTRIES.saturating_sub(1))
                    .cloned(),
            );
            next
        });
        merged
    }

    /// The shared reselector for requests with no hash key and the
    /// cluster's own retry policy (the dominant case).
    pub(super) fn default_reselector(&self) -> &Arc<EndpointReselector> {
        self.default_reselector
            .get_or_init(|| Arc::new(self.reselector_with_policy(None, Arc::clone(&self.retry_policy))))
    }

    /// Capture a reselector with an already-merged retry policy.
    pub(super) fn reselector_with_policy(
        &self,
        hash_key: Option<Arc<str>>,
        retry_policy: Arc<RetryPolicy>,
    ) -> EndpointReselector {
        EndpointReselector::new(
            Arc::clone(&self.strategy),
            Arc::clone(&self.opts),
            self.tls.clone(),
            self.authority.clone(),
            hash_key,
            retry_policy,
            Arc::clone(&self.retry_state),
        )
    }
}

/// Find the memoized merge for `route` by [`Arc`] identity.
fn lookup_memo(memo: &RetryMemo, route: &Arc<RetryPolicy>) -> Option<Arc<RetryPolicy>> {
    memo.iter()
        .find(|(cached_route, _)| Arc::ptr_eq(cached_route, route))
        .map(|(_, merged)| Arc::clone(merged))
}

/// Derive a TLS SNI name from an authority (`host[:port]`).
///
/// Strips the port and a trailing root dot. Returns `None` for an
/// empty host or an IP literal, since [RFC 6066] forbids IP
/// addresses in the `server_name` extension.
///
/// [RFC 6066]: https://datatracker.ietf.org/doc/html/rfc6066#section-3
fn sni_candidate(host: &str) -> Option<&str> {
    let host = super::super::strip_port(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty() && bare.parse::<std::net::IpAddr>().is_err()).then_some(host)
}

/// Build a [`ClusterEntry`] from a cluster definition.
///
/// # Errors
///
/// Returns [`FilterError`] if the authority override, or an endpoint
/// address the authority is taken from, cannot be parsed as a valid HTTP
/// authority.
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
    let authority = AuthorityResolver::build(cluster)?;
    let strategy = Arc::new(build_strategy(&cluster.load_balancer_strategy, endpoints));
    let retry_policy = Arc::new(cluster.retry_policy.clone().unwrap_or_else(RetryPolicy::legacy_default));
    let retry_state = Arc::new(ClusterRetryState::new(retry_policy.retry_budget.as_ref()));
    Ok(ClusterEntry {
        authority,
        opts: Arc::new(ConnectionOptions::from(cluster)),
        strategy,
        tls,
        application_protocol: cluster.http.application_protocol.clone(),
        application_provider: cluster.http.application_provider.clone(),
        retry_policy,
        retry_state,
        merged_retry_memo: ArcSwap::from_pointee(RetryMemo::new()),
        panic_mode_logged: std::sync::atomic::AtomicBool::new(false),
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn sni_candidate_strips_port() {
        assert_eq!(
            sni_candidate("example.com:443"),
            Some("example.com"),
            "port should be stripped"
        );
    }

    #[test]
    fn sni_candidate_strips_root_dot() {
        assert_eq!(
            sni_candidate("example.com."),
            Some("example.com"),
            "root dot should be stripped"
        );
    }

    #[test]
    fn sni_candidate_rejects_ipv4() {
        assert_eq!(sni_candidate("10.0.0.1"), None, "IPv4 literal must not become SNI");
    }

    #[test]
    fn sni_candidate_rejects_ipv6_with_port() {
        assert_eq!(sni_candidate("[::1]:8443"), None, "IPv6 literal must not become SNI");
    }

    #[test]
    fn sni_candidate_rejects_empty() {
        assert_eq!(sni_candidate(""), None, "empty host must not become SNI");
    }

    #[test]
    fn merged_retry_policy_memoizes_alternating_routes() -> Result<(), FilterError> {
        let cluster: Cluster =
            serde_yaml::from_str("name: memo\nendpoints:\n  - \"203.0.113.1:80\"\nretry_policy:\n  max_retries: 2\n")?;
        let entry = build_cluster_entry(&cluster)?;
        let route_a = Arc::new(RetryPolicy {
            max_retries: Some(5),
            ..RetryPolicy::default()
        });
        let route_b = Arc::new(RetryPolicy {
            max_retries: Some(7),
            ..RetryPolicy::default()
        });

        let first_a = entry.merged_retry_policy(&route_a);
        let first_b = entry.merged_retry_policy(&route_b);
        let second_a = entry.merged_retry_policy(&route_a);
        let second_b = entry.merged_retry_policy(&route_b);
        assert!(
            Arc::ptr_eq(&first_a, &second_a),
            "route A must stay memoized after route B is merged"
        );
        assert!(Arc::ptr_eq(&first_b, &second_b), "route B must stay memoized");
        Ok(())
    }

    #[test]
    fn merged_retry_policy_memo_is_bounded() -> Result<(), FilterError> {
        let cluster = Cluster::with_defaults("memo", vec!["203.0.113.1:80".into()]);
        let entry = build_cluster_entry(&cluster)?;
        let routes: Vec<Arc<RetryPolicy>> = std::iter::repeat_with(|| Arc::new(RetryPolicy::default()))
            .take(40)
            .collect();
        for route in &routes {
            drop(entry.merged_retry_policy(route));
        }
        assert_eq!(
            entry.merged_retry_memo.load().len(),
            MAX_RETRY_MEMO_ENTRIES,
            "memo must not grow past its bound"
        );
        Ok(())
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
