// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Resolved cluster entry: strategy, connection options, and TLS config.

use std::sync::Arc;

use praxis_core::{
    config::{CachedClusterTls, Cluster},
    connectivity::{ConnectionOptions, Upstream},
};
use tracing::{debug, warn};

use super::strategy::{Strategy, build_strategy};
use crate::{filter::HttpFilterContext, load_balancing::endpoint::build_weighted_endpoints};

// -----------------------------------------------------------------------------
// ClusterEntry
// -----------------------------------------------------------------------------

/// Resolved state for a single cluster.
pub(super) struct ClusterEntry {
    /// Connection options derived from the cluster config, [`Arc`]-wrapped
    /// to avoid per-request cloning.
    pub(super) opts: Arc<ConnectionOptions>,

    /// The load-balancing strategy for this cluster.
    pub(super) strategy: Strategy,

    /// Pre-cached TLS material. `None` means plain TCP.
    pub(super) tls: Option<CachedClusterTls>,
}

impl ClusterEntry {
    /// Build an [`Upstream`] from a selected address and request context.
    ///
    /// When TLS is configured and no explicit SNI is set, falls back
    /// to the `Host` header from the request. The port is stripped
    /// from the host value because SNI must be a bare hostname
    /// per [RFC 6066].
    ///
    /// [RFC 6066]: https://datatracker.ietf.org/doc/html/rfc6066
    pub(super) fn build_upstream(&self, addr: Arc<str>, ctx: &HttpFilterContext<'_>) -> Upstream {
        let tls = self.tls.clone().map(|mut t| {
            if t.sni().is_none()
                && let Some(host) = ctx.request.headers.get("host").and_then(|v| v.to_str().ok())
            {
                t.set_sni(strip_host_port(host).to_owned());
            }
            t
        });
        Upstream {
            address: addr,
            connection: Arc::clone(&self.opts),
            tls,
        }
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
pub(super) fn build_cluster_entry(cluster: &Cluster) -> ClusterEntry {
    let endpoints = build_weighted_endpoints(cluster);
    let total_weight: u32 = endpoints.iter().map(|ep| ep.weight).sum();
    debug!(
        cluster = %cluster.name,
        endpoints = endpoints.len(),
        total_weight,
        "cluster registered"
    );

    let tls = cluster
        .tls
        .as_ref()
        .and_then(|t| match CachedClusterTls::try_from_config(t) {
            Ok(cached) => Some(cached),
            Err(e) => {
                warn!(
                    cluster = %cluster.name,
                    error = %e,
                    "failed to cache TLS certificates; TLS disabled for this cluster"
                );
                None
            },
        });

    let strategy = build_strategy(&cluster.load_balancer_strategy, endpoints);
    ClusterEntry {
        opts: Arc::new(ConnectionOptions::from(cluster)),
        strategy,
        tls,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
}
