// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! HTTP-specific strategy wrapper that extracts the hash key from request context.

use std::sync::Arc;

use praxis_core::{config::LoadBalancerStrategy, health::ClusterHealthState};

use crate::{
    filter::HttpFilterContext,
    load_balancing::{endpoint::WeightedEndpoint, strategy as shared},
};

// -----------------------------------------------------------------------------
// Strategy
// -----------------------------------------------------------------------------

/// HTTP load-balancing strategy that delegates to shared strategies.
///
/// Extracts the consistent-hash key from the HTTP request (header or
/// URI path) before delegating to the protocol-agnostic implementation.
pub(super) struct Strategy {
    /// The protocol-agnostic strategy implementation.
    inner: shared::Strategy,
}

impl Strategy {
    /// Pick the next endpoint address, skipping unhealthy endpoints.
    pub(super) fn select(&self, ctx: &HttpFilterContext<'_>, health: Option<&ClusterHealthState>) -> Arc<str> {
        let hash_key = self.extract_hash_key(ctx);
        self.inner.select(hash_key, health)
    }

    /// Called after a response arrives so that strategies that track in-flight
    /// request counts (e.g. `LeastConnections`) can decrement their counter.
    pub(super) fn release(&self, addr: &str) {
        self.inner.release(addr);
    }

    /// Returns a reference to the inner shared strategy for testing.
    #[cfg(test)]
    pub(super) fn inner(&self) -> &shared::Strategy {
        &self.inner
    }

    /// Extract the hash key from the HTTP context for consistent-hash.
    fn extract_hash_key<'a>(&self, ctx: &'a HttpFilterContext<'_>) -> Option<&'a str> {
        if let shared::Strategy::ConsistentHash(ref ch) = self.inner {
            let key: &str = ch
                .header()
                .and_then(|h| ctx.request.headers.get(h))
                .and_then(|v| v.to_str().ok())
                .unwrap_or_else(|| ctx.request.uri.path());
            Some(key)
        } else {
            None
        }
    }
}

/// Create the appropriate strategy variant from the config.
pub(super) fn build_strategy(lb_strategy: &LoadBalancerStrategy, endpoints: Vec<WeightedEndpoint>) -> Strategy {
    Strategy {
        inner: shared::build_strategy(lb_strategy, endpoints),
    }
}
