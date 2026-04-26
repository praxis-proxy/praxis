// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Load-balancing strategy selection and dispatch.

use std::sync::Arc;

use praxis_core::{
    config::{LoadBalancerStrategy, ParameterisedStrategy, SimpleStrategy},
    health::ClusterHealthState,
};

use super::{
    consistent_hash::ConsistentHash, endpoint::WeightedEndpoint, least_connections::LeastConnections,
    round_robin::RoundRobin,
};

// -----------------------------------------------------------------------------
// Strategy
// -----------------------------------------------------------------------------

/// Load-balancing strategy variant for a cluster.
pub(crate) enum Strategy {
    /// Cycle through endpoints in order, respecting weights.
    RoundRobin(RoundRobin),

    /// Pick the endpoint with the fewest active requests.
    LeastConnections(LeastConnections),

    /// Hash a request attribute to a stable endpoint.
    ConsistentHash(ConsistentHash),
}

impl Strategy {
    /// Pick the next endpoint address using a protocol-agnostic hash key.
    ///
    /// For HTTP, the caller extracts the key from headers or URI path.
    /// For TCP, the caller typically passes the client IP address.
    pub(crate) fn select(&self, hash_key: Option<&str>, health: Option<&ClusterHealthState>) -> Arc<str> {
        match self {
            Self::RoundRobin(rr) => rr.select(health),
            Self::LeastConnections(lc) => lc.select(health),
            Self::ConsistentHash(ch) => ch.select(hash_key, health),
        }
    }

    /// Called after a response arrives so that strategies that track in-flight
    /// request counts (e.g. `LeastConnections`) can decrement their counter.
    pub(crate) fn release(&self, addr: &str) {
        if let Self::LeastConnections(lc) = self {
            lc.release(addr);
        }
    }
}

/// Create the appropriate strategy variant from the config.
pub(crate) fn build_strategy(lb_strategy: &LoadBalancerStrategy, endpoints: Vec<WeightedEndpoint>) -> Strategy {
    match lb_strategy {
        LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin) => Strategy::RoundRobin(RoundRobin::new(endpoints)),
        LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections) => {
            Strategy::LeastConnections(LeastConnections::new(endpoints))
        },
        LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(opts)) => {
            Strategy::ConsistentHash(ConsistentHash::new(endpoints, opts.header.clone()))
        },
    }
}
