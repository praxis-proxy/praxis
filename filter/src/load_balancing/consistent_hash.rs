// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Consistent-hash endpoint selection for session affinity.

use std::sync::Arc;

use praxis_core::health::ClusterHealthState;

use super::endpoint::WeightedEndpoint;

// -----------------------------------------------------------------------------
// ConsistentHash
// -----------------------------------------------------------------------------

/// Routes each request to the same endpoint by hashing a stable
/// attribute. Virtual nodes are proportional to endpoint weight.
pub(crate) struct ConsistentHash {
    /// Deduplicated endpoint list with weights and original indices.
    endpoints: Vec<WeightedEndpoint>,

    /// Virtual-node ring: each entry is an index into `endpoints`.
    /// Built by expanding each endpoint proportionally to its weight.
    ring: Vec<usize>,

    /// Header whose value is hashed. Falls back to the URI path when `None`
    /// or when the header is absent from the request.
    header: Option<String>,
}

impl ConsistentHash {
    /// Create a consistent-hash selector with weight-proportional virtual nodes.
    pub(crate) fn new(endpoints: Vec<WeightedEndpoint>, header: Option<String>) -> Self {
        let ring: Vec<usize> = endpoints
            .iter()
            .enumerate()
            .flat_map(|(i, ep)| std::iter::repeat_n(i, ep.weight as usize))
            .collect();
        debug_assert!(!ring.is_empty(), "consistent-hash requires at least one endpoint");
        Self {
            endpoints,
            ring,
            header,
        }
    }

    /// The optional header name this instance hashes on.
    pub(crate) fn header(&self) -> Option<&str> {
        self.header.as_deref()
    }

    /// Hash the key and return the corresponding healthy endpoint.
    ///
    /// Skips unhealthy endpoints by probing adjacent ring slots, falling
    /// back to the original selection if all are unhealthy.
    #[allow(clippy::indexing_slicing, reason = "within bounds")]
    pub(crate) fn select(&self, hash_key: Option<&str>, health: Option<&ClusterHealthState>) -> Arc<str> {
        let key = hash_key.unwrap_or("");

        let len = self.ring.len();
        #[allow(clippy::cast_possible_truncation, reason = "modulo fits usize")]
        let start = (fnv1a(key) as usize) % len;

        if let Some(state) = health {
            for offset in 0..len {
                let ring_idx = (start + offset) % len;
                let ep = &self.endpoints[self.ring[ring_idx]];
                if ep.index < state.endpoints().len() && state.endpoints()[ep.index].is_healthy() {
                    return Arc::clone(&ep.address);
                }
            }
        }

        Arc::clone(&self.endpoints[self.ring[start]].address)
    }
}

/// FNV-1a 64-bit hash (fast).
fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for byte in s.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

    use super::*;

    #[test]
    fn same_key_same_endpoint() {
        let ch = ConsistentHash::new(
            vec![
                WeightedEndpoint {
                    address: Arc::from("10.0.0.1:80"),
                    weight: 1,
                    index: 0,
                },
                WeightedEndpoint {
                    address: Arc::from("10.0.0.2:80"),
                    weight: 1,
                    index: 1,
                },
            ],
            None,
        );

        let first = ch.select(Some("/stable-path"), None);
        let second = ch.select(Some("/stable-path"), None);
        assert_eq!(first, second, "same key should always select same endpoint");
    }

    #[test]
    fn different_keys_select_different_endpoints() {
        let ch = ConsistentHash::new(
            vec![
                WeightedEndpoint {
                    address: Arc::from("10.0.0.1:80"),
                    weight: 1,
                    index: 0,
                },
                WeightedEndpoint {
                    address: Arc::from("10.0.0.2:80"),
                    weight: 1,
                    index: 1,
                },
            ],
            None,
        );

        let ep_a = ch.select(Some("/path-a"), None);
        let ep_b = ch.select(Some("/path-b"), None);
        assert_ne!(
            ep_a, ep_b,
            "FNV-1a of /path-a and /path-b should not collide with only 2 endpoints"
        );
    }

    #[test]
    fn skips_unhealthy() {
        let ch = ConsistentHash::new(
            vec![
                WeightedEndpoint {
                    address: Arc::from("10.0.0.1:80"),
                    weight: 1,
                    index: 0,
                },
                WeightedEndpoint {
                    address: Arc::from("10.0.0.2:80"),
                    weight: 1,
                    index: 1,
                },
                WeightedEndpoint {
                    address: Arc::from("10.0.0.3:80"),
                    weight: 1,
                    index: 2,
                },
            ],
            None,
        );
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new(), EndpointHealth::new()],
            vec![
                Arc::from("10.0.0.1:80"),
                Arc::from("10.0.0.2:80"),
                Arc::from("10.0.0.3:80"),
            ],
            None,
            None,
        ));
        state.endpoints()[1].mark_unhealthy();

        let paths = ["/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h"];
        for path in &paths {
            let selected = ch.select(Some(path), Some(&state));
            assert_ne!(
                &*selected, "10.0.0.2:80",
                "unhealthy endpoint should never be selected for path {path}"
            );
        }
    }

    #[test]
    fn panic_mode_when_all_unhealthy() {
        let ch = ConsistentHash::new(
            vec![
                WeightedEndpoint {
                    address: Arc::from("10.0.0.1:80"),
                    weight: 1,
                    index: 0,
                },
                WeightedEndpoint {
                    address: Arc::from("10.0.0.2:80"),
                    weight: 1,
                    index: 1,
                },
            ],
            None,
        );
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new()],
            vec![Arc::from("10.0.0.1:80"), Arc::from("10.0.0.2:80")],
            None,
            None,
        ));
        state.endpoints()[0].mark_unhealthy();
        state.endpoints()[1].mark_unhealthy();

        let selected = ch.select(Some("/panic"), Some(&state));
        assert!(
            &*selected == "10.0.0.1:80" || &*selected == "10.0.0.2:80",
            "panic mode should still return an endpoint, got: {selected}"
        );
    }

    #[test]
    fn weight_stability() {
        let endpoints = vec![
            WeightedEndpoint {
                address: Arc::from("10.0.0.1:80"),
                weight: 3,
                index: 0,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.2:80"),
                weight: 1,
                index: 1,
            },
        ];
        let ch = ConsistentHash::new(endpoints, None);

        let keys: Vec<String> = (0..300).map(|i| format!("/weighted-{i}")).collect();
        let mut ep1_count = 0usize;

        for key in &keys {
            let selected = ch.select(Some(key), None);
            let again = ch.select(Some(key), None);
            assert_eq!(selected, again, "weighted hashing must be deterministic for key {key}");
            if &*selected == "10.0.0.1:80" {
                ep1_count += 1;
            }
        }

        let ep1_ratio = ep1_count as f64 / keys.len() as f64;
        let expected_ep1_ratio = 0.75;
        let tolerance = 0.10;
        assert!(
            (ep1_ratio - expected_ep1_ratio).abs() < tolerance,
            "endpoint 10.0.0.1 ratio {ep1_ratio:.3} should be near {expected_ep1_ratio} (tolerance={tolerance})"
        );
    }
}
