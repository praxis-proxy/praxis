// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Consistent-hash endpoint selection for session affinity.

use std::sync::Arc;

use praxis_core::health::{ClusterHealthState, EndpointHealth};

use super::{endpoint::WeightedEndpoint, hash::fnv1a};

// -----------------------------------------------------------------------------
// ConsistentHash
// -----------------------------------------------------------------------------

/// Routes each request to the same endpoint by hashing a stable
/// attribute. Each endpoint owns a slice of the hash space proportional
/// to its weight.
pub(crate) struct ConsistentHash {
    /// Deduplicated endpoint list with weights and original indices.
    endpoints: Vec<WeightedEndpoint>,

    /// Header whose value is hashed. Falls back to the URI path when `None`
    /// or when the header is absent from the request.
    header: Option<String>,

    /// Cumulative weight boundaries: `boundaries[i]` is the sum of weights
    /// `0..=i`, so endpoint `i` owns the hash slots
    /// `boundaries[i] - weight[i] .. boundaries[i]`.
    ///
    /// Boundaries rather than one ring entry per unit of weight (the
    /// round-robin and random precedent): the ring is rebuilt from
    /// scratch on every config reload, and the endpoint and weight
    /// ceilings alone (10 000 × 1 000) allowed a 10 M-entry, 80 MiB
    /// expansion, far past the 1 Mi ceiling `ring_hash` is held to.
    boundaries: Vec<u64>,
}

impl ConsistentHash {
    /// Create a consistent-hash selector with a weight-proportional hash space.
    pub(crate) fn new(endpoints: Vec<WeightedEndpoint>, header: Option<String>) -> Self {
        let mut running = 0_u64;
        let boundaries: Vec<u64> = endpoints
            .iter()
            .map(|ep| {
                running += u64::from(ep.weight);
                running
            })
            .collect();
        debug_assert!(running > 0, "consistent-hash requires at least one weighted endpoint");
        Self {
            endpoints,
            header,
            boundaries,
        }
    }

    /// The optional header name this instance hashes on.
    pub(crate) fn header(&self) -> Option<&str> {
        self.header.as_deref()
    }

    /// Number of stored weight boundaries; test observability for the
    /// O(endpoints) memory invariant.
    #[cfg(test)]
    pub(crate) fn stored_slots(&self) -> usize {
        self.boundaries.len()
    }

    /// Hash the key and return the corresponding healthy endpoint.
    ///
    /// Skips unhealthy endpoints by probing adjacent endpoints, falling
    /// back to the original selection if all are unhealthy.
    pub(crate) fn select(
        &self,
        hash_key: Option<&str>,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
    ) -> Option<Arc<str>> {
        let key = hash_key.unwrap_or("");

        let total = self.boundaries.last().copied().unwrap_or(0);
        if total == 0 {
            return None;
        }
        // The first endpoint whose cumulative weight exceeds the hashed
        // slot owns it; zero-weight endpoints share their predecessor's
        // boundary and are therefore never landed on.
        let slot = fnv1a(key) % total;
        let start = self.boundaries.partition_point(|&end| end <= slot);

        if let Some(state) = health
            && let Some(addr) = self.probe(start, exclude, |ep| {
                ep.index < state.endpoints().len()
                    && state.endpoints().get(ep.index).is_some_and(EndpointHealth::is_healthy)
            })
        {
            return Some(addr);
        }

        self.probe(start, exclude, |_| true)
    }

    /// Walk endpoints clockwise from `start` for one that is not excluded
    /// and passes `accept`.
    ///
    /// Walking endpoints rather than individual hash slots yields the same
    /// first match, every slot an endpoint owns resolves to that same
    /// endpoint, while visiting each candidate exactly once, which is
    /// what a full-cluster outage needs.
    #[expect(clippy::indexing_slicing, reason = "endpoint indices are bounded via modulo")]
    fn probe(
        &self,
        start: usize,
        exclude: &[Arc<str>],
        accept: impl Fn(&WeightedEndpoint) -> bool,
    ) -> Option<Arc<str>> {
        let len = self.endpoints.len();
        (0..len)
            .map(|offset| &self.endpoints[(start + offset) % len])
            .filter(|ep| ep.weight > 0)
            .find(|ep| !is_excluded(&ep.address, exclude) && accept(ep))
            .map(|ep| Arc::clone(&ep.address))
    }
}

/// Returns `true` if `addr` appears in the exclusion list.
fn is_excluded(addr: &str, exclude: &[Arc<str>]) -> bool {
    exclude.iter().any(|e| e.as_ref() == addr)
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
    clippy::panic,
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "tests"
)]
mod tests {
    use praxis_core::health::ClusterHealthEntry;

    use super::*;

    #[test]
    fn same_key_same_endpoint() {
        let ch = ConsistentHash::new(
            vec![
                WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 0, 1),
                WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1, 1),
            ],
            None,
        );

        let first = ch.select(Some("/stable-path"), None, &[]).unwrap();
        let second = ch.select(Some("/stable-path"), None, &[]).unwrap();
        assert_eq!(first, second, "same key should always select same endpoint");
    }

    #[test]
    fn different_keys_select_different_endpoints() {
        let ch = ConsistentHash::new(
            vec![
                WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 0, 1),
                WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1, 1),
            ],
            None,
        );

        let ep_a = ch.select(Some("/path-a"), None, &[]).unwrap();
        let ep_b = ch.select(Some("/path-b"), None, &[]).unwrap();
        assert_ne!(
            ep_a, ep_b,
            "FNV-1a of /path-a and /path-b should not collide with only 2 endpoints"
        );
    }

    #[test]
    fn skips_unhealthy() {
        let ch = ConsistentHash::new(
            vec![
                WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 0, 1),
                WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1, 1),
                WeightedEndpoint::simple(Arc::from("10.0.0.3:80"), 2, 1),
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
            let selected = ch.select(Some(path), Some(&state), &[]).unwrap();
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
                WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 0, 1),
                WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1, 1),
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

        let selected = ch.select(Some("/panic"), Some(&state), &[]).unwrap();
        assert!(
            &*selected == "10.0.0.1:80" || &*selected == "10.0.0.2:80",
            "panic mode should still return an endpoint, got: {selected}"
        );
    }

    #[test]
    fn select_with_none_hash_key_uses_fallback() {
        let ch = ConsistentHash::new(
            vec![
                WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 0, 1),
                WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1, 1),
                WeightedEndpoint::simple(Arc::from("10.0.0.3:80"), 2, 1),
            ],
            None,
        );

        let first = ch.select(None, None, &[]).unwrap();
        for _ in 0..10 {
            let again = ch.select(None, None, &[]).unwrap();
            assert_eq!(
                first, again,
                "None hash key should consistently select the same endpoint"
            );
        }
    }

    #[test]
    fn stored_slots_do_not_grow_with_weight() {
        // The selector must stay O(endpoints): the previous
        // weight-expanded ring stored one entry per unit of weight, so
        // this cluster alone materialised 3 000 entries, and a cluster at
        // the configured ceilings (10 000 endpoints x weight 1 000)
        // materialised 10 M -- rebuilt on every config reload.
        let ch = ConsistentHash::new(
            vec![
                WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 0, 1_000),
                WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1, 1_000),
                WeightedEndpoint::simple(Arc::from("10.0.0.3:80"), 2, 1_000),
            ],
            None,
        );
        assert_eq!(
            ch.stored_slots(),
            3,
            "stored slots must scale with endpoint count, not summed weight"
        );
    }

    #[test]
    fn matches_weight_expanded_ring_selection() {
        // Boundary search must pick exactly the endpoint the expanded
        // ring would have picked, for every key and at every weight.
        let endpoints = vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 0, 3),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1, 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.3:80"), 2, 5),
            WeightedEndpoint::simple(Arc::from("10.0.0.4:80"), 3, 2),
        ];
        let ring: Vec<usize> = endpoints
            .iter()
            .enumerate()
            .flat_map(|(i, ep)| std::iter::repeat_n(i, ep.weight as usize))
            .collect();
        let ch = ConsistentHash::new(endpoints.clone(), None);

        for i in 0..500 {
            let key = format!("/key-{i}");
            let expected = &endpoints[ring[(fnv1a(&key) as usize) % ring.len()]].address;
            assert_eq!(
                ch.select(Some(&key), None, &[]).unwrap(),
                *expected,
                "boundary search diverged from the weight-expanded ring for {key}"
            );
        }
    }

    #[test]
    fn weight_stability() {
        let endpoints = vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 0, 3),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1, 1),
        ];
        let ch = ConsistentHash::new(endpoints, None);

        let keys: Vec<String> = (0..300).map(|i| format!("/weighted-{i}")).collect();
        let mut ep1_count = 0_usize;

        for key in &keys {
            let selected = ch.select(Some(key), None, &[]).unwrap();
            let again = ch.select(Some(key), None, &[]).unwrap();
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
