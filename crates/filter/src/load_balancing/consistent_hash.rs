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
/// attribute. Virtual nodes are proportional to endpoint weight.
pub(crate) struct ConsistentHash {
    /// Deduplicated endpoint list with weights and original indices.
    endpoints: Vec<WeightedEndpoint>,

    /// Header whose value is hashed. Falls back to the URI path when `None`
    /// or when the header is absent from the request.
    header: Option<String>,

    /// Virtual-node ring: each entry is an index into `endpoints`.
    /// Built by expanding each endpoint proportionally to its weight.
    ring: Vec<usize>,
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
            header,
            ring,
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
    pub(crate) fn select(
        &self,
        hash_key: Option<&str>,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
    ) -> Option<Arc<str>> {
        let key = hash_key.unwrap_or("");

        let len = self.ring.len();
        if len == 0 {
            return None;
        }
        #[expect(clippy::cast_possible_truncation, reason = "modulo fits usize")]
        let start = (fnv1a(key) as usize) % len;

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

    /// Walk the ring clockwise from `start` for an endpoint that is not
    /// excluded and passes `accept`.
    ///
    /// Bounded by distinct endpoints rather than ring entries (the
    /// ring-hash precedent): with every endpoint rejected, walking the
    /// weight-expanded ring would revisit each endpoint once per unit of
    /// weight — per request, exactly during a full-cluster outage.
    #[expect(clippy::indexing_slicing, reason = "ring indices are bounded via modulo")]
    fn probe(
        &self,
        start: usize,
        exclude: &[Arc<str>],
        accept: impl Fn(&WeightedEndpoint) -> bool,
    ) -> Option<Arc<str>> {
        let len = self.ring.len();
        // Built lazily on the first rejected slot (the ring-hash
        // precedent): the dominant healthy-first-slot case must not pay
        // a per-request memset — or, past the inline capacity, a heap
        // allocation — for a set it never reads.
        let mut visited: Option<smallvec::SmallVec<[bool; 32]>> = None;
        let mut remaining = self.endpoints.len();
        for offset in 0..len {
            let ep_idx = self.ring[(start + offset) % len];
            let ep = &self.endpoints[ep_idx];
            if !is_excluded(&ep.address, exclude) && accept(ep) {
                return Some(Arc::clone(&ep.address));
            }
            let visited = visited.get_or_insert_with(|| smallvec::smallvec![false; self.endpoints.len()]);
            if !visited[ep_idx] {
                visited[ep_idx] = true;
                remaining -= 1;
                if remaining == 0 {
                    break;
                }
            }
        }
        None
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
