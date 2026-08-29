// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Maglev consistent-hash endpoint selection.
//!
//! Builds a fixed-size lookup table via Google's Maglev population
//! algorithm. Compared to the ring-based `consistent_hash`, Maglev gives
//! more even load distribution and minimal disruption (near-`1/M` per-slot
//! churn) when endpoints are added or removed.

use std::sync::Arc;

use praxis_core::health::{ClusterHealthState, EndpointHealth};

use super::endpoint::WeightedEndpoint;

/// Size of the Maglev lookup table. Must be prime so the permutation
/// visits every slot. `65537` is Google's default and keeps per-cluster
/// memory at ~256 `KiB` (4 bytes per entry).
const TABLE_SIZE: usize = 65_537;

/// Seed mixed into the FNV-1a offset basis to derive the permutation
/// `skip`, independent of the `offset` hash. Golden-ratio constant.
const SKIP_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

/// Sentinel marking an unfilled lookup-table slot during population.
const SENTINEL: u32 = u32::MAX;

// -----------------------------------------------------------------------------
// Maglev
// -----------------------------------------------------------------------------

/// Routes each request to a stable endpoint via a Maglev lookup table.
///
/// Endpoints are expanded into `weight` replicas during population, so the
/// resulting distribution is proportional to endpoint weight.
pub(crate) struct Maglev {
    /// Deduplicated endpoint list with weights and original indices.
    endpoints: Vec<WeightedEndpoint>,

    /// Header whose value is hashed. Falls back to the URI path when `None`
    /// or when the header is absent from the request.
    header: Option<String>,

    /// Maglev lookup table of length `TABLE_SIZE`; each entry is an index
    /// into `endpoints`.
    table: Vec<u32>,
}

impl Maglev {
    /// Create a Maglev selector, building the lookup table once.
    pub(crate) fn new(endpoints: Vec<WeightedEndpoint>, header: Option<String>) -> Self {
        let table = build_table(&endpoints);
        Self {
            endpoints,
            header,
            table,
        }
    }

    /// The optional header name this instance hashes on.
    pub(crate) fn header(&self) -> Option<&str> {
        self.header.as_deref()
    }

    /// Hash the key and return the corresponding healthy endpoint.
    ///
    /// Skips unhealthy and excluded endpoints by probing adjacent table slots,
    /// falling back to the original selection if all are unhealthy.
    pub(crate) fn select(
        &self,
        hash_key: Option<&str>,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
    ) -> Option<Arc<str>> {
        let len = self.table.len();
        if len == 0 {
            return None;
        }
        let key = hash_key.unwrap_or("");
        #[expect(clippy::cast_possible_truncation, reason = "modulo fits usize")]
        let start = (fnv1a_seeded(key, 0) as usize) % len;

        if let Some(state) = health
            && let Some(addr) = self.probe(start, exclude, |ep| {
                state.endpoints().get(ep.index).is_some_and(EndpointHealth::is_healthy)
            })
        {
            return Some(addr);
        }

        self.probe(start, exclude, |_| true)
    }

    /// Probe table slots clockwise from `start` for an endpoint that is
    /// not excluded and passes `accept`.
    ///
    /// The probe is bounded by distinct endpoints rather than table
    /// slots (the ring-hash precedent): with every endpoint rejected,
    /// walking all 65k slots would revisit each endpoint's slots
    /// thousands of times — hundreds of microseconds per request exactly
    /// during a full-cluster outage.
    #[expect(
        clippy::indexing_slicing,
        reason = "table slot and owner index are in bounds by construction"
    )]
    fn probe(
        &self,
        start: usize,
        exclude: &[Arc<str>],
        accept: impl Fn(&WeightedEndpoint) -> bool,
    ) -> Option<Arc<str>> {
        let len = self.table.len();
        // Built lazily on the first rejected slot (the ring-hash
        // precedent): the dominant healthy-first-slot case must not pay
        // a per-request memset — or, past the inline capacity, a heap
        // allocation — for a set it never reads.
        let mut visited: Option<smallvec::SmallVec<[bool; 32]>> = None;
        let mut remaining = self.endpoints.len();
        for offset in 0..len {
            let owner = self.table[(start + offset) % len] as usize;
            let ep = &self.endpoints[owner];
            if !is_excluded(&ep.address, exclude) && accept(ep) {
                return Some(Arc::clone(&ep.address));
            }
            let visited = visited.get_or_insert_with(|| smallvec::smallvec![false; self.endpoints.len()]);
            if !visited[owner] {
                visited[owner] = true;
                remaining -= 1;
                if remaining == 0 {
                    break;
                }
            }
        }
        None
    }
}

/// Check if an address is in the exclusion set.
fn is_excluded(addr: &str, exclude: &[Arc<str>]) -> bool {
    exclude.iter().any(|e| e.as_ref() == addr)
}

/// A weighted replica's Maglev permutation over the lookup table.
struct Replica {
    /// Starting slot of this replica's permutation.
    offset: usize,

    /// Step between successive slots; coprime with `TABLE_SIZE`.
    skip: usize,

    /// Index into the endpoints Vec that this replica belongs to.
    owner: u32,
}

/// Expand each endpoint into `weight` replicas, each with an independent
/// permutation (`offset`, `skip`) derived from the address plus replica index.
fn build_replicas(endpoints: &[WeightedEndpoint]) -> Vec<Replica> {
    let mut replicas = Vec::new();
    for (idx, ep) in endpoints.iter().enumerate() {
        for replica in 0..ep.weight {
            let key = format!("{}#{replica}", ep.address);
            // Modulo in u64 space, then convert the bounded (< TABLE_SIZE) result.
            let offset = usize::try_from(fnv1a_seeded(&key, 0) % TABLE_SIZE as u64).unwrap_or(0);
            let skip = usize::try_from(fnv1a_seeded(&key, SKIP_SEED) % (TABLE_SIZE as u64 - 1)).unwrap_or(0) + 1;
            #[expect(clippy::cast_possible_truncation, reason = "endpoint count fits u32")]
            let owner = idx as u32;
            replicas.push(Replica { offset, skip, owner });
        }
    }
    replicas
}

/// Build the Maglev lookup table by populating slots from each replica's
/// permutation in round-robin order. Returns an empty table when there are
/// no endpoints.
#[expect(clippy::indexing_slicing, reason = "table index is a modulo of its length")]
fn build_table(endpoints: &[WeightedEndpoint]) -> Vec<u32> {
    let replicas = build_replicas(endpoints);
    if replicas.is_empty() {
        return Vec::new();
    }

    let mut table = vec![SENTINEL; TABLE_SIZE];
    let mut cursors = vec![0_usize; replicas.len()];
    let mut filled = 0_usize;
    loop {
        for (r, cursor) in replicas.iter().zip(cursors.iter_mut()) {
            let mut c = (r.offset + *cursor * r.skip) % TABLE_SIZE;
            while table[c] != SENTINEL {
                *cursor += 1;
                c = (r.offset + *cursor * r.skip) % TABLE_SIZE;
            }
            table[c] = r.owner;
            *cursor += 1;
            filled += 1;
            if filled == TABLE_SIZE {
                debug_assert!(!table.contains(&SENTINEL), "maglev table must be fully populated");
                return table;
            }
        }
    }
}

/// FNV-1a 64-bit hash with the offset basis salted by `seed`.
///
/// `seed = 0` reproduces plain FNV-1a. A non-zero `seed` yields an
/// independent hash stream, which Maglev needs for its `offset`/`skip` pair.
///
/// **Security note:** FNV-1a is unkeyed; an attacker who knows the backend
/// addresses can brute-force header values to target a specific backend.
/// For adversarial environments, consider a keyed hash (e.g. `SipHash` with
/// a random seed) as an alternative strategy.
fn fnv1a_seeded(s: &str, seed: u64) -> u64 {
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325 ^ seed;
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
    clippy::cast_lossless,
    reason = "tests"
)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use praxis_core::health::ClusterHealthEntry;

    use super::*;

    #[test]
    fn same_key_same_endpoint() {
        let mg = Maglev::new(endpoints(3), None);
        let first = mg.select(Some("/stable"), None, &[]).unwrap();
        let second = mg.select(Some("/stable"), None, &[]).unwrap();
        assert_eq!(first, second, "same key should always select same endpoint");
    }

    #[test]
    fn different_keys_reach_all_endpoints() {
        let mg = Maglev::new(endpoints(2), None);
        let selections: HashSet<Arc<str>> = (0..100)
            .map(|i| mg.select(Some(&format!("/k{i}")), None, &[]).unwrap())
            .collect();
        assert_eq!(
            selections.len(),
            2,
            "distinct keys should reach both endpoints across many keys"
        );
    }

    #[test]
    fn distribution_is_even() {
        let n = 5;
        let mg = Maglev::new(endpoints(n), None);
        let mut counts: HashMap<Arc<str>, usize> = HashMap::new();
        let total = 10_000;
        for i in 0..total {
            let sel = mg.select(Some(&format!("/key-{i}")), None, &[]).unwrap();
            *counts.entry(sel).or_default() += 1;
        }
        let expected = total as f64 / n as f64;
        for (addr, count) in &counts {
            let ratio = *count as f64 / expected;
            assert!(
                (0.85..=1.15).contains(&ratio),
                "endpoint {addr} share {ratio:.3} should be near 1.0 (count={count}, expected={expected})"
            );
        }
        assert_eq!(counts.len(), n, "all endpoints should receive traffic");
    }

    #[test]
    fn skips_unhealthy() {
        let mg = Maglev::new(endpoints(3), None);
        let state = health_state(&["10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80"]);
        state.endpoints()[1].mark_unhealthy();

        for i in 0..100 {
            let sel = mg.select(Some(&format!("/k{i}")), Some(&state), &[]).unwrap();
            assert_ne!(&*sel, "10.0.0.2:80", "unhealthy endpoint must never be selected");
        }
    }

    #[test]
    fn panic_mode_when_all_unhealthy() {
        let mg = Maglev::new(endpoints(2), None);
        let state = health_state(&["10.0.0.1:80", "10.0.0.2:80"]);
        state.endpoints()[0].mark_unhealthy();
        state.endpoints()[1].mark_unhealthy();

        let sel = mg.select(Some("/panic"), Some(&state), &[]).unwrap();
        assert!(
            &*sel == "10.0.0.1:80" || &*sel == "10.0.0.2:80",
            "panic mode should still return an endpoint, got: {sel}"
        );
    }

    #[test]
    fn select_with_none_hash_key_uses_fallback() {
        let mg = Maglev::new(endpoints(3), None);
        let first = mg.select(None, None, &[]).unwrap();
        for _ in 0..10 {
            assert_eq!(
                first,
                mg.select(None, None, &[]).unwrap(),
                "None key must be deterministic"
            );
        }
    }

    #[test]
    fn weight_stability() {
        let eps = vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 0, 3),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1, 1),
        ];
        let mg = Maglev::new(eps, None);

        let total = 4_000;
        let mut ep1 = 0_usize;
        for i in 0..total {
            let key = format!("/w-{i}");
            let sel = mg.select(Some(&key), None, &[]).unwrap();
            assert_eq!(sel, mg.select(Some(&key), None, &[]).unwrap(), "must be deterministic");
            if &*sel == "10.0.0.1:80" {
                ep1 += 1;
            }
        }
        let ratio = ep1 as f64 / total as f64;
        assert!(
            (ratio - 0.75).abs() < 0.05,
            "weight-3 endpoint share {ratio:.3} should be near 0.75"
        );
    }

    #[test]
    fn minimal_disruption_on_backend_removal() {
        let four = Maglev::new(endpoints(4), None);
        let keys: Vec<String> = (0..10_000).map(|i| format!("/k-{i}")).collect();
        let before: Vec<Arc<str>> = keys.iter().map(|k| four.select(Some(k), None, &[]).unwrap()).collect();

        // Drop the 4th backend (10.0.0.4:80).
        let three = Maglev::new(endpoints(3), None);

        let dropped: Arc<str> = Arc::from("10.0.0.4:80");
        let mut survivors = 0_usize;
        let mut reassigned = 0_usize;
        for (k, prev) in keys.iter().zip(&before) {
            if *prev == dropped {
                continue; // These must move; not counted.
            }
            survivors += 1;
            if four.select(Some(k), None, &[]).unwrap() != three.select(Some(k), None, &[]).unwrap() {
                reassigned += 1;
            }
        }
        let churn = reassigned as f64 / survivors as f64;
        assert!(
            churn < 0.10,
            "Maglev should reassign <10% of surviving keys on removal, got {churn:.3}"
        );
    }

    #[test]
    fn single_endpoint_owns_every_key() {
        let mg = Maglev::new(endpoints(1), None);
        for i in 0..50 {
            let sel = mg.select(Some(&format!("/k{i}")), None, &[]).unwrap();
            assert_eq!(&*sel, "10.0.0.1:80", "a single endpoint must own every key");
        }
        assert!(
            !mg.table.contains(&SENTINEL),
            "table must be fully populated with one endpoint"
        );
    }

    #[test]
    fn minimal_disruption_on_backend_addition() {
        let three = Maglev::new(endpoints(3), None);
        let four = Maglev::new(endpoints(4), None);
        let added: Arc<str> = Arc::from("10.0.0.4:80");

        // Keys that don't land on the newly-added backend should almost all
        // stay on the backend they had before (Maglev's minimal-disruption
        // property, in the scale-up direction).
        let mut stayed_existing = 0_usize;
        let mut reassigned = 0_usize;
        for i in 0..10_000 {
            let k = format!("/k-{i}");
            let before = three.select(Some(&k), None, &[]).unwrap();
            let after = four.select(Some(&k), None, &[]).unwrap();
            if after == added {
                continue; // Expected to move onto the new backend.
            }
            stayed_existing += 1;
            if before != after {
                reassigned += 1;
            }
        }
        let churn = reassigned as f64 / stayed_existing as f64;
        assert!(
            churn < 0.10,
            "adding a backend should not reshuffle keys among existing backends, got {churn:.3}"
        );
    }

    #[test]
    fn empty_endpoints_returns_none() {
        let mg = Maglev::new(Vec::new(), None);
        assert!(
            mg.select(Some("/x"), None, &[]).is_none(),
            "no endpoints should yield None"
        );
    }

    #[test]
    fn table_is_fully_populated() {
        let mg = Maglev::new(endpoints(3), None);
        assert_eq!(mg.table.len(), TABLE_SIZE, "table must be full size");
        assert!(!mg.table.contains(&SENTINEL), "no slot should remain unfilled");
        for idx in 0..3_u32 {
            assert!(mg.table.contains(&idx), "endpoint {idx} should appear in the table");
        }
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build `n` equal-weight endpoints `10.0.0.{i+1}:80`.
    fn endpoints(n: usize) -> Vec<WeightedEndpoint> {
        (0..n)
            .map(|i| WeightedEndpoint::simple(Arc::from(format!("10.0.0.{}:80", i + 1).as_str()), i, 1))
            .collect()
    }

    /// Build a health state where every endpoint starts healthy.
    fn health_state(addrs: &[&str]) -> ClusterHealthState {
        Arc::new(ClusterHealthEntry::new(
            addrs.iter().map(|_| EndpointHealth::new()).collect(),
            addrs.iter().map(|a| Arc::from(*a)).collect(),
            None,
            None,
        ))
    }
}
