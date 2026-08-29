// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Ring-hash endpoint selection with configurable hash function and virtual nodes.
//!
//! Extends the basic consistent-hash by offering pluggable hash functions
//! (FNV-1a, xxHash64, `MurmurHash3`), operator-tunable virtual node count per
//! unit of endpoint weight, and sorted-ring binary search for O(log N) lookup.

use std::sync::Arc;

use praxis_core::{config::HashFunction, health::ClusterHealthState};
use smallvec::SmallVec;

use super::{endpoint::WeightedEndpoint, hash::fnv1a};

// -----------------------------------------------------------------------------
// RingHash
// -----------------------------------------------------------------------------

/// Consistent-hash ring with configurable hash function and virtual node density.
pub(crate) struct RingHash {
    /// Deduplicated endpoint list with weights and original indices.
    endpoints: Vec<WeightedEndpoint>,

    /// Header whose value is hashed. Falls back to the URI path when `None`
    /// or when the header is absent from the request.
    header: Option<String>,

    /// Sorted ring of `(hash_value, endpoint_index)` pairs.
    ring: Vec<(u64, usize)>,

    /// Hash function used for key hashing and virtual node placement.
    hash_fn: HashFunction,
}

impl RingHash {
    /// Create a ring-hash selector with the given options.
    pub(crate) fn new(
        endpoints: Vec<WeightedEndpoint>,
        header: Option<String>,
        hash_fn: HashFunction,
        virtual_nodes_per_weight: u32,
    ) -> Self {
        let ring = build_ring(&endpoints, &hash_fn, virtual_nodes_per_weight);
        Self {
            endpoints,
            header,
            ring,
            hash_fn,
        }
    }

    /// The optional header name this instance hashes on.
    pub(crate) fn header(&self) -> Option<&str> {
        self.header.as_deref()
    }

    /// Hash the key and return the corresponding healthy endpoint.
    ///
    /// Uses binary search on the sorted ring to find the first virtual node
    /// with a hash >= the key hash. Probes clockwise to skip unhealthy endpoints.
    pub(crate) fn select(
        &self,
        hash_key: Option<&str>,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
    ) -> Option<Arc<str>> {
        if self.ring.is_empty() {
            return None;
        }

        let key = hash_key.unwrap_or("");
        let key_hash = compute_hash(key, &self.hash_fn);

        let start = match self.ring.binary_search_by_key(&key_hash, |(h, _)| *h) {
            Ok(i) | Err(i) => i % self.ring.len(),
        };

        if let Some(state) = health
            && let Some(addr) = self.healthy_probe(start, state, exclude)
        {
            return Some(addr);
        }

        Some(self.panic_mode_select(start, exclude))
    }

    /// Walk the ring clockwise from `start` for a healthy, non-excluded endpoint.
    ///
    /// The probe is bounded by distinct endpoints rather than ring entries:
    /// with every endpoint unhealthy, walking the full ring would revisit
    /// each endpoint's virtual nodes hundreds of times.
    #[expect(clippy::indexing_slicing, reason = "ring indices are bounded by ring_len via modulo")]
    fn healthy_probe(&self, start: usize, state: &ClusterHealthState, exclude: &[Arc<str>]) -> Option<Arc<str>> {
        let ring_len = self.ring.len();
        // Bound the clockwise probe by distinct endpoints, not ring
        // entries: with every endpoint unhealthy, walking the full ring
        // would visit each endpoint's virtual nodes hundreds of times.
        // The visited set is built lazily on the first failed probe: in
        // the dominant case the first slot is healthy and clusters past
        // the 32-endpoint inline capacity never pay its heap allocation.
        let mut visited: Option<SmallVec<[bool; 32]>> = None;
        let mut remaining = self.endpoints.len();
        for offset in 0..ring_len {
            let idx = (start + offset) % ring_len;
            let ep_idx = self.ring[idx].1;
            let ep = &self.endpoints[ep_idx];
            if !super::is_excluded(&ep.address, exclude)
                && ep.index < state.endpoints().len()
                && state.endpoints()[ep.index].is_healthy()
            {
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

    /// Panic-mode pick: all endpoints unhealthy, or no health state at all.
    ///
    /// Still honours the exclusion set so a retry does not land back on the
    /// endpoint that just failed, falling back to the hashed position only
    /// when every endpoint has been excluded.
    #[expect(clippy::indexing_slicing, reason = "ring indices are bounded by ring_len via modulo")]
    fn panic_mode_select(&self, start: usize, exclude: &[Arc<str>]) -> Arc<str> {
        let ring_len = self.ring.len();
        for offset in 0..ring_len {
            let ep = &self.endpoints[self.ring[(start + offset) % ring_len].1];
            if !super::is_excluded(&ep.address, exclude) {
                return Arc::clone(&ep.address);
            }
        }
        let ep_idx = self.ring[start].1;
        Arc::clone(&self.endpoints[ep_idx].address)
    }
}

// -----------------------------------------------------------------------------
// Ring Construction
// -----------------------------------------------------------------------------

/// Build a sorted ring of `(hash, endpoint_index)` tuples.
fn build_ring(endpoints: &[WeightedEndpoint], hash_fn: &HashFunction, vnodes_per_weight: u32) -> Vec<(u64, usize)> {
    let mut ring: Vec<(u64, usize)> = Vec::new();
    for (idx, ep) in endpoints.iter().enumerate() {
        let count = ep.weight.saturating_mul(vnodes_per_weight);
        for vnode in 0..count {
            let key = format!("{}#{vnode}", ep.address);
            let hash = compute_hash(&key, hash_fn);
            ring.push((hash, idx));
        }
    }
    ring.sort_unstable_by_key(|(h, _)| *h);
    ring
}

// -----------------------------------------------------------------------------
// Hash Functions
// -----------------------------------------------------------------------------

/// Compute a 64-bit hash using the selected function.
fn compute_hash(s: &str, hash_fn: &HashFunction) -> u64 {
    match hash_fn {
        HashFunction::Fnv1a => fnv1a(s),
        HashFunction::Xxhash => xxhash64(s),
        HashFunction::Murmur3 => murmur3_64(s),
    }
}


/// `xxHash64` with seed 0.
#[expect(clippy::too_many_lines, reason = "hash algorithm is inherently sequential")]
#[expect(clippy::indexing_slicing, reason = "slice index `i` is bounded by input.len()")]
fn xxhash64(s: &str) -> u64 {
    const PRIME1: u64 = 0x9E37_79B1_85EB_CA87;
    const PRIME2: u64 = 0xC2B2_AE3D_27D4_EB4F;
    const PRIME3: u64 = 0x1656_67B1_9E37_79F9;
    const PRIME4: u64 = 0x85EB_CA77_C2B2_AE63;
    const PRIME5: u64 = 0x27D4_EB2F_1656_67C5;

    let input = s.as_bytes();
    let len = input.len();
    let mut hash: u64;

    if len >= 32 {
        let mut v1 = PRIME1.wrapping_add(PRIME2);
        let mut v2 = PRIME2;
        let mut v3: u64 = 0;
        let mut v4 = 0_u64.wrapping_sub(PRIME1);

        let mut i = 0;
        while i + 32 <= len {
            v1 = xxh64_round(v1, read_u64(input, i));
            v2 = xxh64_round(v2, read_u64(input, i + 8));
            v3 = xxh64_round(v3, read_u64(input, i + 16));
            v4 = xxh64_round(v4, read_u64(input, i + 24));
            i += 32;
        }

        hash = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        hash = xxh64_merge_round(hash, v1);
        hash = xxh64_merge_round(hash, v2);
        hash = xxh64_merge_round(hash, v3);
        hash = xxh64_merge_round(hash, v4);
    } else {
        hash = PRIME5;
    }

    hash = hash.wrapping_add(len as u64);

    let mut i = if len >= 32 { len & !31 } else { 0 };

    while i + 8 <= len {
        let k = read_u64(input, i).wrapping_mul(PRIME2);
        hash ^= k.rotate_left(31).wrapping_mul(PRIME1);
        hash = hash.rotate_left(27).wrapping_mul(PRIME1).wrapping_add(PRIME4);
        i += 8;
    }

    while i + 4 <= len {
        let k = u64::from(read_u32(input, i));
        hash ^= k.wrapping_mul(PRIME1);
        hash = hash.rotate_left(23).wrapping_mul(PRIME2).wrapping_add(PRIME3);
        i += 4;
    }

    for &byte in &input[i..] {
        hash ^= u64::from(byte).wrapping_mul(PRIME5);
        hash = hash.rotate_left(11).wrapping_mul(PRIME1);
    }

    hash ^= hash >> 33;
    hash = hash.wrapping_mul(PRIME2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(PRIME3);
    hash ^= hash >> 32;
    hash
}

/// Single round of the `xxHash64` accumulator.
fn xxh64_round(mut acc: u64, input: u64) -> u64 {
    const PRIME2: u64 = 0xC2B2_AE3D_27D4_EB4F;
    const PRIME1: u64 = 0x9E37_79B1_85EB_CA87;
    acc = acc.wrapping_add(input.wrapping_mul(PRIME2));
    acc = acc.rotate_left(31);
    acc.wrapping_mul(PRIME1)
}

/// Merge an accumulator lane back into the hash state.
fn xxh64_merge_round(mut hash: u64, val: u64) -> u64 {
    const PRIME1: u64 = 0x9E37_79B1_85EB_CA87;
    const PRIME4: u64 = 0x85EB_CA77_C2B2_AE63;
    let val = xxh64_round(0, val);
    hash ^= val;
    hash.wrapping_mul(PRIME1).wrapping_add(PRIME4)
}

/// `MurmurHash3` finalization mix applied to a simple accumulation (lower 64 bits).
#[expect(clippy::indexing_slicing, reason = "tail indices are bounded by tail.len()")]
#[expect(clippy::too_many_lines, reason = "hash algorithm is inherently sequential")]
fn murmur3_64(s: &str) -> u64 {
    const C1: u64 = 0x87C3_7B91_1142_53D5;
    const C2: u64 = 0x4CF5_AD43_2745_937F;

    let input = s.as_bytes();
    let len = input.len();
    let mut h1: u64 = 0;
    let mut h2: u64 = 0;

    let nblocks = len / 16;
    for i in 0..nblocks {
        let mut k1 = read_u64(input, i * 16);
        let mut k2 = read_u64(input, i * 16 + 8);

        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(27);
        h1 = h1.wrapping_add(h2);
        h1 = h1.wrapping_mul(5).wrapping_add(0x52DC_E729);

        k2 = k2.wrapping_mul(C2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1);
        h2 ^= k2;
        h2 = h2.rotate_left(31);
        h2 = h2.wrapping_add(h1);
        h2 = h2.wrapping_mul(5).wrapping_add(0x3849_5AB5);
    }

    let tail = &input[nblocks * 16..];
    let mut k1: u64 = 0;
    let mut k2: u64 = 0;
    let tail_len = tail.len();

    // Process tail bytes into k2 (bytes 8..tail_len) and k1 (bytes 0..min(8, tail_len))
    if tail_len > 8 {
        for j in (8..tail_len).rev() {
            k2 ^= u64::from(tail[j]) << ((j - 8) * 8);
        }
        k2 = k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
        h2 ^= k2;
    }
    if tail_len > 0 {
        let k1_end = tail_len.min(8);
        for j in (0..k1_end).rev() {
            k1 ^= u64::from(tail[j]) << (j * 8);
        }
        k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
        h1 ^= k1;
    }

    h1 ^= len as u64;
    h2 ^= len as u64;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    h1 = h1.wrapping_add(h2);

    h1
}

/// `MurmurHash3` finalization mixer.
fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    k ^= k >> 33;
    k = k.wrapping_mul(0xC4CE_B9FE_1A85_EC53);
    k ^= k >> 33;
    k
}

// -----------------------------------------------------------------------------
// Byte Readers (little-endian)
// -----------------------------------------------------------------------------

/// Read a little-endian u64 from `buf` at `offset`.
#[expect(clippy::indexing_slicing, reason = "caller guarantees bounds")]
fn read_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ])
}

/// Read a little-endian u32 from `buf` at `offset`.
#[expect(clippy::indexing_slicing, reason = "caller guarantees bounds")]
fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
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
    use std::collections::{HashMap, HashSet};

    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

    use super::*;

    #[test]
    fn same_key_same_endpoint_fnv1a() {
        let rh = make_ring_hash(3, HashFunction::Fnv1a);
        let first = rh.select(Some("/stable"), None, &[]).unwrap();
        let second = rh.select(Some("/stable"), None, &[]).unwrap();
        assert_eq!(first, second, "same key should always select same endpoint");
    }

    #[test]
    fn same_key_same_endpoint_xxhash() {
        let rh = make_ring_hash(3, HashFunction::Xxhash);
        let first = rh.select(Some("/stable"), None, &[]).unwrap();
        let second = rh.select(Some("/stable"), None, &[]).unwrap();
        assert_eq!(first, second, "same key should always select same endpoint (xxhash)");
    }

    /// Known-answer vectors from the reference `xxHash64` implementation
    /// (seed 0), covering the <4B, 4–31B, and ≥32B code paths.
    #[test]
    fn xxhash64_known_answers() {
        assert_eq!(xxhash64(""), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxhash64("a"), 0xD24E_C4F1_A98C_6E5B);
        assert_eq!(xxhash64("abc"), 0x44BC_2CF5_AD77_0999);
        assert_eq!(xxhash64("session-key-12345"), 0xF0C4_C121_17BE_EEAC);
        assert_eq!(
            xxhash64("0123456789abcdef0123456789abcdef0123456789abcdef"),
            0xE352_1644_4A3C_253B,
            "≥32-byte input exercises the accumulator-lane path"
        );
    }

    /// Known-answer vectors from the reference `MurmurHash3` `x64_128`
    /// implementation (seed 0, lower 64 bits), covering tail-only and
    /// full-block code paths.
    #[test]
    fn murmur3_known_answers() {
        assert_eq!(murmur3_64(""), 0x0);
        assert_eq!(murmur3_64("a"), 0x8555_5565_F659_7889);
        assert_eq!(murmur3_64("abc"), 0xB496_3F3F_3FAD_7867);
        assert_eq!(murmur3_64("session-key-12345"), 0x7726_3005_1E18_5514);
        assert_eq!(
            murmur3_64("0123456789abcdef0123456789abcdef0123456789abcdef"),
            0x9AC8_FB1C_6EC3_A370,
            "≥16-byte input exercises the block loop"
        );
    }

    /// Known-answer vectors for FNV-1a 64.
    #[test]
    fn fnv1a_known_answers() {
        assert_eq!(fnv1a(""), 0xCBF2_9CE4_8422_2325);
        assert_eq!(fnv1a("a"), 0xAF63_DC4C_8601_EC8C);
        assert_eq!(fnv1a("abc"), 0xE71F_A219_0541_574B);
    }

    #[test]
    fn same_key_same_endpoint_murmur3() {
        let rh = make_ring_hash(3, HashFunction::Murmur3);
        let first = rh.select(Some("/stable"), None, &[]).unwrap();
        let second = rh.select(Some("/stable"), None, &[]).unwrap();
        assert_eq!(first, second, "same key should always select same endpoint (murmur3)");
    }

    #[test]
    fn different_keys_reach_all_endpoints() {
        let rh = make_ring_hash(3, HashFunction::Xxhash);
        let selections: HashSet<Arc<str>> = (0..200)
            .map(|i| rh.select(Some(&format!("/user/{i}/profile")), None, &[]).unwrap())
            .collect();
        assert_eq!(selections.len(), 3, "distinct keys should reach all 3 endpoints");
    }

    #[test]
    fn distribution_is_reasonable() {
        let rh = make_ring_hash(4, HashFunction::Xxhash);
        let mut counts: HashMap<Arc<str>, usize> = HashMap::new();
        let total = 4000;
        for i in 0..total {
            let sel = rh.select(Some(&format!("/key-{i}")), None, &[]).unwrap();
            *counts.entry(sel).or_default() += 1;
        }
        let expected = f64::from(total) / 4.0;
        for (addr, count) in &counts {
            let ratio = *count as f64 / expected;
            assert!(
                (0.5..=1.5).contains(&ratio),
                "endpoint {addr} ratio {ratio:.3} should be reasonable (count={count})"
            );
        }
    }

    #[test]
    fn skips_unhealthy() {
        let rh = make_ring_hash(3, HashFunction::Fnv1a);
        let state = health_state(3);
        state.endpoints()[1].mark_unhealthy();

        for i in 0..50 {
            let sel = rh.select(Some(&format!("/k{i}")), Some(&state), &[]).unwrap();
            assert_ne!(&*sel, "10.0.0.2:80", "unhealthy endpoint must not be selected");
        }
    }

    #[test]
    fn panic_mode_when_all_unhealthy() {
        let rh = make_ring_hash(2, HashFunction::Fnv1a);
        let state = health_state(2);
        state.endpoints()[0].mark_unhealthy();
        state.endpoints()[1].mark_unhealthy();

        let sel = rh.select(Some("/panic"), Some(&state), &[]).unwrap();
        assert!(
            &*sel == "10.0.0.1:80" || &*sel == "10.0.0.2:80",
            "panic mode should still return an endpoint"
        );
    }

    #[test]
    fn empty_endpoints_returns_none() {
        let rh = RingHash::new(Vec::new(), None, HashFunction::Fnv1a, 100);
        assert!(rh.select(Some("/x"), None, &[]).is_none());
    }

    #[test]
    fn virtual_nodes_affect_ring_size() {
        let eps = endpoints(3);
        let ring_50 = build_ring(&eps, &HashFunction::Fnv1a, 50);
        let ring_200 = build_ring(&eps, &HashFunction::Fnv1a, 200);
        assert_eq!(ring_50.len(), 150, "3 endpoints * 50 vnodes = 150");
        assert_eq!(ring_200.len(), 600, "3 endpoints * 200 vnodes = 600");
    }

    #[test]
    fn weighted_endpoints_get_more_vnodes() {
        let eps = vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 0, 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1, 3),
        ];
        let ring = build_ring(&eps, &HashFunction::Fnv1a, 100);
        assert_eq!(ring.len(), 400, "weight 1 + weight 3 = 4 * 100 = 400 vnodes");
    }

    #[test]
    fn xxhash64_reference_vector_empty() {
        // Canonical XXH64("", seed=0) from the xxHash specification.
        assert_eq!(xxhash64(""), 0xEF46_DB37_51D8_E999);
    }

    #[test]
    fn xxhash64_deterministic() {
        // Same input must always produce the same output across calls.
        let inputs = ["a", "abc", "Hello, world!", "abcdefghijklmnopqrstuvwxyz012345"];
        for input in inputs {
            let first = xxhash64(input);
            let second = xxhash64(input);
            assert_eq!(first, second, "xxhash64 must be deterministic for {input:?}");
            assert_ne!(first, 0, "xxhash64 should not produce 0 for {input:?}");
        }
    }

    #[test]
    fn hash_functions_produce_different_results() {
        let s = "test-key";
        let h1 = fnv1a(s);
        let h2 = xxhash64(s);
        let h3 = murmur3_64(s);
        assert_ne!(h1, h2, "fnv1a and xxhash should differ");
        assert_ne!(h1, h3, "fnv1a and murmur3 should differ");
        assert_ne!(h2, h3, "xxhash and murmur3 should differ");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn endpoints(n: usize) -> Vec<WeightedEndpoint> {
        (0..n)
            .map(|i| WeightedEndpoint::simple(Arc::from(format!("10.0.0.{}:80", i + 1).as_str()), i, 1))
            .collect()
    }

    fn make_ring_hash(n: usize, hash_fn: HashFunction) -> RingHash {
        RingHash::new(endpoints(n), None, hash_fn, 100)
    }

    fn health_state(n: usize) -> Arc<ClusterHealthEntry> {
        let healths: Vec<_> = std::iter::repeat_with(EndpointHealth::new).take(n).collect();
        let addrs: Vec<_> = (0..n)
            .map(|i| Arc::from(format!("10.0.0.{}:80", i + 1).as_str()))
            .collect();
        Arc::new(ClusterHealthEntry::new(healths, addrs, None, None))
    }
}
