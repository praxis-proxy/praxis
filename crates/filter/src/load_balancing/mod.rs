// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Protocol-agnostic load-balancing strategies and endpoint types.

use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) mod consistent_hash;
pub(crate) mod endpoint;
pub(crate) mod hash;
pub(crate) mod least_connections;
pub(crate) mod maglev;
pub(crate) mod p2c;
pub(crate) mod priority;
pub(crate) mod random;
pub(crate) mod ring_hash;
pub(crate) mod round_robin;
pub(crate) mod strategy;
pub(crate) mod subset;
pub(crate) mod zone_aware;

// -----------------------------------------------------------------------------
// Shared LCG RNG
// -----------------------------------------------------------------------------

/// Multiplier for the LCG RNG (Knuth MMIX, truncated to 64 bits).
const LCG_A: u64 = 6_364_136_223_846_793_005;

/// Increment for the LCG RNG.
const LCG_C: u64 = 1_442_695_040_888_963_407;

/// First multiplier of the `SplitMix64` output finalizer.
const MIX_A: u64 = 0xBF58_476D_1CE4_E5B9;

/// Second multiplier of the `SplitMix64` output finalizer.
const MIX_B: u64 = 0x94D0_49BB_1331_11EB;

/// Advance an atomic LCG state and return a random value.
///
/// A power-of-two LCG's low bits have short periods (the lowest bit
/// alternates), and callers reduce with `%`, so the state is passed
/// through a finalizer that spreads the high bits into the low ones.
fn next_random(rng: &AtomicU64) -> u64 {
    let state = rng
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |s| {
            Some(s.wrapping_mul(LCG_A).wrapping_add(LCG_C))
        })
        .unwrap_or(0);
    let mixed = (state ^ (state >> 30)).wrapping_mul(MIX_A);
    let mixed = (mixed ^ (mixed >> 27)).wrapping_mul(MIX_B);
    mixed ^ (mixed >> 31)
}

// -----------------------------------------------------------------------------
// Shared Utilities
// -----------------------------------------------------------------------------

/// Whether `addr` appears in a retry-exclusion list.
///
/// Exclusion lists hold endpoints already attempted for this request, so a
/// retry lands somewhere new.
pub(crate) fn is_excluded(addr: &str, exclude: &[std::sync::Arc<str>]) -> bool {
    exclude.iter().any(|e| e.as_ref() == addr)
}
