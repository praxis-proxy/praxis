// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Protocol-agnostic load-balancing strategies and endpoint types.

use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) mod consistent_hash;
pub(crate) mod endpoint;
pub(crate) mod least_connections;
pub(crate) mod maglev;
pub(crate) mod p2c;
pub(crate) mod random;
pub(crate) mod round_robin;
pub(crate) mod strategy;

// -----------------------------------------------------------------------------
// Shared LCG RNG
// -----------------------------------------------------------------------------

/// Multiplier for the LCG RNG (Knuth MMIX, truncated to 64 bits).
const LCG_A: u64 = 6_364_136_223_846_793_005;

/// Increment for the LCG RNG.
const LCG_C: u64 = 1_442_695_040_888_963_407;

/// Advance an atomic LCG state and return the new value.
fn next_random(rng: &AtomicU64) -> u64 {
    rng.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |s| {
        Some(s.wrapping_mul(LCG_A).wrapping_add(LCG_C))
    })
    .unwrap_or(0)
}
