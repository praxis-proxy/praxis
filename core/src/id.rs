// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis contributors

//! Per-instance request ID generation.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::time::TimeSource;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Mask for the lower 48 bits of the counter.
const COUNTER_MASK: u64 = 0xFFFF_FFFF_FFFF; // 2^48 - 1

// -----------------------------------------------------------------------------
// IdGenerator
// -----------------------------------------------------------------------------

/// Generates 32-character hex request IDs with per-instance entropy.
///
/// Combines a wall-clock timestamp (microseconds since epoch), a
/// random 32-bit seed (set once at construction), and a 48-bit
/// monotone counter to produce IDs that are probabilistically
/// unique across instances.
///
/// ```
/// use std::time::Duration;
///
/// use praxis_core::{id::IdGenerator, time::FixedTimeSource};
///
/// let generator = IdGenerator::with_seed(0x1234_5678);
/// let ts = FixedTimeSource::new(Duration::from_micros(1));
/// let id = generator.generate(&ts);
/// assert_eq!(id.len(), 32);
/// ```
pub struct IdGenerator {
    /// Monotone counter for the sequential component.
    counter: AtomicU64,

    /// Random per-instance seed for cross-instance uniqueness.
    seed: u32,
}

impl Default for IdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl IdGenerator {
    /// Create a generator with a random seed.
    ///
    /// The seed is drawn from the OS random number generator
    /// via [`rand::random`]. Panics only if the OS entropy
    /// source is unavailable, which indicates a fundamentally
    /// broken environment.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
            seed: rand::random(),
        }
    }

    /// Create a generator with a fixed seed for deterministic tests.
    #[must_use]
    pub fn with_seed(seed: u32) -> Self {
        Self {
            counter: AtomicU64::new(0),
            seed,
        }
    }

    /// Generate a 32-character hex request ID.
    ///
    /// Format: `{micros:012x}{seed:08x}{counter:012x}`
    ///
    /// - Chars 0-11: microseconds since epoch (48-bit)
    /// - Chars 12-19: per-instance seed (32-bit)
    /// - Chars 20-31: monotone counter (48-bit, masked)
    #[must_use]
    pub fn generate(&self, time_source: &dyn TimeSource) -> String {
        #[allow(clippy::cast_possible_truncation, reason = "clamped to u64::MAX before cast")]
        let micros = time_source.now().as_micros().min(u128::from(u64::MAX)) as u64;
        let micros_masked = micros & COUNTER_MASK;

        let seq = self.counter.fetch_add(1, Ordering::Relaxed) & COUNTER_MASK;

        format!("{micros_masked:012x}{:08x}{seq:012x}", self.seed)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::time::FixedTimeSource;

    #[test]
    fn deterministic_output_with_fixed_seed() {
        let generator = IdGenerator::with_seed(0xDEAD_BEEF);
        let ts = FixedTimeSource::new(Duration::from_micros(0x0011_2233_4455));
        let id = generator.generate(&ts);
        assert_eq!(
            id, "001122334455deadbeef000000000000",
            "fixed seed + fixed time should produce a known ID"
        );
    }

    #[test]
    fn consecutive_ids_differ() {
        let generator = IdGenerator::with_seed(0);
        let ts = FixedTimeSource::new(Duration::from_secs(1_700_000_000));
        let id1 = generator.generate(&ts);
        let id2 = generator.generate(&ts);
        assert_ne!(id1, id2, "consecutive IDs must differ");
    }

    #[test]
    fn ids_are_32_chars() {
        let generator = IdGenerator::with_seed(0);
        let ts = FixedTimeSource::new(Duration::from_secs(1_700_000_000));
        let id = generator.generate(&ts);
        assert_eq!(id.len(), 32, "ID must be 32 hex characters");
    }

    #[test]
    fn different_seeds_produce_different_ids() {
        let ts = FixedTimeSource::new(Duration::from_secs(1_700_000_000));
        let generator_a = IdGenerator::with_seed(1);
        let generator_b = IdGenerator::with_seed(2);
        let id_a = generator_a.generate(&ts);
        let id_b = generator_b.generate(&ts);
        assert_ne!(
            id_a, id_b,
            "same timestamp + same counter but different seeds must differ"
        );
    }

    #[test]
    fn counter_masks_to_48_bits() {
        let generator = IdGenerator::with_seed(0);
        let ts = FixedTimeSource::new(Duration::from_secs(0));

        // Advance counter past 48-bit boundary
        generator.counter.store(COUNTER_MASK, Ordering::Relaxed);
        let id = generator.generate(&ts);

        // Counter should be COUNTER_MASK (all 1s in 48 bits)
        assert!(
            id.ends_with("ffffffffffff"),
            "counter at 48-bit max should show 12 hex f's, got: {id}"
        );

        // Next generate wraps to 0
        let id_next = generator.generate(&ts);
        assert!(
            id_next.ends_with("000000000000"),
            "counter past 48-bit max should wrap to zero, got: {id_next}"
        );
    }

    #[test]
    fn new_creates_with_random_seed() {
        let generator = IdGenerator::new();
        let ts = FixedTimeSource::new(Duration::from_secs(1_700_000_000));
        let id = generator.generate(&ts);
        assert_eq!(id.len(), 32, "new() generator should produce 32-char IDs");
    }
}
