// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Shared hash functions used by multiple load-balancing strategies.

/// FNV-1a 64-bit hash (fast, deterministic).
///
/// **Security note:** FNV-1a is unkeyed; an attacker who knows
/// the backend addresses can brute-force header values to target
/// a specific backend. The same risk applies to xxHash and
/// `MurmurHash3` in the ring-hash strategy. For adversarial
/// environments, consider a keyed hash (e.g. `SipHash` with a
/// random seed) as an alternative.
pub(crate) fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for byte in s.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}
