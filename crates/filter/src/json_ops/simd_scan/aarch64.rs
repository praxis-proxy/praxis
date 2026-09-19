// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! NEON-accelerated scanner for JSON string delimiters (`aarch64`).
//!
//! This module is compiled only when `cfg(target_feature = "neon")` holds for
//! the whole crate (see the gate in `lib.rs`). NEON is in the default feature
//! set of the mainstream `aarch64` targets, but not of every one (for example
//! `aarch64-unknown-none-softfloat` disables it); such builds fall back to the
//! scalar scanner instead of relying on an ISA assumption.

use core::arch::aarch64::{
    uint8x16_t, vceqq_u8, vcltq_u8, vdupq_n_u8, vget_lane_u64, vld1q_u8, vmaxvq_u8, vorrq_u8, vreinterpret_u64_u8,
    vreinterpretq_u16_u8, vshrn_n_u16,
};

/// Width of one NEON register in bytes.
const LANE: usize = 16;

/// Find the first `"`, `\`, or control-char (< 0x20) in `haystack`.
///
/// Inputs shorter than one lane go straight to the scalar scanner; longer
/// inputs are processed 16 bytes per iteration using NEON intrinsics, with
/// the scalar scanner handling any remainder.
pub(crate) fn find(haystack: &[u8]) -> Option<usize> {
    if haystack.len() < LANE {
        return super::generic::find(haystack);
    }

    #[expect(unsafe_code, reason = "call into a `#[target_feature(enable = \"neon\")]` function")]
    // SAFETY:
    // Operation: calling the safe `#[target_feature(enable = "neon")]` function
    // `find_inner` from a function that does not itself enable `neon`.
    // Contract (Reference, `attributes.codegen.target_feature.safety-restrictions`
    // and `undefined.target_feature`): a safe `#[target_feature]` function may
    // only be called from an unsafe context unless the caller enables the same
    // features, and executing code compiled with a feature the running
    // platform does not support is UB. The caller must therefore ensure NEON is
    // supported by the CPU executing this code.
    // Evidence:
    // - This module exists only under `cfg(target_feature = "neon")` (gate in `lib.rs`), which the Reference
    //   (`cfg.target_feature.def`) defines as "set for each platform feature available for the current compilation
    //   target". Under that configuration the compiler may already emit NEON instructions in every function of this
    //   crate, so a CPU without NEON would make the program UB before this call is reached. This call therefore adds no
    //   runtime requirement beyond the one the build configuration already imposes on the whole program.
    // - `find_inner` is a safe function: it has no further preconditions.
    // Postcondition: none. The callee borrows `haystack` immutably and returns
    // a plain `Option<usize>`.
    unsafe {
        find_inner(haystack)
    }
}

/// Inner NEON loop: 16 bytes per iteration, then the scalar scanner for the
/// remainder.
///
/// Correct for every `haystack` length; when `haystack.len() < LANE` the loop
/// body never runs and the whole slice is handed to the scalar scanner.
#[expect(unsafe_code, reason = "NEON load intrinsic reads through a raw pointer")]
#[target_feature(enable = "neon")]
fn find_inner(haystack: &[u8]) -> Option<usize> {
    let len = haystack.len();
    let ptr = haystack.as_ptr();

    // These intrinsics are safe functions carrying
    // `#[target_feature(enable = "neon")]`; calling them is safe here because
    // this function enables `neon` (Reference,
    // `attributes.codegen.target_feature.safety-restrictions`).
    let v_quote = vdupq_n_u8(b'"');
    let v_backslash = vdupq_n_u8(b'\\');
    let v_ctrl_bound = vdupq_n_u8(0x20);

    let mut offset: usize = 0;

    while offset.saturating_add(LANE) <= len {
        // SAFETY:
        // Operation: `ptr.add(offset)`.
        // Contract from `pointer::add` (std docs): (a) the byte offset
        // `offset * size_of::<u8>()`, computed without wrapping, must fit in an
        // `isize`; (b) if non-zero, `ptr` must be derived from a pointer to some
        // allocation and the entire range between `ptr` and the result must be
        // in bounds of that allocation, without wrapping around the address
        // space.
        // Evidence:
        // - LOCAL FACT: the loop condition `offset.saturating_add(LANE) <= len` just succeeded. `len` is the length of
        //   a `[u8]` slice; a slice reference points to its entire range inside one live allocation (Reference,
        //   `undefined.validity.reference-box`, `undefined.dangling.dynamic-size`) and allocations never exceed
        //   `isize::MAX` bytes (`pointer::add` docs). Hence `len <= isize::MAX < usize::MAX`, the saturating add did
        //   not saturate, and `offset + LANE <= len` holds as a mathematical integer fact.
        // - (a) `offset <= len - LANE < len <= isize::MAX`.
        // - (b) `ptr` is `haystack.as_ptr()`, derived from the live `&[u8]` (TYPE FACT); the slice covers bytes `[0,
        //   len)` of one allocation and `offset < len`, so `[ptr, ptr + offset]` lies inside it. Per the `pointer::add`
        //   docs an in-bounds range cannot wrap.
        // - `offset`, `ptr`, and `len` are locals not modified between the loop check and this block, and this function
        //   runs no caller-provided code.
        // Postcondition: `lane_ptr` points at `haystack[offset]` and bytes
        // `[offset, offset + LANE)` are all inside `haystack`.
        let lane_ptr = unsafe { ptr.add(offset) };

        // SAFETY:
        // Operation: `vld1q_u8(lane_ptr)`, a non-atomic 16-byte read.
        // Contract: `vld1q_u8` takes a `*const u8`, so its alignment requirement is that
        //    of `u8` (1), satisfied by every pointer. Its std doc gives no
        //    contract beyond "Neon intrinsic unsafe".
        //    What remains is the std `ptr` module validity model for a
        //    non-atomic 16-byte read: `lane_ptr` must be non-null and
        //    dereferenceable (the 16-byte range starting at it lies entirely
        //    within one allocation), no other thread may write those bytes
        //    concurrently, and the bytes must be initialized so that the
        //    produced `uint8x16_t` — an integer vector — is a valid value
        //    (Reference, `undefined.validity.int`: integers must not be
        //    obtained from uninitialized memory).
        // Evidence:
        // - POSTCONDITION of the `add` above: the bytes read are `haystack[offset..offset + 16]`, all inside the slice.
        //   A `&[u8]` is non-null, covers one allocation, and every element is a valid, hence initialized, `u8`
        //   (Reference, `undefined.validity.reference-box`, `undefined.validity.int`, `undefined.validity.str`).
        // - No concurrent or intervening mutation: `haystack` is a shared reference to `u8` data containing no
        //   `UnsafeCell`, so for its whole lifetime — which spans this read — that memory is not mutated by anyone
        //   (Reference, `undefined.alias`: "`&T` must point to memory that is not mutated while they are live").
        // Postcondition: `chunk` is a bitwise copy of
        // `haystack[offset..offset + 16]`; the read transfers no ownership and
        // changes no initialization state.
        let chunk: uint8x16_t = unsafe { vld1q_u8(lane_ptr) };

        let combined = classify(chunk, v_quote, v_backslash, v_ctrl_bound);

        // Fast reject: if no lane matched, vmaxvq_u8 returns 0.
        if vmaxvq_u8(combined) != 0 {
            let bit_offset = neon_first_match(combined)?;
            return offset.checked_add(bit_offset);
        }
        offset = offset.checked_add(LANE)?;
    }

    let tail = haystack.get(offset..)?;
    super::generic::find(tail).and_then(|pos| offset.checked_add(pos))
}

/// Classify 16 bytes, returning a mask vector (0xFF in matching lanes).
///
/// Pure register arithmetic: no memory access, no unsafe operation. Safe to
/// call from any function that enables `neon`.
#[target_feature(enable = "neon")]
#[inline]
fn classify(chunk: uint8x16_t, v_quote: uint8x16_t, v_backslash: uint8x16_t, v_ctrl_bound: uint8x16_t) -> uint8x16_t {
    let m_quote = vceqq_u8(chunk, v_quote);
    let m_backslash = vceqq_u8(chunk, v_backslash);
    // `vcltq_u8` is unsigned less-than, directly available on NEON.
    let m_control = vcltq_u8(chunk, v_ctrl_bound);
    vorrq_u8(vorrq_u8(m_quote, m_backslash), m_control)
}

/// Extract the byte offset of the first set lane from a NEON mask vector.
///
/// Uses the same movemask emulation as the `memchr` crate: narrow pairs via
/// `vshrn_n_u16`, extract as a scalar, and count trailing zeros of the sparse
/// bitmask.
///
/// Every lane of `combined` is expected to be `0x00` or `0xFF`; any other
/// lane value yields a meaningless index but cannot cause undefined behaviour,
/// since this is pure register arithmetic with no memory access.
#[target_feature(enable = "neon")]
#[inline]
fn neon_first_match(combined: uint8x16_t) -> Option<usize> {
    let narrowed = vshrn_n_u16(vreinterpretq_u16_u8(combined), 4);
    let scalar = vget_lane_u64(vreinterpret_u64_u8(narrowed), 0);
    // Only bit 3 of each nibble survives (0x8 per nibble position).
    let bits = scalar & 0x8888_8888_8888_8888;
    if bits == 0 {
        return None;
    }
    // Each nibble represents one byte lane; trailing_zeros / 4 = lane index.
    let tz = bits.trailing_zeros();
    let lane = tz.checked_div(4)?;
    usize::try_from(lane).ok()
}
