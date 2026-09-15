// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! SSE2-accelerated scanner for JSON string delimiters (`x86_64`).
//!
//! This module is compiled only when `cfg(target_feature = "sse2")` holds for
//! the whole crate (see the gate in `lib.rs`). SSE2 is in the default feature
//! set of every `x86_64` target, so the gate is normally satisfied; a build
//! that disables SSE2 falls back to the scalar scanner instead of relying on
//! an ISA assumption.

use core::arch::x86_64::{
    __m128i, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8, _mm_or_si128, _mm_set1_epi8, _mm_setzero_si128,
    _mm_subs_epu8,
};

/// Width of one SSE2 register in bytes.
const LANE: usize = 16;

/// Find the first `"`, `\`, or control-char (< 0x20) in `haystack`.
///
/// Inputs shorter than one lane go straight to the scalar scanner; longer
/// inputs are processed 16 bytes per iteration using SSE2 intrinsics, with
/// the scalar scanner handling any remainder.
pub(crate) fn find(haystack: &[u8]) -> Option<usize> {
    if haystack.len() < LANE {
        return crate::generic::find(haystack);
    }

    #[expect(unsafe_code, reason = "call into a `#[target_feature(enable = \"sse2\")]` function")]
    // SAFETY:
    // Operation: calling the safe `#[target_feature(enable = "sse2")]` function
    // `find_inner` from a function that does not itself enable `sse2`.
    // Contract (Reference, `attributes.codegen.target_feature.safety-restrictions`
    // and `undefined.target_feature`): a safe `#[target_feature]` function may
    // only be called from an unsafe context unless the caller enables the same
    // features, and executing code compiled with a feature the running
    // platform does not support is UB. The caller must therefore ensure SSE2 is
    // supported by the CPU executing this code.
    // Evidence:
    // - This module exists only under `cfg(target_feature = "sse2")` (gate in `lib.rs`), which the Reference
    //   (`cfg.target_feature.def`) defines as "set for each platform feature available for the current compilation
    //   target". Under that configuration the compiler may already emit SSE2 instructions in every function of this
    //   crate, so a CPU without SSE2 would make the program UB before this call is reached. This call therefore adds no
    //   runtime requirement beyond the one the build configuration already imposes on the whole program.
    // - `find_inner` is a safe function: it has no further preconditions.
    // Postcondition: none. The callee borrows `haystack` immutably and returns
    // a plain `Option<usize>`.
    unsafe {
        find_inner(haystack)
    }
}

/// Inner SIMD loop: 16 bytes per iteration, then the scalar scanner for the
/// remainder.
///
/// Correct for every `haystack` length; when `haystack.len() < LANE` the loop
/// body never runs and the whole slice is handed to the scalar scanner.
#[expect(unsafe_code, reason = "SSE2 load intrinsic reads through a raw pointer")]
#[target_feature(enable = "sse2")]
fn find_inner(haystack: &[u8]) -> Option<usize> {
    let len = haystack.len();
    let ptr = haystack.as_ptr();

    // These intrinsics are safe functions carrying
    // `#[target_feature(enable = "sse2")]`; calling them is safe here because
    // this function enables `sse2` (Reference,
    // `attributes.codegen.target_feature.safety-restrictions`).
    let v_quote = _mm_set1_epi8(b'"'.cast_signed());
    let v_backslash = _mm_set1_epi8(b'\\'.cast_signed());
    let v_ctrl_max = _mm_set1_epi8(0x1F);
    let v_zero = _mm_setzero_si128();

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
        // Operation: `_mm_loadu_si128(lane_ptr)`, a non-atomic 16-byte read.
        // Contract: `_mm_loadu_si128` documents that "`mem_addr` does not need to be
        //    aligned on any particular boundary", so the `*const u8` to
        //    `*const __m128i` cast imposes no alignment obligation.
        //    What remains is the std `ptr` module validity model for a
        //    non-atomic 16-byte read: `lane_ptr` must be non-null and
        //    dereferenceable (the 16-byte range starting at it lies entirely
        //    within one allocation), no other thread may write those bytes
        //    concurrently, and the bytes must be initialized so that the
        //    produced `__m128i` — an integer vector — is a valid value
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
        let chunk: __m128i = unsafe { _mm_loadu_si128(lane_ptr.cast::<__m128i>()) };

        let mask = classify(chunk, v_quote, v_backslash, v_ctrl_max, v_zero);

        if mask != 0 {
            let bit_offset = mask.trailing_zeros();
            return offset.checked_add(usize::try_from(bit_offset).ok()?);
        }
        offset = offset.checked_add(LANE)?;
    }

    let tail = haystack.get(offset..)?;
    crate::generic::find(tail).and_then(|pos| offset.checked_add(pos))
}

/// Classify 16 bytes, returning a bitmask where bit *i* is set when lane *i*
/// contains `"`, `\`, or a byte < 0x20.
///
/// Pure register arithmetic: no memory access, no unsafe operation. Safe to
/// call from any function that enables `sse2`.
#[target_feature(enable = "sse2")]
#[inline]
fn classify(chunk: __m128i, v_quote: __m128i, v_backslash: __m128i, v_ctrl_max: __m128i, v_zero: __m128i) -> i32 {
    let m_quote = _mm_cmpeq_epi8(chunk, v_quote);
    let m_backslash = _mm_cmpeq_epi8(chunk, v_backslash);
    // `subs_epu8(byte, 0x1F)` saturates to 0 when byte <= 0x1F.
    // Comparing that result against zero produces 0xFF for control chars.
    let m_control = _mm_cmpeq_epi8(_mm_subs_epu8(chunk, v_ctrl_max), v_zero);
    let combined = _mm_or_si128(_mm_or_si128(m_quote, m_backslash), m_control);
    _mm_movemask_epi8(combined)
}
