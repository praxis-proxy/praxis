// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! SIMD-accelerated byte scanner for JSON string delimiters.
//!
//! Provides [`find_json_string_delim`], which finds the first byte in a slice
//! that is a JSON string delimiter: `"` (quote), `\` (backslash), or any
//! control character (< 0x20).
//!
//! On `x86_64` with SSE2 and `aarch64` with NEON enabled at compile time the
//! search is vectorised (the default for both architectures). All other
//! targets use a scalar fallback.

#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86_64;

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod aarch64;

mod generic;

/// Find the first byte in `haystack` that is `"`, `\`, or a control
/// character (< 0x20).
///
/// Returns `Some(offset)` of the first match, or `None` when every byte in
/// `haystack` is a safe JSON string interior character (printable ASCII or
/// high byte ≥ 0x20 that is not `"` or `\`).
///
/// # Examples
///
/// ```
/// use praxis_simd_scan::find_json_string_delim;
///
/// assert_eq!(find_json_string_delim(b"hello"), None);
/// assert_eq!(find_json_string_delim(b"hel\"lo"), Some(3));
/// assert_eq!(find_json_string_delim(b"ab\x01cd"), Some(2));
/// ```
pub fn find_json_string_delim(haystack: &[u8]) -> Option<usize> {
    imp::find(haystack)
}

/// Architecture-specific dispatch. Inlined so the public function
/// resolves to the right backend at compile time.
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod imp {
    /// Delegate to the SSE2 scanner.
    pub(super) fn find(haystack: &[u8]) -> Option<usize> {
        super::x86_64::find(haystack)
    }
}

/// Architecture-specific dispatch.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod imp {
    /// Delegate to the NEON scanner.
    pub(super) fn find(haystack: &[u8]) -> Option<usize> {
        super::aarch64::find(haystack)
    }
}

/// Architecture-specific dispatch.
#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "sse2"),
    all(target_arch = "aarch64", target_feature = "neon")
)))]
mod imp {
    /// Delegate to the scalar fallback.
    pub(super) fn find(haystack: &[u8]) -> Option<usize> {
        super::generic::find(haystack)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    /// Verify the public function and the generic fallback agree.
    fn assert_both(haystack: &[u8], expected: Option<usize>) {
        assert_eq!(
            find_json_string_delim(haystack),
            expected,
            "public fn mismatch for {haystack:?}"
        );
        assert_eq!(
            generic::find(haystack),
            expected,
            "generic fallback mismatch for {haystack:?}"
        );
    }

    #[test]
    fn empty_slice() {
        assert_both(b"", None);
    }

    #[test]
    fn all_safe_ascii() {
        assert_both(b"hello world 0123456789 ABCDEF !@#$%^&*()", None);
    }

    #[test]
    fn quote_at_offset_0() {
        assert_both(b"\"hello", Some(0));
    }

    #[test]
    fn quote_at_offset_1() {
        assert_both(b"a\"ello", Some(1));
    }

    #[test]
    fn quote_at_offset_15() {
        let mut buf = vec![b'a'; 16];
        buf[15] = b'"';
        assert_both(&buf, Some(15));
    }

    #[test]
    fn quote_at_offset_16() {
        let mut buf = vec![b'a'; 17];
        buf[16] = b'"';
        assert_both(&buf, Some(16));
    }

    #[test]
    fn quote_at_offset_17() {
        let mut buf = vec![b'a'; 18];
        buf[17] = b'"';
        assert_both(&buf, Some(17));
    }

    #[test]
    fn quote_at_offset_31() {
        let mut buf = vec![b'a'; 32];
        buf[31] = b'"';
        assert_both(&buf, Some(31));
    }

    #[test]
    fn quote_at_offset_32() {
        let mut buf = vec![b'a'; 33];
        buf[32] = b'"';
        assert_both(&buf, Some(32));
    }

    #[test]
    fn quote_at_offset_33() {
        let mut buf = vec![b'a'; 34];
        buf[33] = b'"';
        assert_both(&buf, Some(33));
    }

    #[test]
    fn backslash_at_various_offsets() {
        for offset in [0_usize, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
            let size = offset.saturating_add(2);
            let mut buf = vec![b'a'; size];
            buf[offset] = b'\\';
            assert_both(&buf, Some(offset));
        }
    }

    #[test]
    fn control_null() {
        assert_both(b"hello\x00world", Some(5));
    }

    #[test]
    fn control_0x01() {
        assert_both(b"hello\x01world", Some(5));
    }

    #[test]
    fn control_0x1f() {
        assert_both(b"hello\x1fworld", Some(5));
    }

    #[test]
    fn control_at_various_offsets() {
        for offset in [0_usize, 1, 15, 16, 17, 31, 32, 33] {
            let size = offset.saturating_add(2);
            let mut buf = vec![b'a'; size];
            buf[offset] = 0x01;
            assert_both(&buf, Some(offset));
        }
    }

    #[test]
    fn long_input_with_trailing_control() {
        let size: usize = 10_000;
        let mut buf = vec![b'a'; size.saturating_add(1)];
        buf[size] = 0x01;
        assert_both(&buf, Some(size));
    }

    #[test]
    fn long_safe_input() {
        let buf = vec![b'a'; 10_000];
        assert_both(&buf, None);
    }

    #[test]
    fn high_bytes_are_safe() {
        let buf: Vec<u8> = (0x20..=0xFF).filter(|&bb| bb != b'"' && bb != b'\\').collect();
        assert_both(&buf, None);
    }

    #[test]
    fn first_match_wins() {
        assert_both(b"ab\x01\"cd", Some(2));
        assert_both(b"ab\"\\cd", Some(2));
    }

    /// Scan sub-slices whose base pointer sits at every offset `0..=17` into
    /// one heap buffer, so the 16-byte SIMD loads run at every misalignment
    /// relative to the vector width. Exercises the unaligned-load contract.
    #[test]
    fn unaligned_base_pointers() {
        let mut buf = [b'a'; 200];
        buf[100] = b'"';
        buf[150] = 0x07;
        for start in 0..=17_usize {
            for end in [start + 15, start + 16, start + 17, start + 33, 120, 199, 200] {
                let hay = &buf[start..end];
                let expected = generic::find(hay);
                assert_eq!(
                    find_json_string_delim(hay),
                    expected,
                    "mismatch for start={start} end={end}"
                );
            }
        }
    }

    /// Place every byte value in a lane covered by the SIMD path and compare
    /// against the scalar definition, pinning the vector classification for
    /// all 256 inputs.
    #[test]
    fn every_byte_value_in_simd_lane() {
        for byte in 0..=u8::MAX {
            let mut buf = [b'x'; 32];
            buf[7] = byte;
            let expected = (byte == b'"' || byte == b'\\' || byte < 0x20).then_some(7);
            assert_both(&buf, expected);
        }
    }
}
