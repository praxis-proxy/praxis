// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Scalar (non-SIMD) fallback for [`super::find_json_string_delim`].

/// Scan `haystack` byte-by-byte for the first JSON string delimiter.
///
/// A delimiter is `"` (0x22), `\` (0x5C), or any byte < 0x20.
pub(crate) fn find(haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&bb| bb == b'"' || bb == b'\\' || bb < 0x20)
}
