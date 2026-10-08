// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Path segment traversal detection for inbound and upstream paths.
//!
//! Behavior must stay aligned with [`praxis_filter::has_dot_dot_traversal`]
//! in the filter crate's `path_sanitize` module.

/// Return true when any path segment is a `..` traversal segment,
/// including percent-encoded dot variants (`%2e%2e`, `.%2e`, `%2e.`).
pub(in crate::http) fn has_dot_dot_traversal(path: &str) -> bool {
    path.split('/').any(is_traversal_segment)
}

/// Whether a single path segment encodes a `..` traversal.
fn is_traversal_segment(seg: &str) -> bool {
    if seg == ".." {
        return true;
    }
    let mut dots = 0_u16;
    let mut i = 0;
    let b = seg.as_bytes();
    while let Some(&c) = b.get(i) {
        if c == b'%'
            && b.get(i + 1).is_some_and(|d| d.eq_ignore_ascii_case(&b'2'))
            && b.get(i + 2).is_some_and(|e| e.eq_ignore_ascii_case(&b'e'))
        {
            dots += 1;
            i += 3;
        } else if c == b'.' {
            dots += 1;
            i += 1;
        } else {
            return false;
        }
    }
    dots == 2
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::has_dot_dot_traversal;

    #[test]
    fn traversal_detector_matches_encoded_variants() {
        assert!(has_dot_dot_traversal("/a/../b"), "literal '..' is traversal");
        assert!(has_dot_dot_traversal("/a/%2e%2e/b"), "fully encoded is traversal");
        assert!(has_dot_dot_traversal("/a/%2E%2E/b"), "uppercase encoded is traversal");
        assert!(has_dot_dot_traversal("/a/.%2e/b"), "mixed dot+encoded is traversal");
        assert!(has_dot_dot_traversal("/a/%2e./b"), "mixed encoded+dot is traversal");
    }

    #[test]
    fn traversal_detector_allows_non_traversal_dot_segments() {
        assert!(!has_dot_dot_traversal("/a/..config"), "'..config' is not traversal");
        assert!(!has_dot_dot_traversal("/a/."), "single dot is not traversal");
        assert!(
            !has_dot_dot_traversal("/a/%2e%2e%2e"),
            "triple encoded dot is not traversal"
        );
        assert!(
            !has_dot_dot_traversal(&format!("/a/{}", "%2e".repeat(258))),
            "long encoded dot segment is not traversal"
        );
    }
}
