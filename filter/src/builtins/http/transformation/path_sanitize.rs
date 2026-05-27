// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Path sanitization utilities shared by rewrite filters.

use std::borrow::Cow;

// -----------------------------------------------------------------------------
// Path Normalization
// -----------------------------------------------------------------------------

/// Normalize a rewritten path for defense-in-depth against traversal.
///
/// Applies three transformations:
/// 1. Strip `/./` segments (and leading `./`)
/// 2. Strip `/../` segments (and leading `../`)
/// 3. Collapse `//` to `/`
///
/// Ensures the result starts with `/`. Returns [`Cow::Borrowed`] when
/// no normalization was needed.
///
/// ```
/// use praxis_filter::normalize_rewritten_path;
///
/// assert_eq!(normalize_rewritten_path("/a/b/c"), "/a/b/c");
/// assert_eq!(normalize_rewritten_path("/a/../b"), "/b");
/// assert_eq!(normalize_rewritten_path("/a/./b"), "/a/b");
/// assert_eq!(normalize_rewritten_path("/a//b"), "/a/b");
/// assert_eq!(normalize_rewritten_path("no-slash"), "/no-slash");
/// assert_eq!(
///     normalize_rewritten_path("/../../../etc/passwd"),
///     "/etc/passwd"
/// );
/// ```
///
/// [`Cow::Borrowed`]: std::borrow::Cow::Borrowed
pub fn normalize_rewritten_path(path: &str) -> Cow<'_, str> {
    if !needs_normalization(path) {
        return Cow::Borrowed(path);
    }
    Cow::Owned(normalize(path))
}

/// Return true when any path segment is a `..` traversal segment,
/// including percent-encoded dot variants (`%2e%2e`, `.%2e`, `%2e.`).
pub fn has_dot_dot_traversal(path: &str) -> bool {
    path.split('/').any(is_traversal_segment)
}

/// Fast check: does the path contain sequences that need normalization?
fn needs_normalization(path: &str) -> bool {
    !path.starts_with('/')
        || path.contains("//")
        || path.contains("/./")
        || path.contains("/../")
        || path.ends_with("/.")
        || path.ends_with("/..")
}

/// Normalize the path by resolving `.` and `..` segments and
/// collapsing repeated slashes.
fn normalize(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();

    for seg in path.split('/') {
        match seg {
            "" | "." => {},
            ".." => {
                segments.pop();
            },
            s => segments.push(s),
        }
    }

    let mut result = String::with_capacity(path.len());
    if segments.is_empty() {
        result.push('/');
    } else {
        for seg in &segments {
            result.push('/');
            result.push_str(seg);
        }
    }
    result
}

/// Return true when a path segment is exactly two literal or percent-encoded dots.
#[allow(clippy::indexing_slicing, reason = "bounds checked by i + 2 < b.len()")]
fn is_traversal_segment(seg: &str) -> bool {
    if seg == ".." {
        return true;
    }
    let mut dots = 0u16;
    let mut i = 0;
    let b = seg.as_bytes();
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && b[i + 1].eq_ignore_ascii_case(&b'2')
            && b[i + 2].eq_ignore_ascii_case(&b'e')
        {
            dots += 1;
            i += 3;
        } else if b[i] == b'.' {
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
mod tests {
    use std::borrow::Cow;

    use super::*;

    #[test]
    fn clean_path_returns_borrowed() {
        let result = normalize_rewritten_path("/a/b/c");
        assert!(matches!(result, Cow::Borrowed(_)), "clean path should not allocate");
        assert_eq!(&*result, "/a/b/c", "clean path should be unchanged");
    }

    #[test]
    fn dot_dot_segments_resolved() {
        assert_eq!(
            normalize_rewritten_path("/a/../b"),
            "/b",
            "/../ should resolve by removing preceding segment"
        );
    }

    #[test]
    fn dot_segments_resolved() {
        assert_eq!(normalize_rewritten_path("/a/./b"), "/a/b", "/./ should be collapsed");
    }

    #[test]
    fn double_slashes_collapsed() {
        assert_eq!(normalize_rewritten_path("/a//b"), "/a/b", "// should collapse to /");
    }

    #[test]
    fn triple_slashes_collapsed() {
        assert_eq!(normalize_rewritten_path("/a///b"), "/a/b", "/// should collapse to /");
    }

    #[test]
    fn ensures_leading_slash() {
        assert_eq!(
            normalize_rewritten_path("no-slash"),
            "/no-slash",
            "path without leading / should get one"
        );
    }

    #[test]
    fn traversal_to_root() {
        assert_eq!(
            normalize_rewritten_path("/../../../etc/passwd"),
            "/etc/passwd",
            "traversal beyond root should clamp to root"
        );
    }

    #[test]
    fn traversal_past_root_yields_root() {
        assert_eq!(
            normalize_rewritten_path("/a/../../.."),
            "/",
            "traversal past root should yield /"
        );
    }

    #[test]
    fn root_path_unchanged() {
        let result = normalize_rewritten_path("/");
        assert!(matches!(result, Cow::Borrowed(_)), "root path should not allocate");
        assert_eq!(&*result, "/", "root path should stay /");
    }

    #[test]
    fn trailing_dot_dot_resolved() {
        assert_eq!(
            normalize_rewritten_path("/a/b/.."),
            "/a",
            "trailing /.. should remove last segment"
        );
    }

    #[test]
    fn trailing_dot_resolved() {
        assert_eq!(
            normalize_rewritten_path("/a/b/."),
            "/a/b",
            "trailing /. should be dropped"
        );
    }

    #[test]
    fn mixed_traversal_and_double_slashes() {
        assert_eq!(
            normalize_rewritten_path("/a//../b//c/../d"),
            "/b/d",
            "mixed traversal and double slashes should normalize"
        );
    }

    #[test]
    fn empty_path_yields_root() {
        assert_eq!(normalize_rewritten_path(""), "/", "empty path should normalize to /");
    }

    #[test]
    fn only_dot_dot_yields_root() {
        assert_eq!(normalize_rewritten_path("/.."), "/", "single /.. should yield /");
    }

    #[test]
    fn percent_encoded_dot_dot_not_decoded() {
        let result = normalize_rewritten_path("/a/%2e%2e/b");
        assert!(
            matches!(result, Cow::Borrowed(_)),
            "percent-encoded .. should not be decoded"
        );
        assert_eq!(
            &*result, "/a/%2e%2e/b",
            "percent-encoded traversal should pass through verbatim"
        );
    }

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

    #[test]
    fn percent_encoded_slash_not_decoded() {
        let result = normalize_rewritten_path("/a%2fb");
        assert!(
            matches!(result, Cow::Borrowed(_)),
            "percent-encoded slash should not be decoded"
        );
        assert_eq!(&*result, "/a%2fb", "percent-encoded slash should pass through verbatim");
    }

    #[test]
    fn only_slashes_yields_root() {
        assert_eq!(
            normalize_rewritten_path("///"),
            "/",
            "only slashes should normalize to /"
        );
    }

    #[test]
    fn path_with_query_chars_unchanged() {
        let result = normalize_rewritten_path("/path?query=val");
        assert!(
            matches!(result, Cow::Borrowed(_)),
            "path with query chars should not trigger normalization"
        );
        assert_eq!(&*result, "/path?query=val", "query portion should pass through");
    }
}
