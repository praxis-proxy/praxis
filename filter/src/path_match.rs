// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Segment-boundary path prefix matching per Gateway API semantics.
//!
//! A prefix `/api` matches `/api`, `/api/`, and `/api/v1` but NOT `/apikeys`.
//! A trailing slash on the configured prefix is ignored (`/api` ≡ `/api/`).

/// Returns `true` if `path` matches `prefix` at a segment boundary.
///
/// An empty or root-only prefix matches everything. Otherwise the prefix is
/// trimmed of a trailing `/` and the path must either equal the trimmed prefix
/// or continue with a `/` separator.
pub(crate) fn path_prefix_matches(path: &str, prefix: &str) -> bool {
    let trimmed = prefix.strip_suffix('/').unwrap_or(prefix);
    if trimmed.is_empty() {
        return true;
    }
    if path == trimmed {
        return true;
    }
    path.starts_with(trimmed) && path.as_bytes().get(trimmed.len()) == Some(&b'/')
}

/// Returns the specificity (effective length) of a path prefix.
///
/// Trailing `/` is stripped so `/api/` and `/api` have equal specificity.
/// An empty prefix gets specificity 1 (root `/`).
pub(crate) fn path_prefix_specificity(prefix: &str) -> usize {
    let trimmed = prefix.strip_suffix('/').unwrap_or(prefix);
    if trimmed.is_empty() { 1 } else { trimmed.len() }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn root_matches_everything() {
        assert!(path_prefix_matches("/anything", "/"));
        assert!(path_prefix_matches("/", "/"));
    }

    #[test]
    fn empty_prefix_matches_everything() {
        assert!(path_prefix_matches("/foo", ""));
        assert!(path_prefix_matches("/", ""));
    }

    #[test]
    fn exact_match() {
        assert!(path_prefix_matches("/api", "/api"));
    }

    #[test]
    fn with_trailing_slash_on_path() {
        assert!(path_prefix_matches("/api/", "/api"));
    }

    #[test]
    fn subpath_match() {
        assert!(path_prefix_matches("/api/v1", "/api"));
    }

    #[test]
    fn no_segment_boundary_rejected() {
        assert!(!path_prefix_matches("/apikeys", "/api"));
    }

    #[test]
    fn prefix_with_trailing_slash_equivalent() {
        assert!(path_prefix_matches("/api/v1", "/api/"));
        assert!(path_prefix_matches("/api", "/api/"));
    }

    #[test]
    fn specificity_trims_trailing_slash() {
        assert_eq!(path_prefix_specificity("/api"), path_prefix_specificity("/api/"));
    }

    #[test]
    fn specificity_root() {
        assert_eq!(path_prefix_specificity("/"), 1);
        assert_eq!(path_prefix_specificity(""), 1);
    }

    #[test]
    fn specificity_value() {
        assert_eq!(path_prefix_specificity("/api"), 4);
        assert_eq!(path_prefix_specificity("/api/v1"), 7);
    }

    /// `"//"` strips to `"/"` which is non-empty, so it enters the
    /// `starts_with` + segment-boundary check instead of the early
    /// "empty means match everything" return. This means `"//"` only
    /// matches paths whose second byte is `/`.
    #[test]
    fn double_slash_prefix() {
        assert!(
            !path_prefix_matches("/foo", "//"),
            "/foo must not match // prefix"
        );
        assert!(
            path_prefix_matches("//bar", "//"),
            "//bar should match // prefix"
        );
    }
}
