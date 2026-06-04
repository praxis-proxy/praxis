// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared value-safety helpers for HTTP body-derived data promotion.

// -----------------------------------------------------------------------------
// Header Value Safety
// -----------------------------------------------------------------------------

/// Returns `true` if `s` is safe to promote to an HTTP header value.
///
/// Body-derived values that are promoted to metadata or filter results use
/// the same rule as headers so every promotion sink has one safety policy.
pub(crate) fn is_safe_promoted_value(s: &str) -> bool {
    http::HeaderValue::from_str(s).is_ok()
}

/// Returns `true` if `s` is unsafe to promote to headers or metadata.
pub(crate) fn contains_control_chars(s: &str) -> bool {
    !is_safe_promoted_value(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promoted_value_allows_visible_ascii() {
        assert!(is_safe_promoted_value("gpt-4.1-mini"));
    }

    #[test]
    fn promoted_value_rejects_newline() {
        assert!(!is_safe_promoted_value("bad\nvalue"));
    }

    #[test]
    fn promoted_value_allows_tab() {
        assert!(is_safe_promoted_value("bad\tvalue"));
    }
}
