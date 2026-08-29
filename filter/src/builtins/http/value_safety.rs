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
pub fn is_safe_promoted_value(s: &str) -> bool {
    // Byte-scan equivalent of `HeaderValue::from_str(s).is_ok()` without
    // allocating a value just to learn Ok/Err: the http crate accepts
    // HTAB, SP, visible ASCII, and obs-text (0x80-0xFF), rejecting other
    // control bytes and DEL. Parity is pinned by a test over every byte.
    s.bytes().all(|b| b == b'\t' || (b >= 0x20 && b != 0x7F))
}

/// Returns `true` if `s` is unsafe to promote to headers or metadata.
pub fn contains_control_chars(s: &str) -> bool {
    !is_safe_promoted_value(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_scan_matches_header_value_parse_for_every_byte() {
        for byte in 0_u8..=255 {
            let Ok(s) = std::str::from_utf8(std::slice::from_ref(&byte)) else {
                continue;
            };
            assert_eq!(
                is_safe_promoted_value(s),
                http::HeaderValue::from_str(s).is_ok(),
                "byte 0x{byte:02x} must classify exactly like HeaderValue::from_str"
            );
        }
        for s in ["caf\u{e9}", "\u{1F600}", "mixed caf\u{e9}\ttab", "nul\u{0}"] {
            assert_eq!(
                is_safe_promoted_value(s),
                http::HeaderValue::from_str(s).is_ok(),
                "multi-byte sample {s:?} must classify exactly like HeaderValue::from_str"
            );
        }
    }

    #[test]
    fn promoted_value_allows_visible_ascii() {
        assert!(
            is_safe_promoted_value("model-gamma-2"),
            "visible ASCII should be safe for promotion"
        );
    }

    #[test]
    fn promoted_value_rejects_newline() {
        assert!(!is_safe_promoted_value("bad\nvalue"), "newline should be rejected");
    }

    #[test]
    fn promoted_value_allows_tab() {
        assert!(is_safe_promoted_value("bad\tvalue"), "tab should be allowed");
    }

    #[test]
    fn rejects_null_byte() {
        assert!(!is_safe_promoted_value("bad\0value"), "null byte should be rejected");
    }

    #[test]
    fn rejects_carriage_return() {
        assert!(
            !is_safe_promoted_value("bad\rvalue"),
            "carriage return should be rejected"
        );
    }

    #[test]
    fn rejects_del_character() {
        assert!(
            !is_safe_promoted_value("bad\x7Fvalue"),
            "DEL character should be rejected"
        );
    }

    #[test]
    fn accepts_empty_string() {
        assert!(
            is_safe_promoted_value(""),
            "empty string should be accepted (no control chars)"
        );
    }
}
