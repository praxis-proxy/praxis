// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Request header normalization per [RFC 9110] and [RFC 9112].
//!
//! Provides a single entry point, `normalize_request_headers`, that
//! runs before the filter pipeline to enforce consistent header semantics:
//!
//! - Rejects requests with conflicting single-value headers (`Content-Length`, `Content-Type`)
//! - Unfolds obsolete line folding (obs-fold) per [RFC 9112 Section 5.2]
//! - Rejects obs-fold on security-sensitive headers (`Host`, `Content-Length`)
//!
//! Case normalization is handled by Pingora's underlying [`HeaderMap`],
//! which uses case-insensitive keys.
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
//! [RFC 9112]: https://datatracker.ietf.org/doc/html/rfc9112
//! [RFC 9112 Section 5.2]: https://datatracker.ietf.org/doc/html/rfc9112#section-5.2
//! [`HeaderMap`]: http::HeaderMap

use pingora_proxy::Session;
use praxis_filter::Rejection;
use tracing::debug;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Headers that MUST NOT appear with conflicting duplicate values.
/// Host is already validated in `validation.rs`; Content-Length and
/// Content-Type are checked here.
const SINGLE_VALUE_HEADERS: &[http::header::HeaderName] = &[http::header::CONTENT_LENGTH, http::header::CONTENT_TYPE];

/// Headers where obs-fold is a security risk and must be rejected.
const OBS_FOLD_REJECT_HEADERS: &[http::header::HeaderName] = &[http::header::HOST, http::header::CONTENT_LENGTH];

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Normalize request headers, rejecting malformed requests.
///
/// Returns `Some(rejection)` if the request is invalid:
/// - Conflicting duplicate `Content-Length` or `Content-Type` values
/// - Obs-fold on `Host` or `Content-Length` headers
///
/// On success, obs-fold sequences in non-sensitive headers are replaced
/// with a single space per [RFC 9112 Section 5.2].
///
/// ```ignore
/// // Requires a live `pingora_proxy::Session`.
/// if let Some(rejection) = normalize_request_headers(session) {
///     send_rejection(session, rejection).await;
///     return Ok(true);
/// }
/// ```
///
/// [RFC 9112 Section 5.2]: https://datatracker.ietf.org/doc/html/rfc9112#section-5.2
pub(in crate::http) fn normalize_request_headers(session: &mut Session) -> Option<Rejection> {
    if let Some(r) = reject_conflicting_single_value_headers(session) {
        return Some(r);
    }
    if let Some(r) = handle_obs_fold(session) {
        return Some(r);
    }
    None
}

// -----------------------------------------------------------------------------
// Duplicate Single-Value Headers
// -----------------------------------------------------------------------------

/// Reject requests where a single-value header appears multiple
/// times with differing values. Identical duplicates are collapsed.
fn reject_conflicting_single_value_headers(session: &mut Session) -> Option<Rejection> {
    for header_name in SINGLE_VALUE_HEADERS {
        let values: Vec<_> = session.req_header().headers.get_all(header_name).iter().collect();

        if values.len() <= 1 {
            continue;
        }

        let Some(first) = values.first() else {
            continue;
        };
        let first_bytes = first.as_bytes();
        if values.iter().skip(1).any(|v| v.as_bytes() != first_bytes) {
            debug!(header = %header_name, "rejecting request with conflicting duplicate header");
            return Some(Rejection::status(400));
        }

        debug!(header = %header_name, "canonicalizing duplicate identical header");
        let canonical = (*first).clone();
        let _remove = session.req_header_mut().remove_header(header_name.as_str());
        let _insert = session.req_header_mut().insert_header(header_name.clone(), canonical);
    }

    None
}

// -----------------------------------------------------------------------------
// Obs-Fold (RFC 9112 Section 5.2)
// -----------------------------------------------------------------------------

/// Returns `true` if the byte sequence contains obs-fold (`\r\n` followed by SP/HTAB).
fn contains_obs_fold(value: &[u8]) -> bool {
    value.windows(3).any(|w| matches!(w, [b'\r', b'\n', b' ' | b'\t']))
}

/// Replace obs-fold sequences with a single SP.
///
/// Each `\r\n[ \t]+` sequence becomes one space character.
fn unfold_obs_fold(value: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        let is_obs_fold = value.get(i) == Some(&b'\r')
            && value.get(i + 1) == Some(&b'\n')
            && matches!(value.get(i + 2), Some(b' ' | b'\t'));

        if is_obs_fold {
            result.push(b' ');
            i += 3;
            while matches!(value.get(i), Some(b' ' | b'\t')) {
                i += 1;
            }
        } else {
            if let Some(&b) = value.get(i) {
                result.push(b);
            }
            i += 1;
        }
    }
    result
}

/// Handle obs-fold in all request headers.
///
/// Rejects the request if obs-fold is found in security-sensitive
/// headers. For other headers, replaces obs-fold with a single SP.
fn handle_obs_fold(session: &mut Session) -> Option<Rejection> {
    for name in OBS_FOLD_REJECT_HEADERS {
        if let Some(value) = session.req_header().headers.get(name)
            && contains_obs_fold(value.as_bytes())
        {
            debug!(header = %name, "rejecting request with obs-fold in security-sensitive header");
            return Some(Rejection::status(400));
        }
    }

    let headers_snapshot: Vec<(http::header::HeaderName, http::header::HeaderValue)> = session
        .req_header()
        .headers
        .iter()
        .filter(|(name, value)| !OBS_FOLD_REJECT_HEADERS.contains(name) && contains_obs_fold(value.as_bytes()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();

    for (name, value) in headers_snapshot {
        let unfolded = unfold_obs_fold(value.as_bytes());
        if let Ok(new_value) = http::header::HeaderValue::from_bytes(&unfolded) {
            debug!(header = %name, "replacing obs-fold with single SP");
            let _insert = session.req_header_mut().insert_header(name, new_value);
        }
    }

    None
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn contains_obs_fold_detects_crlf_sp() {
        assert!(
            contains_obs_fold(b"value\r\n continuation"),
            "CRLF followed by SP is obs-fold"
        );
    }

    #[test]
    fn contains_obs_fold_detects_crlf_htab() {
        assert!(
            contains_obs_fold(b"value\r\n\tcontinuation"),
            "CRLF followed by HTAB is obs-fold"
        );
    }

    #[test]
    fn contains_obs_fold_ignores_bare_crlf() {
        assert!(
            !contains_obs_fold(b"value\r\nno-fold"),
            "CRLF without following whitespace is not obs-fold"
        );
    }

    #[test]
    fn contains_obs_fold_false_for_normal_value() {
        assert!(
            !contains_obs_fold(b"plain header value"),
            "normal value has no obs-fold"
        );
    }

    #[test]
    fn contains_obs_fold_false_for_empty() {
        assert!(!contains_obs_fold(b""), "empty value has no obs-fold");
    }

    #[test]
    fn contains_obs_fold_false_for_trailing_crlf() {
        assert!(
            !contains_obs_fold(b"value\r\n"),
            "trailing CRLF without whitespace is not obs-fold"
        );
    }

    #[test]
    fn unfold_replaces_crlf_sp_with_single_sp() {
        let input = b"value\r\n continuation";
        let result = unfold_obs_fold(input);
        assert_eq!(result, b"value continuation", "obs-fold should become single SP");
    }

    #[test]
    fn unfold_replaces_crlf_htab_with_single_sp() {
        let input = b"value\r\n\tcontinuation";
        let result = unfold_obs_fold(input);
        assert_eq!(result, b"value continuation", "CRLF+HTAB should become single SP");
    }

    #[test]
    fn unfold_collapses_multiple_whitespace_after_fold() {
        let input = b"value\r\n   continuation";
        let result = unfold_obs_fold(input);
        assert_eq!(
            result, b"value continuation",
            "obs-fold with extra whitespace should collapse to single SP"
        );
    }

    #[test]
    fn unfold_handles_multiple_folds() {
        let input = b"a\r\n b\r\n c";
        let result = unfold_obs_fold(input);
        assert_eq!(result, b"a b c", "multiple obs-folds should each become single SP");
    }

    #[test]
    fn unfold_preserves_normal_value() {
        let input = b"plain value";
        let result = unfold_obs_fold(input);
        assert_eq!(result, b"plain value", "value without obs-fold should be unchanged");
    }

    #[test]
    fn unfold_preserves_empty() {
        let result = unfold_obs_fold(b"");
        assert!(result.is_empty(), "empty input should produce empty output");
    }

    #[test]
    fn contains_obs_fold_single_crlf_sp() {
        assert!(
            contains_obs_fold(b"\r\n value"),
            "CRLF+SP at the very start of the value is obs-fold"
        );
    }

    #[test]
    fn contains_obs_fold_multiple_folds() {
        assert!(
            contains_obs_fold(b"a\r\n b\r\n c"),
            "value with multiple obs-fold sequences should be detected"
        );
    }

    #[test]
    fn contains_obs_fold_only_cr_no_lf() {
        assert!(
            !contains_obs_fold(b"value\r continuation"),
            "bare CR followed by space is not obs-fold"
        );
    }

    #[test]
    fn contains_obs_fold_only_lf_sp() {
        assert!(
            !contains_obs_fold(b"value\n continuation"),
            "bare LF followed by space is not obs-fold"
        );
    }

    #[test]
    fn unfold_at_start_of_value() {
        let result = unfold_obs_fold(b"\r\n continuation");
        assert_eq!(
            result, b" continuation",
            "obs-fold at the very start should become single SP"
        );
    }

    #[test]
    fn unfold_consecutive_folds() {
        let result = unfold_obs_fold(b"a\r\n \r\n b");
        assert_eq!(
            result, b"a  b",
            "two back-to-back obs-folds should each become single SP"
        );
    }

    #[test]
    fn unfold_mixed_whitespace_after_fold() {
        let result = unfold_obs_fold(b"val\r\n\t  rest");
        assert_eq!(
            result, b"val rest",
            "CRLF followed by tab then spaces should collapse to single SP"
        );
    }

    #[test]
    fn unfold_preserves_internal_crlf_without_continuation() {
        let result = unfold_obs_fold(b"before\r\nafter");
        assert_eq!(
            result, b"before\r\nafter",
            "bare CRLF without following whitespace should be kept as-is"
        );
    }

    #[test]
    fn unfold_single_byte_values() {
        assert_eq!(unfold_obs_fold(b"x"), b"x", "single byte input unchanged");
        assert_eq!(unfold_obs_fold(b"ab"), b"ab", "two byte input unchanged");
    }
}
