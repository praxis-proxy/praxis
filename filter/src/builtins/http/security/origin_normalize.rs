// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Shared origin normalization per [RFC 6454].
//!
//! Used by both the CORS and CSRF filters so that origin
//! matching is consistent across all security filters.
//!
//! [RFC 6454]: https://datatracker.ietf.org/doc/html/rfc6454

// -----------------------------------------------------------------------------
// Origin Normalization
// -----------------------------------------------------------------------------

/// Normalize an origin for comparison per [RFC 6454].
///
/// Lowercases scheme and host ([RFC 6454 Section 6.1]),
/// maps `WebSocket` schemes to their HTTP equivalents
/// (`ws://` to `http://`, `wss://` to `https://`), and
/// strips the default port for the scheme so that
/// `https://example.com:443` and `https://example.com`
/// compare equal ([RFC 6454 Section 4]).
///
/// [RFC 6454]: https://datatracker.ietf.org/doc/html/rfc6454
/// [RFC 6454 Section 4]: https://datatracker.ietf.org/doc/html/rfc6454#section-4
/// [RFC 6454 Section 6.1]: https://datatracker.ietf.org/doc/html/rfc6454#section-6.1
pub(crate) fn normalize_origin(origin: &str) -> std::borrow::Cow<'_, str> {
    // The common browser Origin (`https://app.example.com`) is already
    // normalized: lowercase, non-ws scheme, no default port. Detect that
    // in one scan and borrow — the owned path below runs only for
    // uppercase, ws/wss, or default-port inputs.
    let needs_rewrite = origin.bytes().any(|b| b.is_ascii_uppercase())
        || origin.starts_with("ws://")
        || origin.starts_with("wss://")
        || (origin.starts_with("https://") && origin.ends_with(":443"))
        || (origin.starts_with("http://") && origin.ends_with(":80"));
    if !needs_rewrite {
        return std::borrow::Cow::Borrowed(origin);
    }

    let lowered = origin.to_ascii_lowercase();
    let mut normalized = if let Some(rest) = lowered.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = lowered.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        lowered
    };
    // Strip default ports by truncating in place instead of rebuilding.
    if (normalized.starts_with("https://") && normalized.ends_with(":443"))
        || (normalized.starts_with("http://") && normalized.ends_with(":80"))
    {
        let port_len = if normalized.ends_with(":443") { 4 } else { 3 };
        normalized.truncate(normalized.len() - port_len);
    }
    std::borrow::Cow::Owned(normalized)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn lowercase_scheme_and_host() {
        assert_eq!(
            normalize_origin("HTTPS://EXAMPLE.COM"),
            "https://example.com",
            "should lowercase scheme and host"
        );
    }

    #[test]
    fn strip_default_https_port() {
        assert_eq!(
            normalize_origin("https://example.com:443"),
            "https://example.com",
            "should strip :443 from https"
        );
    }

    #[test]
    fn strip_default_http_port() {
        assert_eq!(
            normalize_origin("http://example.com:80"),
            "http://example.com",
            "should strip :80 from http"
        );
    }

    #[test]
    fn preserve_non_default_port() {
        assert_eq!(
            normalize_origin("https://example.com:8080"),
            "https://example.com:8080",
            "should preserve non-default ports"
        );
    }

    #[test]
    fn map_wss_to_https() {
        assert_eq!(
            normalize_origin("wss://example.com"),
            "https://example.com",
            "should map wss to https"
        );
    }

    #[test]
    fn map_ws_to_http() {
        assert_eq!(
            normalize_origin("ws://example.com"),
            "http://example.com",
            "should map ws to http"
        );
    }

    #[test]
    fn combined_normalization() {
        assert_eq!(
            normalize_origin("WSS://EXAMPLE.COM:443"),
            "https://example.com",
            "should lowercase, map wss, and strip :443"
        );
    }

    #[test]
    fn noop_for_already_normalized() {
        assert_eq!(
            normalize_origin("https://example.com"),
            "https://example.com",
            "already normalized should be unchanged"
        );
    }

    #[test]
    fn http_port_443_preserved() {
        assert_eq!(
            normalize_origin("http://example.com:443"),
            "http://example.com:443",
            ":443 is not default for http, must be preserved"
        );
    }

    #[test]
    fn https_port_80_preserved() {
        assert_eq!(
            normalize_origin("https://example.com:80"),
            "https://example.com:80",
            ":80 is not default for https, must be preserved"
        );
    }

    #[test]
    fn ipv6_bracket_host_preserved() {
        assert_eq!(
            normalize_origin("HTTPS://[::1]:8080"),
            "https://[::1]:8080",
            "IPv6 brackets and non-default port must be preserved"
        );
    }

    #[test]
    fn ipv6_bracket_with_default_port_stripped() {
        assert_eq!(
            normalize_origin("https://[::1]:443"),
            "https://[::1]",
            ":443 is default for https and should be stripped from IPv6"
        );
    }

    #[test]
    fn scheme_only_lowered() {
        assert_eq!(
            normalize_origin("FTP://EXAMPLE.COM"),
            "ftp://example.com",
            "unknown scheme should be lowered with no port stripping"
        );
    }

    #[test]
    fn ws_with_non_default_port() {
        assert_eq!(
            normalize_origin("ws://example.com:9090"),
            "http://example.com:9090",
            "ws maps to http but non-default port must be preserved"
        );
    }

    #[test]
    fn wss_with_port_80() {
        assert_eq!(
            normalize_origin("wss://example.com:80"),
            "https://example.com:80",
            "wss maps to https; :80 is not default for https"
        );
    }

    #[test]
    fn empty_origin() {
        assert_eq!(normalize_origin(""), "", "empty input should stay empty");
    }

    #[test]
    fn origin_with_path() {
        assert_eq!(
            normalize_origin("https://example.com:443/path"),
            "https://example.com:443/path",
            ":443 is not a suffix when path follows, so port is preserved"
        );
    }

    #[test]
    fn no_scheme_just_lowercased() {
        assert_eq!(
            normalize_origin("EXAMPLE.COM"),
            "example.com",
            "input without scheme should be lowercased without crash"
        );
    }
}
