// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! HTTP authority validation for per-cluster upstream authority override.
//!
//! Delegates the grammar to [`http::uri::Authority`] rather than
//! re-implementing RFC 3986 host parsing, then rejects the authority
//! components that are syntactically valid but meaningless (or
//! dangerous) in a `Host` header: userinfo and out-of-range ports.

use std::str::FromStr as _;

use crate::errors::ProxyError;

/// Maximum DNS hostname length without a trailing root label.
const MAX_HOSTNAME_LEN: usize = 253;

/// Validate a per-cluster authority override value.
///
/// The supported form is `host [ ":" port ]`, where `host` is an
/// ASCII DNS hostname or bracketed IPv6 address. Schemes, paths,
/// userinfo, query strings, and fragments are rejected.
pub(super) fn validate_authority(authority: &str, cluster_name: &str) -> Result<(), ProxyError> {
    if authority.is_empty() {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': authority must not be empty"
        )));
    }

    let parsed = http::uri::Authority::from_str(authority).map_err(|e| {
        ProxyError::Config(format!(
            "cluster '{cluster_name}': authority {authority:?} is not a valid HTTP authority \
             (expected host[:port] or [ipv6][:port]): {e}"
        ))
    })?;

    // `Authority` permits `user:pass@host` per RFC 3986; a Host header
    // must not carry credentials.
    if authority.contains('@') {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': authority must not contain userinfo"
        )));
    }

    // `Authority::from_str` accepts an unparseable port (e.g. `:70000`,
    // `:0x1`) and simply reports no port; detect a port delimiter by the
    // host being shorter than the full authority and require it to have
    // parsed as a real u16.
    if authority.len() > parsed.host().len() && parsed.port_u16().is_none() {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': authority port must be an integer in 0..=65535"
        )));
    }

    if parsed.host().len() > MAX_HOSTNAME_LEN {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': authority hostname exceeds {MAX_HOSTNAME_LEN} characters"
        )));
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests use unwrap/expect/panic for brevity"
)]
mod tests {
    use super::*;

    fn ok(authority: &str) {
        validate_authority(authority, "test").unwrap_or_else(|e| panic!("expected Ok for {authority:?}, got: {e}"));
    }

    fn err(authority: &str) -> String {
        validate_authority(authority, "test").unwrap_err().to_string()
    }

    #[test]
    fn accept_supported_forms() {
        ok("api.example.com");
        ok("api.example.com:8443");
        ok("localhost");
        ok("localhost:3000");
        ok("api");
        ok("[2001:db8::1]");
        ok("[2001:db8::1]:8443");
        ok("192.0.2.7:80");
    }

    #[test]
    fn reject_empty() {
        assert!(err("").contains("must not be empty"));
    }

    #[test]
    fn reject_control_and_whitespace() {
        assert!(!err("api.example.com\u{1}").is_empty());
        assert!(!err("api.example.com\n").is_empty());
        assert!(!err("api example.com").is_empty());
        assert!(!err("api\texample.com").is_empty());
    }

    #[test]
    fn reject_uri_components() {
        assert!(!err("https://api.example.com").is_empty(), "scheme");
        assert!(!err("api.example.com/v1").is_empty(), "path");
        assert!(err("user@api.example.com").contains("userinfo"));
        assert!(!err("api.example.com#frag").is_empty(), "fragment");
        assert!(!err("api.example.com?q=1").is_empty(), "query");
    }

    #[test]
    fn reject_out_of_range_port() {
        assert!(err("api.example.com:70000").contains("port"));
    }

    #[test]
    fn reject_overlong() {
        let long = "a".repeat(254);
        assert!(err(&long).contains("253"));
    }

    #[test]
    fn accept_at_253_chars() {
        let host = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(host.len(), 253, "test host should exercise the boundary");
        ok(&host);
    }
}
