// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! SNI server-name validation per [RFC 6125].
//!
//! Validates that a server name (with an optional leading wildcard
//! label) is a well-formed DNS hostname.  Pure DNS label rules live
//! in [`crate::dns`]; this module adds SNI-specific checks: empty
//! name, IP literal rejection, and wildcard position.
//!
//! [RFC 6125]: https://datatracker.ietf.org/doc/html/rfc6125

use crate::dns::DnsLabelError;

// -----------------------------------------------------------------------------
// SniNameError
// -----------------------------------------------------------------------------

/// Why an SNI server name failed validation.
///
/// Covers both plain hostnames and wildcard patterns (`*.example.com`).
/// DNS label errors are wrapped in the [`InvalidLabel`](Self::InvalidLabel) variant;
/// SNI-specific rules (empty, too long, IP literal, wildcard position)
/// have their own variants.
///
/// ```
/// use praxis_tls::sni_name::{SniNameError, validate};
///
/// assert_eq!(validate(""), Err(SniNameError::Empty));
/// assert_eq!(validate("example.com"), Ok(()));
/// assert_eq!(validate("*.example.com"), Ok(()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SniNameError {
    /// The name is empty.
    #[error("must not be empty")]
    Empty,

    /// The name exceeds 253 characters.
    #[error("exceeds 253 characters")]
    TooLong,

    /// The name is an IP address, not a hostname.
    #[error("must be a hostname, not an IP address")]
    IsIpAddress,

    /// A bare `*` with no domain suffix (e.g. `*` instead of
    /// `*.example.com`).
    #[error("wildcard requires a domain suffix")]
    BareWildcard,

    /// A wildcard (`*`) appears somewhere other than as the complete
    /// leftmost label.
    #[error("wildcard is only permitted as the complete leftmost label")]
    InvalidWildcard,

    /// A DNS label within the name is invalid.
    #[error(transparent)]
    InvalidLabel(#[from] DnsLabelError),
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Validate an SNI server name that may include a leading wildcard.
///
/// Accepts plain DNS hostnames (`api.example.com`) and wildcard
/// patterns (`*.example.com`) per [RFC 6125].
///
/// Checks performed (in order):
/// 1. Not empty
/// 2. Total name does not exceed 253 characters
/// 3. Strip leading `*.` (if present)
/// 4. Remainder is not an IP literal ([RFC 6066 §3])
/// 5. Remainder contains no further `*` characters
/// 6. Each label in the remainder passes [`dns::validate_dns_label`](crate::dns::validate_dns_label)
///
/// # Errors
///
/// Returns [`SniNameError`] when the name is empty, exceeds 253
/// characters, is an IP literal, has a misplaced wildcard, or
/// contains invalid DNS labels.
///
/// [RFC 6125]: https://datatracker.ietf.org/doc/html/rfc6125
/// [RFC 6066 §3]: https://datatracker.ietf.org/doc/html/rfc6066#section-3
pub fn validate(name: &str) -> Result<(), SniNameError> {
    if name.is_empty() {
        return Err(SniNameError::Empty);
    }

    if name.len() > 253 {
        return Err(SniNameError::TooLong);
    }

    if name == "*" {
        return Err(SniNameError::BareWildcard);
    }

    let hostname = name.strip_prefix("*.").unwrap_or(name);

    if hostname.parse::<std::net::IpAddr>().is_ok() {
        return Err(SniNameError::IsIpAddress);
    }

    if hostname.contains('*') {
        return Err(SniNameError::InvalidWildcard);
    }

    for label in hostname.split('.') {
        crate::dns::validate_dns_label(label)?;
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn accept_plain_hostname() {
        assert_eq!(validate("example.com"), Ok(()));
    }

    #[test]
    fn accept_wildcard_hostname() {
        assert_eq!(validate("*.example.com"), Ok(()));
    }

    #[test]
    fn accept_deep_wildcard() {
        assert_eq!(validate("*.sub.example.com"), Ok(()));
    }

    #[test]
    fn accept_single_label() {
        assert_eq!(validate("localhost"), Ok(()));
    }

    #[test]
    fn reject_empty() {
        assert_eq!(validate(""), Err(SniNameError::Empty));
    }

    #[test]
    fn reject_ipv4() {
        assert_eq!(validate("192.168.1.1"), Err(SniNameError::IsIpAddress));
    }

    #[test]
    fn reject_ipv6() {
        assert_eq!(validate("::1"), Err(SniNameError::IsIpAddress));
    }

    #[test]
    fn reject_bare_wildcard() {
        assert_eq!(validate("*"), Err(SniNameError::BareWildcard));
    }

    #[test]
    fn reject_mid_label_wildcard() {
        assert_eq!(validate("a*.example.com"), Err(SniNameError::InvalidWildcard));
    }

    #[test]
    fn reject_non_leftmost_wildcard() {
        assert_eq!(validate("foo.*.com"), Err(SniNameError::InvalidWildcard));
    }

    #[test]
    fn reject_double_wildcard() {
        assert_eq!(validate("*.*.com"), Err(SniNameError::InvalidWildcard));
    }

    #[test]
    fn reject_wildcard_ip() {
        assert_eq!(validate("*.192.168.1.1"), Err(SniNameError::IsIpAddress));
    }

    #[test]
    fn reject_leading_hyphen() {
        assert_eq!(
            validate("-example.com"),
            Err(SniNameError::InvalidLabel(DnsLabelError::HyphenBoundary))
        );
    }

    #[test]
    fn reject_invalid_characters() {
        assert_eq!(
            validate("has_underscore.com"),
            Err(SniNameError::InvalidLabel(DnsLabelError::InvalidCharacter))
        );
    }

    #[test]
    fn reject_overlong_label() {
        let name = format!("{}.example.com", "a".repeat(64));
        assert_eq!(
            validate(&name),
            Err(SniNameError::InvalidLabel(DnsLabelError::LabelTooLong))
        );
    }

    #[test]
    fn reject_overlong_hostname() {
        let name = format!("{}.example.com", "a".repeat(250));
        assert_eq!(validate(&name), Err(SniNameError::TooLong));
    }

    #[test]
    fn reject_overlong_wildcard_hostname() {
        // 2 (`*.`) + 252 = 254 > 253; the suffix alone would pass
        let name = format!("*.{}.example.com", "a".repeat(240));
        assert!(name.len() > 253);
        assert_eq!(validate(&name), Err(SniNameError::TooLong));
    }

    #[test]
    fn display_messages() {
        assert_eq!(SniNameError::Empty.to_string(), "must not be empty");
        assert_eq!(
            SniNameError::IsIpAddress.to_string(),
            "must be a hostname, not an IP address"
        );
        assert_eq!(
            SniNameError::BareWildcard.to_string(),
            "wildcard requires a domain suffix"
        );
        assert_eq!(
            SniNameError::InvalidWildcard.to_string(),
            "wildcard is only permitted as the complete leftmost label"
        );
        assert_eq!(SniNameError::TooLong.to_string(), "exceeds 253 characters");
        assert_eq!(
            SniNameError::InvalidLabel(DnsLabelError::EmptyLabel).to_string(),
            DnsLabelError::EmptyLabel.to_string()
        );
    }
}
