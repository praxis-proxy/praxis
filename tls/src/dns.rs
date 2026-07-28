// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! DNS label validation per [RFC 1035 §2.3.1].
//!
//! Provides shared primitives so that TLS SNI validation, config
//! validation, and filter-level hostname checks all use the same
//! rules rather than reimplementing them independently.
//!
//! [RFC 1035 §2.3.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.1

/// Maximum length of a single DNS label (octets).
const MAX_LABEL_LEN: usize = 63;

/// Maximum total length of a DNS hostname (octets), excluding a
/// trailing dot.
const MAX_HOSTNAME_LEN: usize = 253;

/// Why a DNS label or hostname failed validation.
///
/// ```
/// use praxis_tls::dns::{DnsLabelError, validate_dns_label};
///
/// assert_eq!(validate_dns_label(""), Err(DnsLabelError::EmptyLabel));
/// assert_eq!(validate_dns_label("ok"), Ok(()));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DnsLabelError {
    /// The label is empty (zero bytes).
    #[error("label is empty")]
    EmptyLabel,

    /// The label exceeds 63 bytes.
    #[error("label exceeds 63 characters")]
    LabelTooLong,

    /// The label contains a character other than ASCII alphanumeric
    /// or hyphen (`-`).
    #[error("contains invalid characters")]
    InvalidCharacter,

    /// The label starts or ends with a hyphen.
    #[error("label must not start or end with a hyphen")]
    HyphenBoundary,

    /// The total hostname exceeds 253 bytes.
    #[error("exceeds 253 characters")]
    HostnameTooLong,
}

/// Validate a single DNS label per [RFC 1035 §2.3.1].
///
/// A valid label is 1–63 bytes long, contains only ASCII
/// alphanumeric characters or hyphens, and does not start or end
/// with a hyphen.
///
/// # Errors
///
/// Returns [`DnsLabelError`] when the label is empty, too long,
/// contains invalid characters, or has boundary hyphens.
///
/// [RFC 1035 §2.3.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.1
pub fn validate_dns_label(label: &str) -> Result<(), DnsLabelError> {
    if label.is_empty() {
        return Err(DnsLabelError::EmptyLabel);
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(DnsLabelError::LabelTooLong);
    }
    if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(DnsLabelError::InvalidCharacter);
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(DnsLabelError::HyphenBoundary);
    }
    Ok(())
}

/// Checks total hostname length (≤ 253 bytes) then validates each
/// dot-separated label via [`validate_dns_label`].
///
/// # Errors
///
/// Returns [`DnsLabelError`] when the hostname exceeds 253 bytes
/// or any individual label fails validation.
pub fn validate_dns_hostname(hostname: &str) -> Result<(), DnsLabelError> {
    if hostname.len() > MAX_HOSTNAME_LEN {
        return Err(DnsLabelError::HostnameTooLong);
    }
    for label in hostname.split('.') {
        validate_dns_label(label)?;
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
    fn accept_simple_label() {
        assert_eq!(validate_dns_label("example"), Ok(()));
    }

    #[test]
    fn accept_alphanumeric_label() {
        assert_eq!(validate_dns_label("abc123"), Ok(()));
    }

    #[test]
    fn accept_label_with_hyphen() {
        assert_eq!(validate_dns_label("my-host"), Ok(()));
    }

    #[test]
    fn accept_single_char_label() {
        assert_eq!(validate_dns_label("a"), Ok(()));
    }

    #[test]
    fn accept_63_char_label() {
        let label = "a".repeat(63);
        assert_eq!(validate_dns_label(&label), Ok(()));
    }

    #[test]
    fn reject_empty_label() {
        assert_eq!(validate_dns_label(""), Err(DnsLabelError::EmptyLabel));
    }

    #[test]
    fn reject_64_char_label() {
        let label = "a".repeat(64);
        assert_eq!(validate_dns_label(&label), Err(DnsLabelError::LabelTooLong));
    }

    #[test]
    fn reject_leading_hyphen() {
        assert_eq!(validate_dns_label("-start"), Err(DnsLabelError::HyphenBoundary));
    }

    #[test]
    fn reject_trailing_hyphen() {
        assert_eq!(validate_dns_label("end-"), Err(DnsLabelError::HyphenBoundary));
    }

    #[test]
    fn reject_underscore() {
        assert_eq!(
            validate_dns_label("has_underscore"),
            Err(DnsLabelError::InvalidCharacter)
        );
    }

    #[test]
    fn reject_space() {
        assert_eq!(validate_dns_label("has space"), Err(DnsLabelError::InvalidCharacter));
    }

    #[test]
    fn reject_asterisk() {
        assert_eq!(validate_dns_label("*"), Err(DnsLabelError::InvalidCharacter));
    }

    #[test]
    fn accept_simple_hostname() {
        assert_eq!(validate_dns_hostname("example.com"), Ok(()));
    }

    #[test]
    fn accept_multi_label_hostname() {
        assert_eq!(validate_dns_hostname("api.us-east.example.com"), Ok(()));
    }

    #[test]
    fn accept_single_label_hostname() {
        assert_eq!(validate_dns_hostname("localhost"), Ok(()));
    }

    #[test]
    fn reject_empty_label_in_hostname() {
        assert_eq!(
            validate_dns_hostname("api..example.com"),
            Err(DnsLabelError::EmptyLabel)
        );
    }

    #[test]
    fn reject_trailing_dot() {
        assert_eq!(validate_dns_hostname("example.com."), Err(DnsLabelError::EmptyLabel));
    }

    #[test]
    fn reject_leading_dot() {
        assert_eq!(validate_dns_hostname(".example.com"), Err(DnsLabelError::EmptyLabel));
    }

    #[test]
    fn reject_overlong_hostname() {
        let hostname = format!("{}.example.com", "a".repeat(250));
        assert!(hostname.len() > 253);
        assert_eq!(validate_dns_hostname(&hostname), Err(DnsLabelError::HostnameTooLong));
    }

    #[test]
    fn accept_hostname_at_253_bytes() {
        // 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
        let hostname = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        );
        assert_eq!(hostname.len(), 253);
        assert_eq!(validate_dns_hostname(&hostname), Ok(()));
    }

    #[test]
    fn reject_overlong_label_in_hostname() {
        let hostname = format!("{}.example.com", "a".repeat(64));
        assert_eq!(validate_dns_hostname(&hostname), Err(DnsLabelError::LabelTooLong));
    }

    #[test]
    fn display_messages() {
        assert_eq!(DnsLabelError::EmptyLabel.to_string(), "label is empty");
        assert_eq!(DnsLabelError::LabelTooLong.to_string(), "label exceeds 63 characters");
        assert_eq!(
            DnsLabelError::InvalidCharacter.to_string(),
            "contains invalid characters"
        );
        assert_eq!(
            DnsLabelError::HyphenBoundary.to_string(),
            "label must not start or end with a hyphen"
        );
        assert_eq!(DnsLabelError::HostnameTooLong.to_string(), "exceeds 253 characters");
    }
}
