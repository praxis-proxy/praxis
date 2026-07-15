// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! TLS peer identity types exposed to higher-level request processing.

/// Verified downstream TLS peer identity from the client certificate.
///
/// Populated when the downstream connection uses mTLS and the peer
/// presented a valid client certificate. Higher-level request handlers
/// and filters can read this to make trust decisions about the
/// authenticated peer without parsing certificates themselves.
///
/// Fields are extracted from Pingora's SSL digest during request setup.
/// SAN (Subject Alternative Name) and SPIFFE identity parsing are not
/// yet included and are planned for a follow-up.
///
/// ```
/// use praxis_tls::TlsPeerIdentity;
///
/// let identity = TlsPeerIdentity {
///     cert_digest: vec![0xAB, 0xCD],
///     organization: Some("example-org".to_owned()),
///     serial_number: Some("12345".to_owned()),
/// };
/// assert_eq!(identity.hex_digest(), "abcd");
/// assert_eq!(identity.organization.as_deref(), Some("example-org"));
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsPeerIdentity {
    /// Cryptographic digest of the peer's leaf certificate (DER-encoded).
    pub cert_digest: Vec<u8>,

    /// X.509 subject organization (`O=` field), if present.
    pub organization: Option<String>,

    /// Certificate serial number as a decimal string, if present.
    pub serial_number: Option<String>,
}

impl TlsPeerIdentity {
    /// Lowercase hex-encoded certificate digest for logging and
    /// config display.
    ///
    /// ```
    /// use praxis_tls::TlsPeerIdentity;
    ///
    /// let id = TlsPeerIdentity {
    ///     cert_digest: vec![0xDE, 0xAD, 0xBE, 0xEF],
    ///     organization: None,
    ///     serial_number: None,
    /// };
    /// assert_eq!(id.hex_digest(), "deadbeef");
    /// ```
    #[must_use]
    pub fn hex_digest(&self) -> String {
        let mut hex = String::with_capacity(self.cert_digest.len() * 2);
        for byte in &self.cert_digest {
            hex.push(hex_digit(byte >> 4));
            hex.push(hex_digit(byte & 0x0F));
        }
        hex
    }
}

/// Convert a four-bit value to its lowercase hexadecimal character.
fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + nibble - 10) as char,
    }
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn hex_digest_empty() {
        let id = TlsPeerIdentity {
            cert_digest: vec![],
            organization: None,
            serial_number: None,
        };
        assert_eq!(id.hex_digest(), "", "empty digest should produce empty string");
    }

    #[test]
    fn hex_digest_typical_32_byte_length() {
        let id = TlsPeerIdentity {
            cert_digest: vec![0_u8; 32],
            organization: None,
            serial_number: None,
        };
        let hex = id.hex_digest();
        assert_eq!(hex.len(), 64, "32-byte digest should produce 64 hex chars");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "all chars should be hex");
        assert_eq!(hex, "0".repeat(64), "all-zero digest should be all-zero hex");
    }

    #[test]
    fn hex_digest_all_zeros() {
        let id = TlsPeerIdentity {
            cert_digest: vec![0x00; 4],
            organization: None,
            serial_number: None,
        };
        assert_eq!(
            id.hex_digest(),
            "00000000",
            "all-zero bytes should produce all-zero hex"
        );
    }

    #[test]
    fn hex_digest_all_0xff() {
        let id = TlsPeerIdentity {
            cert_digest: vec![0xFF; 4],
            organization: None,
            serial_number: None,
        };
        assert_eq!(id.hex_digest(), "ffffffff", "all-0xFF bytes should produce all-f hex");
    }
}
