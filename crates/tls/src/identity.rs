// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! TLS peer identity types exposed to higher-level request processing.

use rustls::crypto::{CryptoProvider, hash::HashAlgorithm};
use x509_parser::{certificate::X509Certificate, prelude::FromDer as _};

/// Verified downstream TLS peer identity from the client certificate.
///
/// Populated when the downstream connection uses mTLS and the peer
/// presented a valid client certificate. Higher-level request handlers
/// and filters can read this to make trust decisions about the
/// authenticated peer without parsing certificates themselves.
///
/// Pingora extracts these fields from its SSL digest; Hyper extracts them
/// from the authenticated leaf certificate after the TLS handshake.
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

    /// Certificate serial number as colon-delimited hexadecimal, if present.
    pub serial_number: Option<String>,
}

impl TlsPeerIdentity {
    /// Extract identity from a leaf certificate authenticated by the caller's
    /// completed TLS handshake. Parsing and hashing do not verify a chain.
    ///
    /// An undecodable subject organization leaves `organization` absent as a
    /// whole; the authenticated digest and serial remain available.
    ///
    /// # Errors
    ///
    /// Fails when the DER is incomplete or has trailing data, the process has
    /// no installed crypto provider, or that provider has no SHA-256 hash.
    pub fn from_verified_der(der: &[u8]) -> Result<Self, &'static str> {
        let (remaining, certificate) =
            X509Certificate::from_der(der).map_err(|_parse_error| "invalid peer certificate DER")?;
        if !remaining.is_empty() {
            return Err("peer certificate DER has trailing data");
        }
        let provider =
            crate::provider::installed_provider().map_err(|_provider_error| "no installed crypto provider")?;
        let cert_digest = sha256_digest(der, &provider)?;
        let organizations = certificate
            .subject()
            .iter_organization()
            .map(|attribute| attribute.as_str().map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()
            .ok();
        let organization = organizations.and_then(|values| (!values.is_empty()).then(|| values.concat()));
        Ok(Self {
            cert_digest,
            organization,
            serial_number: Some(certificate.raw_serial_as_string()),
        })
    }

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
        let mut hex = String::with_capacity(self.cert_digest.len().saturating_mul(2));
        for byte in &self.cert_digest {
            hex.push(hex_digit(byte >> 4));
            hex.push(hex_digit(byte & 0x0F));
        }
        hex
    }
}

/// SHA-256 of the complete leaf DER through the installed TLS provider.
fn sha256_digest(der: &[u8], provider: &CryptoProvider) -> Result<Vec<u8>, &'static str> {
    let hash = provider
        .cipher_suites
        .iter()
        .filter_map(rustls::SupportedCipherSuite::tls13)
        .map(|suite| suite.common.hash_provider)
        .find(|hash| hash.algorithm() == HashAlgorithm::SHA256)
        .ok_or("installed crypto provider has no SHA-256 hash")?;
    let digest = hash.hash(der);
    if digest.as_ref().len() != 32 {
        return Err("installed SHA-256 hash returned the wrong length");
    }
    Ok(digest.as_ref().to_vec())
}

/// Convert a four-bit value to its lowercase hexadecimal character.
fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0'.saturating_add(nibble)),
        _ => char::from(b'a'.saturating_add(nibble).saturating_sub(10)),
    }
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use std::process::Command;

    use openssl::{
        asn1::{Asn1Time, Asn1Type},
        bn::BigNum,
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509, X509NameBuilder},
    };
    use rcgen::{CertificateParams, DnType, DnValue, KeyPair, string::BmpString};

    use super::*;

    /// A DER leaf with a chosen organization encoding and known hex serial.
    fn certificate(organization: Option<DnValue>) -> Vec<u8> {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        params.serial_number = Some(0x1234_u64.into());
        if let Some(value) = organization {
            params.distinguished_name.push(DnType::OrganizationName, value);
        }
        params.self_signed(&key).unwrap().der().to_vec()
    }

    /// A parsed leaf with two O values, preserving order and ASN.1 encoding.
    fn two_organizations_certificate(second: &str, second_type: Asn1Type) -> Vec<u8> {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Readable").unwrap();
        name.append_entry_by_nid_with_type(Nid::ORGANIZATIONNAME, second, second_type)
            .unwrap();
        let name = name.build();
        let serial = BigNum::from_u32(0x1234).unwrap().to_asn1_integer().unwrap();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_serial_number(&serial).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .unwrap();
        certificate
            .set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
            .unwrap();
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        certificate.build().to_der().unwrap()
    }

    #[test]
    fn verified_der_extracts_sha256_organization_and_hex_serial() {
        crate::provider::install();
        let der = certificate(Some(DnValue::Utf8String("Acme".to_owned())));
        let expected = X509::from_der(&der).unwrap().digest(MessageDigest::sha256()).unwrap();

        let identity = TlsPeerIdentity::from_verified_der(&der).unwrap();

        assert_eq!(
            identity.cert_digest,
            expected.as_ref(),
            "pin is SHA-256 over the whole DER"
        );
        assert_eq!(identity.organization.as_deref(), Some("Acme"));
        assert_eq!(identity.serial_number.as_deref(), Some("12:34"));
    }

    #[test]
    fn verified_der_without_or_with_undecodable_organization_keeps_digest_and_serial() {
        crate::provider::install();
        let absent = certificate(None);
        let bmp = certificate(Some(DnValue::BmpString(BmpString::try_from("Acme").unwrap())));
        for der in [absent, bmp] {
            let identity = TlsPeerIdentity::from_verified_der(&der).unwrap();
            assert_eq!(identity.cert_digest.len(), 32);
            assert_eq!(identity.organization, None, "no partial or guessed organization");
            assert_eq!(identity.serial_number.as_deref(), Some("12:34"));
        }
    }

    #[test]
    fn mixed_readable_and_undecodable_organizations_never_authorize_partial_name() {
        crate::provider::install();
        let der = two_organizations_certificate("\0B\0M\0P", Asn1Type::BMPSTRING);
        let expected = X509::from_der(&der).unwrap().digest(MessageDigest::sha256()).unwrap();

        let identity = TlsPeerIdentity::from_verified_der(&der).unwrap();

        assert_eq!(identity.cert_digest, expected.as_ref());
        assert_eq!(identity.serial_number.as_deref(), Some("12:34"));
        assert_eq!(
            identity.organization, None,
            "the readable O must not survive an undecodable O"
        );
    }

    #[test]
    fn multiple_readable_organizations_concatenate_in_certificate_order() {
        crate::provider::install();
        let der = two_organizations_certificate("Second", Asn1Type::UTF8STRING);
        let expected = X509::from_der(&der).unwrap().digest(MessageDigest::sha256()).unwrap();

        let identity = TlsPeerIdentity::from_verified_der(&der).unwrap();

        assert_eq!(identity.cert_digest, expected.as_ref());
        assert_eq!(identity.organization.as_deref(), Some("ReadableSecond"));
        assert_eq!(identity.serial_number.as_deref(), Some("12:34"));
    }

    #[test]
    fn verified_der_rejects_malformed_and_trailing_data() {
        crate::provider::install();
        let mut der = certificate(None);
        let truncated = der.get(..der.len() / 2).unwrap();
        assert_eq!(
            TlsPeerIdentity::from_verified_der(truncated),
            Err("invalid peer certificate DER")
        );
        der.extend_from_slice(b"garbage");
        assert_eq!(
            TlsPeerIdentity::from_verified_der(&der),
            Err("peer certificate DER has trailing data")
        );
    }

    /// Assert the fresh subprocess has no provider and reports that failure.
    fn verify_without_installed_provider_in_child(sentinel: std::ffi::OsString) {
        assert!(
            CryptoProvider::get_default().is_none(),
            "child must start without a provider"
        );
        let der = certificate(None);
        assert!(
            CryptoProvider::get_default().is_none(),
            "certificate fixture must not install a provider"
        );
        assert_eq!(
            TlsPeerIdentity::from_verified_der(&der),
            Err("no installed crypto provider")
        );
        std::fs::write(std::path::PathBuf::from(sentinel), b"executed").unwrap();
    }

    #[test]
    fn from_verified_der_without_installed_provider_fails_closed() {
        const CHILD: &str = "PRAXIS_TLS_IDENTITY_NO_PROVIDER_CHILD";
        if let Some(sentinel) = std::env::var_os(CHILD) {
            verify_without_installed_provider_in_child(sentinel);
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let sentinel = directory.path().join("identity-child-completed");
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "identity::tests::from_verified_der_without_installed_provider_fails_closed",
            ])
            .env(CHILD, &sentinel)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(sentinel).unwrap(),
            b"executed",
            "the child must execute its assertion path"
        );
    }

    #[test]
    fn missing_sha256_provider_is_an_error() {
        crate::provider::install();
        let mut provider = (*crate::provider::installed_provider().unwrap()).clone();
        provider.cipher_suites.retain(|suite| {
            suite
                .tls13()
                .is_some_and(|tls13| tls13.common.hash_provider.algorithm() != HashAlgorithm::SHA256)
        });
        assert_eq!(
            sha256_digest(&certificate(None), &provider),
            Err("installed crypto provider has no SHA-256 hash")
        );
    }

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
        assert!(hex.chars().all(|ch| ch.is_ascii_hexdigit()), "all chars should be hex");
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
