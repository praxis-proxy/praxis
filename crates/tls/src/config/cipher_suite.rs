// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Cipher suite identifiers for restricting accepted TLS cipher suites.

use rustls::CipherSuite;
use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// CipherSuiteId
// -----------------------------------------------------------------------------

/// Cipher suite identifier for restricting accepted TLS cipher suites.
///
/// Maps to rustls [`CipherSuite`] wire identifiers. TLS 1.3
/// suites begin with `tls13_`; TLS 1.2 suites begin with `tls12_`.
///
/// ```
/// use praxis_tls::CipherSuiteId;
///
/// let suite: CipherSuiteId = serde_yaml::from_str("tls13_aes_256_gcm_sha384").unwrap();
/// assert!(matches!(suite, CipherSuiteId::Tls13Aes256GcmSha384));
///
/// let suite: CipherSuiteId =
///     serde_yaml::from_str("tls12_ecdhe_rsa_with_aes_128_gcm_sha256").unwrap();
/// assert!(matches!(
///     suite,
///     CipherSuiteId::Tls12EcdheRsaWithAes128GcmSha256
/// ));
/// ```
///
/// [`SupportedCipherSuite`]: rustls::SupportedCipherSuite
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum CipherSuiteId {
    // TLS 1.3 suites
    /// TLS 1.3 AES-128-GCM with SHA-256.
    #[serde(rename = "tls13_aes_128_gcm_sha256")]
    Tls13Aes128GcmSha256,

    /// TLS 1.3 AES-256-GCM with SHA-384.
    #[serde(rename = "tls13_aes_256_gcm_sha384")]
    Tls13Aes256GcmSha384,

    /// TLS 1.3 ChaCha20-Poly1305 with SHA-256.
    #[serde(rename = "tls13_chacha20_poly1305_sha256")]
    Tls13Chacha20Poly1305Sha256,

    // TLS 1.2 suites
    /// TLS 1.2 ECDHE-ECDSA with AES-128-GCM SHA-256.
    #[serde(rename = "tls12_ecdhe_ecdsa_with_aes_128_gcm_sha256")]
    Tls12EcdheEcdsaWithAes128GcmSha256,

    /// TLS 1.2 ECDHE-ECDSA with AES-256-GCM SHA-384.
    #[serde(rename = "tls12_ecdhe_ecdsa_with_aes_256_gcm_sha384")]
    Tls12EcdheEcdsaWithAes256GcmSha384,

    /// TLS 1.2 ECDHE-ECDSA with ChaCha20-Poly1305 SHA-256.
    #[serde(rename = "tls12_ecdhe_ecdsa_with_chacha20_poly1305_sha256")]
    Tls12EcdheEcdsaWithChacha20Poly1305Sha256,

    /// TLS 1.2 ECDHE-RSA with AES-128-GCM SHA-256.
    #[serde(rename = "tls12_ecdhe_rsa_with_aes_128_gcm_sha256")]
    Tls12EcdheRsaWithAes128GcmSha256,

    /// TLS 1.2 ECDHE-RSA with AES-256-GCM SHA-384.
    #[serde(rename = "tls12_ecdhe_rsa_with_aes_256_gcm_sha384")]
    Tls12EcdheRsaWithAes256GcmSha384,

    /// TLS 1.2 ECDHE-RSA with ChaCha20-Poly1305 SHA-256.
    #[serde(rename = "tls12_ecdhe_rsa_with_chacha20_poly1305_sha256")]
    Tls12EcdheRsaWithChacha20Poly1305Sha256,
}

impl CipherSuiteId {
    /// Convert to the corresponding rustls [`CipherSuite`] wire identifier.
    ///
    /// Deliberately an identifier rather than a `SupportedCipherSuite`: the
    /// latter carries a provider's *implementation* of the suite, so naming
    /// one here would tie the config surface to a particular provider. The
    /// identifier is provider-independent, and the implementation is resolved
    /// against whichever provider is installed — see
    /// [`crate::provider`] and `setup::maybe_filter_provider`.
    ///
    /// ```
    /// use praxis_tls::CipherSuiteId;
    ///
    /// let suite = CipherSuiteId::Tls13Aes256GcmSha384;
    /// assert_eq!(
    ///     format!("{:?}", suite.to_rustls()),
    ///     "TLS13_AES_256_GCM_SHA384"
    /// );
    /// ```
    ///
    /// [`CipherSuite`]: rustls::CipherSuite
    pub fn to_rustls(&self) -> CipherSuite {
        match self {
            Self::Tls13Aes128GcmSha256 => CipherSuite::TLS13_AES_128_GCM_SHA256,
            Self::Tls13Aes256GcmSha384 => CipherSuite::TLS13_AES_256_GCM_SHA384,
            Self::Tls13Chacha20Poly1305Sha256 => CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            Self::Tls12EcdheEcdsaWithAes128GcmSha256 => CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            Self::Tls12EcdheEcdsaWithAes256GcmSha384 => CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            Self::Tls12EcdheEcdsaWithChacha20Poly1305Sha256 => {
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            },
            Self::Tls12EcdheRsaWithAes128GcmSha256 => CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            Self::Tls12EcdheRsaWithAes256GcmSha384 => CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            Self::Tls12EcdheRsaWithChacha20Poly1305Sha256 => CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        }
    }

    /// Whether this cipher suite belongs to TLS 1.2.
    ///
    /// ```
    /// use praxis_tls::CipherSuiteId;
    ///
    /// assert!(CipherSuiteId::Tls12EcdheRsaWithAes128GcmSha256.is_tls12());
    /// assert!(!CipherSuiteId::Tls13Aes256GcmSha384.is_tls12());
    /// ```
    pub fn is_tls12(&self) -> bool {
        matches!(
            self,
            Self::Tls12EcdheEcdsaWithAes128GcmSha256
                | Self::Tls12EcdheEcdsaWithAes256GcmSha384
                | Self::Tls12EcdheEcdsaWithChacha20Poly1305Sha256
                | Self::Tls12EcdheRsaWithAes128GcmSha256
                | Self::Tls12EcdheRsaWithAes256GcmSha384
                | Self::Tls12EcdheRsaWithChacha20Poly1305Sha256
        )
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn to_rustls_maps_all_tls13_variants() {
        assert_eq!(
            CipherSuiteId::Tls13Aes128GcmSha256.to_rustls(),
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            "TLS13_AES_128_GCM_SHA256 mismatch"
        );
        assert_eq!(
            CipherSuiteId::Tls13Aes256GcmSha384.to_rustls(),
            CipherSuite::TLS13_AES_256_GCM_SHA384,
            "TLS13_AES_256_GCM_SHA384 mismatch"
        );
        assert_eq!(
            CipherSuiteId::Tls13Chacha20Poly1305Sha256.to_rustls(),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            "TLS13_CHACHA20_POLY1305_SHA256 mismatch"
        );
    }

    #[test]
    fn to_rustls_maps_all_tls12_ecdsa_variants() {
        assert_eq!(
            CipherSuiteId::Tls12EcdheEcdsaWithAes128GcmSha256.to_rustls(),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 mismatch"
        );
        assert_eq!(
            CipherSuiteId::Tls12EcdheEcdsaWithAes256GcmSha384.to_rustls(),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 mismatch"
        );
        assert_eq!(
            CipherSuiteId::Tls12EcdheEcdsaWithChacha20Poly1305Sha256.to_rustls(),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 mismatch"
        );
    }

    #[test]
    fn to_rustls_maps_all_tls12_rsa_variants() {
        assert_eq!(
            CipherSuiteId::Tls12EcdheRsaWithAes128GcmSha256.to_rustls(),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 mismatch"
        );
        assert_eq!(
            CipherSuiteId::Tls12EcdheRsaWithAes256GcmSha384.to_rustls(),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 mismatch"
        );
        assert_eq!(
            CipherSuiteId::Tls12EcdheRsaWithChacha20Poly1305Sha256.to_rustls(),
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 mismatch"
        );
    }

    #[test]
    fn is_tls12_correctly_identifies_tls12_variants() {
        assert!(
            CipherSuiteId::Tls12EcdheEcdsaWithAes128GcmSha256.is_tls12(),
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 should be TLS 1.2"
        );
        assert!(
            CipherSuiteId::Tls12EcdheEcdsaWithAes256GcmSha384.is_tls12(),
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 should be TLS 1.2"
        );
        assert!(
            CipherSuiteId::Tls12EcdheEcdsaWithChacha20Poly1305Sha256.is_tls12(),
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 should be TLS 1.2"
        );
        assert!(
            CipherSuiteId::Tls12EcdheRsaWithAes128GcmSha256.is_tls12(),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 should be TLS 1.2"
        );
        assert!(
            CipherSuiteId::Tls12EcdheRsaWithAes256GcmSha384.is_tls12(),
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 should be TLS 1.2"
        );
        assert!(
            CipherSuiteId::Tls12EcdheRsaWithChacha20Poly1305Sha256.is_tls12(),
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 should be TLS 1.2"
        );
    }

    #[test]
    fn is_tls12_correctly_rejects_tls13_variants() {
        assert!(
            !CipherSuiteId::Tls13Aes128GcmSha256.is_tls12(),
            "TLS13_AES_128_GCM_SHA256 should not be TLS 1.2"
        );
        assert!(
            !CipherSuiteId::Tls13Aes256GcmSha384.is_tls12(),
            "TLS13_AES_256_GCM_SHA384 should not be TLS 1.2"
        );
        assert!(
            !CipherSuiteId::Tls13Chacha20Poly1305Sha256.is_tls12(),
            "TLS13_CHACHA20_POLY1305_SHA256 should not be TLS 1.2"
        );
    }

    #[test]
    fn serde_roundtrip_tls13() {
        let original = CipherSuiteId::Tls13Aes256GcmSha384;
        let yaml = serde_yaml::to_string(&original).unwrap();
        let parsed: CipherSuiteId = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, original, "TLS 1.3 round-trip mismatch");
    }

    #[test]
    fn serde_roundtrip_tls12() {
        let original = CipherSuiteId::Tls12EcdheRsaWithAes128GcmSha256;
        let yaml = serde_yaml::to_string(&original).unwrap();
        let parsed: CipherSuiteId = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, original, "TLS 1.2 round-trip mismatch");
    }

    #[test]
    fn deserialize_rejects_unknown_suite() {
        let result = serde_yaml::from_str::<CipherSuiteId>("tls13_unknown_cipher");
        assert!(result.is_err(), "unknown cipher suite should fail deserialization");
    }

    #[test]
    fn deserialize_rejects_invalid_yaml() {
        let result = serde_yaml::from_str::<CipherSuiteId>("{ invalid: yaml }");
        assert!(result.is_err(), "invalid YAML structure should fail");
    }
}
