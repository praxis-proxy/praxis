// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Cipher suite identifiers for restricting accepted TLS cipher suites.

use rustls::{SupportedCipherSuite, crypto::aws_lc_rs::cipher_suite};
use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// CipherSuiteId
// -----------------------------------------------------------------------------

/// Cipher suite identifier for restricting accepted TLS cipher suites.
///
/// Maps to `aws_lc_rs` [`SupportedCipherSuite`] variants. TLS 1.3
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
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
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
    /// Convert to the corresponding rustls [`SupportedCipherSuite`].
    ///
    /// ```
    /// use praxis_tls::CipherSuiteId;
    ///
    /// let suite = CipherSuiteId::Tls13Aes256GcmSha384;
    /// let rustls_suite = suite.to_rustls();
    /// assert_eq!(
    ///     format!("{:?}", rustls_suite.suite()),
    ///     "TLS13_AES_256_GCM_SHA384"
    /// );
    /// ```
    ///
    /// [`SupportedCipherSuite`]: rustls::SupportedCipherSuite
    pub fn to_rustls(&self) -> SupportedCipherSuite {
        match self {
            Self::Tls13Aes128GcmSha256 => cipher_suite::TLS13_AES_128_GCM_SHA256,
            Self::Tls13Aes256GcmSha384 => cipher_suite::TLS13_AES_256_GCM_SHA384,
            Self::Tls13Chacha20Poly1305Sha256 => cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            Self::Tls12EcdheEcdsaWithAes128GcmSha256 => cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            Self::Tls12EcdheEcdsaWithAes256GcmSha384 => cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            Self::Tls12EcdheEcdsaWithChacha20Poly1305Sha256 => {
                cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            },
            Self::Tls12EcdheRsaWithAes128GcmSha256 => cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            Self::Tls12EcdheRsaWithAes256GcmSha384 => cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            Self::Tls12EcdheRsaWithChacha20Poly1305Sha256 => cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
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
