// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Listener TLS configuration: `ListenerTls`, `ClientCertMode`, and `TlsVersion`.

use rustls::{SupportedCipherSuite, crypto::aws_lc_rs::cipher_suite};
use serde::{Deserialize, Deserializer, Serialize, de};

use super::{CaConfig, CertKeyPair, is_default_cert_mode};
use crate::TlsError;

// -----------------------------------------------------------------------------
// ListenerTls
// -----------------------------------------------------------------------------

/// TLS settings for a listener (server role).
///
/// Deserialization validates path traversal, file existence,
/// certificate count, and mTLS consistency.
///
/// ```
/// use praxis_tls::ListenerTls;
///
/// let dir = tempfile::TempDir::new().unwrap();
/// let cert = dir.path().join("cert.pem");
/// let key = dir.path().join("key.pem");
/// std::fs::write(&cert, b"").unwrap();
/// std::fs::write(&key, b"").unwrap();
///
/// let yaml = format!(
///     "certificates:\n  - cert_path: {c}\n    key_path: {k}\n",
///     c = cert.display(),
///     k = key.display(),
/// );
/// let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
/// assert_eq!(tls.certificates.len(), 1);
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct ListenerTls {
    /// Server certificates. At least one required.
    ///
    /// Multiple entries enable SNI-based cert selection.
    pub certificates: Vec<CertKeyPair>,

    /// Restrict accepted cipher suites to this list.
    ///
    /// When `None`, all provider cipher suites are accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher_suites: Option<Vec<CipherSuiteId>>,

    /// CA for client certificate verification (mTLS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ca: Option<CaConfig>,

    /// Client cert verification mode.
    #[serde(skip_serializing_if = "is_default_cert_mode")]
    pub client_cert_mode: ClientCertMode,

    /// Certificate hot-reload via filesystem watching.
    ///
    /// Enabled by default. Set to `false` to disable. Certificate
    /// and key files are monitored for changes and reloaded without
    /// restarting the proxy. Requires exactly one certificate entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hot_reload: Option<bool>,

    /// Minimum TLS version accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_version: Option<TlsVersion>,
}

/// Raw deserialization helper for [`ListenerTls`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListenerTlsRaw {
    /// Server certificates.
    certificates: Vec<CertKeyPair>,

    /// Restrict accepted cipher suites.
    #[serde(default)]
    cipher_suites: Option<Vec<CipherSuiteId>>,

    /// CA for client certificate verification.
    #[serde(default)]
    client_ca: Option<CaConfig>,

    /// Client cert verification mode.
    #[serde(default)]
    client_cert_mode: ClientCertMode,

    /// Enable certificate hot-reload.
    #[serde(default)]
    hot_reload: Option<bool>,

    /// Minimum TLS version.
    #[serde(default)]
    min_version: Option<TlsVersion>,
}

impl<'de> Deserialize<'de> for ListenerTls {
    /// Deserialize and validate listener TLS config.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = ListenerTlsRaw::deserialize(deserializer)?;
        let config = Self {
            certificates: raw.certificates,
            cipher_suites: raw.cipher_suites,
            client_ca: raw.client_ca,
            client_cert_mode: raw.client_cert_mode,
            hot_reload: raw.hot_reload,
            min_version: raw.min_version,
        };
        config.validate().map_err(de::Error::custom)?;
        Ok(config)
    }
}

impl ListenerTls {
    /// Create a [`ListenerTls`] with a single certificate and validate it.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if paths contain `..` traversal or files
    /// do not exist.
    ///
    /// ```
    /// use praxis_tls::ListenerTls;
    ///
    /// let dir = tempfile::TempDir::new().unwrap();
    /// let cert = dir.path().join("cert.pem");
    /// let key = dir.path().join("key.pem");
    /// std::fs::write(&cert, b"").unwrap();
    /// std::fs::write(&key, b"").unwrap();
    ///
    /// let tls = ListenerTls::new_validated(cert.to_str().unwrap(), key.to_str().unwrap()).unwrap();
    /// assert_eq!(tls.certificates.len(), 1);
    ///
    /// let err = ListenerTls::new_validated("/etc/../../bad.pem", "/etc/ssl/key.pem").unwrap_err();
    /// assert!(err.to_string().contains("path traversal"));
    /// ```
    ///
    /// [`TlsError`]: crate::TlsError
    /// [`ListenerTls`]: crate::ListenerTls
    pub fn new_validated(cert_path: impl Into<String>, key_path: impl Into<String>) -> Result<Self, TlsError> {
        let config = Self {
            certificates: vec![CertKeyPair {
                cert_path: cert_path.into(),
                default: false,
                key_path: key_path.into(),
                server_names: Vec::new(),
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            hot_reload: None,
            min_version: None,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate paths, certificate count, and mTLS consistency.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if any path contains `..`, files do not
    /// exist, no certificates are provided, or mTLS mode requires a
    /// CA that is not set.
    ///
    /// ```
    /// use praxis_tls::ListenerTls;
    ///
    /// let dir = tempfile::TempDir::new().unwrap();
    /// let cert = dir.path().join("cert.pem");
    /// let key = dir.path().join("key.pem");
    /// std::fs::write(&cert, b"").unwrap();
    /// std::fs::write(&key, b"").unwrap();
    ///
    /// let ok = ListenerTls::new_validated(cert.to_str().unwrap(), key.to_str().unwrap()).unwrap();
    /// assert!(ok.validate().is_ok());
    ///
    /// let err = serde_yaml::from_str::<ListenerTls>(
    ///     r#"
    /// certificates:
    ///   - cert_path: "/etc/../../bad.pem"
    ///     key_path: "/etc/ssl/key.pem"
    /// "#,
    /// );
    /// assert!(err.is_err());
    /// ```
    ///
    /// [`TlsError`]: crate::TlsError
    pub fn validate(&self) -> Result<(), TlsError> {
        if self.certificates.is_empty() {
            return Err(TlsError::NoCertificates);
        }

        for cert in &self.certificates {
            cert.validate()?;
        }

        if self.certificates.len() > 1 {
            validate_multi_cert_defaults(&self.certificates)?;
        }

        if let Some(ref ca) = self.client_ca {
            ca.validate()?;
        }

        if self.client_cert_mode != ClientCertMode::None && self.client_ca.is_none() {
            return Err(TlsError::MissingClientCa {
                mode: self.client_cert_mode.clone(),
            });
        }

        if self.hot_reload == Some(true) && self.certificates.len() > 1 {
            return Err(TlsError::HotReloadMultipleCerts);
        }

        if let Some(ref suites) = self.cipher_suites {
            if suites.is_empty() {
                return Err(TlsError::EmptyCipherSuites);
            }
            if self.min_version == Some(TlsVersion::Tls13) && suites.iter().any(CipherSuiteId::is_tls12) {
                return Err(TlsError::Tls12SuiteWithTls13Only);
            }
        }

        Ok(())
    }

    /// Whether hot-reload is enabled for this listener.
    ///
    /// ```
    /// use praxis_tls::ListenerTls;
    ///
    /// let dir = tempfile::TempDir::new().unwrap();
    /// let cert = dir.path().join("cert.pem");
    /// let key = dir.path().join("key.pem");
    /// std::fs::write(&cert, b"").unwrap();
    /// std::fs::write(&key, b"").unwrap();
    ///
    /// let tls = ListenerTls::new_validated(cert.to_str().unwrap(), key.to_str().unwrap()).unwrap();
    /// assert!(tls.is_hot_reload());
    /// ```
    pub fn is_hot_reload(&self) -> bool {
        self.hot_reload != Some(false) && self.certificates.len() == 1
    }

    /// Return the first (or only) certificate's paths.
    ///
    /// ```
    /// use praxis_tls::ListenerTls;
    ///
    /// let dir = tempfile::TempDir::new().unwrap();
    /// let cert = dir.path().join("cert.pem");
    /// let key = dir.path().join("key.pem");
    /// std::fs::write(&cert, b"").unwrap();
    /// std::fs::write(&key, b"").unwrap();
    ///
    /// let tls = ListenerTls::new_validated(cert.to_str().unwrap(), key.to_str().unwrap()).unwrap();
    /// let (c, k) = tls.primary_cert_paths();
    /// assert_eq!(c, cert.to_str().unwrap());
    /// assert_eq!(k, key.to_str().unwrap());
    /// ```
    #[allow(clippy::indexing_slicing, reason = "validated non-empty")]
    pub fn primary_cert_paths(&self) -> (&str, &str) {
        let cert = &self.certificates[0];
        (&cert.cert_path, &cert.key_path)
    }
}

// -----------------------------------------------------------------------------
// ClientCertMode
// -----------------------------------------------------------------------------

/// Client certificate verification mode for listener mTLS.
///
/// ```
/// use praxis_tls::ClientCertMode;
///
/// let mode: ClientCertMode = serde_yaml::from_str("require").unwrap();
/// assert!(matches!(mode, ClientCertMode::Require));
///
/// let mode: ClientCertMode = serde_yaml::from_str("request").unwrap();
/// assert!(matches!(mode, ClientCertMode::Request));
///
/// let mode: ClientCertMode = serde_yaml::from_str("none").unwrap();
/// assert!(matches!(mode, ClientCertMode::None));
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientCertMode {
    /// Do not request a client certificate (default).
    #[default]
    None,

    /// Ask the client for a certificate but allow connections without one.
    Request,

    /// Require a valid client certificate; reject connections without one.
    Require,
}

// -----------------------------------------------------------------------------
// TlsVersion
// -----------------------------------------------------------------------------

/// Minimum TLS protocol version.
///
/// ```
/// use praxis_tls::TlsVersion;
///
/// let v: TlsVersion = serde_yaml::from_str("tls13").unwrap();
/// assert!(matches!(v, TlsVersion::Tls13));
///
/// let v: TlsVersion = serde_yaml::from_str("tls12").unwrap();
/// assert!(matches!(v, TlsVersion::Tls12));
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    /// TLS 1.2 (allows both 1.2 and 1.3).
    Tls12,

    /// TLS 1.3 only.
    Tls13,
}

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

// -----------------------------------------------------------------------------
// Multi-Cert Validation
// -----------------------------------------------------------------------------

/// Validate `default` field rules across a multi-cert list.
///
/// Rejects configs with more than one `default: true` entry, or
/// entries that have no `server_names` and are not marked as default.
fn validate_multi_cert_defaults(certificates: &[CertKeyPair]) -> Result<(), TlsError> {
    let mut seen_default = false;
    for cert in certificates {
        if cert.default {
            if seen_default {
                return Err(TlsError::MultipleDefaults);
            }
            seen_default = true;
        } else if cert.server_names.is_empty() {
            return Err(TlsError::AmbiguousCert {
                path: cert.cert_path.clone(),
            });
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn listener_tls_valid_paths_pass() {
        let tmp = temp_cert_key();
        let tls = ListenerTls::new_validated(&tmp.cert, &tmp.key).unwrap();
        assert_eq!(tls.certificates[0].cert_path, tmp.cert, "cert_path mismatch");
        assert_eq!(tls.certificates[0].key_path, tmp.key, "key_path mismatch");
    }

    #[test]
    fn validate_on_deserialized_config() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert!(tls.validate().is_ok(), "valid config should pass validation");
    }

    #[test]
    fn deserialize_rejects_traversal_automatically() {
        let result = serde_yaml::from_str::<ListenerTls>("certificates:\n  - cert_path: /a/../b\n    key_path: /c\n");
        assert!(result.is_err(), "deserialization should reject path traversal");
    }

    #[test]
    fn client_ca_path_traversal_rejected() {
        let tmp = temp_cert_key();
        let tls = ListenerTls {
            client_ca: Some(CaConfig {
                ca_path: "/etc/../../evil-ca.pem".to_owned(),
            }),
            client_cert_mode: ClientCertMode::Require,
            ..ListenerTls::new_validated(&tmp.cert, &tmp.key).unwrap()
        };
        let err = tls.validate().unwrap_err();
        assert!(err.to_string().contains("ca_path"), "should mention ca_path: {err}");
    }

    #[test]
    fn client_cert_mode_require_without_ca_rejected() {
        let tmp = temp_cert_key();
        let tls = ListenerTls {
            client_cert_mode: ClientCertMode::Require,
            ..ListenerTls::new_validated(&tmp.cert, &tmp.key).unwrap()
        };
        let err = tls.validate().unwrap_err();
        assert!(err.to_string().contains("client_ca"), "should require client_ca: {err}");
    }

    #[test]
    fn client_cert_mode_request_without_ca_rejected() {
        let tmp = temp_cert_key();
        let tls = ListenerTls {
            client_cert_mode: ClientCertMode::Request,
            ..ListenerTls::new_validated(&tmp.cert, &tmp.key).unwrap()
        };
        let err = tls.validate().unwrap_err();
        assert!(err.to_string().contains("client_ca"), "should require client_ca: {err}");
    }

    #[test]
    fn client_cert_mode_none_without_ca_accepted() {
        let tmp = temp_cert_key();
        let tls = ListenerTls {
            client_cert_mode: ClientCertMode::None,
            ..ListenerTls::new_validated(&tmp.cert, &tmp.key).unwrap()
        };
        assert!(tls.validate().is_ok(), "mode=none should not require client_ca");
    }

    #[test]
    fn deserialize_mtls_config() {
        let tmp = temp_cert_key_ca();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\nclient_ca:\n  ca_path: {ca}\nclient_cert_mode: require\n",
            cert = tmp.cert,
            key = tmp.key,
            ca = tmp.ca,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(tls.client_ca.as_ref().unwrap().ca_path, tmp.ca, "ca_path mismatch");
        assert_eq!(tls.client_cert_mode, ClientCertMode::Require, "mode should be require");
    }

    #[test]
    fn deserialize_min_tls_version() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\nmin_version: tls13\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(tls.min_version, Some(TlsVersion::Tls13), "version should be tls13");
    }

    #[test]
    fn min_tls_version_defaults_to_none() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert!(tls.min_version.is_none(), "should default to None");
    }

    #[test]
    fn client_cert_mode_defaults_to_none() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(tls.client_cert_mode, ClientCertMode::None, "should default to None");
    }

    #[test]
    fn client_ca_defaults_to_none() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert!(tls.client_ca.is_none(), "should default to None");
    }

    #[test]
    fn no_certificates_rejected() {
        let result = serde_yaml::from_str::<ListenerTls>("certificates: []\n");
        assert!(result.is_err(), "empty certificates should be rejected");
    }

    #[test]
    fn multi_cert_deserializes() {
        let t1 = temp_cert_key();
        let t2 = temp_cert_key();
        let t3 = temp_cert_key();
        let yaml = format!(
            r#"
certificates:
  - cert_path: {c1}
    key_path: {k1}
    server_names: ["api.example.com"]
  - cert_path: {c2}
    key_path: {k2}
    server_names: ["web.example.com"]
  - cert_path: {c3}
    key_path: {k3}
    default: true
"#,
            c1 = t1.cert,
            k1 = t1.key,
            c2 = t2.cert,
            k2 = t2.key,
            c3 = t3.cert,
            k3 = t3.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(tls.certificates.len(), 3, "should have 3 certificates");
        assert_eq!(
            tls.certificates[0].server_names,
            vec!["api.example.com"],
            "first cert server_names mismatch"
        );
        assert!(
            tls.certificates[2].server_names.is_empty(),
            "third cert should have no server_names"
        );
        assert!(tls.certificates[2].default, "third cert should be marked as default");
    }

    #[test]
    fn primary_cert_paths_returns_first() {
        let tmp = temp_cert_key();
        let tls = ListenerTls::new_validated(&tmp.cert, &tmp.key).unwrap();
        let (cert, key) = tls.primary_cert_paths();
        assert_eq!(cert, tmp.cert, "primary cert path mismatch");
        assert_eq!(key, tmp.key, "primary key path mismatch");
    }

    #[test]
    fn hot_reload_defaults_to_none() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert!(tls.hot_reload.is_none(), "hot_reload should default to None");
        assert!(
            tls.is_hot_reload(),
            "is_hot_reload should be true when None (default enabled)"
        );
    }

    #[test]
    fn hot_reload_true_single_cert_accepted() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\nhot_reload: true\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(tls.hot_reload, Some(true), "hot_reload should be Some(true)");
        assert!(tls.is_hot_reload(), "is_hot_reload should be true");
    }

    #[test]
    fn multi_cert_auto_disables_hot_reload() {
        let t1 = temp_cert_key();
        let t2 = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {c1}\n    key_path: {k1}\n    server_names: [\"a.example.com\"]\n  - cert_path: {c2}\n    key_path: {k2}\n    default: true\n",
            c1 = t1.cert,
            k1 = t1.key,
            c2 = t2.cert,
            k2 = t2.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert!(!tls.is_hot_reload(), "multi-cert should auto-disable hot-reload");
    }

    #[test]
    fn multi_cert_explicit_hot_reload_true_rejected() {
        let t1 = temp_cert_key();
        let t2 = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {c1}\n    key_path: {k1}\n    server_names: [\"a.example.com\"]\n  - cert_path: {c2}\n    key_path: {k2}\n    default: true\nhot_reload: true\n",
            c1 = t1.cert,
            k1 = t1.key,
            c2 = t2.cert,
            k2 = t2.key,
        );
        let result = serde_yaml::from_str::<ListenerTls>(&yaml);
        assert!(
            result.is_err(),
            "multi-cert with explicit hot_reload: true should be rejected"
        );
    }

    #[test]
    fn multi_cert_multiple_defaults_rejected() {
        let t1 = temp_cert_key();
        let t2 = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {c1}\n    key_path: {k1}\n    default: true\n  - cert_path: {c2}\n    key_path: {k2}\n    default: true\n",
            c1 = t1.cert,
            k1 = t1.key,
            c2 = t2.cert,
            k2 = t2.key,
        );
        let result = serde_yaml::from_str::<ListenerTls>(&yaml);
        assert!(result.is_err(), "multiple default: true entries should be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("multiple") && msg.contains("default"),
            "error should mention multiple defaults: {msg}"
        );
    }

    #[test]
    fn multi_cert_ambiguous_entry_rejected() {
        let t1 = temp_cert_key();
        let t2 = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {c1}\n    key_path: {k1}\n    server_names: [\"a.example.com\"]\n  - cert_path: {c2}\n    key_path: {k2}\n",
            c1 = t1.cert,
            k1 = t1.key,
            c2 = t2.cert,
            k2 = t2.key,
        );
        let result = serde_yaml::from_str::<ListenerTls>(&yaml);
        assert!(
            result.is_err(),
            "entry without server_names and without default: true should be rejected"
        );
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("ambiguous"), "error should mention ambiguous: {msg}");
    }

    #[test]
    fn multi_cert_all_with_server_names_no_default_valid() {
        let t1 = temp_cert_key();
        let t2 = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {c1}\n    key_path: {k1}\n    server_names: [\"a.example.com\"]\n  - cert_path: {c2}\n    key_path: {k2}\n    server_names: [\"b.example.com\"]\n",
            c1 = t1.cert,
            k1 = t1.key,
            c2 = t2.cert,
            k2 = t2.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            tls.certificates.len(),
            2,
            "all-server_names config should parse successfully"
        );
    }

    #[test]
    fn multi_cert_default_with_server_names_valid() {
        let t1 = temp_cert_key();
        let t2 = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {c1}\n    key_path: {k1}\n    server_names: [\"a.example.com\"]\n    default: true\n  - cert_path: {c2}\n    key_path: {k2}\n    server_names: [\"b.example.com\"]\n",
            c1 = t1.cert,
            k1 = t1.key,
            c2 = t2.cert,
            k2 = t2.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert!(tls.certificates[0].default, "first cert should be marked as default");
    }

    #[test]
    fn hot_reload_false_does_not_trigger() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\nhot_reload: false\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert!(
            !tls.is_hot_reload(),
            "is_hot_reload should be false when explicitly false"
        );
    }

    #[test]
    fn cipher_suites_deserialized() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\ncipher_suites:\n  - tls13_aes_256_gcm_sha384\n  - tls13_aes_128_gcm_sha256\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            tls.cipher_suites.as_ref().unwrap().len(),
            2,
            "should parse two cipher suites"
        );
        assert_eq!(
            tls.cipher_suites.as_ref().unwrap()[0],
            CipherSuiteId::Tls13Aes256GcmSha384,
            "first suite should be AES-256-GCM"
        );
    }

    #[test]
    fn cipher_suites_defaults_to_none() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert!(tls.cipher_suites.is_none(), "cipher_suites should default to None");
    }

    #[test]
    fn empty_cipher_suites_rejected() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\ncipher_suites: []\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let result = serde_yaml::from_str::<ListenerTls>(&yaml);
        assert!(result.is_err(), "empty cipher_suites should be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("cipher_suites must not be empty"),
            "error should mention empty cipher_suites: {msg}"
        );
    }

    #[test]
    fn tls12_cipher_suite_with_tls13_min_version_rejected() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\nmin_version: tls13\ncipher_suites:\n  - tls12_ecdhe_rsa_with_aes_128_gcm_sha256\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let result = serde_yaml::from_str::<ListenerTls>(&yaml);
        assert!(
            result.is_err(),
            "TLS 1.2 cipher suite with min_version tls13 should be rejected"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("TLS 1.2 suites"),
            "error should mention TLS 1.2 suites: {msg}"
        );
    }

    #[test]
    fn tls13_cipher_suite_with_tls13_min_version_accepted() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "certificates:\n  - cert_path: {cert}\n    key_path: {key}\nmin_version: tls13\ncipher_suites:\n  - tls13_aes_256_gcm_sha384\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let tls: ListenerTls = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            tls.cipher_suites.as_ref().unwrap().len(),
            1,
            "TLS 1.3 suite with tls13 min_version should be accepted"
        );
    }

    #[test]
    fn cipher_suite_id_is_tls12() {
        assert!(CipherSuiteId::Tls12EcdheRsaWithAes128GcmSha256.is_tls12());
        assert!(CipherSuiteId::Tls12EcdheEcdsaWithAes256GcmSha384.is_tls12());
        assert!(
            !CipherSuiteId::Tls13Aes256GcmSha384.is_tls12(),
            "TLS 1.3 suite should not be TLS 1.2"
        );
    }

    #[test]
    fn cipher_suite_id_to_rustls_round_trip() {
        let suite = CipherSuiteId::Tls13Aes256GcmSha384;
        let rustls_suite = suite.to_rustls();
        assert_eq!(
            format!("{:?}", rustls_suite.suite()),
            "TLS13_AES_256_GCM_SHA384",
            "should map to the correct rustls suite"
        );
    }

    #[test]
    fn all_cipher_suite_ids_deserialize() {
        let names = [
            "tls13_aes_128_gcm_sha256",
            "tls13_aes_256_gcm_sha384",
            "tls13_chacha20_poly1305_sha256",
            "tls12_ecdhe_ecdsa_with_aes_128_gcm_sha256",
            "tls12_ecdhe_ecdsa_with_aes_256_gcm_sha384",
            "tls12_ecdhe_ecdsa_with_chacha20_poly1305_sha256",
            "tls12_ecdhe_rsa_with_aes_128_gcm_sha256",
            "tls12_ecdhe_rsa_with_aes_256_gcm_sha384",
            "tls12_ecdhe_rsa_with_chacha20_poly1305_sha256",
        ];
        for name in names {
            let result: Result<CipherSuiteId, _> = serde_yaml::from_str(name);
            assert!(result.is_ok(), "cipher suite '{name}' should deserialize");
        }
    }

    // ---------------------------------------------------------------------------
    // Test Utilities
    // ---------------------------------------------------------------------------

    /// Temp file paths for cert and key, kept alive by the temp dir.
    struct TempPaths {
        /// Path string to the certificate file.
        cert: String,
        /// Path string to the key file.
        key: String,
        /// Temp directory holding the files.
        _dir: tempfile::TempDir,
    }

    /// Temp file paths for cert, key, and CA.
    struct TempPathsCa {
        /// Path string to the certificate file.
        cert: String,
        /// Path string to the key file.
        key: String,
        /// Path string to the CA file.
        ca: String,
        /// Temp directory holding the files.
        _dir: tempfile::TempDir,
    }

    /// Create temporary empty cert and key files that exist on disk.
    fn temp_cert_key() -> TempPaths {
        let dir = tempfile::TempDir::new().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, b"").unwrap();
        std::fs::write(&key, b"").unwrap();
        TempPaths {
            cert: cert.to_str().unwrap().to_owned(),
            key: key.to_str().unwrap().to_owned(),
            _dir: dir,
        }
    }

    /// Create temporary empty cert, key, and CA files that exist on disk.
    fn temp_cert_key_ca() -> TempPathsCa {
        let dir = tempfile::TempDir::new().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        let ca = dir.path().join("ca.pem");
        std::fs::write(&cert, b"").unwrap();
        std::fs::write(&key, b"").unwrap();
        std::fs::write(&ca, b"").unwrap();
        TempPathsCa {
            cert: cert.to_str().unwrap().to_owned(),
            key: key.to_str().unwrap().to_owned(),
            ca: ca.to_str().unwrap().to_owned(),
            _dir: dir,
        }
    }
}
