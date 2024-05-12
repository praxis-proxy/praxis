// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Listener TLS configuration: `ListenerTls`, `ClientCertMode`, and `TlsVersion`.

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

    /// CA for client certificate verification (mTLS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ca: Option<CaConfig>,

    /// Client cert verification mode.
    #[serde(skip_serializing_if = "is_default_cert_mode")]
    pub client_cert_mode: ClientCertMode,

    /// Minimum TLS version accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_version: Option<TlsVersion>,
}

/// Raw deserialization helper for [`ListenerTls`].
#[derive(Deserialize)]
struct ListenerTlsRaw {
    /// Server certificates.
    certificates: Vec<CertKeyPair>,

    /// CA for client certificate verification.
    #[serde(default)]
    client_ca: Option<CaConfig>,

    /// Client cert verification mode.
    #[serde(default)]
    client_cert_mode: ClientCertMode,

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
            client_ca: raw.client_ca,
            client_cert_mode: raw.client_cert_mode,
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
                key_path: key_path.into(),
                server_names: Vec::new(),
            }],
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
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

        if let Some(ref ca) = self.client_ca {
            ca.validate()?;
        }

        if self.client_cert_mode != ClientCertMode::None && self.client_ca.is_none() {
            return Err(TlsError::MissingClientCa {
                mode: self.client_cert_mode.clone(),
            });
        }

        Ok(())
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
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
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
    }

    #[test]
    fn primary_cert_paths_returns_first() {
        let tmp = temp_cert_key();
        let tls = ListenerTls::new_validated(&tmp.cert, &tmp.key).unwrap();
        let (cert, key) = tls.primary_cert_paths();
        assert_eq!(cert, tmp.cert, "primary cert path mismatch");
        assert_eq!(key, tmp.key, "primary key path mismatch");
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
