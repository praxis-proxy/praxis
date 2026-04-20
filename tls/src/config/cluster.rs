// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Cluster (upstream) TLS configuration.

use serde::{Deserialize, Deserializer, Serialize, de};

use super::{CaConfig, CertKeyPair, default_true};
use crate::TlsError;

// -----------------------------------------------------------------------------
// ClusterTls
// -----------------------------------------------------------------------------

/// TLS settings for upstream connections (client role).
///
/// Presence of this struct on a cluster implies TLS is enabled.
///
/// ```
/// use praxis_tls::ClusterTls;
///
/// let tls: ClusterTls = serde_yaml::from_str(
///     r#"
/// sni: "api.example.com"
/// "#,
/// )
/// .unwrap();
/// assert_eq!(tls.sni.as_deref(), Some("api.example.com"));
/// assert!(tls.verify);
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct ClusterTls {
    /// Custom CA for verifying upstream certs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca: Option<CaConfig>,

    /// Client certificate Praxis presents to upstream (mTLS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<CertKeyPair>,

    /// SNI hostname for outbound connections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,

    /// Verify upstream certificate. Default: `true`.
    pub verify: bool,
}

/// Raw deserialization helper for [`ClusterTls`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClusterTlsRaw {
    /// Custom CA.
    #[serde(default)]
    ca: Option<CaConfig>,

    /// Client certificate for upstream mTLS.
    #[serde(default)]
    client_cert: Option<CertKeyPair>,

    /// SNI hostname.
    #[serde(default)]
    sni: Option<String>,

    /// Verify upstream certificate.
    #[serde(default = "default_true")]
    verify: bool,
}

impl<'de> Deserialize<'de> for ClusterTls {
    /// Deserialize and validate cluster TLS config.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = ClusterTlsRaw::deserialize(deserializer)?;
        let config = Self {
            ca: raw.ca,
            client_cert: raw.client_cert,
            sni: raw.sni,
            verify: raw.verify,
        };
        config.validate().map_err(de::Error::custom)?;
        Ok(config)
    }
}

impl ClusterTls {
    /// Validate path traversal and cert/key pairing.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if any path contains `..`.
    ///
    /// [`TlsError`]: crate::TlsError
    pub fn validate(&self) -> Result<(), TlsError> {
        if let Some(ref ca) = self.ca {
            ca.validate()?;
        }
        if let Some(ref cert) = self.client_cert {
            cert.validate()?;
        }
        Ok(())
    }
}

impl Default for ClusterTls {
    /// Default cluster TLS: verify enabled, no custom CA or client cert.
    fn default() -> Self {
        Self {
            ca: None,
            client_cert: None,
            sni: None,
            verify: true,
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn cluster_tls_defaults() {
        let tls = ClusterTls::default();
        assert!(tls.verify, "verify should default to true");
        assert!(tls.sni.is_none(), "sni should default to None");
        assert!(tls.ca.is_none(), "ca should default to None");
        assert!(tls.client_cert.is_none(), "client_cert should default to None");
    }

    #[test]
    fn cluster_tls_deserializes_sni() {
        let tls: ClusterTls = serde_yaml::from_str("sni: api.example.com\n").unwrap();
        assert_eq!(tls.sni.as_deref(), Some("api.example.com"), "sni mismatch");
        assert!(tls.verify, "verify should default to true");
    }

    #[test]
    fn cluster_tls_verify_disabled() {
        let tls: ClusterTls = serde_yaml::from_str("verify: false\n").unwrap();
        assert!(!tls.verify, "verify should be false when set to false");
    }

    #[test]
    fn cluster_tls_with_client_cert() {
        let tmp = temp_cert_key();
        let yaml = format!(
            "client_cert:\n  cert_path: {cert}\n  key_path: {key}\n",
            cert = tmp.cert,
            key = tmp.key,
        );
        let tls: ClusterTls = serde_yaml::from_str(&yaml).unwrap();
        let cert = tls.client_cert.unwrap();
        assert_eq!(cert.cert_path, tmp.cert, "client cert_path mismatch");
        assert_eq!(cert.key_path, tmp.key, "client key_path mismatch");
    }

    #[test]
    fn cluster_tls_with_ca() {
        let tmp = temp_ca();
        let yaml = format!("ca:\n  ca_path: {ca}\n", ca = tmp.ca);
        let tls: ClusterTls = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(tls.ca.unwrap().ca_path, tmp.ca, "cluster ca_path mismatch");
    }

    #[test]
    fn cluster_tls_rejects_path_traversal_in_ca() {
        let result = serde_yaml::from_str::<ClusterTls>("ca:\n  ca_path: /etc/../../evil.pem\n");
        assert!(result.is_err(), "path traversal in ca should be rejected");
    }

    #[test]
    fn cluster_tls_rejects_path_traversal_in_client_cert() {
        let result = serde_yaml::from_str::<ClusterTls>(
            "client_cert:\n  cert_path: /etc/../../evil.pem\n  key_path: /key.pem\n",
        );
        assert!(result.is_err(), "path traversal in client_cert should be rejected");
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

    /// Temp file paths for CA, kept alive by the temp dir.
    struct TempCa {
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

    /// Create temporary empty CA file that exists on disk.
    fn temp_ca() -> TempCa {
        let dir = tempfile::TempDir::new().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, b"").unwrap();
        TempCa {
            ca: ca.to_str().unwrap().to_owned(),
            _dir: dir,
        }
    }
}
