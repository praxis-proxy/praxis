// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Certificate/key pair and CA configuration types.

use serde::{Deserialize, Serialize};

use super::{has_parent_dir_component, warn_if_symlink};
use crate::TlsError;

// -----------------------------------------------------------------------------
// CertKeyPair
// -----------------------------------------------------------------------------

/// A certificate and private key pair.
///
/// ```
/// use praxis_tls::CertKeyPair;
///
/// let pair: CertKeyPair = serde_yaml::from_str(
///     r#"
/// cert_path: "/etc/ssl/cert.pem"
/// key_path: "/etc/ssl/key.pem"
/// "#,
/// )
/// .unwrap();
/// assert_eq!(pair.cert_path, "/etc/ssl/cert.pem");
/// assert_eq!(pair.key_path, "/etc/ssl/key.pem");
/// assert!(pair.server_names.is_empty());
///
/// // Paths without traversal pass validation:
/// assert!(pair.validate().is_ok());
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertKeyPair {
    /// Path to the PEM certificate file.
    pub cert_path: String,

    /// Whether this certificate is the default fallback for unmatched SNI.
    ///
    /// At most one certificate in a multi-cert config may set this to
    /// `true`. The default entry does not need `server_names`.
    #[serde(default)]
    pub default: bool,

    /// Path to the PEM private key file.
    pub key_path: String,

    /// SNI hostnames this certificate serves (listener only).
    #[serde(default)]
    pub server_names: Vec<String>,
}

impl CertKeyPair {
    /// Validate paths: reject `..` traversal.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::PathTraversal`] if any path contains `..`.
    ///
    /// [`TlsError::PathTraversal`]: crate::TlsError::PathTraversal
    pub fn validate(&self) -> Result<(), TlsError> {
        for (field, path) in [("cert_path", &self.cert_path), ("key_path", &self.key_path)] {
            if has_parent_dir_component(path) {
                return Err(TlsError::PathTraversal {
                    field: field.to_owned(),
                    path: path.to_owned(),
                });
            }
            warn_if_symlink(field, path);
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// CaConfig
// -----------------------------------------------------------------------------

/// CA trust configuration for peer certificate verification.
///
/// ```
/// use praxis_tls::CaConfig;
///
/// let ca: CaConfig = serde_yaml::from_str("ca_path: /etc/ssl/ca.pem\n").unwrap();
/// assert_eq!(ca.ca_path, "/etc/ssl/ca.pem");
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    /// Path to the PEM CA certificate file.
    pub ca_path: String,
}

impl CaConfig {
    /// Validate the CA path: reject `..` traversal.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::PathTraversal`] if the path contains `..`.
    ///
    /// [`TlsError::PathTraversal`]: crate::TlsError::PathTraversal
    pub fn validate(&self) -> Result<(), TlsError> {
        if has_parent_dir_component(&self.ca_path) {
            return Err(TlsError::PathTraversal {
                field: "ca_path".to_owned(),
                path: self.ca_path.clone(),
            });
        }
        warn_if_symlink("ca_path", &self.ca_path);
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::ListenerTls;

    #[test]
    fn cert_key_pair_validates_existing_paths() {
        let tmp = temp_cert_key();
        let pair = CertKeyPair {
            cert_path: tmp.cert.clone(),
            default: false,
            key_path: tmp.key.clone(),
            server_names: Vec::new(),
        };
        assert!(pair.validate().is_ok(), "existing paths should validate");
    }

    #[test]
    fn cert_path_traversal_rejected() {
        let err = ListenerTls::new_validated("/etc/../../tmp/evil.pem", "/etc/ssl/key.pem").unwrap_err();
        assert!(err.to_string().contains("cert_path"), "should mention cert_path");
        assert!(
            err.to_string().contains("path traversal"),
            "should mention path traversal"
        );
    }

    #[test]
    fn key_path_traversal_rejected() {
        let err = ListenerTls::new_validated("/etc/ssl/cert.pem", "../secret/key.pem").unwrap_err();
        assert!(err.to_string().contains("key_path"), "should mention key_path");
        assert!(
            err.to_string().contains("path traversal"),
            "should mention path traversal"
        );
    }

    #[test]
    fn double_dots_in_filename_not_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let cert = dir.path().join("my..cert.pem");
        let key = dir.path().join("key..pem");
        std::fs::write(&cert, b"").unwrap();
        std::fs::write(&key, b"").unwrap();
        let cert_s = cert.to_str().unwrap();
        let key_s = key.to_str().unwrap();

        let tls = ListenerTls::new_validated(cert_s, key_s).unwrap();
        assert_eq!(tls.certificates[0].cert_path, cert_s, "dotted cert_path mismatch");
        assert_eq!(tls.certificates[0].key_path, key_s, "dotted key_path mismatch");
    }

    #[test]
    fn ca_config_validates_existing_path() {
        let tmp = temp_cert_key_ca();
        let ca = CaConfig {
            ca_path: tmp.ca.clone(),
        };
        assert!(ca.validate().is_ok(), "existing ca_path should validate");
    }

    #[test]
    fn ca_config_rejects_traversal() {
        let ca = CaConfig {
            ca_path: "/etc/../../evil.pem".to_owned(),
        };
        assert!(ca.validate().is_err(), "traversal in ca_path should fail validation");
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
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, b"").unwrap();
        TempPathsCa {
            ca: ca.to_str().unwrap().to_owned(),
            _dir: dir,
        }
    }
}
