// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

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
    /// Absolute paths are allowed because operators commonly use
    /// paths like `/etc/ssl/certs/server.pem` in production.
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
        for name in &self.server_names {
            validate_server_name(name)?;
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
/// assert!(ca.crl_paths.is_empty());
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    /// Path to the PEM CA certificate file.
    pub ca_path: String,

    /// Paths to PEM-encoded certificate revocation list (CRL) files.
    ///
    /// When provided, the mTLS client verifier checks presented
    /// client certificates against these CRLs and rejects revoked
    /// certificates.
    #[serde(default)]
    pub crl_paths: Vec<String>,
}

impl CaConfig {
    /// Validate the CA and CRL paths: reject `..` traversal.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::PathTraversal`] if any path contains `..`.
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

        for (i, crl_path) in self.crl_paths.iter().enumerate() {
            let field = format!("crl_paths[{i}]");
            if has_parent_dir_component(crl_path) {
                return Err(TlsError::PathTraversal {
                    field,
                    path: crl_path.clone(),
                });
            }
            warn_if_symlink(&field, crl_path);
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Server Name Validation
// -----------------------------------------------------------------------------

/// Validate a `server_names` entry as a DNS hostname or wildcard.
fn validate_server_name(name: &str) -> Result<(), TlsError> {
    if name.is_empty() {
        return Err(TlsError::ServerConfigError {
            detail: "server_names entry must not be empty".to_owned(),
        });
    }
    let mut has_wildcard = false;
    let mut label_count: usize = 0;
    for (i, label) in name.split('.').enumerate() {
        label_count += 1;
        if label == "*" && i == 0 {
            has_wildcard = true;
            continue;
        }
        validate_dns_label(name, label)?;
    }
    if has_wildcard && label_count < 3 {
        return Err(TlsError::ServerConfigError {
            detail: format!("server_names '{name}': wildcard requires at least 3 labels (e.g. *.example.com)"),
        });
    }
    Ok(())
}

/// Validate a single DNS label within a server name.
fn validate_dns_label(name: &str, label: &str) -> Result<(), TlsError> {
    if label.is_empty() || label.len() > 63 {
        return Err(TlsError::ServerConfigError {
            detail: format!("server_names '{name}': label has invalid length"),
        });
    }
    if label.contains('*') {
        return Err(TlsError::ServerConfigError {
            detail: format!("server_names '{name}': wildcard only permitted as the complete leftmost label"),
        });
    }
    if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(TlsError::ServerConfigError {
            detail: format!("server_names '{name}': contains invalid characters"),
        });
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(TlsError::ServerConfigError {
            detail: format!("server_names '{name}': label must not start or end with a hyphen"),
        });
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
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
            crl_paths: Vec::new(),
        };
        assert!(ca.validate().is_ok(), "existing ca_path should validate");
    }

    #[test]
    fn ca_config_rejects_traversal() {
        let ca = CaConfig {
            ca_path: "/etc/../../evil.pem".to_owned(),
            crl_paths: Vec::new(),
        };
        assert!(ca.validate().is_err(), "traversal in ca_path should fail validation");
    }

    #[test]
    fn ca_config_rejects_crl_traversal() {
        let ca = CaConfig {
            ca_path: "/etc/ssl/ca.pem".to_owned(),
            crl_paths: vec!["/etc/../../evil.crl".to_owned()],
        };
        let err = ca.validate().unwrap_err();
        assert!(
            err.to_string().contains("crl_paths[0]"),
            "should mention crl_paths: {err}"
        );
    }

    #[test]
    fn reject_bare_wildcard() {
        let err = validate_server_name("*").unwrap_err();
        assert!(
            err.to_string().contains("at least 3 labels"),
            "bare wildcard should be rejected: {err}"
        );
    }

    #[test]
    fn reject_two_label_wildcard() {
        let err = validate_server_name("*.com").unwrap_err();
        assert!(
            err.to_string().contains("at least 3 labels"),
            "two-label wildcard should be rejected: {err}"
        );
    }

    #[test]
    fn accept_three_label_wildcard() {
        validate_server_name("*.example.com").expect("three-label wildcard should be accepted");
    }

    #[test]
    fn reject_server_name_with_leading_hyphen() {
        let pair = CertKeyPair {
            cert_path: "/tmp/cert.pem".to_owned(),
            default: false,
            key_path: "/tmp/key.pem".to_owned(),
            server_names: vec!["-example.com".to_owned()],
        };
        let err = pair.validate().unwrap_err();
        assert!(
            err.to_string().contains("must not start or end with a hyphen"),
            "should reject leading hyphen: {err}"
        );
    }

    #[test]
    fn reject_server_name_with_trailing_hyphen() {
        let pair = CertKeyPair {
            cert_path: "/tmp/cert.pem".to_owned(),
            default: false,
            key_path: "/tmp/key.pem".to_owned(),
            server_names: vec!["example-.com".to_owned()],
        };
        let err = pair.validate().unwrap_err();
        assert!(
            err.to_string().contains("must not start or end with a hyphen"),
            "should reject trailing hyphen in label: {err}"
        );
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_field() {
        let yaml = "cert_path: /etc/ssl/cert.pem\nkey_path: /etc/ssl/key.pem\nbogus: true\n";
        let err = serde_yaml::from_str::<CertKeyPair>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "extra field should be rejected by deny_unknown_fields: {err}"
        );
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
