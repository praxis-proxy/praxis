// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! TLS error types.

use thiserror::Error;

use crate::ClientCertMode;

// -----------------------------------------------------------------------------
// TlsError
// -----------------------------------------------------------------------------

/// Errors from TLS configuration validation.
///
/// ```
/// use praxis_tls::TlsError;
///
/// let e = TlsError::PathTraversal {
///     field: "cert_path".to_owned(),
///     path: "/etc/../../tmp/evil.pem".to_owned(),
/// };
/// assert!(e.to_string().contains("path traversal"));
///
/// let e = TlsError::FileLoadError {
///     path: "/etc/ssl/cert.pem".to_owned(),
///     detail: "file not found".to_owned(),
/// };
/// assert!(e.to_string().contains("failed to load TLS file"));
/// ```
#[derive(Debug, Error)]
pub enum TlsError {
    /// Failed to load or parse a TLS file (certificate, key, or CA).
    #[error("failed to load TLS file {path}: {detail}")]
    FileLoadError {
        /// The path that failed to load.
        path: String,

        /// Underlying error description.
        detail: String,
    },

    /// `client_cert_mode` is `request` or `require` but `client_ca` is not set.
    #[error("client_ca is required when client_cert_mode is {mode:?}")]
    MissingClientCa {
        /// The mode that requires a CA.
        mode: ClientCertMode,
    },

    /// No certificates provided in listener TLS config.
    #[error("at least one certificate is required in listener TLS config")]
    NoCertificates,

    /// A TLS path contains `..` (directory traversal).
    #[error("TLS {field} must not contain path traversal (..): {path}")]
    PathTraversal {
        /// Which field failed validation (e.g. "`cert_path`").
        field: String,

        /// The offending path value.
        path: String,
    },
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_path_traversal() {
        let e = TlsError::PathTraversal {
            field: "key_path".to_owned(),
            path: "../secret/key.pem".to_owned(),
        };
        assert!(
            e.to_string().contains("path traversal"),
            "should mention path traversal"
        );
        assert!(e.to_string().contains("key_path"), "should mention key_path field");
    }

    #[test]
    fn error_display_missing_client_ca() {
        let e = TlsError::MissingClientCa {
            mode: ClientCertMode::Require,
        };
        assert!(
            e.to_string().contains("client_ca"),
            "should mention missing client_ca: {e}"
        );
    }

    #[test]
    fn error_display_no_certificates() {
        let e = TlsError::NoCertificates;
        assert!(
            e.to_string().contains("at least one certificate"),
            "should mention certificate requirement"
        );
    }
}
