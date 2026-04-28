// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Client certificate verifier construction for listener mTLS.

use std::sync::Arc;

use rustls::{
    RootCertStore,
    server::{WebPkiClientVerifier, danger::ClientCertVerifier},
};

use crate::{ClientCertMode, TlsError};

// -----------------------------------------------------------------------------
// Verifier Builder
// -----------------------------------------------------------------------------

/// Build a [`ClientCertVerifier`] from a CA PEM file and verification mode.
///
/// # Errors
///
/// Returns [`TlsError`] if the CA file cannot be read or parsed, or
/// if `mode` is [`ClientCertMode::None`].
///
/// ```ignore
/// use std::sync::Arc;
///
/// use crate::{ClientCertMode, client_auth::build_client_verifier};
///
/// let verifier = build_client_verifier("/etc/ssl/client-ca.pem", &ClientCertMode::Require)
///     .expect("valid CA file");
/// ```
///
/// [`ClientCertVerifier`]: rustls::server::danger::ClientCertVerifier
/// [`TlsError`]: crate::TlsError
/// [`ClientCertMode::None`]: crate::ClientCertMode::None
pub(crate) fn build_client_verifier(
    ca_path: &str,
    mode: &ClientCertMode,
) -> Result<Arc<dyn ClientCertVerifier>, TlsError> {
    let root_store = load_ca_root_store(ca_path)?;
    let builder = WebPkiClientVerifier::builder(Arc::new(root_store));

    let verifier_err = |detail: String| TlsError::FileLoadError {
        path: ca_path.to_owned(),
        detail,
    };

    match mode {
        ClientCertMode::Request => builder
            .allow_unauthenticated()
            .build()
            .map_err(|e| verifier_err(format!("failed to build verifier: {e}"))),
        ClientCertMode::Require => builder
            .build()
            .map_err(|e| verifier_err(format!("failed to build verifier: {e}"))),
        ClientCertMode::None => Err(TlsError::ClientVerifierNotRequired),
    }
}

/// Load CA certificates from a PEM file into a [`RootCertStore`].
///
/// [`RootCertStore`]: rustls::RootCertStore
fn load_ca_root_store(ca_path: &str) -> Result<RootCertStore, TlsError> {
    let ca_pem = std::fs::read(ca_path).map_err(|e| TlsError::FileLoadError {
        path: ca_path.to_owned(),
        detail: e.to_string(),
    })?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut &ca_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::FileLoadError {
            path: ca_path.to_owned(),
            detail: format!("failed to parse PEM: {e}"),
        })?;

    if certs.is_empty() {
        return Err(TlsError::FileLoadError {
            path: ca_path.to_owned(),
            detail: "no certificates found in PEM file".to_owned(),
        });
    }

    let mut root_store = RootCertStore::empty();
    for cert in certs {
        root_store.add(cert).map_err(|e| TlsError::FileLoadError {
            path: ca_path.to_owned(),
            detail: format!("failed to add CA cert: {e}"),
        })?;
    }

    Ok(root_store)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::test_utils::gen_ca_file;

    #[test]
    fn build_client_verifier_require_with_valid_ca() {
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let verifier = build_client_verifier(ca_path, &ClientCertMode::Require)
            .expect("require mode with valid CA should succeed");
        assert!(
            verifier.client_auth_mandatory(),
            "require mode should mandate client auth"
        );
    }

    #[test]
    fn build_client_verifier_request_with_valid_ca() {
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let verifier = build_client_verifier(ca_path, &ClientCertMode::Request)
            .expect("request mode with valid CA should succeed");
        assert!(
            !verifier.client_auth_mandatory(),
            "request mode should not mandate client auth"
        );
    }

    #[test]
    fn build_client_verifier_none_mode_returns_error() {
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let err = build_client_verifier(ca_path, &ClientCertMode::None).expect_err("mode=None should return error");
        assert!(
            matches!(err, TlsError::ClientVerifierNotRequired),
            "error should be ClientVerifierNotRequired, got: {err}"
        );
    }

    #[test]
    fn build_client_verifier_invalid_ca_path_returns_error() {
        let err = build_client_verifier("/nonexistent/ca.pem", &ClientCertMode::Require)
            .expect_err("nonexistent CA should fail");
        assert!(
            matches!(err, TlsError::FileLoadError { .. }),
            "error should be FileLoadError, got: {err}"
        );
    }

    #[test]
    fn load_ca_root_store_with_valid_ca() {
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let store = load_ca_root_store(ca_path).expect("valid CA file should load");
        assert!(!store.is_empty(), "root store should contain at least one certificate");
    }

    #[test]
    fn load_ca_root_store_empty_pem_returns_error() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let empty_path = temp_dir.path().join("empty.pem");
        std::fs::write(&empty_path, "").expect("write empty PEM should succeed");

        let err = load_ca_root_store(empty_path.to_str().expect("path should be valid UTF-8"))
            .expect_err("empty PEM should fail");
        assert!(
            matches!(err, TlsError::FileLoadError { ref detail, .. } if detail.contains("no certificates")),
            "error should mention no certificates, got: {err}"
        );
    }

    #[test]
    fn load_ca_root_store_nonexistent_file_returns_error() {
        let err = load_ca_root_store("/nonexistent/ca.pem").expect_err("nonexistent file should fail");
        assert!(
            matches!(err, TlsError::FileLoadError { .. }),
            "error should be FileLoadError, got: {err}"
        );
    }
}
