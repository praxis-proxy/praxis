// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Certificate and key loading utilities.

use std::sync::Arc;

use rustls::{crypto::CryptoProvider, sign::CertifiedKey};

use crate::{CertKeyPair, TlsError};

// -----------------------------------------------------------------------------
// Crypto Provider
// -----------------------------------------------------------------------------

/// Return the process-wide default [`CryptoProvider`], or fall back to
/// `aws_lc_rs` if none has been installed yet.
///
/// ```ignore
/// let provider = praxis_tls::setup::default_crypto_provider();
/// assert!(!provider.cipher_suites.is_empty());
/// ```
///
/// [`CryptoProvider`]: rustls::crypto::CryptoProvider
pub(crate) fn default_crypto_provider() -> Arc<CryptoProvider> {
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

// -----------------------------------------------------------------------------
// Certificate Loading
// -----------------------------------------------------------------------------

/// Load a [`CertifiedKey`] from a [`CertKeyPair`].
///
/// [`CertifiedKey`]: rustls::sign::CertifiedKey
/// [`CertKeyPair`]: crate::CertKeyPair
pub(super) fn load_certified_key(pair: &CertKeyPair) -> Result<CertifiedKey, TlsError> {
    let (certs, key) = load_cert_and_key(pair)?;
    let provider = default_crypto_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| TlsError::FileLoadError {
            path: pair.key_path.clone(),
            detail: format!("unsupported private key type: {e}"),
        })?;
    Ok(CertifiedKey::new(certs, signing_key))
}

/// Load certificate chain and private key from PEM files.
pub(super) fn load_cert_and_key(
    pair: &CertKeyPair,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    TlsError,
> {
    let cert_pem = std::fs::read(&pair.cert_path).map_err(|e| TlsError::FileLoadError {
        path: pair.cert_path.clone(),
        detail: format!("failed to read cert: {e}"),
    })?;
    let key_pem = std::fs::read(&pair.key_path).map_err(|e| TlsError::FileLoadError {
        path: pair.key_path.clone(),
        detail: format!("failed to read key: {e}"),
    })?;

    let certs = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::FileLoadError {
            path: pair.cert_path.clone(),
            detail: format!("failed to parse cert PEM: {e}"),
        })?;

    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| TlsError::FileLoadError {
            path: pair.key_path.clone(),
            detail: format!("failed to parse key PEM: {e}"),
        })?
        .ok_or_else(|| TlsError::FileLoadError {
            path: pair.key_path.clone(),
            detail: "no private key found in PEM file".to_owned(),
        })?;

    Ok((certs, key))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_crypto_provider_returns_provider() {
        let provider = default_crypto_provider();
        assert!(
            !provider.cipher_suites.is_empty(),
            "crypto provider should have at least one cipher suite"
        );
    }
}
