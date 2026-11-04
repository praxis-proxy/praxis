// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Exact-byte identity for loaded configuration sources.

use chrono::Utc;
use openssl::hash::{MessageDigest, hash};
use serde::Serialize;
use thiserror::Error;

/// Errors that prevent constructing a configuration identity.
#[derive(Debug, Error)]
pub enum ConfigIdentityError {
    /// OpenSSL could not compute a SHA-256 digest.
    #[error("configuration identity digest failed: {0}")]
    Digest(#[from] openssl::error::ErrorStack),
    /// A document length could not be represented by the framing format.
    #[error("configuration document is too large to frame")]
    LengthOverflow,
}

/// Immutable identity of one successfully loaded configuration snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConfigIdentity {
    /// SHA-256 of the main configuration file's exact bytes.
    hash: String,
    /// SHA-256 of ordered referenced-document framing, or empty when none exist.
    documents_hash: String,
    /// UTC publication time in RFC3339 format.
    loaded_at: String,
}

impl ConfigIdentity {
    /// Compute an identity from exact main-file bytes and ordered document bytes.
    pub fn from_bytes(main: &[u8], documents: &[&[u8]]) -> Result<Self, ConfigIdentityError> {
        Ok(Self {
            hash: hex_digest(main)?,
            documents_hash: documents_hash(documents)?,
            loaded_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        })
    }

    /// Return the main configuration file digest.
    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Return the ordered referenced-document digest.
    #[must_use]
    pub fn documents_hash(&self) -> &str {
        &self.documents_hash
    }

    /// Return the UTC publication timestamp.
    #[must_use]
    pub fn loaded_at(&self) -> &str {
        &self.loaded_at
    }
}

/// Hash ordered document bytes with an unambiguous length-prefixed framing.
fn documents_hash(documents: &[&[u8]]) -> Result<String, ConfigIdentityError> {
    if documents.is_empty() {
        return Ok(String::new());
    }
    let mut framed = Vec::new();
    for document in documents {
        let length = u64::try_from(document.len()).map_err(|_| ConfigIdentityError::LengthOverflow)?;
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(document);
    }
    hex_digest(&framed)
}

/// Render an OpenSSL SHA-256 digest as lower-case hexadecimal.
fn hex_digest(bytes: &[u8]) -> Result<String, ConfigIdentityError> {
    Ok(hash(MessageDigest::sha256(), bytes)?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_hash_matches_known_sha256_vector() {
        assert_eq!(
            hex_digest(b"abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn document_hash_is_empty_without_documents() {
        assert!(documents_hash(&[]).unwrap().is_empty());
    }

    #[test]
    fn document_framing_is_ordered_and_length_delimited() {
        assert_ne!(documents_hash(&[b"ab", b"c"]).unwrap(), documents_hash(&[b"a", b"bc"]).unwrap());
        assert_ne!(documents_hash(&[b"ab", b"c"]).unwrap(), documents_hash(&[b"c", b"ab"]).unwrap());
    }
}
