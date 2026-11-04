// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Exact-byte identity for loaded configuration sources.

use chrono::Utc;
use openssl::hash::{MessageDigest, hash};
use serde::Serialize;

/// Immutable identity of one successfully loaded configuration snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConfigIdentity {
    /// SHA-256 of the main configuration file's exact bytes.
    pub hash: String,
    /// SHA-256 of ordered referenced-document framing, or empty when none exist.
    pub documents_hash: String,
    /// UTC publication time in RFC3339 format.
    pub loaded_at: String,
}

impl ConfigIdentity {
    /// Compute an identity from exact main-file bytes and ordered document bytes.
    #[must_use]
    pub fn from_bytes(main: &[u8], documents: &[&[u8]]) -> Self {
        Self {
            hash: hex_digest(main),
            documents_hash: documents_hash(documents),
            loaded_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        }
    }
}

/// Hash ordered document bytes with an unambiguous length-prefixed framing.
fn documents_hash(documents: &[&[u8]]) -> String {
    if documents.is_empty() {
        return String::new();
    }
    let mut framed = Vec::new();
    for document in documents {
        framed.extend_from_slice(&u64::try_from(document.len()).unwrap_or(u64::MAX).to_be_bytes());
        framed.extend_from_slice(document);
    }
    hex_digest(&framed)
}

/// Render an OpenSSL SHA-256 digest as lower-case hexadecimal.
fn hex_digest(bytes: &[u8]) -> String {
    hash(MessageDigest::sha256(), bytes)
        .map(|digest| digest.iter().map(|byte| format!("{byte:02x}")).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_hash_matches_known_sha256_vector() {
        assert_eq!(
            hex_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn document_hash_is_empty_without_documents() {
        assert!(documents_hash(&[]).is_empty());
    }

    #[test]
    fn document_framing_is_ordered_and_length_delimited() {
        assert_ne!(documents_hash(&[b"ab", b"c"]), documents_hash(&[b"a", b"bc"]));
        assert_ne!(documents_hash(&[b"ab", b"c"]), documents_hash(&[b"c", b"ab"]));
    }
}
