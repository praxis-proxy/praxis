// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! HS256 JWTs for the policy example tests, signed through the system OpenSSL.
//!
//! The policy engine verifies tokens with `jsonwebtoken`, whose aws-lc-rs
//! backend is exactly what the FIPS build leaves out. Minting the test tokens
//! with the same crate would put that backend back into the FIPS test build's
//! graph, so the tests do the one thing they need, HMAC-SHA256 over the
//! signing input (RFC 7515 section 5.1), through OpenSSL's EVP interface.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};

/// A compact-serialized HS256 JWT over `claims`, with `kid` in the header when
/// given, signed with `secret`.
pub(super) fn hs256(claims: &serde_json::Value, kid: Option<&str>, secret: &[u8]) -> String {
    let mut header = serde_json::Map::new();
    header.insert("alg".to_owned(), "HS256".into());
    header.insert("typ".to_owned(), "JWT".into());
    if let Some(kid) = kid {
        header.insert("kid".to_owned(), kid.into());
    }
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::Value::Object(header).to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let key = PKey::hmac(secret).expect("HMAC key");
    let mut signer = Signer::new(MessageDigest::sha256(), &key).expect("HMAC-SHA256 signer");
    signer
        .update(signing_input.as_bytes())
        .expect("feed the JWT signing input");
    let signature = signer.sign_to_vec().expect("HMAC-SHA256 signature");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}
