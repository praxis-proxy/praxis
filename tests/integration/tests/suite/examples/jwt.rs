// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Test utilities for JWTs and DPoP proofs signed through the
//! system OpenSSL.
//!
//! The policy engine verifies tokens with `jsonwebtoken`, and its ordinary
//! backend (aws-lc-rs) is exactly what the FIPS build leaves out. Minting the
//! test tokens with the same crate would put that backend back into the FIPS
//! test build's graph, so the tests sign the JWS signing input (RFC 7515
//! section 5.1) through OpenSSL's EVP interface. On a FIPS host that is the
//! FIPS provider, so the asymmetric helpers work in every build.

#![cfg_attr(
    not(feature = "policy-jwt-openssl-fips"),
    expect(dead_code, reason = "the asymmetric and DPoP helpers serve the FIPS examples only")
)]

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    bn::BigNumContext,
    ec::PointConversionForm,
    ecdsa::EcdsaSig,
    hash::{MessageDigest, hash},
    pkey::{PKey, Private},
    sign::Signer,
};
use serde_json::{Value, json};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Sequence number distinguishing tokens and proofs in this process.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A compact-serialized HS256 JWT over `claims`, with `kid` in the header when
/// given, signed with `secret`.
pub(super) fn hs256(claims: &Value, kid: Option<&str>, secret: &[u8]) -> String {
    let key = PKey::hmac(secret).expect("HMAC key");
    sign(&header("HS256", "JWT", kid), claims, |input| sign_with(&key, input))
}

/// A compact-serialized RS256 JWT over `claims`, signed with the RSA key in
/// `pem`.
pub(super) fn rs256(claims: &Value, kid: Option<&str>, pem: &[u8]) -> String {
    let key = PKey::private_key_from_pem(pem).expect("RSA private key");
    sign(&header("RS256", "JWT", kid), claims, |input| sign_with(&key, input))
}

/// A compact-serialized ES256 JWT over `claims`, signed with the P-256 key in
/// `pem`.
pub(super) fn es256(claims: &Value, kid: Option<&str>, pem: &[u8]) -> String {
    let key = PKey::private_key_from_pem(pem).expect("P-256 private key");
    sign(&header("ES256", "JWT", kid), claims, |input| {
        es256_signature(&key, input)
    })
}

/// A DPoP proof (RFC 9449 section 4.2) for `method` and `url`, binding
/// `access_token`, signed with the P-256 client key in `pem`. Each call
/// carries the current `iat` and a fresh `jti`.
pub(super) fn dpop_proof(pem: &[u8], method: &str, url: &str, access_token: &str) -> String {
    let key = PKey::private_key_from_pem(pem).expect("P-256 client key");
    let mut header = header("ES256", "dpop+jwt", None);
    header.insert("jwk".to_owned(), p256_jwk(&key));
    let claims = json!({
        "htm": method,
        "htu": url,
        "iat": now(),
        "jti": fresh_jti(),
        "ath": URL_SAFE_NO_PAD.encode(hash(MessageDigest::sha256(), access_token.as_bytes()).expect("SHA-256")),
    });
    sign(&header, &claims, |input| es256_signature(&key, input))
}

/// The RFC 7638 thumbprint of the P-256 client key in `pem`, as a token's
/// `cnf.jkt` names it.
pub(super) fn jwk_thumbprint(pem: &[u8]) -> String {
    let key = PKey::private_key_from_pem(pem).expect("P-256 client key");
    let jwk = p256_jwk(&key);
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        jwk["x"].as_str().expect("x"),
        jwk["y"].as_str().expect("y")
    );
    URL_SAFE_NO_PAD.encode(hash(MessageDigest::sha256(), canonical.as_bytes()).expect("SHA-256"))
}

/// Seconds since the Unix epoch.
pub(super) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs()
}

// -----------------------------------------------------------------------------
// Signing
// -----------------------------------------------------------------------------

/// A JOSE header with `alg`, `typ` and an optional `kid`.
fn header(alg: &str, typ: &str, kid: Option<&str>) -> serde_json::Map<String, Value> {
    let mut header = serde_json::Map::new();
    header.insert("alg".to_owned(), alg.into());
    header.insert("typ".to_owned(), typ.into());
    if let Some(kid) = kid {
        header.insert("kid".to_owned(), kid.into());
    }
    header
}

/// The compact serialization of `header` and `claims`, signed by `signature`.
fn sign(header: &serde_json::Map<String, Value>, claims: &Value, signature: impl FnOnce(&[u8]) -> Vec<u8>) -> String {
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(Value::Object(header.clone()).to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = signature(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// A SHA-256 signature (HMAC or RSA PKCS#1 v1.5, by key type) over `input`.
fn sign_with(key: &PKey<Private>, input: &[u8]) -> Vec<u8> {
    let mut signer = Signer::new(MessageDigest::sha256(), key).expect("SHA-256 signer");
    signer.update(input).expect("feed the JWS signing input");
    signer.sign_to_vec().expect("JWS signature")
}

/// An ES256 signature: OpenSSL's DER signature as the fixed-width `R || S`
/// JWS requires (RFC 7518 section 3.4).
fn es256_signature(key: &PKey<Private>, input: &[u8]) -> Vec<u8> {
    let der = sign_with(key, input);
    let signature = EcdsaSig::from_der(&der).expect("DER ECDSA signature");
    let mut raw = signature.r().to_vec_padded(32).expect("R in 32 bytes");
    raw.extend(signature.s().to_vec_padded(32).expect("S in 32 bytes"));
    raw
}

/// The public JWK of a P-256 key.
fn p256_jwk(key: &PKey<Private>) -> Value {
    let ec = key.ec_key().expect("an EC key");
    let mut context = BigNumContext::new().expect("BN context");
    let point = ec
        .public_key()
        .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut context)
        .expect("uncompressed point");
    let (x, y) = point
        .get(1..33)
        .zip(point.get(33..65))
        .expect("a 65-byte uncompressed P-256 point");
    json!({ "kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(x), "y": URL_SAFE_NO_PAD.encode(y) })
}

/// A `jti` no other token or proof in this process carries.
pub(super) fn fresh_jti() -> String {
    let mut random = [0_u8; 16];
    openssl::rand::rand_bytes(&mut random).expect("random bytes");
    format!(
        "{}-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed),
        URL_SAFE_NO_PAD.encode(random)
    )
}
