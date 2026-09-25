// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! What the provider offers and refuses in approved mode, and out of it.
//!
//! Every test asserts both branches, keyed on what the installed provider
//! reports (`Status::provider_fips`): on a FIPS host the approved branch
//! runs, anywhere else the other one, so a pass means the right thing on
//! either. `PRAXIS_FIPS_HOST` (set by `make test-fips-host`) insists on the
//! approved branch, so a run on the FIPS runner cannot pass these on
//! OpenSSL's default provider.
//!
//! In approved mode the OpenSSL FIPS provider refuses what FIPS 140-3 does
//! not approve, and the rustls provider only offers what OpenSSL can perform,
//! so a handshake never reaches a non-approved algorithm: no `ChaCha20`, no
//! X25519, no `Ed25519`, no MD5 (see `docs/operating/fips.md`).

#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    reason = "integration tests in tests/"
)]

use std::sync::Arc;

use praxis_tls::{ListenerTls, setup::build_server_config};
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, NamedGroup, RootCertStore, ServerConnection, SignatureScheme,
    crypto::CryptoProvider, pki_types::ServerName,
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Whether the installed provider offers FIPS-approved algorithms only, and
/// therefore which branch each test must take. Fails when `PRAXIS_FIPS_HOST`
/// declares a FIPS host and the provider disagrees.
fn approved_mode() -> bool {
    praxis_tls::provider::install();
    let approved = praxis_tls::provider::status().provider_fips;
    let declared = std::env::var("PRAXIS_FIPS_HOST").is_ok_and(|value| {
        !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        )
    });
    assert!(
        approved || !declared,
        "PRAXIS_FIPS_HOST is set but the installed provider does not offer FIPS-approved algorithms only"
    );
    approved
}

/// A self-signed `localhost` certificate and key, as PEM files in a
/// temporary directory, and the certificate's DER for a client to trust.
fn localhost_certificate() -> (tempfile::TempDir, ListenerTls, Vec<u8>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("self-signed cert");
    let dir = tempfile::tempdir().expect("temp dir");
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, certified.cert.pem()).expect("write cert");
    std::fs::write(&key, certified.signing_key.serialize_pem()).expect("write key");
    let tls = ListenerTls::new_validated(cert.to_str().expect("utf-8 path"), key.to_str().expect("utf-8 path"))
        .expect("listener tls");
    (dir, tls, certified.cert.der().to_vec())
}

/// A listener TLS configuration from YAML, with the certificate files
/// substituted in.
fn listener_from_yaml(tls: &ListenerTls, extra: &str) -> ListenerTls {
    let primary = tls.certificates.first().expect("one certificate");
    let yaml = format!(
        "certificates:\n  - cert_path: {}\n    key_path: {}\n{extra}",
        primary.cert_path, primary.key_path
    );
    serde_yaml::from_str(&yaml).expect("listener tls yaml")
}

/// A client that trusts `cert_der`, built on the installed provider.
fn client_config(cert_der: Vec<u8>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(cert_der))
        .expect("trust the certificate");
    let provider = Arc::clone(CryptoProvider::get_default().expect("provider installed"));
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.require_ems = true;
    Arc::new(config)
}

/// Drive an in-memory handshake to completion; returns the client side.
fn handshake(server_config: Arc<rustls::ServerConfig>, client_config: Arc<ClientConfig>) -> ClientConnection {
    let mut server = ServerConnection::new(server_config).expect("server connection");
    let name = ServerName::try_from("localhost").expect("server name");
    let mut client = ClientConnection::new(client_config, name).expect("client connection");
    for _ in 0..16 {
        let mut client_to_server = Vec::new();
        client.write_tls(&mut client_to_server).expect("client write");
        let mut server_reader = client_to_server.as_slice();
        while !server_reader.is_empty() {
            server.read_tls(&mut server_reader).expect("server read");
        }
        server.process_new_packets().expect("server handshake step");
        let mut server_to_client = Vec::new();
        server.write_tls(&mut server_to_client).expect("server write");
        let mut client_reader = server_to_client.as_slice();
        while !client_reader.is_empty() {
            client.read_tls(&mut client_reader).expect("client read");
        }
        client.process_new_packets().expect("client handshake step");
        if !client.is_handshaking() && !server.is_handshaking() {
            return client;
        }
    }
    panic!("the handshake did not complete in 16 rounds");
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn md5_is_refused_in_approved_mode() {
    let approved = approved_mode();
    let md5 = openssl::hash::hash(openssl::hash::MessageDigest::md5(), b"abc");
    assert_eq!(
        md5.is_err(),
        approved,
        "MD5 through the EVP interface must fail exactly in approved mode, got {md5:?}"
    );
    let sha256 = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), b"abc");
    assert!(sha256.is_ok(), "SHA-256 works in every mode: {sha256:?}");
}

#[test]
#[expect(clippy::too_many_lines, reason = "one assertion pair per algorithm family")]
fn the_provider_offers_only_approved_algorithms_in_approved_mode() {
    let approved = approved_mode();
    let provider = CryptoProvider::get_default().expect("provider installed");
    assert_eq!(provider.fips(), approved, "rustls' own verdict on the provider");

    let chacha20 = provider.cipher_suites.iter().any(|suite| {
        matches!(
            suite.suite(),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                | CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                | CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        )
    });
    assert_eq!(
        chacha20, !approved,
        "ChaCha20-Poly1305 is offered only outside approved mode"
    );
    assert!(
        provider
            .cipher_suites
            .iter()
            .any(|suite| suite.suite() == CipherSuite::TLS13_AES_256_GCM_SHA384),
        "AES-GCM is offered in every mode"
    );

    let nist_only = provider
        .kx_groups
        .iter()
        .all(|group| matches!(group.name(), NamedGroup::secp256r1 | NamedGroup::secp384r1));
    assert_eq!(nist_only, approved, "in approved mode only the NIST curves remain");
    let x25519 = provider
        .kx_groups
        .iter()
        .any(|group| group.name() == NamedGroup::X25519);
    assert_eq!(x25519, !approved, "X25519 is offered only outside approved mode");

    let ed25519 = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .any(|(scheme, _)| *scheme == SignatureScheme::ED25519);
    assert_eq!(ed25519, !approved, "Ed25519 is accepted only outside approved mode");
    assert!(
        provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .any(|(scheme, _)| *scheme == SignatureScheme::ECDSA_NISTP256_SHA256),
        "ECDSA P-256 is accepted in every mode"
    );
}

#[test]
fn a_listener_config_is_fips_exactly_in_approved_mode_and_negotiates_accordingly() {
    let approved = approved_mode();
    let (_dir, tls, cert_der) = localhost_certificate();
    let server_config = build_server_config(&tls, true).expect("listener config");
    assert_eq!(
        server_config.fips(),
        approved,
        "rustls counts the listener config as FIPS exactly in approved mode"
    );

    let client = handshake(server_config, client_config(cert_der));
    let suite = client
        .negotiated_cipher_suite()
        .expect("a suite was negotiated")
        .suite();
    let group = client
        .negotiated_key_exchange_group()
        .expect("a group was negotiated")
        .name();
    let approved_suite = matches!(
        suite,
        CipherSuite::TLS13_AES_128_GCM_SHA256 | CipherSuite::TLS13_AES_256_GCM_SHA384
    );
    let nist_group = matches!(group, NamedGroup::secp256r1 | NamedGroup::secp384r1);
    if approved {
        assert!(approved_suite, "approved mode negotiated {suite:?}");
        assert!(nist_group, "approved mode negotiated {group:?}");
    } else {
        // Both sides prefer X25519 when the provider has it, so the other
        // branch is observable too, not just "it completed".
        assert_eq!(group, NamedGroup::X25519, "outside approved mode X25519 is preferred");
    }
}

#[test]
fn a_chacha20_only_listener_fails_to_build_in_approved_mode() {
    let approved = approved_mode();
    let (_dir, tls, _cert_der) = localhost_certificate();
    let chacha_only = listener_from_yaml(&tls, "cipher_suites:\n  - tls13_chacha20_poly1305_sha256\n");
    let result = build_server_config(&chacha_only, true);
    assert_eq!(
        result.is_err(),
        approved,
        "a listener offering only ChaCha20 has nothing to negotiate in approved mode: {:?}",
        result.err()
    );

    let aes_only = listener_from_yaml(&tls, "cipher_suites:\n  - tls13_aes_256_gcm_sha384\n");
    let config = build_server_config(&aes_only, true).expect("an AES-GCM listener builds in every mode");
    assert_eq!(config.fips(), approved);
}

#[test]
fn a_tls12_listener_still_requires_extended_master_secret_in_every_mode() {
    praxis_tls::provider::install();
    let (_dir, tls, _cert_der) = localhost_certificate();
    let tls12 = listener_from_yaml(&tls, "min_version: tls12\n");
    let config = build_server_config(&tls12, true).expect("listener config");
    assert!(
        config.require_ems,
        "Extended Master Secret is required on TLS 1.2 whatever the mode"
    );
}
