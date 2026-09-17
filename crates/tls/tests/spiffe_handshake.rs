// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional mTLS handshake tests for `RequireNamed` (X.509-SVID) listeners.
//!
//! Drives a real rustls handshake against a `ServerConfig` built the production
//! way, from YAML through [`praxis_tls::ListenerTls`] and
//! [`praxis_tls::setup::build_server_config`], and asserts that the SPIFFE
//! allowlist admits or rejects a peer at the handshake, before any request.

#![cfg(feature = "spiffe")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    reason = "integration test"
)]

use std::sync::Arc;

use praxis_tls::{ListenerTls, setup::build_server_config};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConnection,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject as _},
};

const ALLOWED_ID: &str = "spiffe://grid.internal/signals";
const OTHER_ID: &str = "spiffe://grid.internal/other";

/// Install a process-default provider. When the workspace enables both aws-lc-rs
/// and ring, rustls cannot auto-select one. Idempotent.
fn install_provider() {
    drop(rustls::crypto::aws_lc_rs::default_provider().install_default());
}

/// A test CA that signs the server certificate and mints client SVID leaves.
struct TestPki {
    issuer: Issuer<'static, KeyPair>,
    ca_pem: String,
    server_pem: String,
    server_key_pem: String,
}

impl TestPki {
    fn new() -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "grid test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();
        let issuer = Issuer::new(ca_params, ca_key);

        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        server_params.distinguished_name.push(DnType::CommonName, "localhost");
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

        Self {
            issuer,
            ca_pem,
            server_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
        }
    }

    /// Mint a client leaf signed by the CA with the given URI SAN. A conforming
    /// SVID carries a critical keyUsage with digitalSignature and an EKU with both
    /// serverAuth and clientAuth.
    fn mint_client(&self, uri: &str, conforming: bool) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, "peer");
        params.subject_alt_names.push(SanType::URI(uri.try_into().unwrap()));
        if conforming {
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        }
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        let chain = vec![cert.der().clone()];
        let key_der = PrivateKeyDer::Pkcs8(key.serialize_der().into());
        (chain, key_der)
    }
}

/// Write the PKI to disk and build a production `ServerConfig` from YAML with
/// `require_named` and the given allowlist.
fn server_config(pki: &TestPki, allowlist: &[&str]) -> Arc<rustls::ServerConfig> {
    install_provider();
    let dir = tempfile::TempDir::new().unwrap();
    let ca = dir.path().join("ca.pem");
    let cert = dir.path().join("server.pem");
    let key = dir.path().join("server-key.pem");
    std::fs::write(&ca, &pki.ca_pem).unwrap();
    std::fs::write(&cert, &pki.server_pem).unwrap();
    std::fs::write(&key, &pki.server_key_pem).unwrap();

    let ids = allowlist
        .iter()
        .map(|id| format!("      - {id}"))
        .collect::<Vec<_>>()
        .join("\n");
    let yaml = format!(
        "certificates:\n  - cert_path: {cert}\n    key_path: {key}\nclient_ca:\n  ca_path: {ca}\n\
         client_cert_mode: require_named\ntrusted_spiffe_ids:\n{ids}\nhot_reload: false\n",
        cert = cert.display(),
        key = key.display(),
        ca = ca.display(),
    );
    let tls: ListenerTls = serde_yaml::from_str(&yaml).expect("valid require_named listener config");
    // build_server_config reads the cert, key, and CA eagerly, so the temp dir may drop.
    build_server_config(&tls, false).expect("build server config")
}

/// A client config trusting the test CA, optionally presenting a client leaf.
fn client_config(
    pki: &TestPki,
    identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Arc<ClientConfig> {
    install_provider();
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(pki.ca_pem.as_bytes()).unwrap())
        .unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let config = match identity {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).unwrap(),
        None => builder.with_no_client_auth(),
    };
    Arc::new(config)
}

/// Drive an in-memory handshake to completion or error. `Ok` means both sides
/// finished; `Err` is the rustls error that ended it (an mTLS rejection).
fn handshake(server_cfg: Arc<rustls::ServerConfig>, client_cfg: Arc<ClientConfig>) -> Result<(), rustls::Error> {
    let mut server = ServerConnection::new(server_cfg).unwrap();
    let mut client = ClientConnection::new(client_cfg, ServerName::try_from("localhost").unwrap()).unwrap();

    for _ in 0..32 {
        let mut c2s = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut c2s).unwrap();
        }
        let mut c2s_rd: &[u8] = &c2s;
        while !c2s_rd.is_empty() {
            server.read_tls(&mut c2s_rd).unwrap();
        }
        server.process_new_packets()?;

        let mut s2c = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut s2c).unwrap();
        }
        let mut s2c_rd: &[u8] = &s2c;
        while !s2c_rd.is_empty() {
            client.read_tls(&mut s2c_rd).unwrap();
        }
        client.process_new_packets()?;

        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("handshake did not settle within the round budget");
}

#[test]
fn an_allowlisted_svid_completes_the_handshake() {
    let pki = TestPki::new();
    let server = server_config(&pki, &[ALLOWED_ID]);
    let client = client_config(&pki, Some(pki.mint_client(ALLOWED_ID, true)));
    handshake(server, client).expect("an allowlisted SVID should complete the handshake");
}

#[test]
fn an_empty_allowlist_admits_any_conforming_svid() {
    let pki = TestPki::new();
    let server = server_config(&pki, &[]);
    let client = client_config(&pki, Some(pki.mint_client(OTHER_ID, true)));
    handshake(server, client).expect("an empty allowlist admits any valid SVID the CA signs");
}

#[test]
fn an_unlisted_svid_fails_the_handshake() {
    let pki = TestPki::new();
    let server = server_config(&pki, &[ALLOWED_ID]);
    let client = client_config(&pki, Some(pki.mint_client(OTHER_ID, true)));
    let err = handshake(server, client).expect_err("an unlisted SVID must be rejected");
    assert!(matches!(err, rustls::Error::InvalidCertificate(_)), "got {err:?}");
}

#[test]
fn a_non_conforming_leaf_fails_the_handshake() {
    // CA-signed and in the allowlist, but not a conforming SVID (no keyUsage / EKU).
    let pki = TestPki::new();
    let server = server_config(&pki, &[ALLOWED_ID]);
    let client = client_config(&pki, Some(pki.mint_client(ALLOWED_ID, false)));
    let err = handshake(server, client).expect_err("a non-conforming leaf must be rejected");
    assert!(matches!(err, rustls::Error::InvalidCertificate(_)), "got {err:?}");
}

#[test]
fn a_missing_client_certificate_fails_the_handshake() {
    let pki = TestPki::new();
    let server = server_config(&pki, &[ALLOWED_ID]);
    let client = client_config(&pki, None);
    handshake(server, client).expect_err("require_named must reject a peer with no certificate");
}
