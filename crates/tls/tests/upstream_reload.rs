// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors
//
//! Hot-reloaded upstream TLS material serves the rotated files on new reads.
//!
//! Each case builds a `hot_reload: true` cluster TLS config from temp files,
//! lets the registry spawn the watcher, rotates the files, and asserts the
//! `CachedClusterTls` accessors hand out the rotated material while a broken
//! rotation leaves the previous material in place.

#![cfg(feature = "config-reload")]
#![forbid(unsafe_code)]
#![allow(
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::tests_outside_test_module,
    reason = "integration tests"
)]

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use praxis_tls::{CachedClusterTls, ClusterTls};
use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};

/// One client leaf and key that can be written to the watched cert files.
struct Leaf {
    /// PEM-encoded certificate chain.
    pem: String,
    /// PEM-encoded private key.
    key_pem: String,
}

/// A CA and two client leaves it signed, plus the watched file layout.
struct Fixture {
    /// Keeps the watched files alive.
    dir: tempfile::TempDir,
    /// Cluster TLS config pointing at the watched files.
    tls: ClusterTls,
    /// The identity initially written to the files.
    first: Leaf,
    /// The identity a rotation writes.
    second: Leaf,
}

impl Fixture {
    /// Generate the trust material and write the first identity.
    fn new() -> Self {
        praxis_tls::provider::install();
        let dir = tempfile::tempdir().expect("temp dir");

        let ca_key = KeyPair::generate().expect("CA key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Upstream Test CA");
        let ca = ca_params.self_signed(&ca_key).expect("CA self-sign");
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let first = client_leaf(&issuer, "first.example.com");
        let second = client_leaf(&issuer, "second.example.com");

        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&cert_path, &first.pem).expect("write first cert");
        std::fs::write(&key_path, &first.key_pem).expect("write first key");
        std::fs::write(&ca_path, ca.pem()).expect("write CA");

        let tls = ClusterTls {
            ca: Some(praxis_tls::CaConfig {
                ca_path: ca_path.to_str().expect("CA path").to_owned(),
                crl_paths: Vec::new(),
            }),
            client_cert: Some(praxis_tls::CertKeyPair {
                cert_path: cert_path.to_str().expect("cert path").to_owned(),
                default: false,
                key_path: key_path.to_str().expect("key path").to_owned(),
                server_names: Vec::new(),
            }),
            sni: Some("api.example.com".to_owned()),
            verify: true,
            hot_reload: true,
        };
        Self {
            dir,
            tls,
            first,
            second,
        }
    }

    /// Write the second identity over the watched files, atomically enough
    /// for the debounced watcher.
    fn rotate(&self) {
        let cert_path = self.dir.path().join("tls.crt");
        let key_path = self.dir.path().join("tls.key");
        std::fs::write(&cert_path, &self.second.pem).expect("write second cert");
        std::fs::write(&key_path, &self.second.key_pem).expect("write second key");
    }
}

/// Generate one client leaf signed by the fixture CA.
fn client_leaf(issuer: &Issuer<'_, &KeyPair>, name: &str) -> Leaf {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(vec![name.to_owned()]).expect("leaf params");
    params.distinguished_name.push(DnType::CommonName, name);
    let cert = params.signed_by(&key, issuer).expect("leaf sign");
    Leaf {
        pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// Poll until `condition` holds, bounded to `limit`.
///
/// The bound must exceed the watcher's fallback poll interval: on a
/// filesystem whose notify events are unreliable, the first poll, not an
/// event, performs the reload.
fn wait_for(limit: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < limit {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    condition()
}

#[test]
fn a_rotation_serves_the_new_client_identity() {
    let fixture = Fixture::new();
    let cached = CachedClusterTls::try_from_config(&fixture.tls).expect("hot-reload material");
    let before = cached.client_cert().expect("initial identity");
    assert_eq!(
        before.cert_der().first().map(Vec::as_slice),
        pem_first_block(&fixture.first.pem).as_deref(),
        "the initial slot must hold the first identity"
    );

    fixture.rotate();
    let rotated = wait_for(Duration::from_secs(12), || {
        cached
            .client_cert()
            .is_some_and(|cert| !Arc::ptr_eq(&cert, &before) && cert.cert_der() != before.cert_der())
    });
    assert!(
        rotated,
        "the accessor must serve the rotated identity after the watcher fires"
    );

    let after = cached.client_cert().expect("rotated identity");
    assert_eq!(
        after.cert_der().first().map(Vec::as_slice),
        pem_first_block(&fixture.second.pem).as_deref(),
        "the slot must hold the second identity"
    );
}

#[test]
fn independently_built_handles_share_one_rotation() {
    let fixture = Fixture::new();
    // Two independent constructions from one config, the way the data path
    // (pipeline build) and the TLS health probe each build their own handle.
    let data_path = CachedClusterTls::try_from_config(&fixture.tls).expect("data-path material");
    let probe = CachedClusterTls::try_from_config(&fixture.tls).expect("probe material");

    fixture.rotate();

    let expected = pem_first_block(&fixture.second.pem);
    let rotated = wait_for(Duration::from_secs(12), || {
        serves_identity(&data_path, expected.as_deref()) && serves_identity(&probe, expected.as_deref())
    });
    assert!(
        rotated,
        "every handle built from the same paths must serve the rotated identity, \
         or a health probe would keep presenting the retired certificate"
    );
}

/// Whether one handle's client identity is the expected DER leaf.
fn serves_identity(cached: &CachedClusterTls, expected: Option<&[u8]>) -> bool {
    cached
        .client_cert()
        .is_some_and(|cert| cert.cert_der().first().map(Vec::as_slice) == expected)
}

#[test]
fn a_broken_rotation_keeps_the_previous_material() {
    let fixture = Fixture::new();
    let cached = CachedClusterTls::try_from_config(&fixture.tls).expect("hot-reload material");
    let before = cached.client_cert().expect("initial identity");

    let cert_path = fixture.dir.path().join("tls.crt");
    std::fs::write(&cert_path, "not a certificate").expect("write broken cert");

    std::thread::sleep(Duration::from_millis(1500));
    let after = cached.client_cert().expect("identity after broken rotation");
    assert!(
        Arc::ptr_eq(&before, &after),
        "a broken rotation must leave the previous identity in the slot"
    );
}

#[test]
fn a_ca_rotation_serves_the_new_bundle() {
    let fixture = Fixture::new();
    let cached = CachedClusterTls::try_from_config(&fixture.tls).expect("hot-reload material");
    let before = cached.ca().expect("initial CA bundle");

    let ca_path = fixture.tls.ca.as_ref().expect("CA config").ca_path.clone();
    let replacement = tempfile::tempdir().expect("replacement dir");
    let key = KeyPair::generate().expect("replacement CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("replacement CA params");
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Replacement Upstream CA");
    let replacement_ca = params.self_signed(&key).expect("replacement CA sign");
    let replacement_path = replacement.path().join("ca.pem");
    std::fs::write(&replacement_path, replacement_ca.pem()).expect("write replacement CA");
    std::fs::copy(&replacement_path, &ca_path).expect("rotate CA file");

    let rotated = wait_for(Duration::from_secs(12), || {
        cached
            .ca()
            .is_some_and(|ca| !Arc::ptr_eq(&ca, &before) && ca.der_certs() != before.der_certs())
    });
    assert!(
        rotated,
        "the accessor must serve the rotated CA bundle after the watcher fires"
    );
}

/// DER-decode the first PEM certificate block of `pem`.
fn pem_first_block(pem: &str) -> Option<Vec<u8>> {
    use rustls::pki_types::pem::PemObject as _;
    rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .map(|cert| cert.expect("PEM certificate").to_vec())
}
