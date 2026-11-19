// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Real TLS handshakes crossing a client-trust reload must not seed resumptions.

#![cfg(feature = "config-reload")]
#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::tests_outside_test_module,
    reason = "integration tests"
)]

use std::{
    io::Read as _,
    sync::Arc,
    time::{Duration, Instant},
};

use praxis_tls::{
    CaConfig, ClientCertMode, ListenerTls, setup,
    watcher::{CertWatcher, ClientVerifierReload},
};
use rcgen::{CertificateParams, Issuer, KeyPair};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, HandshakeKind, RootCertStore, ServerConnection,
    SupportedProtocolVersion,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
    version::{TLS12, TLS13},
};

/// One client identity, separate from the server trust anchor.
struct ClientIdentity {
    /// Client leaf signed by the fixture's CA.
    cert: CertificateDer<'static>,
    /// Private key encoded as PKCS#8.
    key: Vec<u8>,
}

/// Server, client identities, and a CRL revoking just the first client.
struct Fixture {
    /// Keeps the listener's PEM files alive.
    dir: tempfile::TempDir,
    /// Reloadable listener with an initially empty CRL.
    tls: ListenerTls,
    /// Trust anchor used by clients to authenticate the unchanged server.
    root: CertificateDer<'static>,
    /// Identity revoked by `revoked_crl`.
    revoked: ClientIdentity,
    /// A second identity that remains valid after the CRL reload.
    trusted: ClientIdentity,
    /// Replacement contents of the watched CRL file.
    revoked_crl: String,
}

impl Fixture {
    /// Generate the trust material independently for each case.
    fn new(mode: ClientCertMode) -> Self {
        praxis_tls::provider::install();
        let dir = tempfile::tempdir().expect("temp dir");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().expect("CA key");
        let ca = ca_params.self_signed(&ca_key).expect("CA cert");
        let issuer = Issuer::new(ca_params, ca_key);
        let server_key = KeyPair::generate().expect("server key");
        let server = CertificateParams::new(vec!["localhost".to_owned()])
            .expect("server params")
            .signed_by(&server_key, &issuer)
            .expect("server cert");
        let cert_path = dir.path().join("server.pem");
        let key_path = dir.path().join("server-key.pem");
        let ca_path = dir.path().join("ca.pem");
        let crl_path = dir.path().join("ca.crl");
        std::fs::write(&cert_path, server.pem()).expect("server PEM");
        std::fs::write(&key_path, server_key.serialize_pem()).expect("server key PEM");
        std::fs::write(&ca_path, ca.pem()).expect("CA PEM");
        std::fs::write(&crl_path, crl(&issuer, false)).expect("empty CRL");
        let mut tls = ListenerTls::new_validated(
            cert_path.to_str().expect("cert path"),
            key_path.to_str().expect("key path"),
        )
        .expect("listener config");
        tls.client_cert_mode = mode;
        tls.client_ca = Some(CaConfig {
            ca_path: ca_path.to_str().expect("CA path").to_owned(),
            crl_paths: vec![crl_path.to_str().expect("CRL path").to_owned()],
        });
        Self {
            dir,
            tls,
            root: ca.der().clone(),
            revoked: identity(&issuer, 1),
            trusted: identity(&issuer, 2),
            revoked_crl: crl(&issuer, true),
        }
    }

    /// Use one shared client config so successive connections offer cached sessions.
    fn client(
        &self,
        version: &'static SupportedProtocolVersion,
        identity: Option<&ClientIdentity>,
    ) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(self.root.clone()).expect("server root");
        let builder = ClientConfig::builder_with_protocol_versions(&[version]).with_root_certificates(roots);
        let mut config = match identity {
            Some(identity) => builder
                .with_client_auth_cert(
                    vec![identity.cert.clone()],
                    PrivatePkcs8KeyDer::from(identity.key.clone()).into(),
                )
                .expect("client identity"),
            None => builder.with_no_client_auth(),
        };
        // Fragment the client flight so CertificateVerify and Finished cannot
        // both complete in the same record, including when TLS 1.3 encrypts it.
        config.max_fragment_size = Some(32);
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    /// Update the configured CRL in place, as an operator does before a reload.
    fn revoke(&self) {
        let path = self.tls.client_ca.as_ref().expect("CA").crl_paths.first().expect("CRL");
        std::fs::write(path, &self.revoked_crl).expect("revoked CRL");
    }

    /// Put verifier inputs in watched directories apart from the server key.
    fn separate_verifier_dirs(&mut self) {
        let ca = self.tls.client_ca.as_mut().expect("client CA");
        let ca_dir = self.dir.path().join("ca-only");
        let crl_dir = self.dir.path().join("crl-only");
        std::fs::create_dir(&ca_dir).expect("CA directory");
        std::fs::create_dir(&crl_dir).expect("CRL directory");
        let next_ca = ca_dir.join("ca.pem");
        let next_crl = crl_dir.join("ca.crl");
        std::fs::copy(&ca.ca_path, &next_ca).expect("copy CA");
        std::fs::copy(ca.crl_paths.first().expect("CRL path"), &next_crl).expect("copy CRL");
        next_ca.to_str().expect("CA path").clone_into(&mut ca.ca_path);
        ca.crl_paths = vec![next_crl.to_str().expect("CRL path").to_owned()];
    }
}

/// Own a watcher thread so every assertion path shuts it down and joins it.
struct WatcherGuard {
    /// Sender that requests watcher shutdown.
    shutdown: tokio::sync::watch::Sender<bool>,
    /// Background watcher thread.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WatcherGuard {
    /// Start the real filesystem watcher for a reloadable listener.
    #[expect(
        clippy::disallowed_methods,
        reason = "synchronous test waits for a separate watcher thread"
    )]
    fn new(server: &setup::ReloadableServerConfig, tls: &ListenerTls) -> Self {
        let ca = tls.client_ca.as_ref().expect("client CA");
        let reload = ClientVerifierReload {
            ca_path: ca.ca_path.clone(),
            crl_paths: ca.crl_paths.clone(),
            mode: tls.client_cert_mode,
            trusted_spiffe_ids: tls.trusted_spiffe_ids.clone(),
            swap_handle: Arc::clone(server.verifier_handle.as_ref().expect("verifier handle")),
        };
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let thread = CertWatcher::spawn(
            Arc::clone(&server.cert_handle),
            tls.certificates.first().expect("server certificate").clone(),
            Some(reload),
            receiver,
            server.startup_hashes.clone(),
        );
        std::thread::sleep(Duration::from_millis(150));
        Self {
            shutdown,
            thread: Some(thread),
        }
    }
}

impl Drop for WatcherGuard {
    fn drop(&mut self) {
        let _sent = self.shutdown.send(true);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("watcher thread must exit cleanly");
        }
    }
}

/// Client identities also satisfy the optional SPIFFE verifier's leaf requirements.
fn identity(issuer: &Issuer<'_, KeyPair>, serial: u64) -> ClientIdentity {
    let key = KeyPair::generate().expect("client key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("client params");
    params.serial_number = Some(serial.into());
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.subject_alt_names = vec![rcgen::SanType::URI(
        "spiffe://example.org/client".try_into().expect("URI"),
    )];
    let cert = params.signed_by(&key, issuer).expect("client cert");
    ClientIdentity {
        cert: cert.der().clone(),
        key: key.serialize_der(),
    }
}

/// Sign an empty CRL or one that revokes client serial 1.
fn crl(issuer: &Issuer<'_, KeyPair>, revoke: bool) -> String {
    let revoked_certs = if revoke {
        vec![rcgen::RevokedCertParams {
            serial_number: 1_u64.into(),
            revocation_time: rcgen::date_time_ymd(2026, 1, 1),
            reason_code: None,
            invalidity_date: None,
        }]
    } else {
        Vec::new()
    };
    rcgen::CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2026, 1, 1),
        next_update: rcgen::date_time_ymd(2036, 1, 1),
        crl_number: u64::from(revoke).into(),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(issuer)
    .expect("sign CRL")
    .pem()
    .expect("CRL PEM")
}

/// Publish the same verifier state the file watcher publishes after a successful reload.
fn reload(server: &setup::ReloadableServerConfig, tls: &ListenerTls) {
    let next = setup::build_reloadable_server_config(tls, false).expect("reload material");
    server
        .verifier_handle
        .as_ref()
        .expect("verifier handle")
        .store(next.verifier_handle.expect("next verifier").load_full());
}

/// Exchange actual TLS records, invoking `after_auth` before the client's Finished.
fn handshake(
    config: &Arc<rustls::ServerConfig>,
    client_config: &Arc<ClientConfig>,
    mut after_auth: Option<&mut dyn FnMut()>,
) -> Result<HandshakeKind, rustls::Error> {
    let mut server = ServerConnection::new(Arc::clone(config))?;
    let mut client = ClientConnection::new(
        Arc::clone(client_config),
        ServerName::try_from("localhost").expect("name"),
    )?;
    for _ in 0..16 {
        let mut flight = Vec::new();
        client.write_tls(&mut flight).expect("client flight");
        let mut remaining = flight.as_slice();
        while !remaining.is_empty() {
            let mut header = [0; 5];
            remaining.read_exact(&mut header).expect("record header");
            let [_, _, _, high, low] = header;
            let size = usize::from(u16::from_be_bytes([high, low]));
            let (body, rest) = remaining.split_at(size);
            let record = [header.as_slice(), body].concat();
            server.read_tls(&mut record.as_slice()).expect("server read");
            server.process_new_packets()?;
            remaining = rest;
            if server.peer_certificates().is_some()
                && server.is_handshaking()
                && let Some(callback) = after_auth.take()
            {
                callback();
            }
        }
        let mut server_flight = Vec::new();
        server.write_tls(&mut server_flight).expect("server flight");
        client.read_tls(&mut server_flight.as_slice()).expect("client read");
        client.process_new_packets()?;
        if !server.is_handshaking() && !client.is_handshaking() {
            assert!(
                after_auth.is_none(),
                "reload must occur after client authentication and before Finished"
            );
            return Ok(server.handshake_kind().expect("handshake kind"));
        }
    }
    panic!("handshake did not complete in 16 flights");
}

/// Exercise both protocol listener settings with a handshake straddling revocation.
fn crl_race(version: &'static SupportedProtocolVersion, mode: ClientCertMode) {
    for http in [false, true] {
        let fixture = Fixture::new(mode);
        let server = setup::build_reloadable_server_config(&fixture.tls, http).expect("server");
        let client = fixture.client(version, Some(&fixture.revoked));
        let mut revoke = || {
            fixture.revoke();
            reload(&server, &fixture.tls);
        };
        handshake(&server.config, &client, Some(&mut revoke)).expect("in-flight connection may finish");
        let fresh = fixture.client(version, Some(&fixture.revoked));
        assert!(
            matches!(
                handshake(&server.config, &fresh, None),
                Err(rustls::Error::InvalidCertificate(CertificateError::Revoked))
            ),
            "the new CRL must reject the same identity without cached sessions"
        );
        let next = handshake(&server.config, &client, None);
        assert!(
            matches!(next, Err(rustls::Error::InvalidCertificate(CertificateError::Revoked))),
            "a new connection must reject the revoked cert, mode={mode:?}, HTTP={http}, got {next:?}"
        );
        let trusted = fixture.client(version, Some(&fixture.trusted));
        assert_eq!(
            handshake(&server.config, &trusted, None).expect("trusted client"),
            HandshakeKind::Full,
            "the connection must perform full authentication"
        );
        assert_eq!(
            handshake(&server.config, &trusted, None).expect("trusted client reconnect"),
            HandshakeKind::Full,
            "the connection must perform full authentication"
        );
    }
}

#[test]
#[expect(clippy::disallowed_methods, reason = "the test waits through real polling intervals")]
fn polling_reloads_the_listener_verifier_without_notifications() {
    let fixture = Fixture::new(ClientCertMode::Require);
    let server = setup::build_reloadable_server_config(&fixture.tls, false).expect("server");
    let ca = fixture.tls.client_ca.clone().expect("client CA");
    let verifier = server.verifier_handle.clone().expect("verifier");
    let pair = fixture.tls.certificates.first().cloned().expect("certificate pair");
    let reload = ClientVerifierReload {
        ca_path: ca.ca_path,
        crl_paths: ca.crl_paths,
        mode: fixture.tls.client_cert_mode,
        trusted_spiffe_ids: fixture.tls.trusted_spiffe_ids.clone(),
        swap_handle: verifier,
    };
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let watcher = CertWatcher::spawn_polling(
        Arc::clone(&server.cert_handle),
        pair,
        Some(reload),
        shutdown,
        server.startup_hashes.clone(),
    );

    let client = fixture.client(&TLS13, Some(&fixture.revoked));
    fixture.revoke();

    let deadline = Instant::now()
        .checked_add(Duration::from_secs(40))
        .expect("deadline fits the clock");
    let mut rejected = false;
    let mut last = "no handshake completed".to_owned();
    while Instant::now() < deadline {
        match handshake(&server.config, &client, None) {
            Err(rustls::Error::InvalidCertificate(CertificateError::Revoked)) => {
                rejected = true;
                break;
            },
            Ok(kind) => last = format!("accepted: {kind:?}"),
            Err(error) => last = format!("error: {error}"),
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let anonymous = fixture.client(&TLS13, None);
    let anonymous_result = handshake(&server.config, &anonymous, None);
    stop.send(true).expect("stop the watcher");
    drop(watcher.join());
    assert!(
        rejected,
        "polling must install the repaired CRL on the listener verifier; last: {last}"
    );
    assert!(
        anonymous_result.is_err(),
        "Require mode must reject an anonymous client after the watcher swap"
    );
}

#[test]
fn tls12_finished_after_crl_reload_cannot_seed_resumption() {
    crl_race(&TLS12, ClientCertMode::Require);
}

#[test]
fn tls13_finished_after_crl_reload_cannot_seed_resumption() {
    crl_race(&TLS13, ClientCertMode::Require);
}

#[test]
fn optional_client_auth_cannot_resume_revoked_identity() {
    for version in [&TLS12, &TLS13] {
        crl_race(version, ClientCertMode::Request);
    }
}

#[test]
#[cfg(feature = "spiffe")]
fn named_client_auth_cannot_resume_revoked_identity() {
    for version in [&TLS12, &TLS13] {
        crl_race(version, ClientCertMode::RequireNamed);
    }
}

#[test]
fn finished_after_ca_replacement_cannot_seed_resumption() {
    for version in [&TLS12, &TLS13] {
        let fixture = Fixture::new(ClientCertMode::Require);
        let replacement = Fixture::new(ClientCertMode::Require);
        let server = setup::build_reloadable_server_config(&fixture.tls, true).expect("server");
        let client = fixture.client(version, Some(&fixture.revoked));
        let mut rotate = || {
            let old_ca = fixture.tls.client_ca.as_ref().expect("original CA");
            let new_ca = replacement.tls.client_ca.as_ref().expect("replacement CA");
            std::fs::copy(&new_ca.ca_path, &old_ca.ca_path).expect("replace CA");
            std::fs::copy(
                new_ca.crl_paths.first().expect("new CRL"),
                old_ca.crl_paths.first().expect("old CRL"),
            )
            .expect("replace CRL");
            reload(&server, &fixture.tls);
        };
        handshake(&server.config, &client, Some(&mut rotate)).expect("in-flight connection may finish");
        let next = handshake(&server.config, &client, None);
        assert!(
            matches!(next, Err(rustls::Error::InvalidCertificate(_))),
            "a new connection must reject the old CA's identity, got {next:?}"
        );
        let trusted = fixture.client(version, Some(&replacement.trusted));
        handshake(&server.config, &trusted, None).expect("new CA's client must work with unchanged server cert");
    }
}

#[test]
fn static_mtls_and_server_only_tls_still_resume() {
    for version in [&TLS12, &TLS13] {
        let mut fixture = Fixture::new(ClientCertMode::Require);
        fixture.tls.hot_reload = Some(false);
        let server = setup::build_server_config(&fixture.tls, true).expect("static mTLS server");
        let client = fixture.client(version, Some(&fixture.trusted));
        assert_eq!(
            handshake(&server, &client, None).expect("first connection"),
            HandshakeKind::Full,
            "the connection must perform full authentication"
        );
        assert_eq!(
            handshake(&server, &client, None).expect("reconnect"),
            HandshakeKind::Resumed,
            "resumption must remain available outside reloadable client authentication"
        );

        fixture.tls.client_cert_mode = ClientCertMode::None;
        fixture.tls.client_ca = None;
        fixture.tls.hot_reload = Some(true);
        let plain_server = setup::build_reloadable_server_config(&fixture.tls, false).expect("server-only TLS");
        let anonymous = fixture.client(version, None);
        assert_eq!(
            handshake(&plain_server.config, &anonymous, None).expect("first connection"),
            HandshakeKind::Full,
            "the connection must perform full authentication"
        );
        assert_eq!(
            handshake(&plain_server.config, &anonymous, None).expect("reconnect"),
            HandshakeKind::Resumed,
            "resumption must remain available outside reloadable client authentication"
        );
    }
}

#[test]
fn optional_client_auth_still_accepts_anonymous_clients_after_reload() {
    for version in [&TLS12, &TLS13] {
        let fixture = Fixture::new(ClientCertMode::Request);
        let server = setup::build_reloadable_server_config(&fixture.tls, true).expect("optional mTLS");
        let client = fixture.client(version, None);
        handshake(&server.config, &client, None).expect("anonymous client before reload");
        fixture.revoke();
        reload(&server, &fixture.tls);
        assert_eq!(
            handshake(&server.config, &client, None).expect("anonymous client after reload"),
            HandshakeKind::Full,
            "the connection must perform full authentication"
        );
    }
}

#[test]
fn watcher_rotates_ca_and_crl_for_fresh_handshakes() {
    for rotate_ca in [true, false] {
        let mut fixture = Fixture::new(ClientCertMode::Require);
        fixture.separate_verifier_dirs();
        if rotate_ca {
            fixture.tls.client_ca.as_mut().expect("client CA").crl_paths.clear();
        }
        let replacement = Fixture::new(ClientCertMode::Require);
        let server = setup::build_reloadable_server_config(&fixture.tls, true).expect("reloadable server");
        let _watcher = WatcherGuard::new(&server, &fixture.tls);
        let old_client = fixture.client(&TLS13, Some(&fixture.revoked));
        handshake(&server.config, &old_client, None).expect("old client initially trusted");
        let replacement_client = fixture.client(&TLS13, Some(&replacement.trusted));
        assert!(
            matches!(
                handshake(&server.config, &replacement_client, None),
                Err(rustls::Error::InvalidCertificate(_))
            ),
            "replacement CA identity must initially be untrusted"
        );

        let ca = fixture.tls.client_ca.as_ref().expect("client CA");
        let changed_path = if rotate_ca {
            &ca.ca_path
        } else {
            ca.crl_paths.first().expect("CRL path")
        };
        let before_cert = server.cert_handle.load_full();
        let verifier_handle = server.verifier_handle.as_ref().expect("verifier handle");
        let before_verifier = verifier_handle.load_full();
        std::fs::write(changed_path, b"invalid verifier material").expect("corrupt verifier file");
        wait_for_condition(
            || !Arc::ptr_eq(&before_cert, &server.cert_handle.load_full()),
            "watcher must begin processing the first corrupt verifier-file event",
        );
        let first_cert = server.cert_handle.load_full();
        std::fs::write(changed_path, b"invalid verifier material").expect("rewrite corrupt verifier file");
        wait_for_condition(
            || !Arc::ptr_eq(&first_cert, &server.cert_handle.load_full()),
            "watcher must publish a second certificate after the first verifier attempt completes",
        );
        assert!(
            Arc::ptr_eq(&before_verifier, &verifier_handle.load_full()),
            "failed verifier reload must retain the same verifier"
        );
        handshake(&server.config, &old_client, None).expect("invalid reload must keep old verifier");
        assert!(
            matches!(
                handshake(&server.config, &replacement_client, None),
                Err(rustls::Error::InvalidCertificate(_))
            ),
            "invalid reload must not trust the independent replacement identity"
        );

        if rotate_ca {
            let replacement_ca = &replacement.tls.client_ca.as_ref().expect("replacement CA").ca_path;
            std::fs::copy(replacement_ca, changed_path).expect("replace CA from distinct watched directory");
        } else {
            fixture.revoke();
        }
        wait_for_condition(
            || {
                matches!(
                    handshake(&server.config, &old_client, None),
                    Err(rustls::Error::InvalidCertificate(_))
                )
            },
            "fresh handshakes must reject the old identity after a CA or CRL file event",
        );
        let trusted = if rotate_ca {
            &replacement.trusted
        } else {
            &fixture.trusted
        };
        let trusted_client = fixture.client(&TLS13, Some(trusted));
        handshake(&server.config, &trusted_client, None).expect("trusted identity must still connect");
    }
}

/// Poll a watcher-visible condition with a finite deadline.
#[expect(clippy::disallowed_methods, reason = "bounded polling in a synchronous watcher test")]
fn wait_for_condition(mut condition: impl FnMut() -> bool, message: &str) {
    let started = Instant::now();
    while !condition() {
        assert!(started.elapsed() < Duration::from_secs(5), "{message}");
        std::thread::sleep(Duration::from_millis(50));
    }
}
