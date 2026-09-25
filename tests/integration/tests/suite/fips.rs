// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! FIPS behavior: what a listener negotiates and refuses, what the upstream
//! client offers and insists on, what a FIPS deployment rejects, and what
//! the binary does under `PRAXIS_REQUIRE_FIPS`.
//!
//! Every test asserts both branches, keyed on whether the installed provider
//! offers approved algorithms only (`expect_approved_mode`) or, for the
//! binary's fail-closed behavior, on whether the process is in FIPS mode
//! outright, kernel flag included (`fips_host`). Under `PRAXIS_FIPS_HOST`
//! (set by `make test-fips-host`) the approved branch is mandatory, so a run
//! on the FIPS runner cannot pass on OpenSSL's default provider.
//!
//! The listener tests can be pointed at a running FIPS image instead of an
//! in-process listener: `PRAXIS_FIPS_PROBE_ADDR` names its TLS address and
//! `PRAXIS_FIPS_PROBE_CA` the CA its certificate chains to. That is how
//! `cargo xtask fips runtime-probe` drives them against the shipped image.
//!
//! The upstream tests use a rogue peer that answers a `ClientHello` with a
//! fixed record and watches the client's reaction (`tls_probe`). It works on
//! every outbound path: the proxy's upstream connector and the sub-request
//! connector are the same Pingora connector, which requires Extended Master
//! Secret on TLS 1.2 and takes its algorithms from the installed provider.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    ProxyGuard, TestCertificates, ensure_crypto_provider, expect_approved_mode, fips_host, free_port, http_get,
    https_get, praxis_bin, start_full_proxy, start_tls_backend, start_tls_backend_from_pem, start_tls_proxy,
    start_tls_proxy_no_wait,
    tls_probe::{self, ClientHello, Reply, RogueReply, RogueServer, TLS12, TLS13, alerts, groups, sigalgs, suites},
    wait_for_http, wait_for_tcp, wait_for_tls,
};
use rustls::{
    CipherSuite, ClientConfig, NamedGroup, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The listener address the probe tests target instead of an in-process
/// listener, when set.
const PROBE_ADDR_ENV: &str = "PRAXIS_FIPS_PROBE_ADDR";

/// The CA the probe target's certificate chains to.
const PROBE_CA_ENV: &str = "PRAXIS_FIPS_PROBE_CA";

/// How long the binary gets to either serve or refuse.
const STARTUP_DEADLINE: Duration = Duration::from_secs(20);

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// A file in `tests/integration/fixtures/fips`.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/fips").join(name)
}

/// A client trusting the CA certificates in `ca_pem`, on the installed
/// provider, with HTTP/2 ALPN when the harness's HTTPS client will use it.
fn client_trusting(ca_pem: &[u8], alpn_h2: bool) -> Arc<ClientConfig> {
    use rustls::pki_types::pem::PemObject as _;
    ensure_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem) {
        roots.add(cert.expect("parse CA PEM")).expect("trust the CA");
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if alpn_h2 {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }
    Arc::new(config)
}

/// A verifier that accepts any certificate and signature, so a handshake's
/// outcome depends on the server alone: what it can sign with, not what the
/// client thinks of the result.
#[derive(Debug)]
struct AcceptAnything(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnything {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A client that verifies nothing; see [`AcceptAnything`].
fn client_verifying_nothing() -> Arc<ClientConfig> {
    ensure_crypto_provider();
    let provider = CryptoProvider::get_default().expect("provider installed").clone();
    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnything(provider)))
        .with_no_client_auth();
    Arc::new(config)
}

/// A one-listener TLS config serving a static response, with `extra_tls`
/// (already indented six spaces) appended to the `tls` block.
fn tls_listener_yaml(port: u16, cert: &Path, key: &Path, extra_tls: &str) -> String {
    format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{port}"
    filter_chains: [main]
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
{extra_tls}filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        body: fips
"#,
        cert = cert.display(),
        key = key.display(),
    )
}

/// A plain listener proxying everything to one TLS upstream that must chain
/// to the CA at `ca`.
fn proxy_to_tls_upstream_yaml(proxy_port: u16, upstream_port: u16, ca: &Path) -> String {
    format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            tls:
              sni: "localhost"
              ca:
                ca_path: "{ca}"
            endpoints:
              - "127.0.0.1:{upstream_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        ca = ca.display(),
    )
}

/// A TLS listener to probe: in-process, or the image the probe variables
/// name.
struct Target {
    /// The listener's address.
    addr: String,
    /// A client that trusts the listener's certificate, with HTTP/2 ALPN.
    client_config: Arc<ClientConfig>,
    /// The in-process proxy, kept alive for the test.
    _proxy: Option<ProxyGuard>,
    /// Its certificates, kept alive with it.
    _certs: Option<TestCertificates>,
}

/// Start (or find) the listener under test.
fn tls_listener() -> Target {
    if let Ok(addr) = std::env::var(PROBE_ADDR_ENV) {
        let ca = std::env::var(PROBE_CA_ENV)
            .unwrap_or_else(|_| panic!("{PROBE_CA_ENV} must name the CA the probe target's certificate chains to"));
        let client_config = client_trusting(&fs::read(&ca).expect("read the probe CA"), true);
        wait_for_tls(&addr, &client_config);
        return Target {
            addr,
            client_config,
            _proxy: None,
            _certs: None,
        };
    }
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();
    let yaml = tls_listener_yaml(free_port(), &certs.cert_path, &certs.key_path, "");
    let config = Config::from_yaml(&yaml).expect("listener config");
    let proxy = start_tls_proxy(&config, &client_config);
    Target {
        addr: proxy.addr().to_owned(),
        client_config,
        _proxy: Some(proxy),
        _certs: Some(certs),
    }
}

/// Complete a handshake with `addr` and report what was negotiated.
fn negotiated(addr: &str, client_config: &Arc<ClientConfig>) -> (CipherSuite, NamedGroup) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
        let name = ServerName::try_from("localhost").expect("server name");
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("TCP connect");
        let tls = connector.connect(name, tcp).await.expect("TLS handshake");
        let (_, conn) = tls.get_ref();
        (
            conn.negotiated_cipher_suite().expect("a suite was negotiated").suite(),
            conn.negotiated_key_exchange_group()
                .expect("a group was negotiated")
                .name(),
        )
    })
}

/// Whether a handshake with `addr` completes.
fn handshake_succeeds(addr: &str, client_config: &Arc<ClientConfig>) -> bool {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
        let name = ServerName::try_from("localhost").expect("server name");
        let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
            return false;
        };
        connector.connect(name, tcp).await.is_ok()
    })
}

/// A spawned praxis binary, killed when dropped.
struct Running {
    /// The process.
    child: Child,
    /// Where its standard output (the log) went.
    stdout: PathBuf,
    /// Where its standard error went.
    stderr: PathBuf,
    /// The directory holding both, removed with the process.
    _dir: tempfile::TempDir,
}

impl Running {
    /// Stop the process and return its log.
    fn stop(mut self) -> String {
        kill(&mut self.child);
        strip_ansi(&fs::read_to_string(&self.stdout).expect("read the log"))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        kill(&mut self.child);
    }
}

/// Kill a process and reap it; a process that already exited is fine.
fn kill(child: &mut Child) {
    let _killed = child.kill();
    let _status = child.wait();
}

/// How the binary's startup ended.
enum Startup {
    /// The TLS listener answers handshakes.
    Ready(Running),
    /// The process exited first.
    Exited {
        /// Its exit status.
        success: bool,
        /// Its standard error.
        stderr: String,
    },
}

/// Start the binary on `config` with `env` on top of the inherited
/// environment, `PRAXIS_REQUIRE_FIPS` removed unless `env` sets it, and wait
/// for it to either serve TLS at `addr` or exit.
fn start_binary(config: &Path, addr: &str, client_config: &Arc<ClientConfig>, env: &[(&str, &str)]) -> Startup {
    let dir = tempfile::tempdir().expect("temp dir");
    let stdout = dir.path().join("stdout.log");
    let stderr = dir.path().join("stderr.log");
    let mut command = Command::new(praxis_bin());
    command
        .arg("-c")
        .arg(config)
        .env_remove("PRAXIS_REQUIRE_FIPS")
        .env_remove("PRAXIS_CONFIG")
        .stdin(Stdio::null())
        .stdout(fs::File::create(&stdout).expect("stdout file"))
        .stderr(fs::File::create(&stderr).expect("stderr file"));
    for (key, value) in env {
        command.env(key, value);
    }
    let child = command.spawn().expect("spawn praxis");
    let mut running = Running {
        child,
        stdout,
        stderr,
        _dir: dir,
    };

    let deadline = Instant::now() + STARTUP_DEADLINE;
    loop {
        if let Some(status) = running.child.try_wait().expect("poll the process") {
            let stderr = fs::read_to_string(&running.stderr).expect("read stderr");
            return Startup::Exited {
                success: status.success(),
                stderr,
            };
        }
        if handshake_succeeds(addr, client_config) {
            return Startup::Ready(running);
        }
        assert!(
            Instant::now() < deadline,
            "praxis neither served nor exited within {STARTUP_DEADLINE:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Remove ANSI escape sequences, which the log carries whether or not
/// standard output is a terminal.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

// -----------------------------------------------------------------------------
// Listener
// -----------------------------------------------------------------------------

#[test]
fn listener_negotiates_only_approved_algorithms_in_approved_mode() {
    let approved = expect_approved_mode();
    let target = tls_listener();

    let (status, body) = https_get(&target.addr, "/", &target.client_config);
    assert_eq!((status, body.as_str()), (200, "fips"), "the listener serves");

    let (suite, group) = negotiated(&target.addr, &target.client_config);
    let aes_gcm = matches!(
        suite,
        CipherSuite::TLS13_AES_128_GCM_SHA256 | CipherSuite::TLS13_AES_256_GCM_SHA384
    );
    let nist = matches!(group, NamedGroup::secp256r1 | NamedGroup::secp384r1);
    if approved {
        assert!(aes_gcm, "approved mode negotiated {suite:?}");
        assert!(nist, "approved mode negotiated {group:?}");
    } else {
        // Both sides prefer X25519 when the provider has it, so the other
        // branch is observable too.
        assert_eq!(group, NamedGroup::X25519, "outside approved mode X25519 is preferred");
    }
}

#[test]
fn listener_answers_an_approved_client_hello_in_every_mode() {
    let target = tls_listener();
    let reply = tls_probe::probe(&target.addr, &ClientHello::approved("localhost"));
    match reply {
        Reply::ServerHello { version, cipher_suite } => {
            assert_eq!(version, TLS13, "TLS 1.3 is selected");
            assert!(
                suites::AES_GCM.contains(&cipher_suite),
                "an AES-GCM suite is selected, got {cipher_suite:#06x}"
            );
        },
        refused => panic!("an approved offer was refused: {refused:?}"),
    }
}

#[test]
fn listener_refuses_tls12_without_extended_master_secret_in_every_mode() {
    let target = tls_listener();

    let refused = tls_probe::probe(&target.addr, &ClientHello::tls12("localhost", false));
    assert!(
        refused.refused(),
        "a TLS 1.2 client without Extended Master Secret must be refused, got {refused:?}"
    );

    let accepted = tls_probe::probe(&target.addr, &ClientHello::tls12("localhost", true));
    assert!(
        matches!(accepted, Reply::ServerHello { version: TLS12, cipher_suite } if suites::AES_GCM.contains(&cipher_suite)),
        "the same client with Extended Master Secret negotiates TLS 1.2, got {accepted:?}"
    );
}

#[test]
fn listener_refuses_chacha20_only_clients_in_approved_mode() {
    let approved = expect_approved_mode();
    let target = tls_listener();
    let mut hello = ClientHello::approved("localhost");
    hello.cipher_suites = suites::CHACHA20.to_vec();

    let reply = tls_probe::probe(&target.addr, &hello);
    assert_eq!(
        reply.refused(),
        approved,
        "a client offering only ChaCha20-Poly1305 is refused exactly in approved mode, got {reply:?}"
    );
    if !approved {
        assert!(
            matches!(reply, Reply::ServerHello { cipher_suite, .. } if suites::is_chacha20(cipher_suite)),
            "outside approved mode a ChaCha20 suite is selected, got {reply:?}"
        );
    }
}

#[test]
fn listener_refuses_x25519_only_clients_in_approved_mode() {
    let approved = expect_approved_mode();
    let target = tls_listener();
    let mut hello = ClientHello::approved("localhost");
    hello.groups = vec![groups::X25519];

    let reply = tls_probe::probe(&target.addr, &hello);
    assert_eq!(
        reply.refused(),
        approved,
        "a client offering only X25519 is refused exactly in approved mode, got {reply:?}"
    );
}

#[test]
fn a_listener_with_a_short_rsa_key_cannot_serve_in_approved_mode() {
    let approved = expect_approved_mode();
    // 1536 bits: below the 2048-bit minimum FIPS 186-5 sets for signature
    // generation, but large enough for the RSA-PSS with SHA-512 the provider
    // prefers, so the key serves outside approved mode (fixtures/fips/README.md).
    let cert = fixture("rsa1536-cert.pem");
    let key = fixture("rsa1536-key.pem");

    // The validated module may refuse the key when it is loaded or when it is
    // first used to sign; the operator guide promises one or the other.
    let tls = praxis_tls::ListenerTls::new_validated(cert.to_str().expect("utf-8"), key.to_str().expect("utf-8"))
        .expect("listener tls");
    if let Err(err) = praxis_tls::setup::build_server_config(&tls, true) {
        assert!(
            approved,
            "a 1536-bit RSA key was refused at load outside approved mode: {err}"
        );
        return;
    }

    let config = Config::from_yaml(&tls_listener_yaml(free_port(), &cert, &key, "")).expect("listener config");
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_tcp(proxy.addr());
    let completed = handshake_succeeds(proxy.addr(), &client_verifying_nothing());
    assert_eq!(
        completed, !approved,
        "signing with a 1536-bit RSA key fails exactly in approved mode"
    );
}

// -----------------------------------------------------------------------------
// Upstream Client
// -----------------------------------------------------------------------------

/// A proxy whose only upstream is the TLS peer on `upstream_port`, chaining
/// to `ca`, ready to take requests.
fn proxy_to(upstream_port: u16, ca: &Path) -> ProxyGuard {
    let yaml = proxy_to_tls_upstream_yaml(free_port(), upstream_port, ca);
    let proxy = start_full_proxy(&Config::from_yaml(&yaml).expect("proxy config"));
    wait_for_http(proxy.addr());
    proxy
}

#[test]
fn upstream_client_offers_only_approved_algorithms_in_approved_mode() {
    let approved = expect_approved_mode();
    let rogue = RogueServer::start(RogueReply::Alert(alerts::HANDSHAKE_FAILURE));
    let proxy = proxy_to(rogue.port(), &fixture("ca-cert.pem"));
    let (status, _) = http_get(proxy.addr(), "/", None);
    assert!(
        status >= 500,
        "the rogue peer refused, so the proxy reports an upstream error, got {status}"
    );

    let offer = rogue.next().offer;
    assert!(
        offer.extended_master_secret,
        "Extended Master Secret is offered in every mode"
    );
    assert!(
        offer.versions.contains(&TLS13) && offer.versions.contains(&TLS12),
        "TLS 1.3 and 1.2 are offered, got {:?}",
        offer.versions
    );
    assert!(
        offer.cipher_suites.contains(&suites::TLS13_AES_256_GCM_SHA384),
        "AES-GCM is offered in every mode"
    );

    let chacha20 = offer.cipher_suites.iter().any(|suite| suites::is_chacha20(*suite));
    assert_eq!(
        chacha20, !approved,
        "ChaCha20-Poly1305 is offered only outside approved mode"
    );
    let nist_only = offer.groups.iter().all(|group| groups::is_nist(*group));
    assert_eq!(
        nist_only, approved,
        "in approved mode only the NIST curves are offered, got {:?}",
        offer.groups
    );
    let x25519 = offer.groups.iter().any(|group| groups::uses_x25519(*group));
    assert_eq!(x25519, !approved, "X25519 is offered only outside approved mode");
    let ed25519 = offer.signature_algorithms.contains(&sigalgs::ED25519);
    assert_eq!(ed25519, !approved, "Ed25519 is accepted only outside approved mode");
    assert!(
        offer.signature_algorithms.contains(&sigalgs::ECDSA_SECP256R1_SHA256),
        "ECDSA P-256 is accepted in every mode"
    );
}

#[test]
fn upstream_client_refuses_tls12_without_extended_master_secret_in_every_mode() {
    let no_ems = tls_probe::tls12_server_hello(suites::ECDHE_ECDSA_AES_128_GCM_SHA256, false);
    let rogue = RogueServer::start(RogueReply::Record(no_ems));
    let proxy = proxy_to(rogue.port(), &fixture("ca-cert.pem"));
    let _response = http_get(proxy.addr(), "/", None);
    let seen = rogue.next();
    assert_eq!(
        seen.client_alert,
        Some(alerts::HANDSHAKE_FAILURE),
        "a TLS 1.2 ServerHello without Extended Master Secret draws a fatal alert"
    );

    let with_ems = tls_probe::tls12_server_hello(suites::ECDHE_ECDSA_AES_128_GCM_SHA256, true);
    let rogue = RogueServer::start(RogueReply::Record(with_ems));
    let proxy = proxy_to(rogue.port(), &fixture("ca-cert.pem"));
    let _response = http_get(proxy.addr(), "/", None);
    let seen = rogue.next();
    assert_eq!(
        seen.client_alert, None,
        "with Extended Master Secret acknowledged the client waits for the rest of the flight"
    );
}

#[test]
fn an_upstream_with_a_sha1_signed_certificate_is_refused_in_every_mode() {
    let cert = fs::read(fixture("sha1-cert.pem")).expect("read fixture");
    let key = fs::read(fixture("sha1-key.pem")).expect("read fixture");
    let sha1_backend = start_tls_backend_from_pem(&cert, &key, "sha1");
    let proxy = proxy_to(sha1_backend, &fixture("ca-cert.pem"));
    let (status, _) = http_get(proxy.addr(), "/", None);
    assert!(
        status >= 500,
        "a SHA-1 certificate signature must not verify, got {status}"
    );

    // Control: the same path with a SHA-256 chain serves.
    let certs = TestCertificates::generate();
    let good_backend = start_tls_backend(&certs, "good");
    let proxy = proxy_to(good_backend, &certs.ca_cert_path);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!((status, body.as_str()), (200, "good"));
}

// -----------------------------------------------------------------------------
// Binary
// -----------------------------------------------------------------------------

#[test]
fn the_binary_serves_under_require_fips_exactly_on_a_fips_host() {
    let in_fips_mode = fips_host();
    let certs = TestCertificates::generate();
    let port = free_port();
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("praxis.yaml");
    fs::write(&config, tls_listener_yaml(port, &certs.cert_path, &certs.key_path, "")).expect("write config");
    let addr = format!("127.0.0.1:{port}");
    let client = certs.client_config();

    match start_binary(&config, &addr, &client, &[("PRAXIS_REQUIRE_FIPS", "1")]) {
        Startup::Exited { success, stderr } => {
            assert!(
                !in_fips_mode,
                "on a FIPS host the binary must serve under PRAXIS_REQUIRE_FIPS, but it exited: {stderr}"
            );
            assert!(!success, "the refusal is an error exit");
            assert!(
                stderr.contains("PRAXIS_REQUIRE_FIPS is set but FIPS mode is not in effect"),
                "the refusal names the variable and the state, got: {stderr}"
            );
        },
        Startup::Ready(running) => {
            let (status, body) = https_get(&addr, "/", &client);
            let log = running.stop();
            assert!(
                in_fips_mode,
                "the binary served under PRAXIS_REQUIRE_FIPS on a host that is not in FIPS mode"
            );
            assert_eq!((status, body.as_str()), (200, "fips"));
            let line = log
                .lines()
                .find(|line| line.contains("installed rustls crypto provider"))
                .unwrap_or_else(|| panic!("the startup status line is missing from the log:\n{log}"));
            for field in [
                "provider=\"openssl\"",
                "provider_fips=true",
                "kernel_fips=Some(true)",
                "fips_required=true",
            ] {
                assert!(line.contains(field), "the status line lacks {field}: {line}");
            }
        },
    }
}

#[test]
fn a_chacha20_only_listener_cannot_start_in_approved_mode() {
    let approved = expect_approved_mode();
    let certs = TestCertificates::generate();
    let port = free_port();
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("praxis.yaml");
    let yaml = tls_listener_yaml(
        port,
        &certs.cert_path,
        &certs.key_path,
        "      cipher_suites: [tls13_chacha20_poly1305_sha256]\n",
    );
    fs::write(&config, yaml).expect("write config");
    let addr = format!("127.0.0.1:{port}");
    let client = certs.client_config();

    match start_binary(&config, &addr, &client, &[]) {
        Startup::Exited { success, stderr } => {
            assert!(
                approved,
                "a ChaCha20-only listener failed to start outside approved mode: {stderr}"
            );
            assert!(!success, "the refusal is an error exit");
        },
        Startup::Ready(running) => {
            let (suite, _) = negotiated(&addr, &client);
            drop(running);
            assert!(!approved, "a ChaCha20-only listener started in approved mode");
            assert_eq!(
                suite,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                "outside approved mode it serves ChaCha20"
            );
        },
    }
}
