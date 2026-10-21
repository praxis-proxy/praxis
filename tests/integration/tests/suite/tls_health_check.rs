// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! TLS health probes through the background runner and health registry.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use praxis_core::{
    config::{Cluster, HealthCheckType},
    health::build_health_registry,
};
use praxis_protocol::http::health::runner::spawn_health_checks_with_ca;
use praxis_test_utils::{TestCertificates, ensure_crypto_provider, parse_cert_chain_and_key};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
async fn https_probe_recovers_a_tls_endpoint() {
    let certs = TestCertificates::generate();
    let backend = Backend::new(&certs, false).await;
    let cluster = cluster(&certs, &backend.address, HealthCheckType::Http);
    assert_health(cluster, None, true).await;
    let requests = backend.requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .any(|request| request.starts_with("GET /health HTTP/1.1\r\n")),
        "configured path must reach the backend"
    );
    assert!(
        requests
            .iter()
            .all(|request| request.contains("\r\nHost: localhost\r\n")),
        "HTTPS Host defaults to configured SNI"
    );
    drop(requests);
}

#[test]
fn explicit_ca_probes_do_not_load_platform_roots() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tls_health_check::https_probe_recovers_a_tls_endpoint",
            "--nocapture",
        ])
        .env("SSL_CERT_FILE", "/nonexistent/platform-ca.pem")
        .env("SSL_CERT_DIR", "/nonexistent/platform-ca-dir")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "explicit CA must replace unavailable platform roots: {stdout}"
    );
}

#[tokio::test]
async fn tls_probe_checks_server_identity_and_sends_close_notify() {
    let certs = TestCertificates::generate();
    let backend = Backend::new(&certs, false).await;
    assert_health(cluster(&certs, &backend.address, HealthCheckType::Tls), None, true).await;
    wait_until(|| backend.closes.load(Ordering::Relaxed) > 0).await;
    assert!(
        backend.requests.lock().unwrap().is_empty(),
        "handshake probes send no application bytes"
    );
}

#[tokio::test]
async fn tls_probe_rejects_untrusted_expired_and_wrong_name_certificates() {
    let trusted = TestCertificates::generate();
    let other = TestCertificates::generate();
    let expired = TestCertificates::generate_expired();
    for (server, roots, sni) in [
        (&other, &trusted, "localhost"),
        (&expired, &expired, "localhost"),
        (&trusted, &trusted, "wrong.example"),
    ] {
        let backend = Backend::new(server, false).await;
        let mut config = cluster(roots, &backend.address, HealthCheckType::Tls);
        config.tls.as_mut().unwrap().sni = Some(sni.to_owned());
        assert_health(config, None, false).await;
    }
}

#[tokio::test]
async fn tls_probe_honors_verify_false() {
    let certs = TestCertificates::generate_expired();
    let backend = Backend::new(&certs, false).await;
    let mut config = cluster(&certs, &backend.address, HealthCheckType::Tls);
    config.tls.as_mut().unwrap().verify = false;
    assert_health(config, None, true).await;
}

#[tokio::test]
async fn tls_probe_rejects_missing_tls13_client_credentials() {
    let certs = TestCertificates::generate();
    let backend = Backend::new(&certs, true).await;
    assert_health(cluster(&certs, &backend.address, HealthCheckType::Tls), None, false).await;
}

#[tokio::test]
async fn tls_probe_waits_for_rejection_on_slow_tls13_connection() {
    let certs = TestCertificates::generate();
    let backend = Backend::new(&certs, true).await;
    let (address, relay) = delayed_server_traffic(&backend.address).await;
    let mut config = cluster(&certs, &address, HealthCheckType::Tls);
    config.health_check.as_mut().unwrap().timeout_ms = 5000;
    config.health_check.as_mut().unwrap().interval_ms = 10_000;
    let started = tokio::time::Instant::now();
    assert_health(config, None, false).await;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the delayed rejection must fail before the five-second probe timeout"
    );
    relay.abort();
}

#[tokio::test]
async fn tls_probe_rejects_untrusted_tls13_client_credentials() {
    let certs = TestCertificates::generate();
    let backend = Backend::new(&certs, true).await;
    let other = TestCertificates::generate();
    let untrusted = other.generate_client_cert();
    let mut config = cluster(&certs, &backend.address, HealthCheckType::Tls);
    config.tls.as_mut().unwrap().client_cert = Some(
        serde_yaml::from_str(&format!(
            "cert_path: {}\nkey_path: {}",
            untrusted.cert_path.display(),
            untrusted.key_path.display()
        ))
        .unwrap(),
    );
    assert_health(config, None, false).await;
}

#[tokio::test]
async fn https_probe_requires_accepted_tls13_client_credentials() {
    let certs = TestCertificates::generate();
    let backend = Backend::new(&certs, true).await;
    let client = certs.generate_client_cert();
    let other = TestCertificates::generate();
    let untrusted = other.generate_client_cert();
    let mut config = cluster(&certs, &backend.address, HealthCheckType::Http);
    assert_health(config.clone(), None, false).await;
    config.tls.as_mut().unwrap().client_cert = Some(
        serde_yaml::from_str(&format!(
            "cert_path: {}\nkey_path: {}",
            untrusted.cert_path.display(),
            untrusted.key_path.display()
        ))
        .unwrap(),
    );
    assert_health(config.clone(), None, false).await;
    config.tls.as_mut().unwrap().client_cert = Some(
        serde_yaml::from_str(&format!(
            "cert_path: {}\nkey_path: {}",
            client.cert_path.display(),
            client.key_path.display()
        ))
        .unwrap(),
    );
    assert_health(config.clone(), None, true).await;
    config.health_check.as_mut().unwrap().check_type = HealthCheckType::Tls;
    assert_health(config, None, true).await;
}

#[tokio::test]
async fn runtime_ca_replaces_system_trust_and_cluster_ca_takes_precedence() {
    let certs = TestCertificates::generate();
    let other = TestCertificates::generate();
    let backend = Backend::new(&certs, false).await;
    let roots = praxis_tls::CachedCaCerts::from_pem_file(certs.ca_cert_path.to_str().unwrap()).unwrap();
    let wrong_roots = praxis_tls::CachedCaCerts::from_pem_file(other.ca_cert_path.to_str().unwrap()).unwrap();
    let mut config = cluster(&certs, &backend.address, HealthCheckType::Tls);
    assert_health(config.clone(), Some(&wrong_roots), true).await;
    config.tls.as_mut().unwrap().ca = None;
    assert_health(config.clone(), Some(&roots), true).await;
    assert_health(config.clone(), Some(&wrong_roots), false).await;
    assert_health(config, None, false).await;
}

#[tokio::test]
async fn https_probe_observes_status_and_fragmented_response() {
    let certs = TestCertificates::generate();
    let backend = Backend::new(&certs, false).await;
    backend.status.store(204, Ordering::Relaxed);
    let mut config = cluster(&certs, &backend.address, HealthCheckType::Http);
    assert_health(config.clone(), None, false).await;
    config.health_check.as_mut().unwrap().expected_status = 204;
    assert_health(config, None, true).await;
    wait_until(|| backend.closes.load(Ordering::Relaxed) >= 2).await;
}

#[tokio::test]
async fn fixed_authority_and_endpoint_fallback_control_sni_and_host() {
    let certs = TestCertificates::generate_for_san("virtual.example");
    let backend = Backend::new(&certs, false).await;
    let mut config = cluster(&certs, &backend.address, HealthCheckType::Http);
    config.tls.as_mut().unwrap().sni = None;
    config.http.authority = Some("virtual.example:8443".into());
    assert_health(config.clone(), None, true).await;
    assert!(
        backend
            .names
            .lock()
            .unwrap()
            .iter()
            .any(|name| name.as_deref() == Some("virtual.example")),
        "fixed authority supplies SNI without its port"
    );
    assert!(
        backend
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request.contains("Host: virtual.example:8443\r\n")),
        "fixed authority supplies Host including port"
    );
    config.http.authority = None;
    assert_health(config, None, true).await;
    assert!(
        backend.names.lock().unwrap().iter().any(Option::is_none),
        "IP fallback must use IP SAN verification without DNS SNI"
    );
    assert!(
        backend
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request.contains(&format!("Host: {}\r\n", backend.address))),
        "endpoint fallback retains nondefault port"
    );
}

#[tokio::test]
async fn hostname_probes_use_the_upstream_address_policy() {
    let certs = TestCertificates::generate();
    let backend = Backend::new(&certs, false).await;
    let address = format!("localhost:{}", backend.address.rsplit_once(':').unwrap().1);
    assert_health(cluster(&certs, &address, HealthCheckType::Http), None, true).await;
}

#[tokio::test]
async fn handshake_probe_honors_h2_only_alpn() {
    let certs = TestCertificates::generate();
    let backend = Backend::new(&certs, false).await;
    let mut server = server_config(&certs, false);
    server.alpn_protocols = vec![b"h2".to_vec()];
    backend.config.store(Arc::new(server));
    let mut config = cluster(&certs, &backend.address, HealthCheckType::Tls);
    config.http.version = praxis_core::config::UpstreamHttpVersion::H2;
    assert_health(config.clone(), None, true).await;
    config.http.version = praxis_core::config::UpstreamHttpVersion::Auto;
    assert_health(config, None, true).await;
}

#[tokio::test]
async fn bad_cached_material_marks_endpoint_unhealthy() {
    let certs = TestCertificates::generate();
    let backend = Backend::new(&certs, false).await;
    let mut config = cluster(&certs, &backend.address, HealthCheckType::Tls);
    config.tls.as_mut().unwrap().ca.as_mut().unwrap().ca_path = "/nonexistent/health-ca.pem".to_owned();
    assert_health(config, None, false).await;
}

#[tokio::test]
async fn tls_probe_times_out_a_stalled_handshake_and_tcp_still_succeeds() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let held = tokio::spawn(async move {
        let (tls_socket, _) = listener.accept().await.unwrap();
        let (tcp_socket, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
        drop((tls_socket, tcp_socket));
    });
    let certs = TestCertificates::generate();
    let mut config = cluster(&certs, &address, HealthCheckType::Tls);
    config.health_check.as_mut().unwrap().timeout_ms = 100;
    let started = tokio::time::Instant::now();
    assert_health(config.clone(), None, false).await;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "stalled TLS must obey the total probe deadline"
    );
    config.health_check.as_mut().unwrap().check_type = HealthCheckType::Tcp;
    assert_health(config, None, true).await;
    held.abort();
}

#[tokio::test]
async fn tls_probe_rejects_plaintext_responses() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            drop(socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await);
        }
    });
    assert_health(
        cluster(&TestCertificates::generate(), &address, HealthCheckType::Tls),
        None,
        false,
    )
    .await;
    task.abort();
}

#[tokio::test]
async fn repeated_probes_do_not_resume_an_old_server_identity() {
    let certs = TestCertificates::generate();
    let replacement = TestCertificates::generate();
    let backend = Backend::new(&certs, false).await;
    let mut config = cluster(&certs, &backend.address, HealthCheckType::Http);
    config.health_check.as_mut().unwrap().interval_ms = 300;
    config.health_check.as_mut().unwrap().timeout_ms = 250;
    let registry = build_health_registry(std::slice::from_ref(&config));
    let state = Arc::clone(&registry["secure"]);
    state.endpoints()[0].mark_unhealthy();
    let shutdown = Default::default();
    spawn_health_checks_with_ca(&[config], &registry, &shutdown, None);
    wait_until(|| backend.requests.lock().unwrap().len() >= 2).await;
    assert!(state.endpoints()[0].is_healthy(), "trusted identity initially serves");
    let old = backend.config.load_full();
    let mut next = server_config(&replacement, false);
    next.session_storage = Arc::clone(&old.session_storage);
    next.ticketer = Arc::clone(&old.ticketer);
    backend.config.store(Arc::new(next));
    wait_until(|| !state.endpoints()[0].is_healthy()).await;
    shutdown.cancel();
    assert_eq!(
        backend.resumed.load(Ordering::Relaxed),
        0,
        "each probe must validate a full handshake"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_keeps_startup_runtime_trust_across_two_generations() {
    let certs = TestCertificates::generate();
    let wrong = TestCertificates::generate();
    let backend = Backend::new(&certs, false).await;
    let proxy_port = praxis_test_utils::free_port();
    let yaml = |generation: &str, roots: &std::path::Path| {
        format!(
            "listeners:\n  - name: proxy\n    address: 127.0.0.1:{proxy_port}\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: static_response\n        status: 200\n        body: {generation}\nruntime:\n  upstream_ca_file: {}\nclusters:\n  - name: secure\n    endpoints: ['{}']\n    tls: {{ sni: localhost }}\n    health_check:\n      type: http\n      path: /{generation}\n      interval_ms: 1000\n      timeout_ms: 500\n      healthy_threshold: 1\n      unhealthy_threshold: 1\ninsecure_options:\n  allow_private_endpoints: true\n  allow_private_health_checks: true\n",
            roots.display(),
            backend.address
        )
    };
    let proxy = praxis_test_utils::start_reloadable_proxy(&yaml("first", &certs.ca_cert_path));
    wait_until(|| {
        backend
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request.starts_with("GET /first "))
    })
    .await;
    for generation in ["second", "third"] {
        proxy.write_config(&yaml(generation, &wrong.ca_cert_path));
        tokio::time::timeout(Duration::from_secs(20), async {
            while !backend
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|request| request.starts_with(&format!("GET /{generation} ")))
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("reloaded probe must still trust the startup CA");
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Delay the server handshake flight by 300 ms and later TLS alerts by 150 ms.
async fn delayed_server_traffic(upstream: &str) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let upstream = upstream.to_owned();
    let task = tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let server = tokio::net::TcpStream::connect(&upstream).await.unwrap();
            tokio::spawn(async move {
                let (mut client_read, mut client_write) = client.into_split();
                let (mut server_read, mut server_write) = server.into_split();
                let to_client = async {
                    let mut delay = Duration::from_millis(300);
                    let mut buf = vec![0; 8192];
                    while let Ok(count) = server_read.read(&mut buf).await {
                        if count == 0 {
                            break;
                        }
                        tokio::time::sleep(delay).await;
                        if client_write.write_all(&buf[..count]).await.is_err() {
                            break;
                        }
                        delay = Duration::from_millis(150);
                    }
                };
                drop(tokio::join!(
                    tokio::io::copy(&mut client_read, &mut server_write),
                    to_client
                ));
            });
        }
    });
    (address, task)
}

/// A TLS 1.3 backend with observable requests and clean TLS shutdowns.
pub(super) struct Backend {
    /// Bound endpoint.
    pub(super) address: String,
    /// Server configurations can rotate while ticket state is preserved.
    pub(super) config: Arc<ArcSwap<rustls::ServerConfig>>,
    /// Observed close_notify alerts, distinguished from abrupt EOF by rustls.
    pub(super) closes: Arc<AtomicUsize>,
    /// Observed TLS SNI values.
    pub(super) names: Arc<Mutex<Vec<Option<String>>>>,
    /// Bounded request header recordings.
    pub(super) requests: Arc<Mutex<Vec<String>>>,
    /// Number of resumed TLS sessions.
    pub(super) resumed: Arc<AtomicUsize>,
    /// Response status.
    pub(super) status: Arc<AtomicUsize>,
    /// Listener task cancelled on drop.
    pub(super) task: tokio::task::JoinHandle<()>,
}

impl Backend {
    /// Start a real TLS server that fragments its status line.
    pub(super) async fn new(certs: &TestCertificates, mtls: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let config = Arc::new(ArcSwap::from_pointee(server_config(certs, mtls)));
        let closes = Arc::new(AtomicUsize::new(0));
        let names = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resumed = Arc::new(AtomicUsize::new(0));
        let status = Arc::new(AtomicUsize::new(200));
        let shared = (
            Arc::clone(&config),
            Arc::clone(&closes),
            Arc::clone(&names),
            Arc::clone(&requests),
            Arc::clone(&resumed),
            Arc::clone(&status),
        );
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (config, closes, names, requests, resumed, status) = shared.clone();
                tokio::spawn(async move {
                    let exchange = async {
                        let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(config.load_full()).accept(socket).await
                        else {
                            return;
                        };
                        names
                            .lock()
                            .unwrap()
                            .push(stream.get_ref().1.server_name().map(str::to_owned));
                        if stream.get_ref().1.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
                            resumed.fetch_add(1, Ordering::Relaxed);
                        }
                        let mut request = Vec::new();
                        let mut buf = [0; 256];
                        while let Ok(count) = stream.read(&mut buf).await {
                            if count == 0 {
                                closes.fetch_add(1, Ordering::Relaxed);
                                return;
                            }
                            request.extend_from_slice(&buf[..count]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                            assert!(request.len() <= 4096, "probe request must be bounded");
                        }
                        requests
                            .lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(&request).into_owned());
                        if stream.write_all(b"HTTP/1.1 ").await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        let response = format!("{} OK\r\nContent-Length: 0\r\n\r\n", status.load(Ordering::Relaxed));
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                        if matches!(stream.read(&mut buf).await, Ok(0)) {
                            closes.fetch_add(1, Ordering::Relaxed);
                        }
                    };
                    drop(tokio::time::timeout(Duration::from_secs(3), exchange).await);
                });
            }
        });
        Self {
            address,
            config,
            closes,
            names,
            requests,
            resumed,
            status,
            task,
        }
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Build a TLS 1.3 server with optional required client authentication.
fn server_config(certs: &TestCertificates, mtls: bool) -> rustls::ServerConfig {
    ensure_crypto_provider();
    let (chain, key) = parse_cert_chain_and_key(
        &std::fs::read(&certs.cert_path).unwrap(),
        &std::fs::read(&certs.key_path).unwrap(),
    );
    let builder = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
    let builder = if mtls {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(certs.ca_cert_der.clone()))
            .unwrap();
        builder.with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap(),
        )
    } else {
        builder.with_no_client_auth()
    };
    builder.with_single_cert(chain, key).unwrap()
}

/// Configure a probe with test trust and short iteration timing.
fn cluster(certs: &TestCertificates, address: &str, kind: HealthCheckType) -> Cluster {
    serde_yaml::from_str(&format!(
        "name: secure\nendpoints: ['{address}']\ntls:\n  sni: localhost\n  ca:\n    ca_path: {}\nhealth_check:\n  type: {kind}\n  path: /health\n  interval_ms: 2000\n  timeout_ms: 1000\n  healthy_threshold: 1\n  unhealthy_threshold: 1\n",
        certs.ca_cert_path.display()
    )).unwrap()
}

/// Require a health transition from the opposite state and stop the runner.
async fn assert_health(cluster: Cluster, roots: Option<&praxis_tls::CachedCaCerts>, healthy: bool) {
    let registry = build_health_registry(std::slice::from_ref(&cluster));
    let state = Arc::clone(&registry["secure"]);
    if healthy {
        state.endpoints()[0].mark_unhealthy();
    }
    let shutdown = Default::default();
    spawn_health_checks_with_ca(&[cluster], &registry, &shutdown, roots);
    let result = tokio::time::timeout(Duration::from_secs(6), async {
        while state.endpoints()[0].is_healthy() != healthy {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    shutdown.cancel();
    result.expect("health runner must transition to the expected state");
}

/// Wait for an observable server or registry condition with a bounded budget.
async fn wait_until<F: Fn() -> bool + Send + Sync>(condition: F) {
    tokio::time::timeout(Duration::from_secs(6), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("expected condition before timeout");
}
