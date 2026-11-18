// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! TLS integration tests: listener termination, upstream origination,
//! TCP TLS forwarding, mTLS, and SNI behavior.

use std::sync::Arc;
#[cfg(feature = "hyper")]
use std::{
    collections::HashMap,
    io::{BufRead as _, Read as _, Write as _},
    sync::atomic::Ordering,
};
#[cfg(target_os = "linux")]
use std::{
    path::Path as FixturePath,
    process::Command,
    time::{Duration as FixtureDuration, Instant},
};

#[cfg(feature = "hyper")]
use openssl::{hash::MessageDigest, x509::X509};
use praxis_core::config::Config;
#[cfg(target_os = "linux")]
use praxis_core::config::LogOutput;
#[cfg(feature = "hyper")]
use praxis_filter::{FilterFactory, FilterRegistry};
#[cfg(target_os = "linux")]
use praxis_protocol::tls_setup::take_test_watcher_handles;
#[cfg(feature = "hyper")]
use praxis_test_utils::start_request_counting_backend;
use praxis_test_utils::{
    TestCertificates, free_port, http_get, https_get, registry_with, start_backend_with_shutdown, start_full_proxy,
    start_mtls_backend, start_proxy, start_tcp_echo_backend, start_tls_backend, start_tls_proxy,
    start_tls_proxy_no_wait, start_tls_proxy_no_wait_with_registry, tls_negative_probe, tls_send_recv, wait_for_https,
    wait_for_tls,
};

/// Marks the isolated process running the TLS fixture watcher regression.
#[cfg(target_os = "linux")]
const TLS_FIXTURE_WATCHER_CHILD: &str = "PRAXIS_TLS_FIXTURE_WATCHER_CHILD";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// Build a static-response config with the requested HTTPS listeners.
#[cfg(target_os = "linux")]
fn fixture_tls_yaml(listeners: &[(u16, &TestCertificates, bool)]) -> String {
    let listeners = listeners
        .iter()
        .map(|(port, certs, hot_reload)| {
            format!(
                "  - name: secure-{port}\n    address: 127.0.0.1:{port}\n    filter_chains: [main]\n    tls:\n      certificates:\n        - cert_path: {}\n          key_path: {}\n      hot_reload: {hot_reload}\n",
                certs.cert_path.display(),
                certs.key_path.display()
            )
        })
        .collect::<String>();
    format!(
        "listeners:\n{listeners}filter_chains:\n  - name: main\n    filters:\n      - filter: static_response\n        status: 200\n        body: fixture-ok\ninsecure_options:\n  allow_root: true\n"
    )
}

/// Build a fixture that owns one HTTP and one TCP certificate watcher.
#[cfg(target_os = "linux")]
fn fixture_mixed_tls_yaml(
    http_port: u16,
    http_certs: &TestCertificates,
    tcp_port: u16,
    tcp_certs: &TestCertificates,
    echo_port: u16,
) -> String {
    format!(
        "insecure_options:\n  allow_private_upstreams: true\nlisteners:\n  - name: secure-http\n    address: 127.0.0.1:{http_port}\n    filter_chains: [main]\n    tls:\n      certificates:\n        - cert_path: {}\n          key_path: {}\n      hot_reload: true\n  - name: secure-tcp\n    address: 127.0.0.1:{tcp_port}\n    protocol: tcp\n    upstream: 127.0.0.1:{echo_port}\n    tls:\n      certificates:\n        - cert_path: {}\n          key_path: {}\n      hot_reload: true\nfilter_chains:\n  - name: main\n    filters:\n      - filter: static_response\n        status: 200\n        body: fixture-ok\n",
        http_certs.cert_path.display(),
        http_certs.key_path.display(),
        tcp_certs.cert_path.display(),
        tcp_certs.key_path.display()
    )
}

/// Count only inotify's anonymous-inode descriptors in this process.
#[cfg(target_os = "linux")]
fn fixture_inotify_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("list process descriptors")
        .map(|entry| entry.expect("read process descriptor entry"))
        .filter_map(|entry| match std::fs::read_link(entry.path()) {
            Ok(target) => Some(target),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("read process descriptor target: {error}"),
        })
        .filter(|target| {
            target == FixturePath::new("anon_inode:inotify") || target == FixturePath::new("anon_inode:[inotify]")
        })
        .count()
}

/// Observe asynchronous watcher startup or shutdown within five seconds.
#[cfg(target_os = "linux")]
fn wait_for_fixture_inotify(expected: usize) {
    let deadline = Instant::now() + FixtureDuration::from_secs(5);
    loop {
        let actual = fixture_inotify_count();
        if actual == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "expected {expected} inotify instances, found {actual}"
        );
        std::thread::sleep(FixtureDuration::from_millis(10));
    }
}

/// Join every watcher spawned by one fixture before checking native cleanup.
#[cfg(target_os = "linux")]
fn assert_fixture_watchers_stopped(expected: usize, baseline: usize) {
    let handles = take_test_watcher_handles();
    assert_eq!(
        handles.len(),
        expected,
        "fixture must spawn the expected watcher threads"
    );
    let deadline = Instant::now() + FixtureDuration::from_secs(5);
    while !handles.iter().all(std::thread::JoinHandle::is_finished) {
        assert!(
            Instant::now() < deadline,
            "fixture left a certificate watcher thread running"
        );
        std::thread::sleep(FixtureDuration::from_millis(10));
    }
    for handle in handles {
        handle.join().expect("certificate watcher thread finished cleanly");
    }
    wait_for_fixture_inotify(baseline);
}

/// Replace one watched certificate and its matching key in place.
#[cfg(target_os = "linux")]
fn rotate_fixture_certificate(original: &TestCertificates, replacement: &TestCertificates) {
    assert_ne!(
        original.server_cert_der, replacement.server_cert_der,
        "rotation fixture must supply a distinct certificate"
    );
    std::fs::copy(&replacement.key_path, &original.key_path).expect("replace TLS key");
    std::fs::copy(&replacement.cert_path, &original.cert_path).expect("replace TLS certificate");
}

/// Wait for a new HTTPS identity, then prove the exact certificate and response.
#[cfg(target_os = "linux")]
fn wait_for_fixture_https_identity(addr: &str, certs: &TestCertificates) {
    let deadline = Instant::now() + FixtureDuration::from_secs(8);
    loop {
        if let Ok(response) = praxis_test_utils::https_get_attempt(addr, "/", &certs.client_config()) {
            assert_eq!(response, (200, "fixture-ok".to_owned()), "rotated TLS response");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "watcher did not serve the expected certificate at {addr}"
        );
        std::thread::sleep(FixtureDuration::from_millis(25));
    }
    assert_eq!(
        get_peer_cert_der(addr, &certs.client_config(), "localhost"),
        certs.server_cert_der,
        "fresh handshake must present the exact expected certificate at {addr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn tls_fixture_watchers_stop_after_each_guard() {
    if std::env::var_os(TLS_FIXTURE_WATCHER_CHILD).is_none() {
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "tls::tls_fixture_watchers_stop_after_each_guard"])
            .env(TLS_FIXTURE_WATCHER_CHILD, "1")
            .output()
            .expect("run isolated TLS fixture test");
        assert!(
            output.status.success(),
            "isolated fixture failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("test tls::tls_fixture_watchers_stop_after_each_guard ... ok"),
            "isolated child must run the exact regression test: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }

    let baseline = fixture_inotify_count();
    for _ in 0..2 {
        let original = TestCertificates::generate();
        let port = free_port();
        let config = Config::from_yaml(&fixture_tls_yaml(&[(port, &original, true)])).expect("TLS fixture config");
        let proxy = start_tls_proxy(&config, &original.client_config());
        wait_for_fixture_inotify(baseline + 1);
        assert_eq!(
            https_get(proxy.addr(), "/", &original.client_config()),
            (200, "fixture-ok".to_owned()),
            "live watcher must preserve verified HTTPS"
        );

        let rotated = TestCertificates::generate();
        assert_ne!(
            original.server_cert_der, rotated.server_cert_der,
            "rotation must change certificate identity"
        );
        std::fs::copy(&rotated.key_path, &original.key_path).expect("replace TLS key");
        std::fs::copy(&rotated.cert_path, &original.cert_path).expect("replace TLS certificate");
        let rotated_client = rotated.client_config();
        let deadline = Instant::now() + FixtureDuration::from_secs(8);
        loop {
            if let Ok(response) = praxis_test_utils::https_get_attempt(proxy.addr(), "/", &rotated_client) {
                assert_eq!(response, (200, "fixture-ok".to_owned()), "rotated TLS response");
                break;
            }
            assert!(Instant::now() < deadline, "watcher did not serve rotated certificate");
            std::thread::sleep(FixtureDuration::from_millis(25));
        }
        assert!(
            praxis_test_utils::https_get_attempt(proxy.addr(), "/", &original.client_config()).is_err(),
            "original CA must not verify the rotated certificate"
        );
        drop(proxy);
        assert_fixture_watchers_stopped(1, baseline);
    }

    let original = TestCertificates::generate();
    let port = free_port();
    let config = Config::from_yaml(&fixture_tls_yaml(&[(port, &original, true)]))
        .expect("invalid-then-repaired TLS fixture config");
    let log_dir = tempfile::TempDir::new().expect("certificate reload log directory");
    let log_path = log_dir.path().join("certificate-reload.log");
    let mut log_config = config.clone();
    log_config.runtime.logging.output = LogOutput::File;
    log_config.runtime.logging.file_path = Some(log_path.to_string_lossy().into_owned());
    log_config.runtime.logging.non_blocking = false;
    log_config
        .runtime
        .log_overrides
        .insert("praxis_tls::watcher".to_owned(), "warn".to_owned());
    let _tracing_guard =
        praxis_core::logging::init_tracing(&log_config).expect("capture watcher warnings in the isolated child");
    let proxy = start_tls_proxy(&config, &original.client_config());
    wait_for_fixture_inotify(baseline + 1);
    std::fs::write(&original.cert_path, b"not a certificate").expect("corrupt watched certificate");
    std::fs::write(&original.key_path, b"not a key").expect("corrupt watched key");
    let deadline = Instant::now() + FixtureDuration::from_secs(15);
    loop {
        let logged = std::fs::read_to_string(&log_path).expect("read watcher log");
        if logged.contains("TLS certificate reload failed, keeping previous certificate")
            && logged.contains(original.cert_path.to_str().expect("certificate path"))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "watcher never attempted the invalid certificate reload: {logged}"
        );
        std::thread::sleep(FixtureDuration::from_millis(25));
    }
    assert_eq!(
        get_peer_cert_der(proxy.addr(), &original.client_config(), "localhost"),
        original.server_cert_der,
        "invalid rotation must retain the last good certificate"
    );
    assert_eq!(
        https_get(proxy.addr(), "/", &original.client_config()),
        (200, "fixture-ok".to_owned()),
        "invalid rotation must leave the listener serving"
    );
    let repaired = TestCertificates::generate();
    rotate_fixture_certificate(&original, &repaired);
    wait_for_fixture_https_identity(proxy.addr(), &repaired);
    assert!(
        praxis_test_utils::https_get_attempt(proxy.addr(), "/", &original.client_config()).is_err(),
        "the original CA must not verify the repaired certificate"
    );
    drop(proxy);
    assert_fixture_watchers_stopped(1, baseline);

    let first = TestCertificates::generate();
    let second = TestCertificates::generate();
    let first_port = free_port();
    let second_port = free_port();
    let config = Config::from_yaml(&fixture_tls_yaml(&[
        (first_port, &first, true),
        (second_port, &second, true),
    ]))
    .expect("multi-listener TLS config");
    let proxy = start_full_proxy(&config);
    for (port, certs) in [(first_port, &first), (second_port, &second)] {
        let addr = format!("127.0.0.1:{port}");
        wait_for_https(&addr, &certs.client_config());
        assert_eq!(
            https_get(&addr, "/", &certs.client_config()),
            (200, "fixture-ok".to_owned()),
            "each listener must serve verified HTTPS"
        );
    }
    wait_for_fixture_inotify(baseline + 2);
    let first_addr = format!("127.0.0.1:{first_port}");
    let second_addr = format!("127.0.0.1:{second_port}");
    let first_rotated = TestCertificates::generate();
    rotate_fixture_certificate(&first, &first_rotated);
    wait_for_fixture_https_identity(&first_addr, &first_rotated);
    assert_eq!(
        get_peer_cert_der(&second_addr, &second.client_config(), "localhost"),
        second.server_cert_der,
        "rotating the first watcher must not change the second listener"
    );
    assert_eq!(https_get(&second_addr, "/", &second.client_config()).1, "fixture-ok");
    let second_rotated = TestCertificates::generate();
    rotate_fixture_certificate(&second, &second_rotated);
    wait_for_fixture_https_identity(&second_addr, &second_rotated);
    assert_eq!(
        get_peer_cert_der(&first_addr, &first_rotated.client_config(), "localhost"),
        first_rotated.server_cert_der,
        "rotating the second watcher must not revert the first listener"
    );
    drop(proxy);
    assert_fixture_watchers_stopped(2, baseline);

    let http_certs = TestCertificates::generate();
    let tcp_certs = TestCertificates::generate();
    let http_port = free_port();
    let tcp_port = free_port();
    let echo_port = start_tcp_echo_backend();
    let mixed_yaml = fixture_mixed_tls_yaml(http_port, &http_certs, tcp_port, &tcp_certs, echo_port);
    let config = Config::from_yaml(&mixed_yaml).expect("mixed HTTP and TCP config");
    let proxy = start_full_proxy(&config);
    let http_addr = format!("127.0.0.1:{http_port}");
    let tcp_addr = format!("127.0.0.1:{tcp_port}");
    wait_for_https(&http_addr, &http_certs.client_config());
    wait_for_tls(&tcp_addr, &tcp_certs.raw_tls_client_config());
    wait_for_fixture_inotify(baseline + 2);
    assert_eq!(
        https_get(&http_addr, "/", &http_certs.client_config()),
        (200, "fixture-ok".to_owned()),
        "HTTP watcher must serve verified HTTPS"
    );
    assert_eq!(
        tls_send_recv(&tcp_addr, b"fixture-tcp", &tcp_certs.raw_tls_client_config()),
        b"fixture-tcp",
        "TCP watcher must preserve TLS forwarding"
    );
    let tcp_rotated = TestCertificates::generate();
    rotate_fixture_certificate(&tcp_certs, &tcp_rotated);
    wait_for_tls(&tcp_addr, &tcp_rotated.raw_tls_client_config());
    assert_eq!(
        get_peer_cert_der(&tcp_addr, &tcp_rotated.raw_tls_client_config(), "localhost"),
        tcp_rotated.server_cert_der,
        "TCP watcher must install its new certificate"
    );
    assert_eq!(
        tls_send_recv(&tcp_addr, b"rotated-tcp", &tcp_rotated.raw_tls_client_config()),
        b"rotated-tcp",
        "rotated TCP listener must still forward bytes"
    );
    assert_eq!(
        get_peer_cert_der(&http_addr, &http_certs.client_config(), "localhost"),
        http_certs.server_cert_der,
        "TCP rotation must leave the HTTP watcher unchanged"
    );
    let http_rotated = TestCertificates::generate();
    rotate_fixture_certificate(&http_certs, &http_rotated);
    wait_for_fixture_https_identity(&http_addr, &http_rotated);
    assert_eq!(
        get_peer_cert_der(&tcp_addr, &tcp_rotated.raw_tls_client_config(), "localhost"),
        tcp_rotated.server_cert_der,
        "HTTP rotation must leave the TCP watcher unchanged"
    );
    drop(proxy);
    assert_fixture_watchers_stopped(2, baseline);

    let invalid_tcp = TestCertificates::generate();
    let invalid_yaml = fixture_mixed_tls_yaml(free_port(), &http_certs, free_port(), &invalid_tcp, echo_port);
    let invalid_config = Config::from_yaml(&invalid_yaml).expect("config with initially valid certificates");
    std::fs::remove_file(&invalid_tcp.key_path).expect("invalidate TCP key before registration");
    let outcome = std::panic::catch_unwind(|| start_full_proxy(&invalid_config));
    let Err(failure) = outcome else {
        panic!("TCP registration must fail after HTTP registration");
    };
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .expect("registration panic text");
    assert!(
        message.contains("TCP protocol registration should succeed"),
        "failure must occur after successful HTTP registration: {message}"
    );
    assert_fixture_watchers_stopped(1, baseline);

    let static_certs = TestCertificates::generate();
    let static_port = free_port();
    let config =
        Config::from_yaml(&fixture_tls_yaml(&[(static_port, &static_certs, false)])).expect("static TLS config");
    let proxy = start_tls_proxy(&config, &static_certs.client_config());
    assert_eq!(fixture_inotify_count(), baseline, "static TLS must not start a watcher");
    drop(proxy);
    assert_fixture_watchers_stopped(0, baseline);

    let plain_port = free_port();
    let plain_yaml = format!(
        "listeners:\n  - name: plain\n    address: 127.0.0.1:{plain_port}\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: static_response\n        status: 200\n        body: fixture-ok\ninsecure_options:\n  allow_root: true\n"
    );
    let plain_config = Config::from_yaml(&plain_yaml).expect("plain HTTP config");
    let proxy = start_proxy(&plain_config);
    assert_eq!(fixture_inotify_count(), baseline, "plain HTTP must not start a watcher");
    drop(proxy);
    assert_fixture_watchers_stopped(0, baseline);

    let panic_certs = TestCertificates::generate();
    let panic_port = free_port();
    let panic_config =
        Config::from_yaml(&fixture_tls_yaml(&[(panic_port, &panic_certs, true)])).expect("panic fixture config");
    let outcome = std::panic::catch_unwind(|| {
        let _proxy = start_tls_proxy_no_wait(&panic_config);
        wait_for_fixture_inotify(baseline + 1);
        panic!("exercise fixture guard drop during unwinding");
    });
    assert!(outcome.is_err(), "fixture body must unwind");
    assert_fixture_watchers_stopped(1, baseline);

    let immediate_certs = TestCertificates::generate();
    let immediate_port = free_port();
    let immediate_config = Config::from_yaml(&fixture_tls_yaml(&[(immediate_port, &immediate_certs, true)]))
        .expect("immediate-drop fixture config");
    drop(start_tls_proxy_no_wait(&immediate_config));
    assert_fixture_watchers_stopped(1, baseline);
}

#[test]
fn listener_tls_termination_end_to_end() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("tls-terminated");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "TLS-terminated proxy should return 200");
    assert_eq!(
        body, "tls-terminated",
        "TLS-terminated proxy should forward backend body"
    );

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "listener should present the configured server certificate"
    );
}

#[test]
fn tls_listener_routing_works() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let api_port_guard = start_backend_with_shutdown("api-response");
    let api_port = api_port_guard.port();
    let web_port_guard = start_backend_with_shutdown("web-response");
    let web_port = web_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: api
          - path_prefix: "/"
            cluster: web
      - filter: load_balancer
        clusters:
          - name: api
            endpoints:
              - "127.0.0.1:{api_port}"
          - name: web
            endpoints:
              - "127.0.0.1:{web_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &client_config);

    let (_, api_body) = https_get(proxy.addr(), "/api/users", &client_config);
    assert_eq!(api_body, "api-response", "TLS proxy should route /api/ to api backend");

    let (_, web_body) = https_get(proxy.addr(), "/index.html", &client_config);
    assert_eq!(web_body, "web-response", "TLS proxy should route / to web backend");

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "listener should present the configured server certificate"
    );
}

#[test]
fn tcp_listener_tls_end_to_end() {
    let certs = TestCertificates::generate();
    let raw_config = certs.raw_tls_client_config();

    let echo_port = start_tcp_echo_backend();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
insecure_options:
  allow_private_upstreams: true

listeners:
  - name: secure-tcp
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{echo_port}"
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);

    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tls(&addr, &raw_config);

    let payload = b"hello from TLS TCP client";
    let response = tls_send_recv(&addr, payload, &raw_config);
    assert_eq!(
        response,
        payload,
        "TCP TLS proxy should echo data bidirectionally, got: {:?}",
        String::from_utf8_lossy(&response)
    );
}

#[test]
fn sni_fallback_to_host_header() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("sni-fallback-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(
        status, 200,
        "proxy with no upstream_sni should still route via Host header fallback"
    );
    assert_eq!(body, "sni-fallback-ok", "response body should match backend");
}

#[test]
fn upstream_tls_origination_end_to_end() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "tls-upstream-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
  allow_tls_no_verify: true
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
              verify: false
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 200,
        "upstream TLS origination should return 200 (status-only: upstream cert not observable from client)"
    );
    assert_eq!(body, "tls-upstream-ok", "response body should come from TLS backend");
}

#[test]
fn both_side_tls_end_to_end() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let backend_port = start_tls_backend(&certs, "both-tls-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
  allow_tls_no_verify: true
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
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
              verify: false
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "both-side TLS proxy should return 200");
    assert_eq!(body, "both-tls-ok", "both-side TLS should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "listener should present the configured server certificate"
    );
}

#[test]
fn listener_mtls_require_valid_client_cert_succeeds() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();
    let client_config = certs.client_config_with_cert(&client_cert);

    let backend_port_guard = start_backend_with_shutdown("mtls-require-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "mTLS require with valid client cert should return 200");
    assert_eq!(body, "mtls-require-ok", "mTLS require should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "mTLS listener should present the configured server certificate"
    );
}

/// Build a `require_named` mTLS listener config, with an optional SPIFFE allowlist.
#[cfg(feature = "spiffe")]
fn require_named_yaml(
    certs: &TestCertificates,
    proxy_port: u16,
    backend_port: u16,
    trusted_spiffe_ids: &[&str],
) -> String {
    let listed: String = trusted_spiffe_ids
        .iter()
        .map(|id| format!("\n        - \"{id}\""))
        .collect();
    let allowlist = if listed.is_empty() {
        String::new()
    } else {
        format!("\n      trusted_spiffe_ids:{listed}")
    };
    format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require_named{allowlist}
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    )
}

#[cfg(feature = "spiffe")]
#[test]
fn listener_mtls_require_named_allowlisted_peer_succeeds() {
    let certs = TestCertificates::generate();
    let id = "spiffe://grid.internal/site/pool-a";
    let client_cert = certs.generate_client_cert_with_spiffe_id(id);
    let client_config = certs.client_config_with_cert(&client_cert);

    let backend_port_guard = start_backend_with_shutdown("mtls-named-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = require_named_yaml(&certs, proxy_port, backend_port, &[id]);

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "an allowlisted SVID peer should be admitted");
    assert_eq!(body, "mtls-named-ok", "require_named should forward the backend body");
}

#[cfg(feature = "spiffe")]
#[test]
fn listener_mtls_require_named_unlisted_peer_is_rejected() {
    let certs = TestCertificates::generate();
    // The client holds a valid, CA-signed SVID, but its identity is not allowlisted.
    let client_cert = certs.generate_client_cert_with_spiffe_id("spiffe://grid.internal/site/pool-b");
    let client_config = certs.client_config_with_cert(&client_cert);

    let backend_port_guard = start_backend_with_shutdown("mtls-named-reject");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = require_named_yaml(
        &certs,
        proxy_port,
        backend_port,
        &["spiffe://grid.internal/site/pool-a"],
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);

    // Prove the listener is up using an allowlisted peer, so the only remaining
    // reason the unlisted attempt can fail is the authorization decision, not a
    // not-yet-bound listener.
    let ready = certs.generate_client_cert_with_spiffe_id("spiffe://grid.internal/site/pool-a");
    let ready_config = certs.client_config_with_cert(&ready);
    wait_for_https(proxy.addr(), &ready_config);

    let cfg_ref = &client_config;
    let addr_ref = proxy.addr();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| https_get(addr_ref, "/", cfg_ref)));
    assert!(
        result.is_err(),
        "an unlisted SVID peer should be rejected at the handshake"
    );
}

#[cfg(feature = "spiffe")]
#[test]
fn listener_mtls_require_named_empty_allowlist_admits_any_svid() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert_with_spiffe_id("spiffe://grid.internal/site/anyone");
    let client_config = certs.client_config_with_cert(&client_cert);

    let backend_port_guard = start_backend_with_shutdown("mtls-named-any");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    // Empty allowlist: any valid SVID the client CA vouches for is admitted.
    let yaml = require_named_yaml(&certs, proxy_port, backend_port, &[]);

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &client_config);

    let (status, _body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "an empty allowlist admits any valid SVID");
}

#[test]
fn listener_mtls_require_no_client_cert_fails() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();
    let mtls_client_config = certs.client_config_with_cert(&client_cert);
    let no_cert_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("mtls-no-cert");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &mtls_client_config);

    let no_cert_ref = &no_cert_config;
    let addr_ref = proxy.addr();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| https_get(addr_ref, "/", no_cert_ref)));

    assert!(
        result.is_err(),
        "mTLS require without client cert should reject the connection"
    );
}

#[test]
fn listener_mtls_request_mode_without_cert_succeeds() {
    let certs = TestCertificates::generate();
    let no_cert_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("mtls-request-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: request
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &no_cert_config);

    let (status, body) = https_get(proxy.addr(), "/", &no_cert_config);
    assert_eq!(status, 200, "mTLS request mode without cert should succeed");
    assert_eq!(body, "mtls-request-ok", "mTLS request mode should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &no_cert_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "mTLS request-mode listener should present the configured server certificate"
    );
}

#[test]
fn upstream_mtls_proxy_presents_client_cert() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();

    let backend_port = start_mtls_backend(&certs, "upstream-mtls-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
  allow_tls_no_verify: true
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
              verify: false
              client_cert:
                cert_path: "{client_cert}"
                key_path: "{client_key}"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        client_cert = client_cert.cert_path.display(),
        client_key = client_cert.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 200,
        "upstream mTLS should return 200 (status-only: proxy's client cert not observable from test client)"
    );
    assert_eq!(body, "upstream-mtls-ok", "upstream mTLS should forward backend body");
}

#[test]
fn upstream_tls_verify_disabled_with_self_signed() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "verify-disabled-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
  allow_tls_no_verify: true
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
              verify: false
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 200,
        "upstream TLS with verify disabled should return 200 (status-only: upstream cert not observable from client)"
    );
    assert_eq!(
        body, "verify-disabled-ok",
        "verify disabled should forward backend body"
    );
}

#[test]
fn upstream_tls_verify_enabled_wrong_cert_returns_502() {
    let proxy_certs = TestCertificates::generate();
    let backend_certs = TestCertificates::generate();

    let backend_port = start_tls_backend(&backend_certs, "should-not-reach");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
insecure_options:
  allow_private_endpoints: true
  allow_tls_without_sni: true
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
              verify: true
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    drop(proxy_certs);
    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 502, "upstream TLS verify with untrusted cert should return 502");
}

#[test]
fn sni_derived_from_hostname_address() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "sni-hostname-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
  allow_tls_no_verify: true
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
              verify: false
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 200,
        "upstream TLS with explicit SNI should return 200 (status-only: SNI sent to upstream not observable)"
    );
    assert_eq!(body, "sni-hostname-ok", "explicit SNI should reach backend");
}

#[test]
fn ip_endpoint_with_an_ip_client_host_dials_tls_with_verify_off() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "sni-ip-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
  allow_tls_no_verify: true
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
              verify: false
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", Some(&format!("127.0.0.1:{proxy_port}")));
    assert_eq!(
        status, 200,
        "an IP Host gives no name, so the peer must name the IP endpoint itself instead of dialing with an empty name"
    );
    assert_eq!(body, "sni-ip-ok", "IP-based upstream should reach backend");
}

#[test]
fn ip_endpoint_with_endpoint_authority_verifies_against_the_ip_san() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "ip-san-ok");
    let yaml = ip_endpoint_authority_yaml(backend_port, &certs.ca_cert_path);

    let config = Config::from_yaml(&yaml).expect("an IP endpoint with the endpoint authority needs no tls.sni");
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", Some("client.example.com"));
    assert_eq!(
        status, 200,
        "the backend certificate carries 127.0.0.1 as an IP SAN, so an IP endpoint must verify against it"
    );
    assert_eq!(body, "ip-san-ok", "the verified upstream should answer");
}

#[test]
fn ip_endpoint_with_endpoint_authority_rejects_a_cert_without_the_ip_san() {
    let certs = TestCertificates::generate_dns_only("upstream.test");
    let backend_port = start_tls_backend(&certs, "should-not-reach");
    let yaml = ip_endpoint_authority_yaml(backend_port, &certs.ca_cert_path);

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", Some("upstream.test"));
    assert_eq!(
        status, 502,
        "a certificate without the endpoint's IP SAN must fail verification, even when the client Host names it"
    );
}

#[test]
fn tcp_listener_mtls_require_valid_client_cert_succeeds() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();
    let mtls_config = certs.raw_tls_client_config_with_cert(&client_cert);

    let echo_port = start_tcp_echo_backend();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
insecure_options:
  allow_private_upstreams: true

listeners:
  - name: secure-tcp
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{echo_port}"
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);

    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tls(&addr, &mtls_config);

    let payload = b"hello from mTLS TCP client";
    let response = tls_send_recv(&addr, payload, &mtls_config);
    assert_eq!(
        response,
        payload,
        "TCP mTLS proxy with valid client cert should echo data, got: {:?}",
        String::from_utf8_lossy(&response)
    );
}

#[test]
fn tcp_listener_mtls_require_no_cert_fails() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();
    let mtls_config = certs.raw_tls_client_config_with_cert(&client_cert);
    let no_cert_config = certs.raw_tls_client_config();

    let echo_port = start_tcp_echo_backend();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure-tcp
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{echo_port}"
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);

    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tls(&addr, &mtls_config);

    let outcome = tls_negative_probe(&addr, "localhost", b"should not echo", &no_cert_config);
    assert!(
        outcome.is_client_auth_alert(),
        "TCP mTLS require without client cert must send a peer authentication alert: {outcome:?}"
    );
}

#[test]
fn upstream_tls_verify_with_ca_file() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "ca-file-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
runtime:
  upstream_ca_file: "{ca}"
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let _proxy = start_full_proxy(&config);

    let addr = format!("127.0.0.1:{proxy_port}");
    praxis_test_utils::wait_for_http(&addr);

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(
        status, 200,
        "upstream TLS with CA file should return 200 (paired with ca_file_without_ca_fails)"
    );
    assert_eq!(
        body, "ca-file-ok",
        "response body should come from verified TLS backend"
    );
}

#[test]
fn upstream_tls_verify_without_ca_file_fails() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "should-not-reach");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
              verify: true
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 502,
        "upstream TLS verify without CA file should fail with 502 (proves CA file config matters)"
    );
}

#[test]
fn multi_cert_config_parses_and_serves_with_primary_cert() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("multi-cert-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
          server_names:
            - localhost
        - cert_path: "{cert}"
          key_path: "{key}"
          server_names:
            - api.example.com
        - cert_path: "{cert}"
          key_path: "{key}"
          default: true
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    assert_eq!(
        config.listeners[0].tls.as_ref().unwrap().certificates.len(),
        3,
        "config should parse all three certificate entries"
    );
    assert_eq!(
        config.listeners[0].tls.as_ref().unwrap().certificates[0].server_names,
        vec!["localhost"],
        "first cert should have server_names set"
    );
    assert!(
        config.listeners[0].tls.as_ref().unwrap().certificates[2]
            .server_names
            .is_empty(),
        "last cert (default) should have no server_names"
    );
    assert!(
        config.listeners[0].tls.as_ref().unwrap().certificates[2].default,
        "last cert should be marked as default"
    );

    let proxy = start_tls_proxy(&config, &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(
        status, 200,
        "multi-cert proxy should serve traffic via primary certificate"
    );
    assert_eq!(body, "multi-cert-ok", "multi-cert proxy should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "multi-cert listener should present the configured server certificate"
    );
}

#[test]
fn listener_min_version_tls13_rejects_tls12() {
    let certs = TestCertificates::generate();
    let tls13_client = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("tls13-only-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      min_version: tls13
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &tls13_client);

    let (status, _) = https_get(proxy.addr(), "/", &tls13_client);
    assert_eq!(status, 200, "TLS 1.3 client should succeed against tls13-only listener");

    let tls12_client = build_tls12_only_client(&certs);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        https_get(proxy.addr(), "/", &tls12_client)
    }));
    assert!(
        result.is_err(),
        "TLS 1.2-only client should be rejected by tls13-only listener"
    );
}

#[test]
fn upstream_mtls_missing_client_cert_returns_502() {
    let certs = TestCertificates::generate();

    let backend_port = start_mtls_backend(&certs, "should-not-reach");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
  allow_tls_no_verify: true
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
              verify: false
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 502,
        "proxy without client cert should get 502 from mTLS backend"
    );
}

#[test]
fn per_cluster_ca_verifies_upstream() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "per-cluster-ca-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "per-cluster CA should verify upstream and return 200");
    assert_eq!(body, "per-cluster-ca-ok", "per-cluster CA should forward backend body");
}

#[test]
fn per_cluster_ca_without_ca_fails_verification() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "should-not-reach");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
              verify: true
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 502,
        "upstream TLS verify without per-cluster CA should fail with 502 (proves CA config matters)"
    );
}

#[test]
fn multi_cert_sni_selects_correct_certificate() {
    let alpha_certs = TestCertificates::generate_for_san("alpha.localhost");
    let beta_certs = TestCertificates::generate_for_san("beta.localhost");

    let backend_port_guard = start_backend_with_shutdown("sni-select-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{alpha_cert}"
          key_path: "{alpha_key}"
          server_names:
            - alpha.localhost
        - cert_path: "{beta_cert}"
          key_path: "{beta_key}"
          default: true
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        alpha_cert = alpha_certs.cert_path.display(),
        alpha_key = alpha_certs.key_path.display(),
        beta_cert = beta_certs.cert_path.display(),
        beta_key = beta_certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();

    let dual_trust = dual_ca_client_config(&alpha_certs, &beta_certs);
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_sni_tls(proxy.addr(), &dual_trust, "alpha.localhost");

    let alpha_peer_der = get_peer_cert_der(proxy.addr(), &dual_trust, "alpha.localhost");
    assert_eq!(
        alpha_peer_der, alpha_certs.server_cert_der,
        "SNI alpha.localhost should select the alpha certificate"
    );

    let beta_peer_der = get_peer_cert_der(proxy.addr(), &dual_trust, "beta.localhost");
    assert_eq!(
        beta_peer_der, beta_certs.server_cert_der,
        "SNI beta.localhost (unmatched) should select the default (beta) certificate"
    );

    assert_ne!(
        alpha_certs.server_cert_der, beta_certs.server_cert_der,
        "alpha and beta certificates must be distinct for this test to be valid"
    );
}

#[test]
fn listener_min_version_tls12_accepts_both_versions() {
    let certs = TestCertificates::generate();
    let tls13_client = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("tls12-min-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      min_version: tls12
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &tls13_client);

    let (status, body) = https_get(proxy.addr(), "/", &tls13_client);
    assert_eq!(status, 200, "TLS 1.3 client should succeed against tls12-min listener");
    assert_eq!(body, "tls12-min-ok", "TLS 1.3 should forward backend body");

    let tls12_client = build_tls12_only_client(&certs);
    let (status12, body12) = https_get(proxy.addr(), "/", &tls12_client);
    assert_eq!(
        status12, 200,
        "TLS 1.2 client should succeed against tls12-min listener"
    );
    assert_eq!(body12, "tls12-min-ok", "TLS 1.2 should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &tls13_client, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "tls12-min listener should present the configured server certificate"
    );
}

#[test]
fn upstream_tls_verify_enabled_with_valid_cert_succeeds() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "verify-valid-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
runtime:
  upstream_ca_file: "{ca}"
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
              verify: true
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let _proxy = start_full_proxy(&config);

    let addr = format!("127.0.0.1:{proxy_port}");
    praxis_test_utils::wait_for_http(&addr);

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(
        status, 200,
        "upstream TLS verify with valid cert should return 200 (paired with wrong_cert_returns_502)"
    );
    assert_eq!(body, "verify-valid-ok", "verified upstream should forward backend body");
}

#[test]
fn full_mtls_listener_and_upstream_end_to_end() {
    let listener_certs = TestCertificates::generate();
    let upstream_certs = TestCertificates::generate();

    let proxy_client_cert = upstream_certs.generate_client_cert();
    let listener_client_cert = listener_certs.generate_client_cert();
    let client_config = listener_certs.client_config_with_cert(&listener_client_cert);

    let backend_port = start_mtls_backend(&upstream_certs, "full-mtls-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
  allow_tls_no_verify: true
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{listener_cert}"
          key_path: "{listener_key}"
      client_ca:
        ca_path: "{listener_ca}"
      client_cert_mode: require
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
              verify: false
              client_cert:
                cert_path: "{proxy_client_cert}"
                key_path: "{proxy_client_key}"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        listener_cert = listener_certs.cert_path.display(),
        listener_key = listener_certs.key_path.display(),
        listener_ca = listener_certs.ca_cert_path.display(),
        proxy_client_cert = proxy_client_cert.cert_path.display(),
        proxy_client_key = proxy_client_cert.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "full mTLS end-to-end should return 200");
    assert_eq!(body, "full-mtls-ok", "full mTLS should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, listener_certs.server_cert_der,
        "full mTLS listener should present the listener certificate, not the upstream certificate"
    );
}

#[test]
fn multi_cert_sni_returns_correct_certificate_subject() {
    let alpha_certs = TestCertificates::generate_for_san("alpha.test");
    let beta_certs = TestCertificates::generate_for_san("beta.test");
    let default_certs = TestCertificates::generate_for_san("default.test");

    let backend_port_guard = start_backend_with_shutdown("sni-subject-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{alpha_cert}"
          key_path: "{alpha_key}"
          server_names:
            - alpha.test
        - cert_path: "{beta_cert}"
          key_path: "{beta_key}"
          server_names:
            - beta.test
        - cert_path: "{default_cert}"
          key_path: "{default_key}"
          default: true
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        alpha_cert = alpha_certs.cert_path.display(),
        alpha_key = alpha_certs.key_path.display(),
        beta_cert = beta_certs.cert_path.display(),
        beta_key = beta_certs.key_path.display(),
        default_cert = default_certs.cert_path.display(),
        default_key = default_certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();

    let triple_trust = triple_ca_client_config(&alpha_certs, &beta_certs, &default_certs);
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_sni_tls(proxy.addr(), &triple_trust, "alpha.test");

    let alpha_peer_der = get_peer_cert_der(proxy.addr(), &triple_trust, "alpha.test");
    assert_eq!(
        alpha_peer_der, alpha_certs.server_cert_der,
        "SNI alpha.test should present the alpha certificate"
    );

    let beta_peer_der = get_peer_cert_der(proxy.addr(), &triple_trust, "beta.test");
    assert_eq!(
        beta_peer_der, beta_certs.server_cert_der,
        "SNI beta.test should present the beta certificate"
    );

    let fallback_peer_der = get_peer_cert_der(proxy.addr(), &triple_trust, "default.test");
    assert_eq!(
        fallback_peer_der, default_certs.server_cert_der,
        "fallback SNI should present the default certificate"
    );

    assert_ne!(
        alpha_certs.server_cert_der, beta_certs.server_cert_der,
        "alpha and beta certificates must be distinct"
    );
    assert_ne!(
        beta_certs.server_cert_der, default_certs.server_cert_der,
        "beta and default certificates must be distinct"
    );
}

#[test]
fn multi_cert_unknown_sni_returns_default_certificate() {
    let alpha_certs = TestCertificates::generate_for_san("alpha.test");
    let default_certs = TestCertificates::generate_for_san("default.test");

    let backend_port_guard = start_backend_with_shutdown("fallback-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{alpha_cert}"
          key_path: "{alpha_key}"
          server_names:
            - alpha.test
        - cert_path: "{default_cert}"
          key_path: "{default_key}"
          default: true
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        alpha_cert = alpha_certs.cert_path.display(),
        alpha_key = alpha_certs.key_path.display(),
        default_cert = default_certs.cert_path.display(),
        default_key = default_certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();

    let no_verify_trust = no_hostname_verify_client_config(&[&alpha_certs.ca_cert_der, &default_certs.ca_cert_der]);
    let alpha_trust = dual_ca_client_config(&alpha_certs, &default_certs);
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_sni_tls(proxy.addr(), &alpha_trust, "alpha.test");

    let alpha_der = get_peer_cert_der(proxy.addr(), &alpha_trust, "alpha.test");
    assert_eq!(
        alpha_der, alpha_certs.server_cert_der,
        "SNI alpha.test should present the alpha certificate"
    );

    let unknown_der = get_peer_cert_der(proxy.addr(), &no_verify_trust, "unknown.test");
    assert_eq!(
        unknown_der, default_certs.server_cert_der,
        "unknown SNI should fall back to the default certificate"
    );

    assert_ne!(
        alpha_certs.server_cert_der, default_certs.server_cert_der,
        "alpha and default certificates must be distinct"
    );
}

#[test]
fn mtls_require_rejects_client_cert_from_wrong_ca() {
    let server_certs = TestCertificates::generate();
    let wrong_ca_certs = TestCertificates::generate();

    let wrong_client_cert = wrong_ca_certs.generate_client_cert();

    let valid_client_cert = server_certs.generate_client_cert();
    let valid_client_config = server_certs.client_config_with_cert(&valid_client_cert);

    let wrong_ca_client_config = build_cross_ca_client_config(&server_certs, &wrong_ca_certs, &wrong_client_cert);

    let backend_port_guard = start_backend_with_shutdown("wrong-ca-should-not-reach");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = server_certs.cert_path.display(),
        key = server_certs.key_path.display(),
        ca = server_certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &valid_client_config);

    let wrong_ref = &wrong_ca_client_config;
    let addr_ref = proxy.addr();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| https_get(addr_ref, "/", wrong_ref)));
    assert!(
        result.is_err(),
        "mTLS require should reject client cert signed by wrong CA"
    );
}

#[test]
fn multi_cert_sni_with_mtls_require() {
    let alpha_certs = TestCertificates::generate_for_san("alpha.mtls");
    let beta_certs = TestCertificates::generate_for_san("beta.mtls");

    let client_cert = alpha_certs.generate_client_cert();
    let client_config = build_sni_mtls_client_config(&alpha_certs, &beta_certs, &client_cert);

    let backend_port_guard = start_backend_with_shutdown("sni-mtls-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{alpha_cert}"
          key_path: "{alpha_key}"
          server_names:
            - alpha.mtls
        - cert_path: "{beta_cert}"
          key_path: "{beta_key}"
          default: true
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        alpha_cert = alpha_certs.cert_path.display(),
        alpha_key = alpha_certs.key_path.display(),
        beta_cert = beta_certs.cert_path.display(),
        beta_key = beta_certs.key_path.display(),
        ca = alpha_certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_sni_tls(proxy.addr(), &client_config, "alpha.mtls");

    let alpha_peer_der = get_peer_cert_der(proxy.addr(), &client_config, "alpha.mtls");
    assert_eq!(
        alpha_peer_der, alpha_certs.server_cert_der,
        "SNI alpha.mtls should present the alpha cert even with mTLS"
    );
}

#[test]
fn multi_cert_sni_with_tls13_only() {
    let alpha_certs = TestCertificates::generate_for_san("alpha.tls13");
    let beta_certs = TestCertificates::generate_for_san("beta.tls13");

    let backend_port_guard = start_backend_with_shutdown("sni-tls13-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{alpha_cert}"
          key_path: "{alpha_key}"
          server_names:
            - alpha.tls13
        - cert_path: "{beta_cert}"
          key_path: "{beta_key}"
          default: true
      min_version: tls13
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        alpha_cert = alpha_certs.cert_path.display(),
        alpha_key = alpha_certs.key_path.display(),
        beta_cert = beta_certs.cert_path.display(),
        beta_key = beta_certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();

    let dual_trust = dual_ca_client_config(&alpha_certs, &beta_certs);
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_sni_tls(proxy.addr(), &dual_trust, "alpha.tls13");

    let alpha_peer_der = get_peer_cert_der(proxy.addr(), &dual_trust, "alpha.tls13");
    assert_eq!(
        alpha_peer_der, alpha_certs.server_cert_der,
        "SNI alpha.tls13 over TLS 1.3 should present the alpha cert"
    );

    let beta_peer_der = get_peer_cert_der(proxy.addr(), &dual_trust, "beta.tls13");
    assert_eq!(
        beta_peer_der, beta_certs.server_cert_der,
        "SNI beta.tls13 (unmatched) over TLS 1.3 should present the default cert"
    );
}

#[test]
fn mtls_require_with_tls13_only() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();
    let client_config = certs.client_config_with_cert(&client_cert);

    let backend_port_guard = start_backend_with_shutdown("mtls-tls13-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
      min_version: tls13
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "mTLS require with TLS 1.3 should return 200");
    assert_eq!(body, "mtls-tls13-ok", "mTLS + TLS 1.3 should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "mTLS + TLS 1.3 listener should present the configured server certificate"
    );
}

#[cfg(any(not(target_os = "macos"), feature = "no-mac-cert-rotation-tests"))]
#[test]
fn hot_reload_serves_rotated_certificate() {
    let original = TestCertificates::generate();
    let client_config = original.client_config();

    let backend_port_guard = start_backend_with_shutdown("hot-reload-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let cert_dir = tempfile::TempDir::new().unwrap();
    let cert_path = cert_dir.path().join("server.pem");
    let key_path = cert_dir.path().join("server-key.pem");
    std::fs::copy(&original.cert_path, &cert_path).unwrap();
    std::fs::copy(&original.key_path, &key_path).unwrap();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      hot_reload: true
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = cert_path.display(),
        key = key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);

    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_https(&addr, &client_config);

    let initial_der = get_peer_cert_der(&addr, &client_config, "localhost");
    assert_eq!(
        initial_der, original.server_cert_der,
        "initial cert should match the original"
    );

    let rotated = TestCertificates::generate();
    let rotated_key_pem = std::fs::read(&rotated.key_path).unwrap();
    let rotated_cert_pem = std::fs::read(&rotated.cert_path).unwrap();
    std::fs::write(&key_path, &rotated_key_pem).unwrap();
    std::fs::write(&cert_path, &rotated_cert_pem).unwrap();

    std::thread::sleep(std::time::Duration::from_secs(3));

    let rotated_client = rotated.client_config();
    let rotated_der = get_peer_cert_der(&addr, &rotated_client, "localhost");
    assert_eq!(
        rotated_der, rotated.server_cert_der,
        "after rotation the proxy should serve the new certificate"
    );

    assert_ne!(
        original.server_cert_der, rotated.server_cert_der,
        "original and rotated certs must be distinct for this test to be valid"
    );
}

#[test]
fn hot_reload_invalid_cert_keeps_old() {
    let original = TestCertificates::generate();
    let client_config = original.client_config();

    let backend_port_guard = start_backend_with_shutdown("hot-reload-invalid-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let cert_dir = tempfile::TempDir::new().unwrap();
    let cert_path = cert_dir.path().join("server.pem");
    let key_path = cert_dir.path().join("server-key.pem");
    std::fs::copy(&original.cert_path, &cert_path).unwrap();
    std::fs::copy(&original.key_path, &key_path).unwrap();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      hot_reload: true
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = cert_path.display(),
        key = key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);

    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_https(&addr, &client_config);

    let initial_der = get_peer_cert_der(&addr, &client_config, "localhost");
    assert_eq!(
        initial_der, original.server_cert_der,
        "initial cert should match the original"
    );

    std::fs::write(&cert_path, b"not a valid cert").unwrap();
    std::fs::write(&key_path, b"not a valid key").unwrap();

    std::thread::sleep(std::time::Duration::from_secs(2));

    let after_der = get_peer_cert_der(&addr, &client_config, "localhost");
    assert_eq!(
        after_der, original.server_cert_der,
        "after invalid rotation the proxy should still serve the original certificate"
    );

    let (status, body) = https_get(&addr, "/", &client_config);
    assert_eq!(
        status, 200,
        "proxy should still serve traffic after invalid cert rotation"
    );
    assert_eq!(body, "hot-reload-invalid-ok", "response body should match backend");
}

#[test]
fn listener_cipher_suite_restriction_accepts_matching_client() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("cipher-suite-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      cipher_suites:
        - tls13_aes_256_gcm_sha384
        - tls13_aes_128_gcm_sha256
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(
        status, 200,
        "cipher-suite-restricted proxy should accept TLS 1.3 client"
    );
    assert_eq!(
        body, "cipher-suite-ok",
        "cipher-suite-restricted proxy should forward backend body"
    );
}

#[test]
fn listener_cipher_suite_restriction_rejects_excluded_suite() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("cipher-rejected");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      cipher_suites:
        - tls13_aes_256_gcm_sha384
        - tls13_aes_128_gcm_sha256
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &client_config);

    let tls12_only = build_tls12_only_client(&certs);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        https_get(proxy.addr(), "/", &tls12_only)
    }));
    assert!(
        result.is_err(),
        "TLS 1.2-only client should be rejected when only TLS 1.3 suites are configured"
    );
}

// -----------------------------------------------------------------------------
// Downstream TLS peer identity tests
//
// These tests prove that `HttpFilterContext.peer_identity` is correctly
// populated when the downstream connection uses mTLS and the peer
// presents a valid client certificate.
//
// The tests use small inline test-only filters that observe peer_identity
// and reject with a 403 when expectations are not met.  This is the
// minimal approach to verify peer identity from outside the proxy without
// depending on any production access-control filter.
//
// All fields extracted from the client certificate — cert_digest,
// organization, and serial_number — are covered end-to-end below.
//
// Regression covered: peer_identity must survive StreamBuffer body
// pre-read.  Root cause was `.take()` in filter_context! macro consuming
// the value during pre_read_body; fixed by switching to `.clone()`.
// -----------------------------------------------------------------------------

struct PeerIdentityRejectIfNone;

#[async_trait::async_trait]
impl praxis_filter::HttpFilter for PeerIdentityRejectIfNone {
    fn name(&self) -> &'static str {
        "test_peer_identity_reject_if_none"
    }

    async fn on_request(
        &self,
        ctx: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        if ctx.peer_identity.is_some() {
            Ok(praxis_filter::FilterAction::Continue)
        } else {
            Ok(praxis_filter::FilterAction::Reject(praxis_filter::Rejection::status(
                403,
            )))
        }
    }
}

struct PeerIdentityRequireOrg(&'static str);

#[async_trait::async_trait]
impl praxis_filter::HttpFilter for PeerIdentityRequireOrg {
    fn name(&self) -> &'static str {
        "test_peer_identity_require_org"
    }

    async fn on_request(
        &self,
        ctx: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        let matches = ctx
            .peer_identity
            .as_ref()
            .and_then(|id| id.organization.as_deref())
            .is_some_and(|org| org == self.0);
        if matches {
            Ok(praxis_filter::FilterAction::Continue)
        } else {
            Ok(praxis_filter::FilterAction::Reject(praxis_filter::Rejection::status(
                403,
            )))
        }
    }
}

#[test]
fn peer_identity_set_for_mtls_connection() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();
    let client_config = certs.client_config_with_cert(&client_cert);

    let backend_port_guard = start_backend_with_shutdown("peer-identity-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
filter_chains:
  - name: main
    filters:
      - filter: test_peer_identity_reject_if_none
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("test_peer_identity_reject_if_none", || {
        Box::new(PeerIdentityRejectIfNone)
    });
    let proxy = start_tls_proxy_no_wait_with_registry(&config, &registry);
    wait_for_https(proxy.addr(), &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(
        status, 200,
        "peer_identity must be populated for valid mTLS client cert (got {status}, body: {body})"
    );
    assert_eq!(body, "peer-identity-ok", "request should reach backend");
}

#[test]
fn peer_identity_is_none_without_client_cert() {
    let certs = TestCertificates::generate();
    let no_cert_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("peer-identity-no-cert");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: request
filter_chains:
  - name: main
    filters:
      - filter: test_peer_identity_reject_if_none
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("test_peer_identity_reject_if_none", || {
        Box::new(PeerIdentityRejectIfNone)
    });
    let proxy = start_tls_proxy_no_wait_with_registry(&config, &registry);
    wait_for_https(proxy.addr(), &no_cert_config);

    let (status, _body) = https_get(proxy.addr(), "/", &no_cert_config);
    assert_eq!(
        status, 403,
        "peer_identity must be None when no client cert is presented (got {status})"
    );
}

#[test]
fn peer_identity_has_organization_when_cert_has_org() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert_with_org("my-org");
    let client_config = certs.client_config_with_cert(&client_cert);

    let backend_port_guard = start_backend_with_shutdown("peer-identity-org-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
filter_chains:
  - name: main
    filters:
      - filter: test_peer_identity_require_org
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("test_peer_identity_require_org", || {
        Box::new(PeerIdentityRequireOrg("my-org"))
    });
    let proxy = start_tls_proxy_no_wait_with_registry(&config, &registry);
    wait_for_https(proxy.addr(), &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(
        status, 200,
        "peer_identity.organization must match cert O= field (got {status}, body: {body})"
    );
    assert_eq!(body, "peer-identity-org-ok", "request should reach backend");
}

struct PeerIdentityRequireSerialNumber;

#[async_trait::async_trait]
impl praxis_filter::HttpFilter for PeerIdentityRequireSerialNumber {
    fn name(&self) -> &'static str {
        "test_peer_identity_require_serial_number"
    }

    async fn on_request(
        &self,
        ctx: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        let has_serial = ctx
            .peer_identity
            .as_ref()
            .and_then(|id| id.serial_number.as_deref())
            .is_some();
        if has_serial {
            Ok(praxis_filter::FilterAction::Continue)
        } else {
            Ok(praxis_filter::FilterAction::Reject(praxis_filter::Rejection::status(
                403,
            )))
        }
    }
}

#[test]
fn peer_identity_has_serial_number_for_mtls_connection() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();
    let client_config = certs.client_config_with_cert(&client_cert);

    let backend_port_guard = start_backend_with_shutdown("peer-identity-serial-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
filter_chains:
  - name: main
    filters:
      - filter: test_peer_identity_require_serial_number
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("test_peer_identity_require_serial_number", || {
        Box::new(PeerIdentityRequireSerialNumber)
    });
    let proxy = start_tls_proxy_no_wait_with_registry(&config, &registry);
    wait_for_https(proxy.addr(), &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(
        status, 200,
        "peer_identity.serial_number must be populated for valid mTLS client cert (got {status}, body: {body})"
    );
    assert_eq!(body, "peer-identity-serial-ok", "request should reach backend");
}

#[test]
fn peer_identity_survives_stream_buffer_pre_read_regression() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert_with_org("test-org");
    let client_config = certs.client_config_with_cert(&client_cert);

    let backend_port_guard = start_backend_with_shutdown("peer-identity-streambuf-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    // json_body_field declares StreamBuffer body mode, so pre_read_body runs
    // before the main pipeline. peer_identity must survive this.
    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
filter_chains:
  - name: main
    filters:
      - filter: test_peer_identity_reject_if_none
      - filter: json_body_field
        field: model
        header: X-Model
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("test_peer_identity_reject_if_none", || {
        Box::new(PeerIdentityRejectIfNone)
    });
    let proxy = start_tls_proxy_no_wait_with_registry(&config, &registry);
    wait_for_https(proxy.addr(), &client_config);

    // `json_body_field` always declares StreamBuffer, triggering pre_read_body.
    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(
        status, 200,
        "peer_identity must survive StreamBuffer pre-read (got {status}, body: {body})"
    );
    assert_eq!(body, "peer-identity-streambuf-ok", "request should reach backend");

    #[cfg(feature = "hyper")]
    {
        let (post_status, post_body) =
            h1_identity_post_with_json(proxy.addr(), certs.raw_tls_client_config_with_cert(&client_cert));
        assert_eq!(
            post_status, 200,
            "identity must survive pre-reading a nonempty JSON body"
        );
        assert_eq!(
            post_body, "peer-identity-streambuf-ok",
            "the body-bearing request reaches the backend"
        );
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A plain listener in front of one verifying TLS cluster with a single
/// `127.0.0.1` endpoint, `authority: { from: endpoint }`, no `tls.sni`, and
/// the CA at `ca` trusted.
fn ip_endpoint_authority_yaml(backend_port: u16, ca: &std::path::Path) -> String {
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
            endpoints:
              - "127.0.0.1:{backend_port}"
            http:
              authority: {{ from: endpoint }}
            tls:
              ca:
                ca_path: "{ca}"
insecure_options:
  allow_private_endpoints: true
"#,
        proxy_port = free_port(),
        ca = ca.display(),
    )
}

fn build_tls12_only_client(certs: &TestCertificates) -> Arc<rustls::ClientConfig> {
    let ca = rustls::pki_types::CertificateDer::from(certs.ca_cert_der.clone());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca).expect("add CA to root store");

    let versions = vec![&rustls::version::TLS12];
    let mut config = rustls::ClientConfig::builder_with_protocol_versions(&versions)
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

fn dual_ca_client_config(a: &TestCertificates, b: &TestCertificates) -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(rustls::pki_types::CertificateDer::from(a.ca_cert_der.clone()))
        .expect("add CA A to root store");
    root_store
        .add(rustls::pki_types::CertificateDer::from(b.ca_cert_der.clone()))
        .expect("add CA B to root store");

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

fn get_peer_cert_der(addr: &str, client_config: &Arc<rustls::ClientConfig>, sni: &str) -> Vec<u8> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
        let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned()).expect("valid SNI");
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("TCP connect");
        let tls = connector.connect(server_name, tcp).await.expect("TLS handshake");
        let (_, conn) = tls.get_ref();
        let certs = conn.peer_certificates().expect("peer certificates present");
        certs[0].as_ref().to_vec()
    })
}

fn wait_for_sni_tls(addr: &str, client_config: &Arc<rustls::ClientConfig>, sni: &str) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    for _ in 0..500 {
        let result = rt.block_on(async {
            let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
            let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned()).ok()?;
            let tcp = tokio::net::TcpStream::connect(addr).await.ok()?;
            connector.connect(server_name, tcp).await.ok().map(|_| ())
        });
        if result.is_some() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("TLS server at {addr} with SNI {sni} did not become ready within 5s");
}

fn triple_ca_client_config(
    a: &TestCertificates,
    b: &TestCertificates,
    c: &TestCertificates,
) -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(rustls::pki_types::CertificateDer::from(a.ca_cert_der.clone()))
        .expect("add CA A to root store");
    root_store
        .add(rustls::pki_types::CertificateDer::from(b.ca_cert_der.clone()))
        .expect("add CA B to root store");
    root_store
        .add(rustls::pki_types::CertificateDer::from(c.ca_cert_der.clone()))
        .expect("add CA C to root store");

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

fn build_cross_ca_client_config(
    server_certs: &TestCertificates,
    wrong_ca_certs: &TestCertificates,
    wrong_client_cert: &praxis_test_utils::ClientCert,
) -> Arc<rustls::ClientConfig> {
    let ca = rustls::pki_types::CertificateDer::from(server_certs.ca_cert_der.clone());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca).expect("add server CA to root store");

    let cert_pem = std::fs::read(&wrong_client_cert.cert_path).expect("read wrong client cert PEM");
    let key_pem = std::fs::read(&wrong_client_cert.key_path).expect("read wrong client key PEM");

    let (certs, key) = praxis_test_utils::parse_cert_chain_and_key(&cert_pem, &key_pem);

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .expect("build cross-CA client config");
    config.alpn_protocols = vec![b"h2".to_vec()];

    let _ = wrong_ca_certs;
    Arc::new(config)
}

fn build_sni_mtls_client_config(
    a: &TestCertificates,
    b: &TestCertificates,
    client_cert: &praxis_test_utils::ClientCert,
) -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(rustls::pki_types::CertificateDer::from(a.ca_cert_der.clone()))
        .expect("add CA A to root store");
    root_store
        .add(rustls::pki_types::CertificateDer::from(b.ca_cert_der.clone()))
        .expect("add CA B to root store");

    let cert_pem = std::fs::read(&client_cert.cert_path).expect("read client cert PEM");
    let key_pem = std::fs::read(&client_cert.key_path).expect("read client key PEM");

    let (certs, key) = praxis_test_utils::parse_cert_chain_and_key(&cert_pem, &key_pem);

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .expect("build SNI mTLS client config");
    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

/// Build a client config that trusts the given CAs but does NOT
/// verify the server hostname. Used to test SNI fallback behavior
/// where the presented cert's subject won't match the SNI sent.
fn no_hostname_verify_client_config(ca_ders: &[&Vec<u8>]) -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    for der in ca_ders {
        root_store
            .add(rustls::pki_types::CertificateDer::from((*der).clone()))
            .expect("add CA to root store");
    }

    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .expect("build WebPki verifier");

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoHostnameVerifier(verifier)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

/// Wrapper that validates the certificate chain against trusted CAs
/// but accepts any hostname. Only for testing SNI fallback.
#[derive(Debug)]
struct NoHostnameVerifier(Arc<dyn rustls::client::danger::ServerCertVerifier>);

impl rustls::client::danger::ServerCertVerifier for NoHostnameVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}
// peer_identity_trust integration tests
// -----------------------------------------------------------------------------

/// Verify that a client cert with a matching org is allowed through.
#[cfg(feature = "spiffe")]
#[test]
fn peer_identity_trust_allows_matching_org() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert_with_org("trusted-org");
    let client_config = certs.client_config_with_cert(&client_cert);

    let backend_port_guard = start_backend_with_shutdown("trust-allowed");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
filter_chains:
  - name: main
    filters:
      - filter: peer_identity_trust
        trusted_peers:
          - organization: trusted-org
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(
        status, 200,
        "peer_identity_trust must allow cert with matching org (got {status}, body: {body})"
    );
    assert_eq!(body, "trust-allowed", "backend should be reached");
}

/// Verify that a cert signed by the same CA but with a non-matching org is rejected.
#[cfg(feature = "spiffe")]
#[test]
fn peer_identity_trust_rejects_wrong_org() {
    let certs = TestCertificates::generate();
    let wrong_cert = certs.generate_client_cert_with_org("untrusted-org");
    let wrong_config = certs.client_config_with_cert(&wrong_cert);

    let backend_port_guard = start_backend_with_shutdown("trust-wrong-org");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
filter_chains:
  - name: main
    filters:
      - filter: peer_identity_trust
        trusted_peers:
          - organization: trusted-org
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &wrong_config);

    let (status, _body) = https_get(proxy.addr(), "/", &wrong_config);
    assert_eq!(
        status, 403,
        "peer_identity_trust must reject cert with non-matching org (got {status})"
    );
}

/// Verify that a connection without a client cert (request mode) is rejected by the filter.
#[cfg(feature = "spiffe")]
#[test]
fn peer_identity_trust_rejects_no_peer_identity() {
    let certs = TestCertificates::generate();
    let no_cert_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("trust-no-cert");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: request
filter_chains:
  - name: main
    filters:
      - filter: peer_identity_trust
        trusted_peers:
          - organization: trusted-org
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &no_cert_config);

    let (status, _body) = https_get(proxy.addr(), "/", &no_cert_config);
    assert_eq!(
        status, 403,
        "peer_identity_trust must reject connections with no peer identity (got {status})"
    );
}

/// Certificate fields independently expected by the Hyper wire identity probe.
#[cfg(feature = "hyper")]
struct ExpectedPeerIdentity {
    digest: Vec<u8>,
    organization: String,
    serial: String,
}

/// Buffered TLS HTTP/1 client, retaining unread bytes between responses.
#[cfg(feature = "hyper")]
type IdentityHttp1Client = std::io::BufReader<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>>;

/// Test-only filter that binds the request path to its expected TLS peer.
#[cfg(feature = "hyper")]
struct ExactPeerIdentity {
    expected: Arc<HashMap<&'static str, ExpectedPeerIdentity>>,
}

#[cfg(feature = "hyper")]
#[async_trait::async_trait]
impl praxis_filter::HttpFilter for ExactPeerIdentity {
    fn name(&self) -> &'static str {
        "test_exact_peer_identity"
    }

    async fn on_request(
        &self,
        ctx: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        let matches = self.expected.get(ctx.request.uri.path()).is_some_and(|expected| {
            ctx.peer_identity.as_ref().is_some_and(|actual| {
                actual.cert_digest == expected.digest
                    && actual.organization.as_deref() == Some(expected.organization.as_str())
                    && actual.serial_number.as_deref().map(normalized_hex) == Some(expected.serial.clone())
            })
        });
        if matches {
            Ok(praxis_filter::FilterAction::Continue)
        } else {
            Ok(praxis_filter::FilterAction::Reject(praxis_filter::Rejection::status(
                403,
            )))
        }
    }
}

/// Normalize the parser's colon-separated serial for an OpenSSL comparison.
#[cfg(feature = "hyper")]
fn normalized_hex(serial: &str) -> String {
    let compact = serial
        .chars()
        .filter(|ch| *ch != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    let trimmed = compact.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Compute expected fields from the file, independently of Praxis' extractor.
#[cfg(feature = "hyper")]
fn expected_peer(cert: &praxis_test_utils::ClientCert, organization: &str) -> ExpectedPeerIdentity {
    let certificate = X509::from_pem(&std::fs::read(&cert.cert_path).unwrap()).unwrap();
    let digest = certificate.digest(MessageDigest::sha256()).unwrap().to_vec();
    let serial = normalized_hex(&certificate.serial_number().to_bn().unwrap().to_hex_str().unwrap());
    ExpectedPeerIdentity {
        digest,
        organization: organization.to_owned(),
        serial,
    }
}

/// Register the exact-certificate probe with one immutable expected-peer map.
#[cfg(feature = "hyper")]
fn identity_probe_registry(expected: Arc<HashMap<&'static str, ExpectedPeerIdentity>>) -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "test_exact_peer_identity",
            FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(ExactPeerIdentity {
                    expected: Arc::clone(&expected),
                }))
            })),
        )
        .unwrap();
    registry
}

/// A request-mode mTLS listener with a test filter and a counted real backend.
#[cfg(feature = "hyper")]
fn identity_probe_config(certs: &TestCertificates, port: u16, backend: u16, sha384_only: bool) -> Config {
    let cipher_suites = if sha384_only {
        "      cipher_suites:\n        - tls13_aes_256_gcm_sha384\n"
    } else {
        ""
    };
    Config::from_yaml(&format!(
        "listeners:\n  - name: identity-probe\n    address: 127.0.0.1:{port}\n    filter_chains: [main]\n    tls:\n      certificates:\n        - cert_path: {cert}\n          key_path: {key}\n      client_ca:\n        ca_path: {ca}\n      client_cert_mode: request\n{cipher_suites}filter_chains:\n  - name: main\n    filters:\n      - filter: test_exact_peer_identity\n      - filter: router\n        routes:\n          - path_prefix: /\n            cluster: backend\n      - filter: load_balancer\n        clusters:\n          - name: backend\n            endpoints: [127.0.0.1:{backend}]\ninsecure_options:\n  allow_private_endpoints: true\n",
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    )).unwrap()
}

/// Build one real peer-identity-trust listener for an exact selector.
#[cfg(all(feature = "hyper", feature = "spiffe"))]
fn peer_trust_probe_config(certs: &TestCertificates, port: u16, backend: u16, selector: &str) -> Config {
    Config::from_yaml(&format!(
        "listeners:\n  - name: peer-trust-probe\n    address: 127.0.0.1:{port}\n    filter_chains: [main]\n    tls:\n      certificates:\n        - cert_path: {cert}\n          key_path: {key}\n      client_ca:\n        ca_path: {ca}\n      client_cert_mode: require\nfilter_chains:\n  - name: main\n    filters:\n      - filter: peer_identity_trust\n        trusted_peers:\n          - {selector}\n      - filter: router\n        routes:\n          - path_prefix: /\n            cluster: backend\n      - filter: load_balancer\n        clusters:\n          - name: backend\n            endpoints: [127.0.0.1:{backend}]\ninsecure_options:\n  allow_private_endpoints: true\n",
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    )).unwrap()
}

/// Read one length-delimited HTTP/1 response without consuming the next one.
#[cfg(feature = "hyper")]
fn read_identity_http1(client: &mut IdentityHttp1Client) -> (u16, String) {
    let mut status = String::new();
    client.read_line(&mut status).unwrap();
    let status_code = status.split_whitespace().nth(1).unwrap().parse::<u16>().unwrap();
    let mut length = None;
    loop {
        let mut line = String::new();
        let read = client.read_line(&mut line).unwrap();
        assert!(read > 0, "HTTP/1 response ended before its headers completed");
        if line == "\r\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            length = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let mut body = vec![0_u8; length.expect("counted backend sends Content-Length")];
    client.read_exact(&mut body).unwrap();
    (status_code, String::from_utf8(body).unwrap())
}

/// Open a single TLS HTTP/1 connection for repeated wire requests.
#[cfg(feature = "hyper")]
fn open_identity_http1(addr: &str, config: Arc<rustls::ClientConfig>) -> IdentityHttp1Client {
    let socket = std::net::TcpStream::connect(addr).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let connection = rustls::ClientConnection::new(config, name).unwrap();
    std::io::BufReader::new(rustls::StreamOwned::new(connection, socket))
}

/// Drive two requests on one real TLS HTTP/1 connection.
#[cfg(feature = "hyper")]
fn h1_identity_responses(addr: &str, config: Arc<rustls::ClientConfig>) -> Vec<(u16, String)> {
    let mut client = open_identity_http1(addr, config);
    let mut responses = Vec::new();
    for _request in 0..2 {
        client
            .get_mut()
            .write_all(b"GET /alpha HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        responses.push(read_identity_http1(&mut client));
    }
    responses
}

/// Exercise StreamBuffer with an actual nonempty JSON body over TLS HTTP/1.
#[cfg(feature = "hyper")]
fn h1_identity_post_with_json(addr: &str, config: Arc<rustls::ClientConfig>) -> (u16, String) {
    let mut client = open_identity_http1(addr, config);
    let body = br#"{"model":"probe"}"#;
    let head = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    client.get_mut().write_all(head.as_bytes()).unwrap();
    client.get_mut().write_all(body).unwrap();
    read_identity_http1(&mut client)
}

/// Send all paths as concurrent streams on one authenticated HTTP/2 connection.
#[cfg(feature = "hyper")]
async fn h2_identity_responses(
    addr: &str,
    config: Arc<rustls::ClientConfig>,
    paths: &[&str],
    spoof: bool,
) -> Vec<(u16, String)> {
    let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls = tokio_rustls::TlsConnector::from(config)
        .connect(name, socket)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(async move {
        connection.await.unwrap();
    });
    let port = addr.rsplit_once(':').unwrap().1;
    let mut responses = Vec::new();
    for path in paths {
        sender = sender.ready().await.unwrap();
        let mut request = http::Request::get(format!("https://localhost:{port}{path}"));
        if spoof {
            request = request.header("x-forwarded-client-cert", "pretend-valid");
        }
        let (response, _send) = sender.send_request(request.body(()).unwrap(), true).unwrap();
        responses.push(response);
    }
    let mut results = Vec::new();
    for response in responses {
        let response = response.await.unwrap();
        let status = response.status().as_u16();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            bytes.extend_from_slice(&chunk);
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        results.push((status, String::from_utf8(bytes).unwrap()));
    }
    driver.abort();
    results
}

#[cfg(feature = "hyper")]
#[test]
fn hyper_verified_identity_isolated_across_h1_keepalive_and_h2_streams() {
    let certs = TestCertificates::generate();
    let alpha = certs.generate_client_cert_with_org("Alpha");
    let beta = certs.generate_client_cert_with_org("Beta");
    let expected = Arc::new(HashMap::from([
        ("/alpha", expected_peer(&alpha, "Alpha")),
        ("/beta", expected_peer(&beta, "Beta")),
    ]));
    let registry = identity_probe_registry(expected);
    let (backend, hits) = start_request_counting_backend("verified-peer");
    let config = identity_probe_config(&certs, free_port(), backend.port(), false);
    let proxy = start_tls_proxy_no_wait_with_registry(&config, &registry);
    let alpha_h1 = certs.raw_tls_client_config_with_cert(&alpha);
    let beta_h2 = certs.client_config_with_cert(&beta);
    let anonymous = certs.client_config();
    wait_for_tls(proxy.addr(), &alpha_h1);

    let h1 = h1_identity_responses(proxy.addr(), alpha_h1);
    assert_eq!(
        h1,
        vec![(200, "verified-peer".to_owned()); 2],
        "both H1 requests retain Alpha identity"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let h2 = runtime.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            h2_identity_responses(proxy.addr(), beta_h2, &["/beta", "/beta"], false),
        )
        .await
        .unwrap()
    });
    assert_eq!(
        h2,
        vec![(200, "verified-peer".to_owned()); 2],
        "concurrent H2 streams retain Beta identity"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        4,
        "each authenticated request reaches the backend once"
    );

    let refused = runtime.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            h2_identity_responses(proxy.addr(), anonymous, &["/alpha"], true),
        )
        .await
        .unwrap()
    });
    assert_eq!(refused.len(), 1, "the anonymous request must have exactly one response");
    assert_eq!(
        refused.first().map(|response| response.0),
        Some(403),
        "an anonymous client cannot spoof a certificate header"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        4,
        "anonymous requests never reach the backend"
    );

    // A distinct issuer name exercises UnknownCA, not a same-name wrong-signature alert.
    let wrong_ca = TestCertificates::generate_for_san("untrusted-client-ca.test");
    let wrong_cert = wrong_ca.generate_client_cert_with_org("Alpha");
    let wrong_config = build_cross_ca_client_config(&certs, &wrong_ca, &wrong_cert);
    let failed = tls_negative_probe(
        proxy.addr(),
        "localhost",
        b"GET /alpha HTTP/1.1\r\nHost: localhost\r\n\r\n",
        &wrong_config,
    );
    assert!(
        failed.is_client_auth_alert(),
        "a presented wrong-CA cert must fail during TLS: {failed:?}"
    );
    assert!(
        matches!(
            &failed,
            praxis_test_utils::TlsProbeOutcome::PeerAlert(rustls::AlertDescription::UnknownCA)
        ),
        "a distinct untrusted issuer must produce UnknownCA: {failed:?}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        4,
        "wrong-CA requests never reach the backend"
    );
}

#[cfg(feature = "hyper")]
#[test]
fn hyper_certificate_pin_remains_sha256_with_sha384_only_tls_cipher() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert_with_org("Pinned");
    let expected = Arc::new(HashMap::from([("/pinned", expected_peer(&client_cert, "Pinned"))]));
    let registry = identity_probe_registry(expected);
    let (backend, hits) = start_request_counting_backend("sha256-pin");
    let config = identity_probe_config(&certs, free_port(), backend.port(), true);
    let proxy = start_tls_proxy_no_wait_with_registry(&config, &registry);
    let client_config = certs.client_config_with_cert(&client_cert);
    wait_for_tls(proxy.addr(), &client_config);

    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                h2_identity_responses(proxy.addr(), client_config, &["/pinned"], false),
            )
            .await
            .unwrap()
        });
    assert_eq!(
        result,
        vec![(200, "sha256-pin".to_owned())],
        "SHA-256 certificate pin must not follow SHA-384 negotiated cipher"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the pinned certificate reaches the backend exactly once"
    );
}

#[cfg(all(feature = "hyper", feature = "spiffe"))]
#[test]
fn hyper_valid_bmp_organization_keeps_digest_but_denies_org_authorization() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert_with_bmp_org("Opaque");
    let client_config = certs.client_config_with_cert(&client_cert);
    let certificate = X509::from_pem(&std::fs::read(&client_cert.cert_path).unwrap()).unwrap();
    let digest = certificate.digest(MessageDigest::sha256()).unwrap();
    let digest_hex = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let (backend, hits) = start_request_counting_backend("digest-authorized");

    let digest_config = peer_trust_probe_config(
        &certs,
        free_port(),
        backend.port(),
        &format!("cert_digest: {digest_hex}"),
    );
    let digest_proxy = start_tls_proxy_no_wait(&digest_config);
    wait_for_tls(digest_proxy.addr(), &client_config);
    let (digest_status, digest_body) = https_get(digest_proxy.addr(), "/", &client_config);
    assert_eq!(
        digest_status, 200,
        "verified BMP peer retains its digest-only authorization"
    );
    assert_eq!(digest_body, "digest-authorized");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let org_config = peer_trust_probe_config(&certs, free_port(), backend.port(), "organization: Opaque");
    let org_proxy = start_tls_proxy_no_wait(&org_config);
    wait_for_tls(org_proxy.addr(), &client_config);
    let (org_status, _org_body) = https_get(org_proxy.addr(), "/", &client_config);
    assert_eq!(
        org_status, 403,
        "an undecodable O never authorizes an organization rule"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "rejected O access never reaches the backend"
    );

    let conjunctive_config = peer_trust_probe_config(
        &certs,
        free_port(),
        backend.port(),
        &format!("cert_digest: {digest_hex}\n            organization: Opaque"),
    );
    let conjunctive_proxy = start_tls_proxy_no_wait(&conjunctive_config);
    wait_for_tls(conjunctive_proxy.addr(), &client_config);
    let (conjunctive_status, _conjunctive_body) = https_get(conjunctive_proxy.addr(), "/", &client_config);
    assert_eq!(
        conjunctive_status, 403,
        "a matching digest cannot override an undecodable O conjunction"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the denied conjunction never reaches the backend"
    );
}
