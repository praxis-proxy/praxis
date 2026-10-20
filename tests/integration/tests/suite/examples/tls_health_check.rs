// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional coverage for both TLS health-check example modes.

use std::{sync::atomic::Ordering, time::Duration};

use praxis_test_utils::{TestCertificates, free_port, http_get, start_full_proxy};

use super::super::tls_health_check::Backend;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_health_check_example_exercises_handshake_and_https_modes() {
    let certs = TestCertificates::generate();
    let handshake = Backend::new(&certs, false).await;
    let https = Backend::new(&certs, false).await;
    let admin_addr = format!("127.0.0.1:{}", free_port());
    let yaml = include_str!("../../../../../examples/configs/observability/tls-health-check.yaml")
        .replace("127.0.0.1:8080", &format!("127.0.0.1:{}", free_port()))
        .replace("127.0.0.1:9902", &admin_addr)
        .replace("127.0.0.1:8443", &handshake.address)
        .replace("127.0.0.1:8444", &https.address)
        .replace("/etc/praxis/upstream-ca.pem", certs.ca_cert_path.to_str().unwrap());
    let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    tokio::time::timeout(Duration::from_secs(15), async {
        while handshake.closes.load(Ordering::Relaxed) == 0 || https.requests.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("both example modes must actually probe TLS");
    assert!(
        handshake.requests.lock().unwrap().is_empty(),
        "handshake mode must send no HTTP"
    );
    assert!(
        https
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.starts_with("GET /health HTTP/1.1\r\n")),
        "HTTPS mode must check configured path"
    );
    https.status.store(503, Ordering::Relaxed);
    let body = tokio::task::spawn_blocking(move || {
        for _ in 0..150 {
            let (_, body) = http_get(&admin_addr, "/ready", None);
            if body.contains(r#""https":{"healthy":0,"unhealthy":1"#) {
                return body;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("HTTPS example must remove the failing endpoint");
    })
    .await
    .unwrap();
    assert!(
        body.contains(r#""handshake":{"healthy":1,"unhealthy":0"#),
        "TLS-only endpoint remains healthy: {body}"
    );
}
