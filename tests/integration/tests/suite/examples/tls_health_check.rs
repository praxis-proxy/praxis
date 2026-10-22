// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional coverage for both TLS health-check example modes.

use std::{collections::HashMap, sync::atomic::Ordering, time::Duration};

use praxis_test_utils::{TestCertificates, free_port, http_get, load_example_config, start_full_proxy};

use super::super::tls_health_check::Backend;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_health_check_example_exercises_handshake_and_https_modes() {
    let certs = TestCertificates::generate();
    let handshake = Backend::new(&certs, false).await;
    let https = Backend::new(&certs, false).await;
    https.status.store(503, Ordering::Relaxed);
    let admin_port = free_port();
    let admin_addr = format!("127.0.0.1:{admin_port}");
    let config = load_example_config(
        "observability/tls-health-check.yaml",
        free_port(),
        HashMap::from([
            ("127.0.0.1:9902", admin_port),
            (
                "127.0.0.1:8443",
                handshake.address.parse::<std::net::SocketAddr>().unwrap().port(),
            ),
            (
                "127.0.0.1:8444",
                https.address.parse::<std::net::SocketAddr>().unwrap().port(),
            ),
        ]),
    );
    let yaml = serde_yaml::to_string(&config)
        .unwrap()
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
    wait_for_https_health(&admin_addr, false).await;
    https.status.store(200, Ordering::Relaxed);
    wait_for_https_health(&admin_addr, true).await;
    https.status.store(503, Ordering::Relaxed);
    let body = wait_for_https_health(&admin_addr, false).await;
    assert!(
        body.contains(r#""handshake":{"healthy":1,"unhealthy":0"#),
        "TLS-only endpoint remains healthy: {body}"
    );
}

/// Observe recovery from a failed probe before testing a later health change.
async fn wait_for_https_health(admin_addr: &str, healthy: bool) -> String {
    let admin_addr = admin_addr.to_owned();
    let expected = if healthy {
        r#""https":{"healthy":1,"unhealthy":0"#
    } else {
        r#""https":{"healthy":0,"unhealthy":1"#
    };
    tokio::task::spawn_blocking(move || {
        for _ in 0..150 {
            let (_, body) = http_get(&admin_addr, "/ready", None);
            if body.contains(expected) {
                return body;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("HTTPS example must reach {expected}");
    })
    .await
    .unwrap()
}
