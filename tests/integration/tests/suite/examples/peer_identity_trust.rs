// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional mTLS coverage for the published peer identity trust example.

use std::{collections::HashMap, sync::atomic::Ordering};

use openssl::{hash::MessageDigest, x509::X509};
use praxis_core::config::Config;
use praxis_test_utils::{
    TestCertificates, free_port, https_get, start_request_counting_backend, start_tls_proxy_no_wait,
    tls_negative_probe, wait_for_tls,
};

use super::load_example_config;

#[test]
fn peer_identity_trust_example_completed_config_authorizes_peers() {
    let certificates = TestCertificates::generate();
    let pinned_cert = certificates.generate_client_cert_with_org("gateway-peer");
    let org_cert = certificates.generate_client_cert_with_org("trusted-sidecar");
    let same_org_other_cert = certificates.generate_client_cert_with_org("gateway-peer");
    let unknown_cert = certificates.generate_client_cert_with_org("untrusted-peer");
    let pinned_client = certificates.client_config_with_cert(&pinned_cert);
    let org_client = certificates.client_config_with_cert(&org_cert);
    let same_org_other_client = certificates.client_config_with_cert(&same_org_other_cert);
    let unknown_client = certificates.client_config_with_cert(&unknown_cert);
    let anonymous_client = certificates.client_config();
    let certificate_der = X509::from_pem(&std::fs::read(&pinned_cert.cert_path).unwrap()).unwrap();
    let digest = certificate_der
        .digest(MessageDigest::sha256())
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let (backend, hits) = start_request_counting_backend("peer-trust-example");
    let listener_port = free_port();
    let config = load_example_config(
        "security/peer-identity-trust.yaml",
        listener_port,
        HashMap::from([("127.0.0.1:3000", backend.port())]),
    );
    let yaml = serde_yaml::to_string(&config)
        .unwrap()
        .replace("/etc/praxis/server.pem", certificates.cert_path.to_str().unwrap())
        .replace("/etc/praxis/server-key.pem", certificates.key_path.to_str().unwrap())
        .replace("/etc/praxis/client-ca.pem", certificates.ca_cert_path.to_str().unwrap())
        .replace(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            &digest,
        );
    assert!(
        yaml.contains(&format!("cert_digest: {digest}")),
        "example digest placeholder must be replaced"
    );
    let configured = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&configured);
    wait_for_tls(proxy.addr(), &pinned_client);

    for (identity, label) in [
        (&pinned_client, "digest and organization"),
        (&org_client, "organization only"),
    ] {
        let (status, body) = https_get(proxy.addr(), "/", identity);
        assert_eq!(status, 200, "{label} entry must permit its CA-verified peer");
        assert_eq!(body, "peer-trust-example", "{label} must reach the backend");
    }
    let accepted_hits = hits.load(Ordering::SeqCst);
    assert_eq!(
        accepted_hits, 2,
        "each accepted peer must reach the backend exactly once"
    );

    let (status, _) = https_get(proxy.addr(), "/", &unknown_client);
    assert_eq!(status, 403, "same-CA untrusted peer must fail the filter");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        accepted_hits,
        "untrusted peer must not reach backend"
    );

    let (status, _) = https_get(proxy.addr(), "/", &same_org_other_client);
    assert_eq!(
        status, 403,
        "same-CA peer with matching organization but different digest must fail"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        accepted_hits,
        "digest mismatch must not reach backend"
    );

    let no_cert = tls_negative_probe(
        proxy.addr(),
        "localhost",
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        &anonymous_client,
    );
    assert!(
        no_cert.is_client_auth_alert(),
        "missing client certificate must receive peer authentication alert: {no_cert:?}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        accepted_hits,
        "anonymous peer must not reach backend"
    );

    let second_port = free_port();
    let mismatched = yaml
        .replacen(
            &format!("127.0.0.1:{listener_port}"),
            &format!("127.0.0.1:{second_port}"),
            1,
        )
        .replacen("organization: gateway-peer", "organization: other-organization", 1);
    assert!(
        mismatched.contains("organization: other-organization"),
        "conjunction variant must change the pinned entry"
    );
    assert!(
        mismatched.contains(&format!("127.0.0.1:{second_port}")),
        "conjunction variant needs an independent listener"
    );
    let second_config = Config::from_yaml(&mismatched).unwrap();
    let second_proxy = start_tls_proxy_no_wait(&second_config);
    wait_for_tls(second_proxy.addr(), &pinned_client);
    let (status, _) = https_get(second_proxy.addr(), "/", &pinned_client);
    assert_eq!(
        status, 403,
        "matching digest with wrong configured organization must fail"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        accepted_hits,
        "conjunction refusal must not reach backend"
    );
}
