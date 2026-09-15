// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! HTTPS IP-literal SNI drives certificate IP-SAN validation, exercised through
//! the peer built by the prepared sub-request (`peer_for` → `HttpPeer`) and the
//! real sub-request connector — not an independent rustls client. A regression
//! that made `peer_for` build an insecure or incorrect peer would flip these.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use pingora_core::utils::tls::WrappedX509;
use praxis_core::{
    connectivity::prepare_url_target,
    subrequest::{SubRequest, SubRequestClient, SubRequestConnector, SubResponse},
};
use praxis_test_utils::{TestCertificates, ensure_crypto_provider, start_tls_backend};

/// Prepare `url`, bind an empty `GET /`, and drive the request through the peer
/// the prepared sub-request builds (`peer_at(0)` → `peer_for`), trusting only
/// `ca_der`. The peer's SNI, TLS mode, and verification settings are whatever
/// `peer_for` produced; only the trust anchor is injected here. Returns the
/// response when the TLS handshake (certificate + hostname validation included)
/// and HTTP exchange both succeed, or `None` on any failure.
async fn request_via_prepared_peer(url: &str, ca_der: &[u8]) -> Option<SubResponse> {
    ensure_crypto_provider();
    let deadline = Instant::now() + Duration::from_secs(5);

    let target = prepare_url_target(url, deadline, |_| Ok(()))
        .await
        .expect("prepare https target");
    let prepared = target.bind(SubRequest {
        method: http::Method::GET,
        uri: "/".parse().expect("origin-form uri"),
        headers: http::HeaderMap::new(),
        body: bytes::Bytes::new(),
    });

    let mut peer = prepared.peer_at(0).expect("one validated peer");
    // Inject only the trust anchor; SNI, TLS mode, and cert/hostname
    // verification stay exactly as `peer_for` built them.
    let ca = WrappedX509::parse(ca_der.to_vec()).expect("parse test CA DER");
    peer.options.ca = Some(Arc::from(vec![ca]));

    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
    Box::pin(client.execute(&peer, prepared.request(), 64 * 1024, Duration::from_secs(5), None))
        .await
        .ok()
}

#[tokio::test]
async fn ip_literal_https_target_validates_matching_ip_san() {
    // `generate()` includes 127.0.0.1 as an IP SAN.
    let certs = TestCertificates::generate();
    let port = start_tls_backend(&certs, "ok");
    let url = format!("https://127.0.0.1:{port}/");

    let target = prepare_url_target(&url, Instant::now() + Duration::from_secs(5), |_| Ok(()))
        .await
        .expect("prepare literal https target");
    assert!(target.is_tls());
    assert_eq!(target.sni(), "127.0.0.1", "SNI must be the bare IP literal");

    let response = Box::pin(request_via_prepared_peer(&url, &certs.ca_cert_der))
        .await
        .expect("a cert bearing the matching IP SAN must validate against the prepared peer's IP-literal SNI");
    assert_eq!(
        response.status, 200,
        "the validated peer must complete the HTTP exchange"
    );
    assert_eq!(response.body.as_ref(), b"ok", "response must come from the TLS backend");
}

#[tokio::test]
async fn ip_literal_https_target_rejects_missing_ip_san() {
    // No loopback IP SAN → IP-literal SNI validation must fail.
    let certs = TestCertificates::generate_dns_only("upstream.test");
    let port = start_tls_backend(&certs, "ok");
    let url = format!("https://127.0.0.1:{port}/");

    assert!(
        Box::pin(request_via_prepared_peer(&url, &certs.ca_cert_der))
            .await
            .is_none(),
        "a cert without the matching IP SAN must fail IP-literal SNI validation through the prepared peer"
    );
}
