// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http::HeaderMap;
use pingora_core::upstreams::peer::HttpPeer;

use super::{
    DEPTH_HEADER, FrameworkHeaders, SubRequest, SubRequestClient, SubRequestConnector, SubRequestConnectorOptions,
    SubRequestError, SubResponse,
    client::CircuitGuard,
    internals::{
        clamp_peer_timeouts, empty_body_needs_framing, ensure_host_header, min_timeout, strip_hop_by_hop_headers,
        strip_request_framing_headers, strip_reserved_headers,
    },
    types::is_transport_header,
};
use crate::circuit::{CircuitBreakerConfig, CircuitBreakerRegistry, CircuitCheck, PeerKey};

// -- SubRequestConnector ------------------------------------------------

#[test]
fn clone_shares_same_arc() {
    let a = SubRequestConnector::new(16, None);
    let b = a.clone();
    assert!(
        Arc::ptr_eq(&a.inner, &b.inner),
        "cloned connectors should share the same Arc"
    );
}

#[test]
fn debug_impl_does_not_panic() {
    let connector = SubRequestConnector::new(8, None);
    let debug = format!("{connector:?}");
    assert!(
        debug.contains("SubRequestConnector"),
        "debug output should contain type name"
    );
}

#[test]
fn unbounded_connector_has_no_admission() {
    let connector = SubRequestConnector::new(8, None);
    assert!(
        connector.admission.is_none(),
        "no max_connections should mean no semaphore"
    );
}

#[test]
fn bounded_connector_has_admission_semaphore() {
    let connector = SubRequestConnector::new(8, Some(16));
    let semaphore = connector
        .admission
        .as_ref()
        .expect("max_connections should create semaphore");
    assert_eq!(
        semaphore.available_permits(),
        16,
        "semaphore should have the configured permits"
    );
}

#[tokio::test]
async fn acquire_permit_returns_none_without_limit() {
    let connector = SubRequestConnector::new(4, None);
    assert!(
        connector.acquire_permit().await.is_none(),
        "unbounded connector should return None"
    );
}

#[tokio::test]
async fn acquire_permit_returns_some_with_limit() {
    let connector = SubRequestConnector::new(4, Some(2));
    assert!(
        connector.acquire_permit().await.is_some(),
        "bounded connector should return a permit"
    );
}

#[tokio::test]
async fn dropping_permit_restores_capacity() {
    let connector = SubRequestConnector::new(4, Some(1));
    let permit = connector.acquire_permit().await.unwrap();
    assert_eq!(
        connector.admission.as_ref().unwrap().available_permits(),
        0,
        "all permits should be taken"
    );
    drop(permit);
    assert_eq!(
        connector.admission.as_ref().unwrap().available_permits(),
        1,
        "dropping permit should restore capacity"
    );
}

#[test]
fn clone_shares_admission_semaphore() {
    let a = SubRequestConnector::new(4, Some(8));
    let b = a.clone();
    assert!(
        Arc::ptr_eq(a.admission.as_ref().unwrap(), b.admission.as_ref().unwrap()),
        "cloned connectors should share the semaphore"
    );
}

// -- SubRequest / SubResponse -------------------------------------------

#[test]
fn subrequest_clone_preserves_fields() {
    let req = SubRequest {
        method: http::Method::POST,
        uri: "/v1/chat".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"hello"),
    };
    let cloned = req.clone();
    assert_eq!(cloned.method, http::Method::POST);
    assert_eq!(cloned.body, Bytes::from_static(b"hello"));
}

#[test]
fn subresponse_clone_preserves_fields() {
    let resp = SubResponse {
        status: 200,
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"world"),
    };
    let cloned = resp.clone();
    assert_eq!(cloned.status, 200);
    assert_eq!(cloned.body, Bytes::from_static(b"world"));
}

// -- SubRequestClient ---------------------------------------------------

#[test]
fn client_wraps_connector() {
    let connector = SubRequestConnector::new(8, None);
    let client = SubRequestClient::new(connector);
    let debug = format!("{client:?}");
    assert!(
        debug.contains("SubRequestClient"),
        "debug output should contain type name"
    );
}

#[test]
fn client_clone_shares_connector() {
    let connector = SubRequestConnector::new(8, Some(4));
    let a = SubRequestClient::new(connector);
    let b = a.clone();
    assert!(
        Arc::ptr_eq(&a.connector().inner, &b.connector().inner,),
        "cloned clients should share the same connector"
    );
}

// -- SubRequestError ----------------------------------------------------

#[test]
fn subrequest_error_invalid_request_display() {
    let err = SubRequestError::InvalidRequest("bad header".to_owned());
    assert!(
        err.to_string().contains("bad header"),
        "InvalidRequest error should include reason: {err}"
    );
}

#[test]
fn subrequest_error_admission_timeout_display() {
    let err = SubRequestError::AdmissionTimeout { max_connections: 64 };
    let msg = err.to_string();
    assert!(msg.contains("64"), "should include max_connections: {msg}");
    assert!(msg.contains("admission"), "should mention admission: {msg}");
}

#[test]
fn subrequest_error_connect_display() {
    let err = SubRequestError::Connect("connection refused".to_owned());
    assert!(
        err.to_string().contains("connection refused"),
        "Connect error should include reason: {err}"
    );
}

#[test]
fn subrequest_error_io_display() {
    let err = SubRequestError::Io("broken pipe".to_owned());
    assert!(
        err.to_string().contains("broken pipe"),
        "Io error should include reason: {err}"
    );
}

#[test]
fn subrequest_error_response_too_large_display() {
    let err = SubRequestError::ResponseTooLarge {
        actual: 20_000,
        limit: 10_000,
    };
    let msg = err.to_string();
    assert!(msg.contains("20000"), "should include actual: {msg}");
    assert!(msg.contains("10000"), "should include limit: {msg}");
}

#[test]
fn subrequest_error_deadline_exceeded_display() {
    let err = SubRequestError::DeadlineExceeded;
    assert!(
        !err.to_string().is_empty(),
        "DeadlineExceeded should have a display message"
    );
}

// -- Header sanitization ------------------------------------------------

#[test]
fn strip_hop_by_hop_removes_static_and_connection_nominated() {
    let mut headers = HeaderMap::new();
    headers.insert("connection", "x-custom, keep-alive".parse().unwrap());
    headers.insert("keep-alive", "timeout=5".parse().unwrap());
    headers.insert("x-custom", "value".parse().unwrap());
    headers.insert("x-safe", "kept".parse().unwrap());
    headers.insert("transfer-encoding", "chunked".parse().unwrap());

    strip_hop_by_hop_headers(&mut headers);

    assert!(!headers.contains_key("connection"));
    assert!(!headers.contains_key("keep-alive"));
    assert!(!headers.contains_key("x-custom"));
    assert!(!headers.contains_key("transfer-encoding"));
    assert_eq!(headers.get("x-safe").unwrap(), "kept");
}

#[test]
fn strip_request_framing_removes_content_length_and_transfer_encoding() {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, "42".parse().unwrap());
    headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
    headers.insert("x-safe", "kept".parse().unwrap());

    strip_request_framing_headers(&mut headers);

    assert!(!headers.contains_key(http::header::CONTENT_LENGTH));
    assert!(!headers.contains_key(http::header::TRANSFER_ENCODING));
    assert_eq!(headers.get("x-safe").unwrap(), "kept");
}

// -- Helpers ------------------------------------------------------------

#[test]
fn empty_entity_methods_get_explicit_framing() {
    assert!(empty_body_needs_framing(&http::Method::POST));
    assert!(empty_body_needs_framing(&http::Method::PUT));
    assert!(empty_body_needs_framing(&http::Method::PATCH));
    assert!(!empty_body_needs_framing(&http::Method::GET));
    assert!(!empty_body_needs_framing(&http::Method::HEAD));
}

#[test]
fn min_timeout_preserves_stricter_cluster_limit() {
    assert_eq!(
        min_timeout(Some(Duration::from_secs(1)), Duration::from_secs(10)),
        Duration::from_secs(1)
    );
    assert_eq!(
        min_timeout(Some(Duration::from_secs(20)), Duration::from_secs(10)),
        Duration::from_secs(10)
    );
    assert_eq!(min_timeout(None, Duration::from_secs(10)), Duration::from_secs(10));
}

#[test]
fn clamp_peer_timeouts_bounds_connection_setup() {
    let mut peer = HttpPeer::new("127.0.0.1:8080", false, String::new());
    peer.options.connection_timeout = Some(Duration::from_secs(1));
    peer.options.total_connection_timeout = Some(Duration::from_secs(20));

    clamp_peer_timeouts(&mut peer, Duration::from_secs(10));

    assert_eq!(peer.options.connection_timeout, Some(Duration::from_secs(1)));
    assert_eq!(peer.options.total_connection_timeout, Some(Duration::from_secs(10)));
}

#[test]
fn ensure_host_header_uses_peer_address_without_overwriting_explicit_host() {
    let peer = HttpPeer::new("127.0.0.1:8443", false, String::new());
    let mut generated = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
    ensure_host_header(&mut generated, &peer).unwrap();
    assert_eq!(generated.headers.get(http::header::HOST).unwrap(), "127.0.0.1:8443");

    let mut explicit = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
    explicit.insert_header(http::header::HOST, "model.example").unwrap();
    ensure_host_header(&mut explicit, &peer).unwrap();
    assert_eq!(explicit.headers.get(http::header::HOST).unwrap(), "model.example");
}

// -- Integration-style tests --------------------------------------------

#[tokio::test]
async fn deadline_bounds_the_complete_exchange() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let backend = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let connector = SubRequestConnector::new(1, None);
    let client = SubRequestClient::new(connector);
    let peer = HttpPeer::new(address.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };

    let started = std::time::Instant::now();
    let result = Box::pin(client.execute(&peer, &request, 1024, Duration::from_millis(10), None)).await;
    let elapsed = started.elapsed();
    backend.abort();

    assert!(result.is_err(), "a backend that never responds must time out");
    assert!(
        elapsed < Duration::from_millis(500),
        "exchange exceeded its deadline: {elapsed:?}"
    );
}

#[tokio::test]
async fn admission_timeout_returns_typed_error() {
    let connector = SubRequestConnector::new(4, Some(1));
    let permit = connector.acquire_permit().await.unwrap();

    let result = connector.try_acquire_permit(Duration::from_millis(10)).await;

    assert!(
        matches!(result, Err(SubRequestError::AdmissionTimeout { .. })),
        "should return AdmissionTimeout when slots are full: {result:?}"
    );
    drop(result);
    drop(permit);
}

#[tokio::test]
async fn admission_timeout_reports_configured_max() {
    let configured_limit = 4;
    let connector = SubRequestConnector::new(4, Some(configured_limit));
    let mut permits = Vec::new();
    for _ in 0..configured_limit {
        permits.push(connector.acquire_permit().await.unwrap());
    }

    let result = connector.try_acquire_permit(Duration::from_millis(10)).await;
    match &result {
        Err(SubRequestError::AdmissionTimeout { max_connections }) => {
            assert_eq!(
                *max_connections, configured_limit,
                "should report configured limit, not available permits"
            );
        },
        other => panic!("expected AdmissionTimeout, got: {other:?}"),
    }
    drop(result);
    drop(permits);
}

#[tokio::test]
async fn try_acquire_permit_returns_none_without_limit() {
    let connector = SubRequestConnector::new(4, None);
    let result = connector.try_acquire_permit(Duration::from_millis(10)).await;
    assert!(
        matches!(result, Ok(None)),
        "unbounded connector should return Ok(None): {result:?}"
    );
    drop(result);
}

// -- Client ceiling -------------------------------------------------------

#[test]
fn client_with_custom_ceiling() {
    let connector = SubRequestConnector::new(8, None);
    let client = SubRequestClient::with_max_response_bytes(connector, 4096);
    assert_eq!(client.max_response_bytes, 4096);
}

#[test]
fn client_default_ceiling_is_absolute_max() {
    let connector = SubRequestConnector::new(8, None);
    let client = SubRequestClient::new(connector);
    assert_eq!(
        client.max_response_bytes,
        crate::config::ABSOLUTE_MAX_BODY_BYTES,
        "default ceiling should be ABSOLUTE_MAX_BODY_BYTES (64 MiB)"
    );
}

// -- Response header sanitization -----------------------------------------

#[test]
fn response_hop_by_hop_headers_are_stripped() {
    let mut headers = HeaderMap::new();
    headers.insert("connection", "x-nominated".parse().unwrap());
    headers.insert("transfer-encoding", "chunked".parse().unwrap());
    headers.insert("keep-alive", "timeout=5".parse().unwrap());
    headers.insert("x-nominated", "internal".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());

    strip_hop_by_hop_headers(&mut headers);

    assert!(!headers.contains_key("connection"));
    assert!(!headers.contains_key("transfer-encoding"));
    assert!(!headers.contains_key("keep-alive"));
    assert!(!headers.contains_key("x-nominated"));
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
}

// -- Reserved header sanitization ------------------------------------------

#[test]
fn strip_reserved_removes_internal_prefixes() {
    let mut headers = HeaderMap::new();
    headers.insert("x-praxis-route", "internal".parse().unwrap());
    headers.insert("x-ext-protocol-model", "gpt-4".parse().unwrap());
    headers.insert("x-ext-agent-task", "classify".parse().unwrap());
    headers.insert("x-custom", "kept".parse().unwrap());
    headers.insert("authorization", "Bearer tok".parse().unwrap());

    strip_reserved_headers(&mut headers);

    assert!(!headers.contains_key("x-praxis-route"));
    assert!(!headers.contains_key("x-ext-protocol-model"));
    assert!(!headers.contains_key("x-ext-agent-task"));
    assert_eq!(headers.get("x-custom").unwrap(), "kept");
    assert_eq!(headers.get("authorization").unwrap(), "Bearer tok");
}

#[test]
fn strip_reserved_is_no_op_for_safe_headers() {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert("x-request-id", "abc".parse().unwrap());

    strip_reserved_headers(&mut headers);

    assert_eq!(headers.len(), 2);
}

// -- Connector configured_max_connections ---------------------------------

#[test]
fn connector_stores_configured_max_connections() {
    let connector = SubRequestConnector::new(4, Some(256));
    assert_eq!(connector.configured_max_connections, Some(256));

    let unbounded = SubRequestConnector::new(4, None);
    assert_eq!(unbounded.configured_max_connections, None);
}

// -- SubRequestConnectorOptions -----------------------------------------------

#[test]
fn with_options_creates_connector() {
    let connector = SubRequestConnector::with_options(SubRequestConnectorOptions {
        keepalive_pool_size: 32,
        max_connections: Some(64),
        circuit_breaker: None,
    });
    assert_eq!(
        connector.configured_max_connections,
        Some(64),
        "max_connections should be forwarded"
    );
    assert!(
        connector.circuit_breakers.is_none(),
        "no circuit breaker config should mean no registry"
    );
}

#[test]
fn with_options_circuit_breaker_enabled() {
    let connector = SubRequestConnector::with_options(SubRequestConnectorOptions {
        keepalive_pool_size: 16,
        max_connections: None,
        circuit_breaker: Some(CircuitBreakerConfig {
            threshold: 3,
            recovery_window: Duration::from_secs(30),
            half_open_timeout: Duration::from_secs(30),
        }),
    });
    assert!(
        connector.circuit_breakers.is_some(),
        "circuit breaker config should create a registry"
    );
}

// -- CircuitGuard outcome classification ------------------------------------

fn test_registry(threshold: u32) -> CircuitBreakerRegistry {
    CircuitBreakerRegistry::new(CircuitBreakerConfig {
        threshold,
        recovery_window: Duration::from_secs(9999),
        half_open_timeout: Duration::from_secs(9999),
    })
}

fn test_peer(addr: &str) -> PeerKey {
    PeerKey::new(addr.parse().unwrap(), "")
}

fn acquire_guard(registry: &CircuitBreakerRegistry, key: PeerKey) -> CircuitGuard<'_> {
    let CircuitCheck::Allowed(token) = registry.try_acquire(key.clone()) else {
        panic!("should be allowed");
    };
    CircuitGuard::new(registry, key, token)
}

#[test]
fn circuit_guard_success_records_success() {
    let registry = test_registry(3);
    let key = test_peer("127.0.0.1:8080");
    let guard = acquire_guard(&registry, key.clone());
    let result: Result<SubResponse, SubRequestError> = Ok(SubResponse {
        status: 200,
        headers: HeaderMap::new(),
        body: Bytes::new(),
    });
    guard.finalize(&result);
    assert!(registry.precheck(&key), "peer should remain healthy after success");
}

#[test]
fn circuit_guard_connect_error_records_failure() {
    let registry = test_registry(1);
    let key = test_peer("127.0.0.1:8080");
    let guard = acquire_guard(&registry, key.clone());
    guard.finalize(&Err(SubRequestError::Connect("refused".to_owned())));
    assert!(!registry.precheck(&key), "peer should be open after connect failure");
}

#[test]
fn circuit_guard_io_error_records_failure() {
    let registry = test_registry(1);
    let key = test_peer("127.0.0.1:8080");
    let guard = acquire_guard(&registry, key.clone());
    guard.finalize(&Err(SubRequestError::Io("broken pipe".to_owned())));
    assert!(!registry.precheck(&key), "peer should be open after I/O failure");
}

#[test]
fn circuit_guard_deadline_exceeded_records_failure() {
    let registry = test_registry(1);
    let key = test_peer("127.0.0.1:8080");
    let guard = acquire_guard(&registry, key.clone());
    guard.finalize(&Err(SubRequestError::DeadlineExceeded));
    assert!(!registry.precheck(&key), "peer should be open after deadline exceeded");
}

#[test]
fn circuit_guard_response_too_large_counts_as_success() {
    let registry = test_registry(1);
    let key = test_peer("127.0.0.1:8080");
    let guard = acquire_guard(&registry, key.clone());
    guard.finalize(&Err(SubRequestError::ResponseTooLarge {
        actual: 20_000,
        limit: 10_000,
    }));
    assert!(
        registry.precheck(&key),
        "response too large is not a peer fault — should remain healthy"
    );
}

#[test]
fn circuit_guard_admission_timeout_not_peer_fault() {
    let registry = test_registry(1);
    let key = test_peer("127.0.0.1:8080");
    let guard = acquire_guard(&registry, key.clone());
    guard.finalize(&Err(SubRequestError::AdmissionTimeout { max_connections: 64 }));
    assert!(
        registry.precheck(&key),
        "admission timeout is not a peer fault — should remain healthy"
    );
}

#[test]
fn circuit_guard_drop_without_finalize_records_failure() {
    let registry = test_registry(1);
    let key = test_peer("127.0.0.1:8080");
    let guard = acquire_guard(&registry, key.clone());
    drop(guard);
    assert!(
        !registry.precheck(&key),
        "dropped guard should record failure (deadline/panic path)"
    );
}

// -- SubRequestError (CircuitOpen) ------------------------------------------

#[test]
fn subrequest_error_circuit_open_display() {
    let err = SubRequestError::CircuitOpen {
        peer: "127.0.0.1:8080".to_owned(),
    };
    let msg = err.to_string();
    assert!(msg.contains("circuit open"), "should mention circuit open: {msg}");
    assert!(msg.contains("127.0.0.1:8080"), "should include peer address: {msg}");
}

// -- Framework headers ------------------------------------------------------

#[test]
fn is_transport_header_rejects_hop_by_hop_and_framing() {
    let transport_names = [
        "connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "content-length",
    ];
    for name in transport_names {
        let hdr: http::header::HeaderName = name.parse().unwrap();
        assert!(is_transport_header(&hdr), "{name} should be classified as transport");
    }

    let safe_names = ["authorization", "x-request-id", "x-custom-header"];
    for name in safe_names {
        let hdr: http::header::HeaderName = name.parse().unwrap();
        assert!(
            !is_transport_header(&hdr),
            "{name} should not be classified as transport"
        );
    }
}

#[test]
fn framework_headers_rejects_transport_headers() {
    let mut fw = FrameworkHeaders::new();
    let val = http::HeaderValue::from_static("1");
    let result = fw.insert(http::header::CONTENT_LENGTH, val);
    assert!(result.is_err(), "transport header should be rejected");
    assert!(fw.is_empty());
}

#[test]
fn framework_headers_rejects_reserved_headers() {
    let mut fw = FrameworkHeaders::new();
    let val = http::HeaderValue::from_static("1");
    let name: http::header::HeaderName = "x-praxis-depth".parse().unwrap();
    let result = fw.insert(name, val);
    assert!(result.is_err(), "reserved header should be rejected");
    assert!(fw.is_empty());
}

#[test]
fn framework_headers_accepts_non_reserved_non_transport() {
    let mut fw = FrameworkHeaders::new();
    let val = http::HeaderValue::from_static("3");
    let name: http::header::HeaderName = "x-request-id".parse().unwrap();
    fw.insert(name, val).unwrap();
    assert!(!fw.is_empty());
    assert_eq!(fw.iter().count(), 1);
}

#[test]
fn framework_headers_set_depth_injects_reserved_header() {
    let mut fw = FrameworkHeaders::new();
    fw.set_depth(2);
    assert_eq!(fw.iter().count(), 1);
    let (name, value) = fw.iter().next().unwrap();
    assert_eq!(name.as_str(), DEPTH_HEADER);
    assert_eq!(value, "2");
}

#[test]
fn framework_headers_set_depth_zero() {
    let mut fw = FrameworkHeaders::new();
    fw.set_depth(0);
    let (_, value) = fw.iter().next().unwrap();
    assert_eq!(value, "0");
}
