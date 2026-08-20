// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http::HeaderMap;

use super::{internals::*, types::*};
use crate::circuit::{CircuitBreakerConfig, CircuitBreakerRegistry, CircuitCheck, PeerKey};

// -- Metrics test utilities -----------------------------------------------

fn install_metrics_recorder() -> &'static metrics_exporter_prometheus::PrometheusHandle {
    use std::sync::OnceLock;
    static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
    HANDLE.get_or_init(|| {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder()
            .expect("failed to install test Prometheus recorder")
    })
}

fn render_metrics() -> String {
    install_metrics_recorder().render()
}

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
    let client = super::client::SubRequestClient::new(connector);
    let debug = format!("{client:?}");
    assert!(
        debug.contains("SubRequestClient"),
        "debug output should contain type name"
    );
}

#[test]
fn client_clone_shares_connector() {
    let connector = SubRequestConnector::new(8, Some(4));
    let a = super::client::SubRequestClient::new(connector);
    let b = a.clone();
    assert!(
        Arc::ptr_eq(&a.connector().inner, &b.connector().inner),
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

#[test]
fn subrequest_error_stream_idle_timeout_display() {
    let err = SubRequestError::StreamIdleTimeout {
        idle_timeout: Duration::from_secs(30),
    };
    let msg = err.to_string();
    assert!(msg.contains("idle timeout"), "should mention idle timeout: {msg}");
    assert!(msg.contains("30s"), "should include duration: {msg}");
}

// -- classify_timeout ---------------------------------------------------

#[test]
fn classify_timeout_deadline_binding_when_no_configured_timeout() {
    let remaining = Duration::from_millis(50);
    let err = classify_timeout(remaining, None, "read");
    assert!(
        matches!(err, SubRequestError::DeadlineExceeded),
        "no configured timeout means deadline is binding: {err}"
    );
}

#[test]
fn classify_timeout_deadline_binding_when_configured_exceeds_budget() {
    let remaining = Duration::from_millis(50);
    let configured = Some(Duration::from_secs(5));
    let err = classify_timeout(remaining, configured, "read");
    assert!(
        matches!(err, SubRequestError::DeadlineExceeded),
        "configured timeout >= remaining means deadline is binding: {err}"
    );
}

#[test]
fn classify_timeout_deadline_binding_when_equal() {
    let remaining = Duration::from_millis(50);
    let configured = Some(Duration::from_millis(50));
    let err = classify_timeout(remaining, configured, "write");
    assert!(
        matches!(err, SubRequestError::DeadlineExceeded),
        "configured timeout == remaining means deadline is binding: {err}"
    );
}

#[test]
fn classify_timeout_io_when_configured_is_stricter() {
    let remaining = Duration::from_millis(500);
    let configured = Some(Duration::from_millis(10));
    let err = classify_timeout(remaining, configured, "read");
    #[expect(clippy::wildcard_enum_match_arm, reason = "test catch-all panic")]
    match err {
        SubRequestError::Io(msg) => {
            assert!(msg.contains("read"), "should include phase: {msg}");
        },
        other => panic!("expected Io, got: {other}"),
    }
}

#[test]
fn classify_timeout_io_includes_phase() {
    let remaining = Duration::from_secs(10);
    let configured = Some(Duration::from_millis(100));
    let err = classify_timeout(remaining, configured, "write");
    #[expect(clippy::wildcard_enum_match_arm, reason = "test catch-all panic")]
    match err {
        SubRequestError::Io(msg) => {
            assert!(msg.contains("write"), "should include write phase: {msg}");
        },
        other => panic!("expected Io, got: {other}"),
    }
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
    use pingora_core::upstreams::peer::HttpPeer;
    let mut peer = HttpPeer::new("127.0.0.1:8080", false, String::new());
    peer.options.connection_timeout = Some(Duration::from_secs(1));
    peer.options.total_connection_timeout = Some(Duration::from_secs(20));

    clamp_peer_timeouts(&mut peer, Duration::from_secs(10));

    assert_eq!(peer.options.connection_timeout, Some(Duration::from_secs(1)));
    assert_eq!(peer.options.total_connection_timeout, Some(Duration::from_secs(10)));
}

#[test]
fn ensure_host_header_uses_peer_address_without_overwriting_explicit_host() {
    use pingora_core::upstreams::peer::HttpPeer;
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
    use pingora_core::upstreams::peer::HttpPeer;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let backend = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
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
    let client = super::client::SubRequestClient::with_max_response_bytes(connector, 4096);
    assert_eq!(client.max_response_bytes, 4096);
}

#[test]
fn client_default_ceiling_is_absolute_max() {
    let connector = SubRequestConnector::new(8, None);
    let client = super::client::SubRequestClient::new(connector);
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

// -- StreamLimits ----------------------------------------------------------

#[test]
fn stream_limits_fields_are_accessible() {
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(30),
        max_stream_duration: Some(Duration::from_secs(300)),
        max_total_bytes: Some(10_485_760), // 10 MiB
    };
    assert_eq!(limits.idle_timeout, Duration::from_secs(30));
    assert_eq!(limits.max_stream_duration, Some(Duration::from_secs(300)));
    assert_eq!(limits.max_total_bytes, Some(10_485_760));
}

#[test]
fn stream_limits_no_optional_bounds() {
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(15),
        max_stream_duration: None,
        max_total_bytes: None,
    };
    assert!(limits.max_stream_duration.is_none());
    assert!(limits.max_total_bytes.is_none());
}

// -- StreamingSubResponse --------------------------------------------------

#[test]
fn streaming_sub_response_exposes_status_and_headers() {
    let body = SubResponseBody::new_done();
    let resp = StreamingSubResponse {
        status: 200,
        headers: {
            let mut h = HeaderMap::new();
            h.insert("content-type", "text/event-stream".parse().unwrap());
            h
        },
        body,
    };
    assert_eq!(resp.status, 200);
    assert_eq!(resp.headers.get("content-type").unwrap(), "text/event-stream");
    drop(resp);
}

// -- SubResponseBody -------------------------------------------------------

#[tokio::test]
async fn sub_response_body_done_returns_none() {
    let mut body = SubResponseBody::new_done();
    assert!(body.is_done());
    let result = body.next_chunk().await;
    drop(body);
    assert!(matches!(result, Ok(None)), "done body should return Ok(None)");
}

// -- Streaming tests -------------------------------------------------------

// Test Utilities

async fn spawn_http_backend(
    body_chunks: Vec<&'static [u8]>,
    chunk_delay: Duration,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::AsyncWriteExt as _;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0_u8; 4096];
        let _bytes_read = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;

        let header = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        socket.write_all(header.as_bytes()).await.unwrap();

        for chunk_data in &body_chunks {
            let chunk = format!("{:x}\r\n", chunk_data.len());
            socket.write_all(chunk.as_bytes()).await.unwrap();
            socket.write_all(chunk_data).await.unwrap();
            socket.write_all(b"\r\n").await.unwrap();
            socket.flush().await.unwrap();
            if !chunk_delay.is_zero() {
                tokio::time::sleep(chunk_delay).await;
            }
        }
        socket.write_all(b"0\r\n\r\n").await.unwrap();
        socket.flush().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    (addr, handle)
}

async fn spawn_stalling_backend() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::AsyncWriteExt as _;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0_u8; 4096];
        drop(tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await);

        let header = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        socket.write_all(header.as_bytes()).await.unwrap();
        socket.write_all(b"5\r\nhello\r\n").await.unwrap();
        socket.flush().await.unwrap();
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    (addr, handle)
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_receives_chunks_incrementally() {
    use pingora_core::upstreams::peer::HttpPeer;
    let chunks: Vec<&[u8]> = vec![b"chunk1", b"chunk2", b"chunk3"];
    let (addr, backend) = spawn_http_backend(chunks.clone(), Duration::ZERO).await;

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/stream".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let StreamingSubResponse { status, mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();

    assert_eq!(status, 200);
    let mut received = Vec::new();
    while let Some(chunk) = body.next_chunk().await.unwrap() {
        received.push(chunk);
    }
    assert!(body.is_done());
    let total: Vec<u8> = received.iter().flat_map(|c| c.iter().copied()).collect();
    assert_eq!(total, b"chunk1chunk2chunk3");
    assert_eq!(body.received_bytes(), 18);
    drop(body);

    backend.abort();
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_records_metrics() {
    use pingora_core::upstreams::peer::HttpPeer;
    install_metrics_recorder();

    let chunks: Vec<&[u8]> = vec![b"hello", b"world"];
    let (addr, backend) = spawn_http_backend(chunks, Duration::ZERO).await;

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/metrics-test".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();

    while body.next_chunk().await.unwrap().is_some() {}

    let rendered = render_metrics();
    assert!(
        rendered.contains("praxis_subrequest_streams_total"),
        "should record streams_total metric:\n{rendered}"
    );
    assert!(
        rendered.contains("praxis_subrequest_stream_duration_seconds"),
        "should record stream_duration metric:\n{rendered}"
    );

    backend.abort();
}

#[tokio::test]
async fn send_streaming_idle_timeout_fires() {
    use pingora_core::upstreams::peer::HttpPeer;
    let (addr, backend) = spawn_stalling_backend().await;

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/stall".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_millis(50),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();

    let first = body.next_chunk().await.unwrap();
    assert!(first.is_some(), "first chunk should arrive");

    let err = body.next_chunk().await.unwrap_err();
    assert!(
        matches!(err, SubRequestError::StreamIdleTimeout { .. }),
        "should get StreamIdleTimeout, got: {err}"
    );
    assert!(body.is_done());
    drop(body);

    backend.abort();
}

#[tokio::test]
async fn send_streaming_read_timeout_fires_as_io_error() {
    use pingora_core::upstreams::peer::HttpPeer;
    let (addr, backend) = spawn_stalling_backend().await;

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let mut peer = HttpPeer::new(addr.to_string(), false, String::new());
    peer.options.read_timeout = Some(Duration::from_millis(30));
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/stall".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();

    let first = body.next_chunk().await.unwrap();
    assert!(first.is_some(), "first chunk should arrive");

    let err = body.next_chunk().await.unwrap_err();
    assert!(
        matches!(&err, SubRequestError::Io(msg) if msg.contains("read timeout")),
        "read_timeout < idle_timeout should produce Io, got: {err}"
    );
    assert!(body.is_done());

    backend.abort();
}

#[tokio::test]
async fn send_streaming_cancel_after_eof_is_noop() {
    use pingora_core::upstreams::peer::HttpPeer;
    let chunks: Vec<&[u8]> = vec![b"one", b"two"];
    let (addr, backend) = spawn_http_backend(chunks, Duration::ZERO).await;

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/eof".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();

    while body.next_chunk().await.unwrap().is_some() {}
    assert!(body.is_done(), "should be done after EOF");

    Box::pin(body.cancel()).await;

    backend.abort();
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_max_stream_duration_fires() {
    use pingora_core::upstreams::peer::HttpPeer;
    let chunks: Vec<&[u8]> = vec![b"a"; 100];
    let (addr, backend) = spawn_http_backend(chunks, Duration::from_millis(10)).await;

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/slow".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: Some(Duration::from_millis(50)),
        max_total_bytes: None,
    };

    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();

    let mut count = 0_u64;
    loop {
        match body.next_chunk().await {
            Ok(Some(_)) => count += 1,
            Ok(None) | Err(SubRequestError::DeadlineExceeded) => break,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    assert!(
        count > 0 && count < 100,
        "should have received some but not all chunks: {count}"
    );
    assert!(body.is_done());
    drop(body);

    backend.abort();
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_max_total_bytes_enforced() {
    use pingora_core::upstreams::peer::HttpPeer;
    let chunks: Vec<&[u8]> = vec![b"12345"; 10];
    let (addr, backend) = spawn_http_backend(chunks, Duration::ZERO).await;

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/limited".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: Some(20),
    };

    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();

    loop {
        match body.next_chunk().await {
            Ok(Some(_chunk)) => {},
            Ok(None) => panic!("should have hit byte limit before EOF"),
            Err(SubRequestError::ResponseTooLarge { actual, limit }) => {
                assert!(actual > 20, "actual should exceed limit: {actual}");
                assert_eq!(limit, 20);
                break;
            },
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    assert!(body.is_done());
    drop(body);

    backend.abort();
}

#[tokio::test]
async fn send_streaming_cancel_shuts_down_session() {
    use pingora_core::upstreams::peer::HttpPeer;
    let (addr, backend) = spawn_stalling_backend().await;

    let connector = SubRequestConnector::new(1, Some(1));
    let client = super::client::SubRequestClient::new(connector.clone());
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/cancel-test".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(30),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();

    drop(body.next_chunk().await.unwrap());

    Box::pin(body.cancel()).await;

    let permit = connector.try_acquire_permit(Duration::from_millis(100)).await;
    assert!(
        matches!(permit, Ok(Some(_))),
        "cancel should release the admission permit: {permit:?}"
    );
    drop(permit);

    backend.abort();
}

#[tokio::test]
async fn send_streaming_drop_before_eof_releases_permit() {
    use pingora_core::upstreams::peer::HttpPeer;
    let (addr, backend) = spawn_stalling_backend().await;

    let connector = SubRequestConnector::new(1, Some(1));
    let client = super::client::SubRequestClient::new(connector.clone());
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/drop-test".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(30),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let StreamingSubResponse { body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();

    drop(body);

    tokio::time::sleep(Duration::from_millis(50)).await;

    let permit = connector.try_acquire_permit(Duration::from_millis(100)).await;
    assert!(
        matches!(permit, Ok(Some(_))),
        "drop should eventually release the admission permit: {permit:?}"
    );
    drop(permit);

    backend.abort();
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_circuit_success_at_headers() {
    use pingora_core::upstreams::peer::HttpPeer;
    let chunks: Vec<&[u8]> = vec![b"data"];
    let (addr, backend) = spawn_http_backend(chunks, Duration::ZERO).await;

    let connector = SubRequestConnector::with_options(SubRequestConnectorOptions {
        keepalive_pool_size: 1,
        max_connections: None,
        circuit_breaker: Some(CircuitBreakerConfig {
            threshold: 1,
            recovery_window: Duration::from_secs(9999),
            half_open_timeout: Duration::from_secs(9999),
        }),
    });
    let client = super::client::SubRequestClient::new(connector.clone());
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/circuit".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();

    let peer_key = PeerKey::new(addr, "");
    assert!(
        connector.circuit_breakers.as_ref().unwrap().precheck(&peer_key),
        "circuit should be healthy after streaming header success"
    );
    while body.next_chunk().await.unwrap().is_some() {}
    drop(body);

    backend.abort();
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_permit_held_until_completion() {
    use pingora_core::upstreams::peer::HttpPeer;
    let chunks: Vec<&[u8]> = vec![b"a", b"b", b"c"];
    let (addr, backend) = spawn_http_backend(chunks, Duration::from_millis(20)).await;

    let connector = SubRequestConnector::new(1, Some(1));
    let client = super::client::SubRequestClient::new(connector.clone());
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/permit-test".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();

    assert_eq!(
        connector.admission.as_ref().unwrap().available_permits(),
        0,
        "permit should be held during streaming"
    );
    while body.next_chunk().await.unwrap().is_some() {}

    assert_eq!(
        connector.admission.as_ref().unwrap().available_permits(),
        1,
        "permit should be released after stream EOF"
    );
    drop(body);

    backend.abort();
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_backpressure_blocks_producer() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use pingora_core::upstreams::peer::HttpPeer;
    use tokio::io::AsyncWriteExt as _;

    // Large chunks to fill TCP send/receive buffers quickly.
    let chunk_count: usize = 500;
    let chunk_size: usize = 65_536; // 64 KiB per chunk
    let chunk_data = vec![b'X'; chunk_size];
    let chunks_sent = Arc::new(AtomicUsize::new(0));
    let chunks_sent_server = Arc::clone(&chunks_sent);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let backend = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0_u8; 4096];
        drop(tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await);

        let header = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        socket.write_all(header.as_bytes()).await.unwrap();

        for _ in 0..chunk_count {
            let hex = format!("{chunk_size:x}\r\n");
            socket.write_all(hex.as_bytes()).await.unwrap();
            socket.write_all(&chunk_data).await.unwrap();
            socket.write_all(b"\r\n").await.unwrap();
            // flush each chunk — write_all blocks when TCP buffers are full.
            socket.flush().await.unwrap();
            chunks_sent_server.fetch_add(1, Ordering::SeqCst);
        }
        socket.write_all(b"0\r\n\r\n").await.unwrap();
        socket.flush().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/backpressure".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(30),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(30), limits, None))
            .await
            .unwrap();

    // Read one chunk then stall — producer should block on TCP backpressure.
    let first = body.next_chunk().await.unwrap().expect("first chunk");
    assert!(!first.is_empty());
    tokio::time::sleep(Duration::from_millis(500)).await;

    let sent_while_stalled = chunks_sent.load(Ordering::SeqCst);
    assert!(
        sent_while_stalled < chunk_count,
        "producer should be blocked by TCP backpressure, but sent {sent_while_stalled}/{chunk_count}"
    );

    // Drain remaining — all data must arrive.
    let mut total_bytes = first.len();
    while let Some(chunk) = body.next_chunk().await.unwrap() {
        total_bytes += chunk.len();
    }
    assert_eq!(
        total_bytes,
        chunk_size * chunk_count,
        "all bytes must arrive despite slow consumer"
    );
    assert!(body.is_done());
    drop(body);

    backend.abort();
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_connection_reused_after_clean_eof() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use pingora_core::upstreams::peer::HttpPeer;
    use tokio::io::AsyncWriteExt as _;

    let connections = Arc::new(AtomicUsize::new(0));
    let connections_backend = Arc::clone(&connections);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        connections_backend.fetch_add(1, Ordering::SeqCst);

        for _ in 0..2 {
            let mut buf = vec![0_u8; 4096];
            drop(tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await);
            let resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                        5\r\nhello\r\n0\r\n\r\n";
            socket.write_all(resp.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/reuse".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let StreamingSubResponse { status, mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits.clone(), None))
            .await
            .unwrap();
    assert_eq!(status, 200);
    while body.next_chunk().await.unwrap().is_some() {}
    drop(body);

    let StreamingSubResponse { status, mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();
    assert_eq!(status, 200);
    while body.next_chunk().await.unwrap().is_some() {}
    drop(body);

    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "second request should reuse the pooled connection"
    );

    handle.abort();
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_circuit_half_open_probe_recovers() {
    use pingora_core::upstreams::peer::HttpPeer;
    use tokio::io::AsyncWriteExt as _;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0_u8; 4096];
        drop(tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await);
        drop(socket);

        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0_u8; 4096];
        drop(tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await);
        let resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n0\r\n\r\n";
        socket.write_all(resp.as_bytes()).await.unwrap();
        socket.flush().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let connector = SubRequestConnector::with_options(SubRequestConnectorOptions {
        keepalive_pool_size: 1,
        max_connections: None,
        circuit_breaker: Some(CircuitBreakerConfig {
            threshold: 1,
            recovery_window: Duration::from_millis(50),
            half_open_timeout: Duration::from_secs(5),
        }),
    });
    let client = super::client::SubRequestClient::new(connector.clone());
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let peer_key = PeerKey::new(addr, "");
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/half-open".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    assert!(
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits.clone(), None))
            .await
            .is_err(),
        "first request should fail (backend closed connection)"
    );

    assert!(
        !connector.circuit_breakers.as_ref().unwrap().precheck(&peer_key),
        "circuit should be open after failure"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;

    let StreamingSubResponse { status, mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .expect("half-open probe should succeed");
    assert_eq!(status, 200);

    assert!(
        connector.circuit_breakers.as_ref().unwrap().precheck(&peer_key),
        "circuit should recover after successful half-open probe"
    );

    while body.next_chunk().await.unwrap().is_some() {}
    drop(body);

    handle.abort();
}

// -- HTTP/2 cleartext (prior-knowledge) helpers ----------------------------

#[expect(clippy::too_many_lines, reason = "H2 server setup")]
async fn spawn_h2_backend(
    body_chunks: Vec<&'static [u8]>,
    chunk_delay: Duration,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let chunks = body_chunks.clone();
            let delay = chunk_delay;
            tokio::spawn(async move {
                let mut connection = h2::server::handshake(socket).await.unwrap();
                while let Some(result) = connection.accept().await {
                    let (_, mut respond) = result.unwrap();
                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let mut send_stream = respond.send_response(response, false).unwrap();
                    for chunk_data in &chunks {
                        send_stream.reserve_capacity(chunk_data.len());
                        send_stream.send_data(Bytes::from_static(chunk_data), false).unwrap();
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                    }
                    send_stream.send_data(Bytes::new(), true).unwrap();
                }
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    (addr, handle)
}

fn h2_peer(addr: std::net::SocketAddr) -> pingora_core::upstreams::peer::HttpPeer {
    let mut peer = pingora_core::upstreams::peer::HttpPeer::new(addr.to_string(), false, String::new());
    peer.options.set_http_version(2, 2);
    peer
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_h2_cleartext_receives_chunks() {
    let chunks: Vec<&[u8]> = vec![b"h2-chunk-1", b"h2-chunk-2", b"h2-chunk-3"];
    let (addr, backend) = spawn_h2_backend(chunks.clone(), Duration::ZERO).await;

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = h2_peer(addr);
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/h2-stream".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let StreamingSubResponse { status, mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();
    assert_eq!(status, 200);

    let mut collected = Vec::new();
    while let Some(chunk) = body.next_chunk().await.unwrap() {
        collected.push(chunk);
    }
    assert!(body.is_done());

    let total_bytes: usize = collected.iter().map(Bytes::len).sum();
    let expected: usize = chunks.iter().map(|c| c.len()).sum();
    assert_eq!(total_bytes, expected, "all H2 bytes must arrive");

    drop(body);
    backend.abort();
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_h2_cleartext_cancel_resets_stream_and_connection_survives() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let connections = Arc::new(AtomicUsize::new(0));
    let connections_backend = Arc::clone(&connections);
    let resets_observed = Arc::new(AtomicUsize::new(0));
    let resets_backend = Arc::clone(&resets_observed);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let backend = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            connections_backend.fetch_add(1, Ordering::SeqCst);
            let resets = Arc::clone(&resets_backend);
            tokio::spawn(async move {
                let mut connection = h2::server::handshake(socket).await.unwrap();
                while let Some(result) = connection.accept().await {
                    let (_, mut respond) = result.unwrap();
                    let resets = Arc::clone(&resets);
                    tokio::spawn(async move {
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        let mut send_stream = respond.send_response(response, false).unwrap();
                        for _ in 0..100 {
                            send_stream.reserve_capacity(11);
                            if send_stream
                                .send_data(Bytes::from_static(b"cancel-data"), false)
                                .is_err()
                            {
                                resets.fetch_add(1, Ordering::SeqCst);
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    });
                }
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let connector = SubRequestConnector::new(4, Some(4));
    let client = super::client::SubRequestClient::new(connector.clone());
    let peer = h2_peer(addr);
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/h2-cancel".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    // First request — cancel mid-stream.
    let StreamingSubResponse { status, body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits.clone(), None))
            .await
            .unwrap();
    assert_eq!(status, 200);
    Box::pin(body.cancel()).await;

    // Allow RST_STREAM to propagate to the server.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let available = connector.admission.as_ref().unwrap().available_permits();
    assert_eq!(available, 4, "permit must be released after H2 cancel");
    assert!(
        resets_observed.load(Ordering::SeqCst) >= 1,
        "server must observe the RST_STREAM from the cancelled stream"
    );

    // Second request on same connection must succeed.
    let StreamingSubResponse { status, mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();
    assert_eq!(status, 200);
    let chunk = body.next_chunk().await.unwrap();
    assert!(chunk.is_some(), "second stream should deliver data");
    Box::pin(body.cancel()).await;

    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "cancelled H2 stream should not destroy the underlying connection"
    );

    backend.abort();
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_h2_cleartext_connection_reused() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let connections = Arc::new(AtomicUsize::new(0));
    let connections_backend = Arc::clone(&connections);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            connections_backend.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut connection = h2::server::handshake(socket).await.unwrap();
                while let Some(result) = connection.accept().await {
                    let (_, mut respond) = result.unwrap();
                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let mut send_stream = respond.send_response(response, false).unwrap();
                    send_stream.send_data(Bytes::from_static(b"reuse"), true).unwrap();
                }
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let connector = SubRequestConnector::new(4, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = h2_peer(addr);
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/h2-reuse".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    for _ in 0..3 {
        let StreamingSubResponse { status, mut body, .. } =
            Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits.clone(), None))
                .await
                .unwrap();
        assert_eq!(status, 200);
        while body.next_chunk().await.unwrap().is_some() {}
        drop(body);
    }

    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "all H2 requests should multiplex on a single connection"
    );

    handle.abort();
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_h1_incomplete_body_not_reused() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use pingora_core::upstreams::peer::HttpPeer;
    use tokio::io::AsyncWriteExt as _;

    let connections = Arc::new(AtomicUsize::new(0));
    let connections_backend = Arc::clone(&connections);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            connections_backend.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0_u8; 4096];
            drop(tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await);
            // Send chunked response then drop mid-body (no terminating 0\r\n\r\n).
            let resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                        5\r\nhello\r\n";
            socket.write_all(resp.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
            drop(socket);
        }
    });

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/incomplete".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    // First request — will get an incomplete body.
    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits.clone(), None))
            .await
            .unwrap();
    let chunk = body.next_chunk().await.unwrap();
    assert!(chunk.is_some(), "should receive partial data");
    let result = body.next_chunk().await;
    assert!(result.is_err(), "incomplete body should produce an error");
    drop(body);

    // Second request must open a new connection.
    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .expect("second request should connect successfully");
    let chunk = body.next_chunk().await.unwrap();
    assert!(chunk.is_some(), "second request should receive data");
    drop(body);

    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "incomplete H1 body must not reuse the connection"
    );

    handle.abort();
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_h1_cancel_does_not_reuse_connection() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use pingora_core::upstreams::peer::HttpPeer;
    use tokio::io::AsyncWriteExt as _;

    let connections = Arc::new(AtomicUsize::new(0));
    let connections_backend = Arc::clone(&connections);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            connections_backend.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                loop {
                    let mut buf = vec![0_u8; 4096];
                    if tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await.unwrap_or(0) == 0 {
                        break;
                    }
                    let resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
                    socket.write_all(resp.as_bytes()).await.unwrap();
                    // Send chunks slowly — caller will cancel mid-stream.
                    for _ in 0..100 {
                        socket.write_all(b"5\r\nhello\r\n").await.unwrap();
                        socket.flush().await.unwrap();
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    socket.write_all(b"0\r\n\r\n").await.unwrap();
                    socket.flush().await.unwrap();
                }
            });
        }
    });

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/h1-cancel".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    // First request — cancel mid-stream.
    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits.clone(), None))
            .await
            .unwrap();
    let chunk = body.next_chunk().await.unwrap();
    assert!(chunk.is_some(), "should receive first chunk");
    Box::pin(body.cancel()).await;

    // Second request — must open a new connection since H1 has
    // unread response bytes on the cancelled connection.
    let StreamingSubResponse { mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();
    let chunk = body.next_chunk().await.unwrap();
    assert!(chunk.is_some(), "second request should receive data");
    Box::pin(body.cancel()).await;

    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "cancelled H1 stream must not reuse the connection"
    );

    handle.abort();
}

// -- Header-time completion (204, incomplete) --------------------------------

async fn spawn_204_backend() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::AsyncWriteExt as _;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0_u8; 4096];
        drop(tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await);

        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
        socket.write_all(response.as_bytes()).await.unwrap();
        socket.flush().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    (addr, handle)
}

#[tokio::test]
async fn send_streaming_204_returns_done_body() {
    use pingora_core::upstreams::peer::HttpPeer;
    let (addr, backend) = spawn_204_backend().await;

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/empty".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let StreamingSubResponse { status, mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None))
            .await
            .unwrap();

    assert_eq!(status, 204);
    assert!(body.is_done(), "204 response body should be pre-done");
    assert!(
        matches!(body.next_chunk().await, Ok(None)),
        "next_chunk on done body should return Ok(None)"
    );

    backend.abort();
}

// -- Framework headers in streaming -----------------------------------------

async fn spawn_echo_headers_backend() -> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
    use tokio::io::AsyncWriteExt as _;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0_u8; 8192];
        let n = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await.unwrap();
        let request_text = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[])).to_string();
        let headers: Vec<String> = request_text
            .lines()
            .filter(|l| l.starts_with("x-praxis-") || l.starts_with("x-custom-"))
            .map(String::from)
            .collect();

        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        socket.write_all(response.as_bytes()).await.unwrap();
        socket.flush().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        headers
    });
    (addr, handle)
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "test setup and validation")]
async fn send_streaming_propagates_framework_headers() {
    use pingora_core::upstreams::peer::HttpPeer;
    let (addr, backend) = spawn_echo_headers_backend().await;

    let connector = SubRequestConnector::new(1, None);
    let client = super::client::SubRequestClient::new(connector);
    let peer = HttpPeer::new(addr.to_string(), false, String::new());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/fw-test".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: None,
    };

    let mut fw = FrameworkHeaders::new();
    fw.set_depth(3);

    let StreamingSubResponse { status, mut body, .. } =
        Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, Some(&fw)))
            .await
            .unwrap();

    assert_eq!(status, 200);
    while body.next_chunk().await.unwrap().is_some() {}

    let captured_headers = backend.await.unwrap();
    assert!(
        captured_headers
            .iter()
            .any(|h| h.contains("x-praxis-iterative-depth") && h.contains('3')),
        "upstream should receive depth header, got: {captured_headers:?}"
    );
}
