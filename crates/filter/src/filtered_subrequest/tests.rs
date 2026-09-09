// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the reusable filtered sub-request executor helpers.
//!
//! These exercise the transport, sanitization, header-mutation, and
//! nested-context helpers the executor owns, independent of any particular
//! caller (the iterative request router is the only caller today).

use http::HeaderMap;

// ---------------------------------------------------------------------------
// Rejection Conversion
// ---------------------------------------------------------------------------

#[test]
fn local_rejection_becomes_transition_response() {
    let mut rejection = crate::Rejection::status(503)
        .with_header("Retry-After", "1")
        .with_header("Connection", "x-private")
        .with_header("x-private", "secret")
        .with_header("x-praxis-private", "secret")
        .with_body(bytes::Bytes::from_static(b"unavailable"));
    rejection
        .header_map
        .get_or_insert_with(Default::default)
        .append("x-opaque", http::HeaderValue::from_bytes(&[0x80]).unwrap());
    let response = super::sanitize::subresponse_from_rejection(rejection);
    assert_eq!(response.status, 503);
    assert_eq!(response.headers.get("retry-after").unwrap(), "1");
    assert!(!response.headers.contains_key("connection"));
    assert!(!response.headers.contains_key("x-private"));
    assert!(!response.headers.contains_key("x-praxis-private"));
    assert_eq!(response.headers.get("x-opaque").unwrap().as_bytes(), &[0x80]);
    assert_eq!(response.body, bytes::Bytes::from_static(b"unavailable"));
}

// ---------------------------------------------------------------------------
// classify_transport_failure
// ---------------------------------------------------------------------------

#[test]
fn classify_admission_timeout_returns_503() {
    let error = praxis_core::subrequest::SubRequestError::AdmissionTimeout { max_connections: 64 };
    let (status, kind) = super::transport::classify_transport_failure(&error);
    assert_eq!(status, 503, "AdmissionTimeout should return 503");
    assert_eq!(kind, super::TransportFailure::AdmissionTimeout);
}

#[test]
fn classify_connect_returns_502() {
    let error = praxis_core::subrequest::SubRequestError::Connect("refused".to_owned());
    let (status, kind) = super::transport::classify_transport_failure(&error);
    assert_eq!(status, 502, "Connect should return 502");
    assert_eq!(kind, super::TransportFailure::Connect);
}

#[test]
fn classify_deadline_exceeded_returns_504() {
    let error = praxis_core::subrequest::SubRequestError::DeadlineExceeded;
    let (status, kind) = super::transport::classify_transport_failure(&error);
    assert_eq!(status, 504, "DeadlineExceeded should return 504");
    assert_eq!(kind, super::TransportFailure::DeadlineExceeded);
}

#[test]
fn classify_response_too_large_returns_502() {
    let error = praxis_core::subrequest::SubRequestError::ResponseTooLarge {
        actual: 200,
        limit: 100,
    };
    let (status, kind) = super::transport::classify_transport_failure(&error);
    assert_eq!(status, 502, "ResponseTooLarge should return 502");
    assert_eq!(kind, super::TransportFailure::ResponseTooLarge);
}

#[test]
fn classify_io_returns_502() {
    let error = praxis_core::subrequest::SubRequestError::Io("broken pipe".to_owned());
    let (status, kind) = super::transport::classify_transport_failure(&error);
    assert_eq!(status, 502, "Io should return 502");
    assert_eq!(kind, super::TransportFailure::Io);
}

#[test]
fn classify_invalid_request_falls_through_to_io() {
    let error = praxis_core::subrequest::SubRequestError::InvalidRequest("bad uri".to_owned());
    let (status, kind) = super::transport::classify_transport_failure(&error);
    assert_eq!(status, 502, "InvalidRequest wildcard should return 502");
    assert_eq!(kind, super::TransportFailure::Io);
}

#[test]
fn classify_circuit_open_returns_503() {
    let error = praxis_core::subrequest::SubRequestError::CircuitOpen {
        peer: "backend".to_owned(),
    };
    let (status, kind) = super::transport::classify_transport_failure(&error);
    assert_eq!(status, 503, "CircuitOpen should return 503");
    assert_eq!(kind, super::TransportFailure::CircuitOpen);
}

// ---------------------------------------------------------------------------
// strip_reserved_headers
// ---------------------------------------------------------------------------

#[test]
fn strip_reserved_empty_map() {
    let mut headers = HeaderMap::new();
    super::sanitize::strip_reserved_headers(&mut headers);
    assert!(headers.is_empty(), "empty map should stay empty");
}

#[test]
fn strip_reserved_praxis_prefix() {
    let mut headers = HeaderMap::new();
    headers.insert("x-praxis-foo", "bar".parse().unwrap());
    super::sanitize::strip_reserved_headers(&mut headers);
    assert!(headers.is_empty(), "x-praxis-* should be removed");
}

#[test]
fn strip_reserved_ext_protocol_prefix() {
    let mut headers = HeaderMap::new();
    headers.insert("x-ext-protocol-route", "value".parse().unwrap());
    super::sanitize::strip_reserved_headers(&mut headers);
    assert!(headers.is_empty(), "x-ext-protocol-* should be removed");
}

#[test]
fn strip_reserved_ext_agent_prefix() {
    let mut headers = HeaderMap::new();
    headers.insert("x-ext-agent-task", "value".parse().unwrap());
    super::sanitize::strip_reserved_headers(&mut headers);
    assert!(headers.is_empty(), "x-ext-agent-* should be removed");
}

#[test]
fn strip_reserved_preserves_non_reserved() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer token".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());
    super::sanitize::strip_reserved_headers(&mut headers);
    assert_eq!(headers.len(), 2, "non-reserved headers should be preserved");
}

#[test]
fn strip_reserved_mixed() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer token".parse().unwrap());
    headers.insert("x-praxis-internal", "secret".parse().unwrap());
    headers.insert("x-ext-agent-id", "agent1".parse().unwrap());
    headers.insert("x-custom", "value".parse().unwrap());
    super::sanitize::strip_reserved_headers(&mut headers);
    assert_eq!(headers.len(), 2, "only reserved should be removed");
    assert!(headers.contains_key("authorization"));
    assert!(headers.contains_key("x-custom"));
}

#[test]
fn strip_reserved_no_dash_not_removed() {
    let mut headers = HeaderMap::new();
    headers.insert("x-praxisfoo", "value".parse().unwrap());
    super::sanitize::strip_reserved_headers(&mut headers);
    assert_eq!(
        headers.len(),
        1,
        "x-praxisfoo (no dash after prefix) should NOT be removed"
    );
}

// ---------------------------------------------------------------------------
// Body Limits
// ---------------------------------------------------------------------------

#[test]
fn nested_body_limit_detects_oversized_buffer() {
    assert!(super::sanitize::body_exceeds_limit(
        crate::BodyMode::StreamBuffer { max_bytes: Some(4) },
        5
    ));
    assert!(!super::sanitize::body_exceeds_limit(
        crate::BodyMode::SizeLimit { max_bytes: 5 },
        5
    ));
    assert!(!super::sanitize::body_exceeds_limit(
        crate::BodyMode::Stream,
        usize::MAX
    ));
}

#[test]
fn transformed_response_must_remain_within_all_limits() {
    assert!(super::sanitize::response_body_exceeds_limits(
        crate::BodyMode::Stream,
        4,
        5
    ));
    assert!(super::sanitize::response_body_exceeds_limits(
        crate::BodyMode::StreamBuffer { max_bytes: Some(3) },
        4,
        4,
    ));
    assert!(!super::sanitize::response_body_exceeds_limits(
        crate::BodyMode::StreamBuffer { max_bytes: Some(4) },
        4,
        4,
    ));
}

#[test]
fn streaming_transport_uses_only_listener_limit() {
    assert_eq!(
        super::sanitize::streaming_transport_limit(crate::BodyMode::SizeLimit { max_bytes: 4 }),
        Some(4)
    );
    assert_eq!(
        super::sanitize::streaming_transport_limit(crate::BodyMode::Stream),
        None
    );
}

// ---------------------------------------------------------------------------
// Header Sanitization
// ---------------------------------------------------------------------------

#[test]
fn strip_request_framing_headers_removes_stale_lengths() {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, "100".parse().unwrap());
    headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
    headers.insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());

    super::sanitize::strip_request_framing_headers(&mut headers);

    assert!(!headers.contains_key(http::header::CONTENT_LENGTH));
    assert!(!headers.contains_key(http::header::TRANSFER_ENCODING));
    assert!(headers.contains_key(http::header::CONTENT_TYPE));
}

#[test]
fn request_sanitization_strips_all_reserved_headers_including_depth() {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONNECTION, "x-remove, keep-alive".parse().unwrap());
    headers.insert("x-remove", "secret".parse().unwrap());
    headers.insert("keep-alive", "timeout=5".parse().unwrap());
    headers.insert("x-praxis-route", "internal".parse().unwrap());
    headers.insert(praxis_core::subrequest::DEPTH_HEADER, "1".parse().unwrap());
    headers.insert(http::header::AUTHORIZATION, "Bearer step-token".parse().unwrap());
    headers.insert(http::header::CONTENT_LENGTH, "99".parse().unwrap());

    super::sanitize::sanitize_subrequest_headers(&mut headers);

    assert!(!headers.contains_key(http::header::CONNECTION));
    assert!(!headers.contains_key("x-remove"));
    assert!(!headers.contains_key("keep-alive"));
    assert!(!headers.contains_key("x-praxis-route"));
    assert!(!headers.contains_key(http::header::CONTENT_LENGTH));
    assert!(
        !headers.contains_key(praxis_core::subrequest::DEPTH_HEADER),
        "sanitize must strip depth; core executor re-injects via framework_headers"
    );
    assert_eq!(headers.get(http::header::AUTHORIZATION).unwrap(), "Bearer step-token");
}

#[test]
fn sanitize_strips_depth_header_for_framework_reinsertion() {
    let mut headers = HeaderMap::new();
    headers.insert(praxis_core::subrequest::DEPTH_HEADER, "spoofed".parse().unwrap());
    headers.insert("x-praxis-route", "internal".parse().unwrap());
    headers.insert(http::header::AUTHORIZATION, "Bearer token".parse().unwrap());

    super::sanitize::sanitize_subrequest_headers(&mut headers);

    assert!(
        !headers.contains_key(praxis_core::subrequest::DEPTH_HEADER),
        "sanitize must strip depth so core executor can re-inject via framework_headers"
    );
    assert!(!headers.contains_key("x-praxis-route"));
    assert_eq!(headers.get(http::header::AUTHORIZATION).unwrap(), "Bearer token");
}

#[test]
fn response_sanitization_strips_hop_by_hop_and_internal_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONNECTION, "x-remove".parse().unwrap());
    headers.insert("x-remove", "secret".parse().unwrap());
    headers.insert("upgrade", "h2c".parse().unwrap());
    headers.insert("x-ext-agent-task", "internal".parse().unwrap());
    headers.append(http::header::SET_COOKIE, "first=1".parse().unwrap());
    headers.append(http::header::SET_COOKIE, "second=2".parse().unwrap());

    super::sanitize::sanitize_subresponse_headers(&mut headers);

    assert!(!headers.contains_key(http::header::CONNECTION));
    assert!(!headers.contains_key("x-remove"));
    assert!(!headers.contains_key("upgrade"));
    assert!(!headers.contains_key("x-ext-agent-task"));
    assert_eq!(headers.get_all(http::header::SET_COOKIE).iter().count(), 2);
}

#[test]
fn destination_host_is_synthesized_without_overwriting_step_override() {
    let mut generated = HeaderMap::new();
    super::sanitize::ensure_destination_host(&mut generated, "model.example:443").unwrap();
    assert_eq!(generated.get(http::header::HOST).unwrap(), "model.example:443");

    let mut explicit = HeaderMap::new();
    explicit.insert(http::header::HOST, "override.example".parse().unwrap());
    super::sanitize::ensure_destination_host(&mut explicit, "model.example:443").unwrap();
    assert_eq!(explicit.get(http::header::HOST).unwrap(), "override.example");
}

#[test]
fn destination_host_rejects_unencodable_address() {
    let mut headers = HeaderMap::new();
    let result = super::sanitize::ensure_destination_host(&mut headers, "bad\nhost:80");
    assert!(result.is_err(), "control characters in the Host value must error");
}

// ---------------------------------------------------------------------------
// Header Mutation Helpers
// ---------------------------------------------------------------------------

#[test]
fn request_header_mutations_remove_set_and_add() {
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.request_headers_to_remove.push("x-old".parse().unwrap());
    ctx.request_headers_to_set
        .push(("x-set".parse().unwrap(), http::HeaderValue::from_static("set")));
    ctx.extra_request_headers
        .push((std::borrow::Cow::Borrowed("x-extra"), "extra".to_owned()));
    ctx.extra_request_headers
        .push((std::borrow::Cow::Borrowed("bad name"), "dropped".to_owned()));

    let mut headers = HeaderMap::new();
    headers.insert("x-old", http::HeaderValue::from_static("stale"));
    super::sanitize::apply_request_header_mutations(&mut headers, &ctx);

    assert!(headers.get("x-old").is_none(), "removed headers must be gone");
    assert_eq!(
        headers.get("x-set").map(http::HeaderValue::as_bytes),
        Some(b"set".as_slice()),
        "set headers must be applied"
    );
    assert_eq!(
        headers.get("x-extra").map(http::HeaderValue::as_bytes),
        Some(b"extra".as_slice()),
        "extra headers must be applied"
    );
    assert!(
        headers.get("bad name").is_none(),
        "invalid extra header names must be dropped"
    );
}

#[test]
fn pre_read_mutations_apply_remove_set_and_add() {
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.pre_read_mutations = vec![
        crate::TrustedHeaderMutation::Remove("x-gone".parse().unwrap()),
        crate::TrustedHeaderMutation::Set("x-set".parse().unwrap(), http::HeaderValue::from_static("set")),
        crate::TrustedHeaderMutation::Add("x-add".parse().unwrap(), "added".to_owned()),
        crate::TrustedHeaderMutation::Add("x-bad".parse().unwrap(), "bad\nvalue".to_owned()),
    ];

    let mut headers = HeaderMap::new();
    headers.insert("x-gone", http::HeaderValue::from_static("stale"));
    super::sanitize::apply_pre_read_header_mutations(&mut headers, &ctx);

    assert!(headers.get("x-gone").is_none(), "Remove mutations must apply");
    assert_eq!(
        headers.get("x-set").map(http::HeaderValue::as_bytes),
        Some(b"set".as_slice()),
        "Set mutations must apply"
    );
    assert_eq!(
        headers.get("x-add").map(http::HeaderValue::as_bytes),
        Some(b"added".as_slice()),
        "Add mutations must apply"
    );
    assert!(
        headers.get("x-bad").is_none(),
        "Add mutations with invalid values must be dropped"
    );
}

// ---------------------------------------------------------------------------
// Sub-Filter Context
// ---------------------------------------------------------------------------

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "resource identity assertions are intentionally explicit"
)]
fn sub_filter_context_inherits_parent_runtime_resources() {
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use praxis_core::{
        health::HealthRegistry,
        id::IdGenerator,
        kv::KvStoreRegistry,
        subrequest::{SubRequestClient, SubRequestConnector},
        time::FixedTimeSource,
    };

    let registry = crate::FilterRegistry::with_builtins();
    let pipeline = crate::FilterPipeline::build(&mut [], &registry).unwrap();
    let request = crate::Request {
        headers: HeaderMap::new(),
        method: http::Method::POST,
        uri: http::Uri::from_static("/v1/responses"),
    };
    let health_registry: HealthRegistry = Arc::new(HashMap::new());
    let id_generator = IdGenerator::with_seed(42);
    let kv_stores = KvStoreRegistry::new();
    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
    let time_source = FixedTimeSource::new(Duration::from_secs(123));

    let ctx = super::context::build_sub_filter_context(
        &pipeline,
        &request,
        super::context::SubrequestRuntimeResources {
            client_addr: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            downstream_tls: true,
            health_registry: Some(&health_registry),
            id_generator: &id_generator,
            kv_stores: Some(&kv_stores),
            peer_identity: None,
            request_start: std::time::Instant::now(),
            subrequest_client: Some(&client),
            time_source: &time_source,
        },
    );

    assert!(std::ptr::eq(ctx.health_registry.unwrap(), &health_registry));
    assert!(std::ptr::eq(ctx.id_generator, &id_generator));
    assert!(std::ptr::eq(ctx.kv_stores.unwrap(), &kv_stores));
    assert!(std::ptr::eq(ctx.subrequest_client.unwrap(), &client));
    assert_eq!(
        ctx.client_addr,
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    );
    assert!(ctx.downstream_tls);
    assert_eq!(ctx.time_source.now(), Duration::from_secs(123));
}

// ---------------------------------------------------------------------------
// Peer Construction
// ---------------------------------------------------------------------------

#[tokio::test]
async fn build_peer_applies_tls_with_explicit_sni() {
    let tls: praxis_tls::ClusterTls = serde_yaml::from_str("sni: backend.example\nverify: true").unwrap();
    let cached = praxis_tls::CachedClusterTls::try_from_config(&tls).unwrap();
    let upstream = praxis_core::connectivity::Upstream {
        address: std::sync::Arc::from("127.0.0.1:9443"),
        connection: std::sync::Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        tls: Some(cached),
        authority: None,
    };

    let peer = super::transport::build_peer(&upstream, false).await.unwrap();
    assert_eq!(peer.sni, "backend.example", "the configured SNI must be applied");
}

#[tokio::test]
async fn build_peer_derives_sni_from_hostname_address() {
    let tls: praxis_tls::ClusterTls = serde_yaml::from_str("verify: false").unwrap();
    let cached = praxis_tls::CachedClusterTls::try_from_config(&tls).unwrap();
    let upstream = praxis_core::connectivity::Upstream {
        address: std::sync::Arc::from("localhost:9443"),
        connection: std::sync::Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        tls: Some(cached),
        authority: None,
    };

    let peer = super::transport::build_peer(&upstream, true).await.unwrap();
    assert_eq!(peer.sni, "localhost", "the SNI must derive from the address hostname");
}

#[tokio::test]
async fn build_peer_rejects_hostname_resolving_to_private_address() {
    // A sub-request upstream is as exposed to DNS rebinding as the main
    // upstream path: the resolved address must be checked, not trusted.
    let upstream = praxis_core::connectivity::Upstream {
        address: std::sync::Arc::from("localhost:9444"),
        connection: std::sync::Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        tls: None,
        authority: None,
    };

    let err = super::transport::build_peer(&upstream, false)
        .await
        .expect_err("a hostname resolving to loopback must be refused by default");
    assert!(
        matches!(
            err,
            praxis_core::connectivity::peer::AddressResolutionError::PrivateAddress { .. }
        ),
        "expected PrivateAddress, got: {err}"
    );

    super::transport::build_peer(&upstream, true)
        .await
        .expect("allow_private_upstreams must permit the same upstream");
}
