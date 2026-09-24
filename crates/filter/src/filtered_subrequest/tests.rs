// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the reusable filtered sub-request executor utilities.
//!
//! These exercise the transport, sanitization, header-mutation, and
//! nested-context utilities the executor owns, independent of any particular
//! caller (the iterative request router is the only caller today).

use http::HeaderMap;

// -----------------------------------------------------------------------------
// Rejection Conversion
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// classify_transport_failure
// -----------------------------------------------------------------------------

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
    assert_eq!(
        kind,
        super::TransportFailure::ResponseTooLarge {
            actual: 200,
            limit: 100,
        },
        "the typed overflow detail must be carried onto the transport classification"
    );
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

// -----------------------------------------------------------------------------
// sanitize_subrequest_headers
// -----------------------------------------------------------------------------

#[test]
fn connection_token_survives_obs_text_sibling() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONNECTION,
        http::HeaderValue::from_bytes(b"x-custom, \xff").unwrap(),
    );
    headers.insert("x-custom", "value".parse().unwrap());
    super::sanitize::sanitize_subrequest_headers(&mut headers);
    assert!(
        !headers.contains_key("x-custom"),
        "a non-UTF-8 sibling token must not keep a nominated header"
    );
}

// -----------------------------------------------------------------------------
// strip_reserved_headers
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Body Limits
// -----------------------------------------------------------------------------

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
    assert_eq!(
        super::sanitize::response_body_overflow_limit(crate::BodyMode::Stream, 4, 5),
        Some(4),
        "a body over the global ceiling reports the global ceiling as the tripped limit"
    );
    assert_eq!(
        super::sanitize::response_body_overflow_limit(crate::BodyMode::StreamBuffer { max_bytes: Some(3) }, 4, 4),
        Some(3),
        "the smaller nested ceiling must be the reported limit"
    );
    assert_eq!(
        super::sanitize::response_body_overflow_limit(crate::BodyMode::StreamBuffer { max_bytes: Some(4) }, 4, 4),
        None,
        "a body within every limit must not overflow"
    );
    assert_eq!(
        super::sanitize::response_body_overflow_limit(crate::BodyMode::SizeLimit { max_bytes: 3 }, 4, 4),
        Some(3),
        "a SizeLimit tighter than the global ceiling must be the reported limit"
    );
    assert_eq!(
        super::sanitize::response_body_overflow_limit(crate::BodyMode::StreamBuffer { max_bytes: None }, 4, 5),
        Some(4),
        "StreamBuffer with no mode limit falls back to the global ceiling"
    );
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

// -----------------------------------------------------------------------------
// Header Sanitization
// -----------------------------------------------------------------------------

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
fn sanitize_keeps_essential_and_proxy_owned_headers_named_in_connection() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONNECTION,
        "x-app-state, host, x-forwarded-for, forwarded".parse().unwrap(),
    );
    headers.insert("x-app-state", "drop-me".parse().unwrap());
    headers.insert(http::header::HOST, "backend.internal".parse().unwrap());
    headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
    headers.insert("forwarded", "for=203.0.113.9".parse().unwrap());

    super::sanitize::sanitize_subrequest_headers(&mut headers);

    assert!(
        !headers.contains_key("x-app-state"),
        "a custom connection-scoped header is stripped"
    );
    assert_eq!(
        headers.get(http::header::HOST).unwrap(),
        "backend.internal",
        "Host must survive a Connection: host token"
    );
    assert_eq!(
        headers.get("x-forwarded-for").unwrap(),
        "203.0.113.9",
        "X-Forwarded-For must survive a Connection token"
    );
    assert_eq!(
        headers.get("forwarded").unwrap(),
        "for=203.0.113.9",
        "Forwarded must survive a Connection token"
    );
    assert!(
        !headers.contains_key(http::header::CONNECTION),
        "Connection itself is hop-by-hop and removed"
    );
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

// -----------------------------------------------------------------------------
// Header Mutation Utilities
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Sub-Filter Context
// -----------------------------------------------------------------------------

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "resource identity assertions are intentionally explicit"
)]
fn sub_filter_context_inherits_parent_runtime_resources() {
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use praxis_core::{
        health::HealthRegistry, id::IdGenerator, kv::KvStoreRegistry, subrequest::SubRequestClient,
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
    let client = SubRequestClient::new(crate::test_support::connector(1, None));
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
            session_stores: None,
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

// -----------------------------------------------------------------------------
// Peer Construction
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Public callout entry point (run)
// -----------------------------------------------------------------------------

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_returns_buffered_for_locally_produced_response() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::SubRequestClient;

    let registry = crate::FilterRegistry::with_builtins();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(
        "
- filter: static_response
  status: 200
  body: hello from outbound
",
    )
    .unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let client = SubRequestClient::new(crate::test_support::connector(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let response = match executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("run should return the locally-produced response")
    {
        crate::CalloutResponse::Buffered(response) => response,
        crate::CalloutResponse::Streaming { .. } => {
            panic!("a locally-produced static response must be buffered, not streaming")
        },
    };

    assert_eq!(
        response.status, 200,
        "the outbound chain's static status must be returned"
    );
    assert_eq!(
        response.body,
        bytes::Bytes::from_static(b"hello from outbound"),
        "the outbound chain's static body must be returned buffered"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_falls_back_to_next_staged_address_on_connection_refusal() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::SubRequestClient;

    let (_reserved, dead) = crate::test_support::refusing_addr();
    let (live_addr, backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;

    let registry = crate::FilterRegistry::with_builtins();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str("[]").unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let client = SubRequestClient::new(crate::test_support::connector(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    let staged = super::StagedUpstream(praxis_core::connectivity::Upstream {
        address: Arc::from(dead.to_string().as_str()),
        authority: None,
        connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        tls: None,
    });
    let fallback = super::StagedUpstreamFallback(vec![dead, live_addr]);
    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(staged);
    extensions.insert(fallback);

    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let response = match executor
        .run(&pipeline, &request, extensions, deadline)
        .await
        .expect("run should fall back to the live address and return its response")
    {
        crate::CalloutResponse::Buffered(response) => response,
        crate::CalloutResponse::Streaming { .. } => {
            panic!("a buffered outbound chain must not produce a streaming response")
        },
    };
    backend.abort();

    assert_eq!(
        response.status, 200,
        "a connection refusal on the pinned primary must fall back to the next \
         validated address, whose live backend returns 200"
    );
    assert_eq!(
        response.body,
        bytes::Bytes::from_static(b"ok"),
        "the response must come from the live fallback backend"
    );
}

// -----------------------------------------------------------------------------
// StagedUpstream / StagedUpstreamFallback::from_prepared_target
// -----------------------------------------------------------------------------
//
// IP-literal URLs skip DNS, so these constructor tests are hermetic. The
// zero-address error branch in `StagedUpstream::from_prepared_target` (mod.rs)
// is deliberately not exercised: it is unreachable through the public API. The
// only public constructor of `PreparedTarget` is `prepare_url_target`, which
// returns `Err(UrlTargetError::Resolve(Empty))` before building the target when
// resolution yields no addresses, and `PreparedTarget::new` is `pub(crate)`.
// The branch is retained as defense in depth; reaching it would require adding
// test-only public surface to `praxis-core`.

#[tokio::test]
async fn staged_upstream_from_prepared_target_non_tls_has_no_tls() {
    use std::time::{Duration, Instant};

    let target = praxis_core::connectivity::prepare_url_target(
        "http://127.0.0.1:9/health",
        Instant::now() + Duration::from_secs(5),
        |_addrs| Ok(()),
    )
    .await
    .expect("preparing an IP-literal http URL must succeed");

    let staged = super::StagedUpstream::from_prepared_target(&target)
        .expect("a target with a resolved address must build a staged upstream");

    assert_eq!(
        &*staged.0.address, "127.0.0.1:9",
        "the transport address must pin to the target's first resolved address"
    );
    assert_eq!(
        staged.0.authority.as_ref().expect("Host authority must be set"),
        "127.0.0.1:9",
        "the Host authority must be the URL authority"
    );
    assert!(
        staged.0.tls.is_none(),
        "a plain-http target must derive no TLS material"
    );
}

#[tokio::test]
async fn staged_upstream_from_prepared_target_tls_derives_sni() {
    use std::time::{Duration, Instant};

    let target = praxis_core::connectivity::prepare_url_target(
        "https://127.0.0.1:8443/v1/messages",
        Instant::now() + Duration::from_secs(5),
        |_addrs| Ok(()),
    )
    .await
    .expect("preparing an IP-literal https URL must succeed");

    let staged =
        super::StagedUpstream::from_prepared_target(&target).expect("a TLS target must build a staged upstream");

    assert_eq!(&*staged.0.address, "127.0.0.1:8443");
    let tls = staged
        .0
        .tls
        .as_ref()
        .expect("an https target must derive cached TLS material");
    assert_eq!(tls.sni(), Some("127.0.0.1"), "the derived SNI must be the URL host");
}

#[tokio::test]
async fn staged_upstream_fallback_from_prepared_target_captures_addresses() {
    use std::time::{Duration, Instant};

    let target = praxis_core::connectivity::prepare_url_target(
        "http://127.0.0.1:9/health",
        Instant::now() + Duration::from_secs(5),
        |_addrs| Ok(()),
    )
    .await
    .expect("preparing an IP-literal http URL must succeed");

    let fallback = super::StagedUpstreamFallback::from_prepared_target(&target);

    assert_eq!(
        fallback.addresses(),
        target.addresses(),
        "the fallback set must capture the target's resolved addresses in order"
    );
    assert_eq!(
        fallback.addresses(),
        &["127.0.0.1:9".parse::<std::net::SocketAddr>().unwrap()],
        "an IP-literal target must resolve to exactly its literal address"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities: upstream re-pin regression harness
// -----------------------------------------------------------------------------

// A malicious outbound-chain filter that rewrites `ctx.upstream` during the
// request phase to redirect the callout at a different authority — the exact
// credential-exfiltration move the executor's post-request re-pin defeats.
struct UpstreamHijackFilter {
    redirect_to: std::net::SocketAddr,
}

#[async_trait::async_trait]
impl crate::HttpFilter for UpstreamHijackFilter {
    fn name(&self) -> &'static str {
        "test_upstream_hijack"
    }

    async fn on_request(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        ctx.upstream = Some(praxis_core::connectivity::Upstream {
            address: std::sync::Arc::from(self.redirect_to.to_string().as_str()),
            authority: None,
            connection: std::sync::Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });
        Ok(crate::FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Test Utilities: selected-upstream request-body participants
// -----------------------------------------------------------------------------

// Selects a fixed upstream in `on_request` (so the selected-upstream phase runs
// without a load balancer) and rejects during the phase, letting a test assert a
// rejection short-circuits before any dial.
struct SelectedUpstreamRejectFilter {
    upstream_addr: std::net::SocketAddr,
}

#[async_trait::async_trait]
impl crate::HttpFilter for SelectedUpstreamRejectFilter {
    fn name(&self) -> &'static str {
        "test_selected_upstream_reject"
    }

    async fn on_request(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        ctx.upstream = Some(praxis_core::connectivity::Upstream {
            address: std::sync::Arc::from(self.upstream_addr.to_string().as_str()),
            authority: None,
            connection: std::sync::Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });
        Ok(crate::FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> crate::BodyMode {
        crate::BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<bytes::Bytes>,
    ) -> Result<crate::SelectedUpstreamBodyOutcome, crate::FilterError> {
        Ok(crate::SelectedUpstreamBodyOutcome::Reject(crate::Rejection::status(
            403,
        )))
    }
}

// Selects a fixed upstream in `on_request` and grows the body beyond the
// declared StreamBuffer limit during the phase, letting a test assert a 413.
struct SelectedUpstreamExpandFilter {
    upstream_addr: std::net::SocketAddr,
    output: &'static [u8],
}

#[async_trait::async_trait]
impl crate::HttpFilter for SelectedUpstreamExpandFilter {
    fn name(&self) -> &'static str {
        "test_selected_upstream_expand"
    }

    async fn on_request(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        ctx.upstream = Some(praxis_core::connectivity::Upstream {
            address: std::sync::Arc::from(self.upstream_addr.to_string().as_str()),
            authority: None,
            connection: std::sync::Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });
        Ok(crate::FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> crate::BodyMode {
        crate::BodyMode::StreamBuffer { max_bytes: Some(64) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<bytes::Bytes>,
    ) -> Result<crate::SelectedUpstreamBodyOutcome, crate::FilterError> {
        *body = Some(bytes::Bytes::from_static(self.output));
        Ok(crate::SelectedUpstreamBodyOutcome::Continue)
    }
}

// Selects a fixed upstream in `on_request` (no load balancer) and records the
// selected-application provider observed during the selected-upstream phase, so
// a test can assert metadata isolation from the reader's point of view.
struct SelectedProviderRecorderFilter {
    upstream_addr: std::net::SocketAddr,
    #[expect(
        clippy::option_option,
        reason = "three observation states: phase not run / run without provider / run with provider"
    )]
    seen: std::sync::Arc<std::sync::Mutex<Option<Option<String>>>>,
    // When set, published as this step's provider during `on_request`, exercising
    // the staged-upstream clear (a value published for a discarded selection).
    publish: Option<&'static str>,
}

#[async_trait::async_trait]
impl crate::HttpFilter for SelectedProviderRecorderFilter {
    fn name(&self) -> &'static str {
        "test_selected_provider_recorder"
    }

    async fn on_request(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        ctx.upstream = Some(praxis_core::connectivity::Upstream {
            address: std::sync::Arc::from(self.upstream_addr.to_string().as_str()),
            authority: None,
            connection: std::sync::Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });
        if let Some(provider) = self.publish {
            ctx.publish_selected_application(None, Some(std::sync::Arc::from(provider)));
        }
        Ok(crate::FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> crate::BodyMode {
        crate::BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<bytes::Bytes>,
    ) -> Result<crate::SelectedUpstreamBodyOutcome, crate::FilterError> {
        *self.seen.lock().unwrap() = Some(ctx.selected_application_provider().map(str::to_owned));
        Ok(crate::SelectedUpstreamBodyOutcome::Continue)
    }
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn selected_upstream_phase_does_not_inherit_parent_provider() {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};

    let (addr, backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
    let seen: Arc<Mutex<Option<Option<String>>>> = Arc::new(Mutex::new(None));

    let seen_factory = Arc::clone(&seen);
    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "test_selected_provider_recorder",
            crate::FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(SelectedProviderRecorderFilter {
                    upstream_addr: addr,
                    seen: Arc::clone(&seen_factory),
                    publish: None,
                }))
            })),
        )
        .unwrap();
    let mut entries: Vec<crate::FilterEntry> =
        serde_yaml::from_str("- filter: test_selected_provider_recorder").unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    let mut extensions = crate::RequestExtensions::default();
    extensions
        .insert(crate::extensions::SelectedClusterApplication::new(None, Some(Arc::from("parent-provider"))).unwrap());

    let request = crate::SubRequest {
        method: http::Method::POST,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::from_static(b"body"),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    drop(executor.run(&pipeline, &request, extensions, deadline).await);
    backend.abort();

    assert_eq!(
        *seen.lock().unwrap(),
        Some(None),
        "the child must not inherit the parent's selected-application provider"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn staged_upstream_clears_discarded_selection_metadata() {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};

    let (addr, backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
    let seen: Arc<Mutex<Option<Option<String>>>> = Arc::new(Mutex::new(None));

    let seen_factory = Arc::clone(&seen);
    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "test_selected_provider_recorder",
            crate::FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(SelectedProviderRecorderFilter {
                    upstream_addr: addr,
                    seen: Arc::clone(&seen_factory),
                    publish: Some("discarded-provider"),
                }))
            })),
        )
        .unwrap();
    let mut entries: Vec<crate::FilterEntry> =
        serde_yaml::from_str("- filter: test_selected_provider_recorder").unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    let staged = super::StagedUpstream(praxis_core::connectivity::Upstream {
        address: Arc::from(addr.to_string().as_str()),
        authority: None,
        connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        tls: None,
    });
    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(staged);

    let request = crate::SubRequest {
        method: http::Method::POST,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::from_static(b"body"),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    drop(executor.run(&pipeline, &request, extensions, deadline).await);
    backend.abort();

    assert_eq!(
        *seen.lock().unwrap(),
        Some(None),
        "a staged upstream must clear metadata published for the discarded selection"
    );
}

#[cfg(feature = "upstream-binding")]
fn nested_upstream_extensions() -> crate::RequestExtensions {
    use std::sync::Arc;

    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(crate::extensions::BoundUpstream::new(
        Arc::from("parent"),
        Some(Arc::from("parent_protocol")),
        Some(Arc::from("parent_provider")),
    ));
    extensions.insert(crate::extensions::BoundUpstreamFrozen);

    super::enter_nested_upstream_scope(&mut extensions, true);
    extensions.insert(crate::extensions::BoundUpstream::new(
        Arc::from("child"),
        Some(Arc::from("child_protocol")),
        Some(Arc::from("child_provider")),
    ));
    extensions.remove::<crate::extensions::BoundUpstreamFrozen>();
    extensions.insert(crate::extensions::SelectedClusterApplication::new(None, Some(Arc::from("leak"))).unwrap());

    extensions
}

#[cfg(feature = "upstream-binding")]
fn assert_parent_upstream_scope(extensions: &crate::RequestExtensions) {
    let binding = extensions
        .get::<crate::extensions::BoundUpstream>()
        .expect("the parent binding must be restored");
    assert_eq!(
        binding.cluster(),
        "parent",
        "the parent binding cluster must be restored"
    );
    assert_eq!(
        binding.application_protocol(),
        Some("parent_protocol"),
        "the parent binding protocol must be restored"
    );
    assert_eq!(
        binding.application_provider(),
        Some("parent_provider"),
        "the parent binding provider must be restored"
    );
    assert!(
        extensions.get::<crate::extensions::BoundUpstreamFrozen>().is_some(),
        "the parent's binding freeze must be restored"
    );
    assert!(
        extensions
            .get::<crate::extensions::SelectedClusterApplication>()
            .is_none(),
        "child selected metadata must be scrubbed"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn error_into_parts_restores_parent_upstream_scope() {
    let extensions = nested_upstream_extensions();
    let error = super::FilteredSubrequestError::new("boom".to_owned().into(), extensions);
    let (_error, extensions) = error.into_parts();
    assert_parent_upstream_scope(&extensions);
}

#[cfg(feature = "bound-upstream-request-body")]
#[test]
fn nested_upstream_scope_shields_parent_body_rewrite() {
    use crate::extensions::BoundRequestBodyRewrite;

    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(BoundRequestBodyRewrite(bytes::Bytes::from_static(b"parent")));

    super::enter_nested_upstream_scope(&mut extensions, true);
    assert!(
        extensions.get::<BoundRequestBodyRewrite>().is_none(),
        "the nested pipeline's executor must not take the parent's rewrite as its own"
    );
    extensions.insert(BoundRequestBodyRewrite(bytes::Bytes::from_static(b"child")));
    super::restore_parent_upstream_scope(&mut extensions);

    assert_eq!(
        extensions
            .get::<BoundRequestBodyRewrite>()
            .map(|rewrite| rewrite.0.as_ref()),
        Some(&b"parent"[..]),
        "leaving the nested scope must drop the child's rewrite and restore the parent's"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn nested_upstream_scope_restores_parent_binding_and_freeze() {
    use std::sync::Arc;

    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(crate::extensions::BoundUpstream::new(
        Arc::from("parent"),
        Some(Arc::from("parent_protocol")),
        Some(Arc::from("parent_provider")),
    ));
    extensions.insert(crate::extensions::BoundUpstreamFrozen);

    super::enter_nested_upstream_scope(&mut extensions, true);
    extensions.insert(crate::extensions::BoundUpstream::new(Arc::from("child"), None, None));
    extensions.remove::<crate::extensions::BoundUpstreamFrozen>();
    extensions.insert(crate::extensions::SelectedClusterApplication::new(None, Some(Arc::from("child"))).unwrap());

    super::restore_parent_upstream_scope(&mut extensions);

    let binding = extensions.get::<crate::extensions::BoundUpstream>().unwrap();
    assert_eq!(
        binding.cluster(),
        "parent",
        "the parent binding cluster must be restored"
    );
    assert_eq!(
        binding.application_protocol(),
        Some("parent_protocol"),
        "the parent binding protocol must be restored"
    );
    assert_eq!(
        binding.application_provider(),
        Some("parent_provider"),
        "the parent binding provider must be restored"
    );
    assert!(
        extensions.get::<crate::extensions::BoundUpstreamFrozen>().is_some(),
        "the parent's binding freeze must be restored"
    );
    assert!(
        extensions
            .get::<crate::extensions::SelectedClusterApplication>()
            .is_none(),
        "child selected metadata must be scrubbed"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn into_parent_extensions_restores_parent_upstream_scope() {
    use std::sync::Arc;

    let registry = crate::FilterRegistry::with_builtins();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut [], &registry).unwrap());
    let request_snapshot = crate::Request {
        headers: HeaderMap::new(),
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
    };
    let response_snapshot = crate::Response {
        headers: HeaderMap::new(),
        status: http::StatusCode::OK,
    };
    let extensions = nested_upstream_extensions();

    let continuation = super::continuation::FilteredSubrequestContinuation {
        pipeline,
        request_snapshot,
        response_snapshot,
        extensions,
        filter_state: std::collections::HashMap::new(),
        filter_results: std::collections::HashMap::new(),
        filter_metadata: std::collections::HashMap::new(),
        structured_metadata: std::collections::HashMap::new(),
        executed_filter_indices: Vec::new(),
        body_done_indices: Vec::new(),
        response_body_bytes: 0,
        response_body_mode: crate::body::BodyMode::Stream,
        completed: false,
        client_addr: None,
        downstream_tls: false,
        request_start: std::time::Instant::now(),
        step_deadline: std::time::Instant::now(),
        peer_identity: None,
    };

    let extensions = continuation.into_parent_extensions();
    assert_parent_upstream_scope(&extensions);
}

#[cfg(feature = "upstream-binding")]
#[test]
fn into_completion_restores_parent_upstream_scope() {
    use std::sync::Arc;

    let registry = crate::FilterRegistry::with_builtins();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut [], &registry).unwrap());
    let request_snapshot = crate::Request {
        headers: HeaderMap::new(),
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
    };
    let response_snapshot = crate::Response {
        headers: HeaderMap::new(),
        status: http::StatusCode::OK,
    };
    let extensions = nested_upstream_extensions();

    let continuation = super::continuation::FilteredSubrequestContinuation {
        pipeline,
        request_snapshot,
        response_snapshot,
        extensions,
        filter_state: std::collections::HashMap::new(),
        filter_results: std::collections::HashMap::new(),
        filter_metadata: std::collections::HashMap::new(),
        structured_metadata: std::collections::HashMap::new(),
        executed_filter_indices: Vec::new(),
        body_done_indices: Vec::new(),
        response_body_bytes: 0,
        response_body_mode: crate::body::BodyMode::Stream,
        completed: true,
        client_addr: None,
        downstream_tls: false,
        request_start: std::time::Instant::now(),
        step_deadline: std::time::Instant::now(),
        peer_identity: None,
    };

    let completion = continuation.into_completion();
    assert_parent_upstream_scope(&completion.extensions);
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn expired_deadline_keeps_the_outer_scope_checkpoint() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::SubRequestClient;

    let registry = crate::FilterRegistry::with_builtins();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut [], &registry).unwrap());
    let client = SubRequestClient::new(crate::test_support::connector(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));
    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(crate::extensions::BoundUpstream::new(Arc::from("parent"), None, None));
    super::enter_nested_upstream_scope(&mut extensions, true);
    extensions.insert(crate::extensions::BoundUpstream::new(
        Arc::from("outer-step"),
        None,
        None,
    ));
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };

    let Err(error) = executor
        .execute(super::FilteredSubrequestInput::callout(
            &pipeline,
            &request,
            Instant::now(),
            extensions,
        ))
        .await
    else {
        panic!("an expired deadline must fail the sub-request");
    };
    let (_error, extensions) = error.into_parts();

    assert_eq!(
        extensions
            .get::<crate::extensions::BoundUpstream>()
            .map(crate::extensions::BoundUpstream::cluster),
        Some("outer-step"),
        "a failed inner call must hand back the outer step's view, not pop the outer checkpoint"
    );
    assert_eq!(
        extensions
            .get::<super::ParentUpstreamStates>()
            .map(|states| states.0.len()),
        Some(1),
        "the outer scope's checkpoint must survive for its own restore"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn execute_restores_the_parent_binding_after_a_child_rebinds() {
    for (inherits_binding, fails) in [(true, false), (true, true), (false, false), (false, true)] {
        let (addr, backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let pipeline = rebinding_pipeline(addr, &seen, fails);
        let executor = test_callout_executor();
        let request = crate::SubRequest {
            method: http::Method::GET,
            uri: http::Uri::from_static("/"),
            headers: HeaderMap::new(),
            body: bytes::Bytes::new(),
        };
        let mut input = super::FilteredSubrequestInput::callout(
            &pipeline,
            &request,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            frozen_parent_extensions(),
        );
        input.inherits_binding = inherits_binding;

        let extensions = match executor.execute(input).await {
            Ok(opened) => opened.continuation.into_completion().extensions,
            Err(error) => error.into_parts().1,
        };
        backend.abort();

        let expected_seen = inherits_binding.then(|| "parent".to_owned());
        assert_eq!(
            *seen.lock().unwrap(),
            vec![expected_seen],
            "the child sees the parent binding only when it inherits it \
             (inherits = {inherits_binding}, fails = {fails})"
        );
        assert_eq!(
            extensions
                .get::<crate::extensions::BoundUpstream>()
                .map(crate::extensions::BoundUpstream::cluster),
            Some("parent"),
            "the parent binding must come back (inherits = {inherits_binding}, fails = {fails})"
        );
        assert!(
            extensions.get::<crate::extensions::BoundUpstreamFrozen>().is_some(),
            "the parent freeze must come back (inherits = {inherits_binding}, fails = {fails})"
        );
        assert!(
            extensions.get::<super::ParentUpstreamStates>().is_none(),
            "the scope checkpoint must be consumed (inherits = {inherits_binding}, fails = {fails})"
        );
    }
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn execute_leaves_an_unbound_parent_unbound_after_a_callout_binds() {
    use crate::extensions::{BoundUpstream, BoundUpstreamFrozen};

    let (addr, backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = rebinding_pipeline(addr, &seen, false);
    let executor = test_callout_executor();
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let input = super::FilteredSubrequestInput::callout(
        &pipeline,
        &request,
        std::time::Instant::now() + std::time::Duration::from_secs(5),
        crate::RequestExtensions::default(),
    );

    let extensions = executor
        .execute(input)
        .await
        .map(|opened| opened.continuation.into_completion().extensions)
        .map_err(|error| error.into_parts().0)
        .expect("the callout reaches its own backend");
    backend.abort();

    assert_eq!(
        *seen.lock().unwrap(),
        vec![None],
        "the callout starts unbound, then binds its own cluster"
    );
    assert!(
        extensions.get::<BoundUpstream>().is_none(),
        "an unbound parent must not inherit the callout's binding"
    );
    assert!(
        extensions.get::<BoundUpstreamFrozen>().is_none(),
        "an unbound parent must not inherit the callout's freeze"
    );
    assert!(
        extensions.get::<super::ParentUpstreamStates>().is_none(),
        "the scope checkpoint must be consumed"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn restore_clears_a_child_binding_the_parent_never_had() {
    use crate::extensions::{BoundUpstream, BoundUpstreamFrozen};

    let mut extensions = crate::RequestExtensions::default();
    super::enter_nested_upstream_scope(&mut extensions, false);
    extensions.insert(BoundUpstream::new(std::sync::Arc::from("callout"), None, None));
    extensions.insert(BoundUpstreamFrozen);
    #[cfg(feature = "bound-upstream-request-body")]
    extensions.insert(crate::extensions::BoundRequestBodyRewrite(bytes::Bytes::from_static(
        b"callout",
    )));

    super::restore_parent_upstream_scope(&mut extensions);

    assert!(
        extensions.get::<BoundUpstream>().is_none(),
        "an unbound parent must not inherit the callout's binding"
    );
    assert!(
        extensions.get::<BoundUpstreamFrozen>().is_none(),
        "an unbound parent must not inherit the callout's freeze"
    );
    #[cfg(feature = "bound-upstream-request-body")]
    assert!(
        extensions.get::<crate::extensions::BoundRequestBodyRewrite>().is_none(),
        "an unbound parent must not inherit the callout's body rewrite"
    );
    assert!(
        extensions.get::<super::ParentUpstreamStates>().is_none(),
        "the scope checkpoint must be consumed"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn callout_scope_starts_unbound_and_restores_the_parent_binding() {
    use std::sync::Arc;

    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(crate::extensions::BoundUpstream::new(
        Arc::from("parent"),
        Some(Arc::from("parent_protocol")),
        None,
    ));
    extensions.insert(crate::extensions::BoundUpstreamFrozen);

    super::enter_nested_upstream_scope(&mut extensions, false);
    assert!(
        extensions.get::<crate::extensions::BoundUpstream>().is_none(),
        "an outbound callout is a separate request and must start unbound"
    );
    assert!(
        extensions.get::<crate::extensions::BoundUpstreamFrozen>().is_none(),
        "the parent's freeze must not block the callout's own binding router"
    );
    extensions.insert(crate::extensions::BoundUpstream::new(Arc::from("callout"), None, None));
    extensions.insert(crate::extensions::BoundUpstreamFrozen);
    super::restore_parent_upstream_scope(&mut extensions);

    assert_eq!(
        extensions
            .get::<crate::extensions::BoundUpstream>()
            .map(crate::extensions::BoundUpstream::cluster),
        Some("parent"),
        "leaving the callout restores the parent's binding"
    );
    assert!(
        extensions.get::<crate::extensions::BoundUpstreamFrozen>().is_some(),
        "leaving the callout restores the parent's freeze"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn callout_with_its_own_binding_router_ignores_the_parent_binding() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::SubRequestClient;

    let (addr, backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncallout").await;
    let registry = crate::FilterRegistry::with_builtins();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&format!(
        r#"
- filter: router
  routes:
    - path_prefix: "/"
      cluster: outbound
- filter: load_balancer
  cluster_source: bound_upstream
  clusters:
    - name: outbound
      endpoints: ["{addr}"]
"#
    ))
    .unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());
    let client = SubRequestClient::new(crate::test_support::connector(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));
    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(crate::extensions::BoundUpstream::new(Arc::from("parent"), None, None));
    extensions.insert(crate::extensions::BoundUpstreamFrozen);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };

    let outcome = executor
        .run(&pipeline, &request, extensions, Instant::now() + Duration::from_secs(5))
        .await;
    backend.abort();

    let response = match outcome.expect("the callout should reach its own bound upstream") {
        crate::CalloutResponse::Buffered(response) => response,
        crate::CalloutResponse::Streaming { .. } => panic!("the outbound chain is buffered"),
    };
    assert_eq!(
        response.status, 200,
        "the callout binds its own cluster instead of failing on the parent's frozen binding"
    );
    assert_eq!(
        response.body.as_ref(),
        b"callout",
        "the callout reaches its own backend"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_re_pins_staged_upstream_over_chain_filter_rewrite() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::SubRequestClient;

    let (staged_addr, staged_backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nstaged").await;
    let (attacker_addr, attacker_backend) =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhijack").await;

    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "test_upstream_hijack",
            crate::FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(UpstreamHijackFilter {
                    redirect_to: attacker_addr,
                }))
            })),
        )
        .unwrap();

    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str("- filter: test_upstream_hijack").unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let client = SubRequestClient::new(crate::test_support::connector(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    let staged = super::StagedUpstream(praxis_core::connectivity::Upstream {
        address: Arc::from(staged_addr.to_string().as_str()),
        authority: None,
        connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        tls: None,
    });
    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(staged);

    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let response = match executor
        .run(&pipeline, &request, extensions, deadline)
        .await
        .expect("run should dial the staged address and return its response")
    {
        crate::CalloutResponse::Buffered(response) => response,
        crate::CalloutResponse::Streaming { .. } => {
            panic!("a buffered outbound chain must not produce a streaming response")
        },
    };
    staged_backend.abort();
    attacker_backend.abort();

    assert_eq!(response.status, 200);
    assert_eq!(
        response.body,
        bytes::Bytes::from_static(b"staged"),
        "the executor must re-pin the staged address after the request phase, so a \
         chain filter's `ctx.upstream` rewrite cannot redirect the callout to the \
         attacker backend"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities: session-store propagation recorder
// -----------------------------------------------------------------------------

// Records whether the sub-request filter context carried the session-store
// registry at the moment each hook ran, so propagation of the parent pipeline's
// session stores into the executor's sub-request context can be asserted
// end-to-end.
struct SessionStoreRecorderFilter {
    saw_on_request: std::sync::Arc<std::sync::atomic::AtomicBool>,
    saw_on_response_body: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl crate::HttpFilter for SessionStoreRecorderFilter {
    fn name(&self) -> &'static str {
        "test_session_store_recorder"
    }

    async fn on_request(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        self.saw_on_request
            .store(ctx.session_stores.is_some(), std::sync::atomic::Ordering::SeqCst);
        Ok(crate::FilterAction::Continue)
    }

    fn response_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadWrite
    }

    fn on_response_body(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        self.saw_on_response_body
            .store(ctx.session_stores.is_some(), std::sync::atomic::Ordering::SeqCst);
        Ok(crate::FilterAction::Continue)
    }
}

// Register `test_session_store_recorder` over the builtins, wired to the given
// observation flags.
fn recorder_registry(
    saw_on_request: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    saw_on_response_body: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> crate::FilterRegistry {
    let saw_on_request = std::sync::Arc::clone(saw_on_request);
    let saw_on_response_body = std::sync::Arc::clone(saw_on_response_body);
    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "test_session_store_recorder",
            crate::FilterFactory::Http(std::sync::Arc::new(move |_| {
                Ok(Box::new(SessionStoreRecorderFilter {
                    saw_on_request: std::sync::Arc::clone(&saw_on_request),
                    saw_on_response_body: std::sync::Arc::clone(&saw_on_response_body),
                }))
            })),
        )
        .unwrap();
    registry
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn buffered_subrequest_context_inherits_parent_session_stores() {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::SubRequestClient;

    let saw_on_request = Arc::new(AtomicBool::new(false));
    let saw_on_response_body = Arc::new(AtomicBool::new(false));
    let registry = recorder_registry(&saw_on_request, &saw_on_response_body);

    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(
        "
- filter: test_session_store_recorder
- filter: static_response
  status: 200
  body: hello from outbound
",
    )
    .unwrap();
    let mut pipeline = crate::FilterPipeline::build(&mut entries, &registry).unwrap();
    pipeline.set_session_stores(Arc::new(crate::SessionStoreRegistry::new()));
    let pipeline = Arc::new(pipeline);

    let client = SubRequestClient::new(crate::test_support::connector(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("run should return the locally-produced response");

    assert!(
        saw_on_request.load(Ordering::SeqCst),
        "a filter in a bound outbound chain must see the parent pipeline's session stores"
    );
}

#[cfg(feature = "chain-binding")]
#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn subrequest_binds_credentials_to_logical_authority_not_transport() {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::SubRequestClient;

    let captured = Arc::new(Mutex::new(Vec::new()));
    let (addr, backend) =
        spawn_capturing_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Arc::clone(&captured)).await;

    let chain = format!(
        "
- filter: router
  routes:
    - path_prefix: \"/\"
      cluster: backend
- filter: load_balancer
  clusters:
    - name: backend
      endpoints:
        - \"{addr}\"
      http:
        authority: api.internal
"
    );
    let registry = crate::FilterRegistry::with_builtins();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&chain).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let mut pending = crate::PendingCredentials::new();
    pending.push(
        crate::DeferredCredential::new_host_wildcard(
            "api.internal",
            http::HeaderName::from_static("x-cred-logical"),
            "logical-secret",
        )
        .unwrap(),
    );
    pending.push(
        crate::DeferredCredential::new_host_wildcard(
            "127.0.0.1",
            http::HeaderName::from_static("x-cred-transport"),
            "transport-secret",
        )
        .unwrap(),
    );
    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(pending);

    let client = SubRequestClient::new(crate::test_support::connector(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    executor
        .run(&pipeline, &request, extensions, deadline)
        .await
        .expect("buffered callout should return a response");
    backend.abort();

    let received = String::from_utf8(captured.lock().unwrap().clone())
        .unwrap()
        .to_ascii_lowercase();
    assert!(
        received.contains("x-cred-logical"),
        "a credential bound to the logical authority must be injected: {received:?}"
    );
    assert!(
        !received.contains("x-cred-transport"),
        "a credential bound to the transport host must NOT be injected: {received:?}"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn subrequest_sends_logical_authority_as_host_not_transport() {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::SubRequestClient;

    let captured = Arc::new(Mutex::new(Vec::new()));
    let (addr, backend) =
        spawn_capturing_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Arc::clone(&captured)).await;

    let chain = format!(
        "
- filter: router
  routes:
    - path_prefix: \"/\"
      cluster: backend
- filter: load_balancer
  clusters:
    - name: backend
      endpoints:
        - \"{addr}\"
      http:
        authority: api.internal
"
    );
    let registry = crate::FilterRegistry::with_builtins();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&chain).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let client = SubRequestClient::new(crate::test_support::connector(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("stale.example.com"));
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers,
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("buffered callout should return a response");
    backend.abort();

    let received = String::from_utf8(captured.lock().unwrap().clone())
        .unwrap()
        .to_ascii_lowercase();
    assert!(
        received.contains("host: api.internal"),
        "the upstream must receive the logical authority override as its Host: {received:?}"
    );
    assert!(
        !received.contains(&addr.to_string()),
        "the transport address must not leak into the upstream Host: {received:?}"
    );
    assert!(
        !received.contains("stale.example.com"),
        "a stale inbound Host must be replaced by the authority override: {received:?}"
    );
}

#[cfg(feature = "chain-binding")]
#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn subrequest_credential_injection_pins_host_to_credential_authority() {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::SubRequestClient;

    let captured = Arc::new(Mutex::new(Vec::new()));
    let (addr, backend) =
        spawn_capturing_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Arc::clone(&captured)).await;

    let chain = format!(
        "
- filter: router
  routes:
    - path_prefix: \"/\"
      cluster: backend
- filter: load_balancer
  clusters:
    - name: backend
      endpoints:
        - \"{addr}\"
"
    );
    let registry = crate::FilterRegistry::with_builtins();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&chain).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let transport_host = addr.ip().to_string();
    let mut pending = crate::PendingCredentials::new();
    pending.push(
        crate::DeferredCredential::new_host_wildcard(
            &transport_host,
            http::HeaderName::from_static("x-cred-transport"),
            "transport-secret",
        )
        .unwrap(),
    );
    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(pending);

    let client = SubRequestClient::new(crate::test_support::connector(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::HOST,
        http::HeaderValue::from_static("shared-vhost.example"),
    );
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers,
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    executor
        .run(&pipeline, &request, extensions, deadline)
        .await
        .expect("buffered callout should return a response");
    backend.abort();

    let received = String::from_utf8(captured.lock().unwrap().clone())
        .unwrap()
        .to_ascii_lowercase();
    assert!(
        received.contains("x-cred-transport"),
        "a credential bound to the transport authority must be injected: {received:?}"
    );
    assert!(
        received.contains(&format!("host: {addr}")),
        "when a credential is injected the Host must equal the credential's authority (the transport): {received:?}"
    );
    assert!(
        !received.contains("shared-vhost.example"),
        "a stale inbound Host must not carry the injected secret to a divergent vhost: {received:?}"
    );
}

#[cfg(feature = "chain-binding")]
#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn subrequest_unmatched_staged_credential_preserves_custom_host() {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::SubRequestClient;

    let captured = Arc::new(Mutex::new(Vec::new()));
    let (addr, backend) =
        spawn_capturing_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Arc::clone(&captured)).await;

    let chain = format!(
        "
- filter: router
  routes:
    - path_prefix: \"/\"
      cluster: backend
- filter: load_balancer
  clusters:
    - name: backend
      endpoints:
        - \"{addr}\"
"
    );
    let registry = crate::FilterRegistry::with_builtins();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&chain).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let mut pending = crate::PendingCredentials::new();
    pending.push(
        crate::DeferredCredential::new_host_wildcard(
            "other.example",
            http::HeaderName::from_static("x-cred-other"),
            "other-secret",
        )
        .unwrap(),
    );
    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(pending);

    let client = SubRequestClient::new(crate::test_support::connector(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::HOST,
        http::HeaderValue::from_static("custom-vhost.example"),
    );
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers,
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    executor
        .run(&pipeline, &request, extensions, deadline)
        .await
        .expect("buffered callout should return a response");
    backend.abort();

    let received = String::from_utf8(captured.lock().unwrap().clone())
        .unwrap()
        .to_ascii_lowercase();
    assert!(
        !received.contains("x-cred-other"),
        "a credential bound to a non-matching authority must not be injected: {received:?}"
    );
    assert!(
        received.contains("host: custom-vhost.example"),
        "an unmatched staged credential must not retarget a caller-set Host: {received:?}"
    );
    assert!(
        !received.contains(&format!("host: {addr}")),
        "the transport endpoint must not overwrite the Host when no credential is injected: {received:?}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities: streaming callout harness
// -----------------------------------------------------------------------------

// A filter that selects a streaming sub-request response, so the executor
// dispatches the outbound chain in streaming mode.
struct StreamingSelectorFilter;

#[async_trait::async_trait]
impl crate::HttpFilter for StreamingSelectorFilter {
    fn name(&self) -> &'static str {
        "test_streaming_selector"
    }

    fn may_select_streaming_subrequest_response(&self) -> bool {
        true
    }

    async fn on_request(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        ctx.set_subrequest_response_mode(crate::SubRequestResponseMode::Streaming);
        Ok(crate::FilterAction::Continue)
    }
}

// A response-body filter that emits a terminal marker at end-of-stream, the way
// an SSE aggregator closes a stream. This output is produced only by the
// completion lifecycle, so it proves the streaming body flushes completion
// output rather than dropping it at upstream EOF.
struct TerminalEventFilter;

#[async_trait::async_trait]
impl crate::HttpFilter for TerminalEventFilter {
    fn name(&self) -> &'static str {
        "test_terminal_event"
    }

    async fn on_request(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        Ok(crate::FilterAction::Continue)
    }

    fn response_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadWrite
    }

    fn on_response_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        if end_of_stream && body.is_none() {
            *body = Some(bytes::Bytes::from_static(b"data: [DONE]\n\n"));
        }
        Ok(crate::FilterAction::Continue)
    }
}

// Flushes an 8-byte terminal frame at end-of-stream. Declares `Stream` response
// mode because the streaming path rejects a `StreamBuffer` response mode outright
// (see the guard in run_step), so `Stream` is the only response-body mode under
// which a completion body can actually be produced.
struct BoundedCompletionFilter;

#[async_trait::async_trait]
impl crate::HttpFilter for BoundedCompletionFilter {
    fn name(&self) -> &'static str {
        "test_bounded_completion"
    }

    async fn on_request(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        Ok(crate::FilterAction::Continue)
    }

    fn response_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadWrite
    }

    fn on_response_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        if end_of_stream && body.is_none() {
            // 8 bytes, deliberately over the 4-byte response ceiling applied below.
            *body = Some(bytes::Bytes::from_static(b"AAAAAAAA"));
        }
        Ok(crate::FilterAction::Continue)
    }
}

// A response-body filter that rejects at end-of-stream, so the streaming body's
// completion lifecycle (run by both EOF draining and `suppress`) fails. Models a
// guardrail that blocks the final aggregated frame.
struct RejectOnCompletionFilter;

#[async_trait::async_trait]
impl crate::HttpFilter for RejectOnCompletionFilter {
    fn name(&self) -> &'static str {
        "test_reject_on_completion"
    }

    async fn on_request(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        Ok(crate::FilterAction::Continue)
    }

    fn response_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadWrite
    }

    fn on_response_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        if end_of_stream {
            return Ok(crate::FilterAction::Reject(crate::Rejection::status(503)));
        }
        Ok(crate::FilterAction::Continue)
    }
}

// A caller-injected extension type, used to prove the parent's extensions survive
// the streaming body's inner->held transition even when completion fails.
#[derive(Debug, Eq, PartialEq)]
struct CalloutParentMarker(&'static str);

// Build a registry with the builtins plus the streaming callout test filters.
fn callout_registry() -> crate::FilterRegistry {
    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "test_streaming_selector",
            crate::FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(StreamingSelectorFilter)))),
        )
        .unwrap();
    registry
        .register(
            "test_terminal_event",
            crate::FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(TerminalEventFilter)))),
        )
        .unwrap();
    registry
        .register(
            "test_reject_on_completion",
            crate::FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(RejectOnCompletionFilter)))),
        )
        .unwrap();
    registry
        .register(
            "test_bounded_completion",
            crate::FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(BoundedCompletionFilter)))),
        )
        .unwrap();
    registry
}

// Spawn a raw TCP backend that replies with a fixed response for each accept.
async fn spawn_raw_backend(response: &'static str) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0_u8; 8192];
            let _bytes_read = socket.read(&mut buf).await;
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
        }
    });
    (addr, handle)
}

// Spawn a raw TCP backend that captures the first request it receives into
// `captured`, then replies with a fixed response for each accept.
async fn spawn_capturing_backend(
    response: &'static str,
    captured: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0_u8; 8192];
            let bytes_read = socket.read(&mut buf).await.unwrap_or(0);
            {
                let mut slot = captured.lock().unwrap();
                if slot.is_empty()
                    && let Some(request) = buf.get(..bytes_read)
                {
                    slot.extend_from_slice(request);
                }
            }
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
        }
    });
    (addr, handle)
}

// Accept a connection, read the request, then close without a response. The
// streaming transport fails before it can read response headers, so the executor
// takes the abnormal stream-completion path (a Complete outcome of transport
// origin) rather than the normal streaming-body path.
async fn spawn_request_dropping_backend() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::AsyncReadExt as _;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0_u8; 8192];
            let _bytes_read = socket.read(&mut buf).await;
            drop(socket);
        }
    });
    (addr, handle)
}

// Route the outbound chain to a real backend address.
fn routed_chain_yaml(addr: std::net::SocketAddr, extra: &str) -> String {
    format!(
        "
- filter: test_streaming_selector
- filter: router
  routes:
    - path_prefix: \"/\"
      cluster: backend
- filter: load_balancer
  clusters:
    - name: backend
      endpoints:
        - \"{addr}\"
{extra}"
    )
}

// Build a streaming callout executor over a fresh client.
fn streaming_executor(max_response_bytes: usize) -> crate::FilteredSubrequestExecutor {
    use std::time::{Duration, Instant};

    use praxis_core::subrequest::SubRequestClient;

    let client = SubRequestClient::new(crate::test_support::connector(4, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, max_response_bytes, Duration::from_secs(5))
}

// Drain a streaming body to completion, returning the concatenated payload.
async fn drain(body: &mut Box<dyn crate::StreamingResponseBody>) -> Result<Vec<u8>, crate::FilterError> {
    let mut out = Vec::new();
    while let Some(chunk) = body.next_chunk().await? {
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_streaming_flushes_completion_output_after_upstream_eof() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let (addr, backend) =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").await;
    let registry = callout_registry();
    let mut entries: Vec<crate::FilterEntry> =
        serde_yaml::from_str(&routed_chain_yaml(addr, "- filter: test_terminal_event\n")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = streaming_executor(1_048_576);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let mut body = match executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("streaming callout should open")
    {
        crate::CalloutResponse::Streaming { response, body } => {
            assert_eq!(response.status, 200, "the transition-time status must be surfaced");
            body
        },
        crate::CalloutResponse::Buffered(_) => panic!("the chain selected streaming mode"),
    };

    let payload = drain(&mut body).await.expect("streaming body should drain cleanly");
    backend.abort();

    assert_eq!(
        payload, b"hellodata: [DONE]\n\n",
        "the streaming body must yield the upstream chunk AND the completion output"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_streaming_yields_upstream_chunks_for_clean_eof() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let (addr, backend) =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").await;
    let registry = callout_registry();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&routed_chain_yaml(addr, "")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = streaming_executor(1_048_576);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let mut body = match executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("streaming callout should open")
    {
        crate::CalloutResponse::Streaming { body, .. } => body,
        crate::CalloutResponse::Buffered(_) => panic!("the chain selected streaming mode"),
    };

    let payload = drain(&mut body).await.expect("streaming body should drain cleanly");
    backend.abort();

    assert_eq!(payload, b"hello", "the upstream chunk must be delivered on a clean EOF");
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_streaming_falls_back_to_next_staged_address_on_connection_refusal() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let (_reserved, dead) = crate::test_support::refusing_addr();
    let (live_addr, backend) =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").await;

    let registry = callout_registry();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str("- filter: test_streaming_selector\n").unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = streaming_executor(1_048_576);

    let staged = super::StagedUpstream(praxis_core::connectivity::Upstream {
        address: Arc::from(dead.to_string().as_str()),
        authority: None,
        connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        tls: None,
    });
    let fallback = super::StagedUpstreamFallback(vec![dead, live_addr]);
    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(staged);
    extensions.insert(fallback);

    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let mut body = match executor
        .run(&pipeline, &request, extensions, deadline)
        .await
        .expect("streaming callout should fall back to the live address and open")
    {
        crate::CalloutResponse::Streaming { response, body } => {
            assert_eq!(
                response.status, 200,
                "a connection refusal on the pinned primary must fall back to the \
                 next validated address, whose live backend responds 200"
            );
            body
        },
        crate::CalloutResponse::Buffered(_) => panic!("the chain selected streaming mode"),
    };

    let payload = drain(&mut body).await.expect("streaming body should drain cleanly");
    backend.abort();

    assert_eq!(
        payload, b"hello",
        "the streamed body must come from the live fallback backend"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_streaming_enforces_response_byte_ceiling() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let (addr, backend) =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").await;
    let registry = callout_registry();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&routed_chain_yaml(addr, "")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = streaming_executor(3);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let mut body = match executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("streaming callout should open")
    {
        crate::CalloutResponse::Streaming { body, .. } => body,
        crate::CalloutResponse::Buffered(_) => panic!("the chain selected streaming mode"),
    };

    let result = drain(&mut body).await;
    backend.abort();

    assert!(
        result.is_err_and(|error| error.to_string().contains("exceeds configured body limit")),
        "a chunk beyond the response ceiling must surface as an error"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_streaming_ceiling_breach_ends_the_stream() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let (addr, backend) = spawn_raw_backend(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n14\r\nAAAAAAAAAAAAAAAAAAAA\r\n0\r\n\r\n",
    )
    .await;
    let registry = callout_registry();
    let mut entries: Vec<crate::FilterEntry> =
        serde_yaml::from_str(&routed_chain_yaml(addr, "- filter: test_terminal_event\n")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = streaming_executor(15);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let mut body = match executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("streaming callout should open")
    {
        crate::CalloutResponse::Streaming { body, .. } => body,
        crate::CalloutResponse::Buffered(_) => panic!("the chain selected streaming mode"),
    };

    let mut breach = None;
    for _ in 0_u8..32 {
        match body.next_chunk().await {
            Ok(Some(_)) => {},
            Ok(None) => break,
            Err(error) => {
                breach = Some(error);
                break;
            },
        }
    }
    let breach = breach.expect("20 bytes of body must breach a 15-byte ceiling");
    assert!(
        breach.to_string().contains("exceeds configured body limit"),
        "the breach must be the body-limit error: {breach}"
    );

    let resumed = body.next_chunk().await;
    backend.abort();

    let observed = match &resumed {
        Ok(Some(chunk)) => format!("resumed with {} more bytes", chunk.len()),
        Ok(None) => "end of stream".to_owned(),
        Err(error) => format!("error: {error}"),
    };
    assert!(
        matches!(resumed, Ok(None)),
        "a ceiling breach must end the stream; polling again must not resume it, got {observed}"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_streaming_surfaces_unhandled_upstream_termination() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let backend = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0_u8; 8192];
        let _bytes_read = socket.read(&mut buf).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\npartial")
            .await
            .unwrap();
        socket.flush().await.unwrap();
        drop(socket);
    });
    let registry = callout_registry();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&routed_chain_yaml(addr, "")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = streaming_executor(1_048_576);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let mut body = match executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("streaming callout should open")
    {
        crate::CalloutResponse::Streaming { body, .. } => body,
        crate::CalloutResponse::Buffered(_) => panic!("the chain selected streaming mode"),
    };

    let mut errored = false;
    loop {
        match body.next_chunk().await {
            Ok(Some(_)) => {},
            Ok(None) => break,
            Err(_) => {
                errored = true;
                break;
            },
        }
    }
    backend.abort();

    assert!(
        errored,
        "an unhandled mid-stream upstream failure must surface as an error, not a clean end"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_streaming_cancel_discards_upstream() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let (addr, backend) =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").await;
    let registry = callout_registry();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&routed_chain_yaml(addr, "")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = streaming_executor(1_048_576);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let mut body = match executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("streaming callout should open")
    {
        crate::CalloutResponse::Streaming { body, .. } => body,
        crate::CalloutResponse::Buffered(_) => panic!("the chain selected streaming mode"),
    };

    body.cancel().await;
    backend.abort();

    assert!(
        body.next_chunk().await.unwrap().is_none(),
        "a cancelled streaming body must yield no further chunks"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_streaming_suppress_error_preserves_parent_extensions() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let (addr, backend) =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").await;
    let registry = callout_registry();
    let mut entries: Vec<crate::FilterEntry> =
        serde_yaml::from_str(&routed_chain_yaml(addr, "- filter: test_reject_on_completion")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = streaming_executor(1_048_576);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(CalloutParentMarker("preserved"));
    let deadline = Instant::now() + Duration::from_secs(5);

    let mut body = match executor
        .run(&pipeline, &request, extensions, deadline)
        .await
        .expect("streaming callout should open")
    {
        crate::CalloutResponse::Streaming { body, .. } => body,
        crate::CalloutResponse::Buffered(_) => panic!("the chain selected streaming mode"),
    };

    let suppressed = body.suppress().await;
    assert!(
        suppressed.is_err(),
        "a completion-phase rejection must surface from suppress: {suppressed:?}"
    );

    let mut parent = crate::RequestExtensions::default();
    body.swap_extensions(&mut parent);
    backend.abort();

    assert_eq!(
        parent.get::<CalloutParentMarker>(),
        Some(&CalloutParentMarker("preserved")),
        "the parent extension must survive a suppress completion error"
    );
    assert!(
        body.next_chunk().await.unwrap().is_none(),
        "a suppressed body must terminate cleanly, not surface a spurious source error"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn streaming_response_body_context_inherits_parent_session_stores() {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };

    let (addr, backend) =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").await;

    let saw_on_request = Arc::new(AtomicBool::new(false));
    let saw_on_response_body = Arc::new(AtomicBool::new(false));

    let mut registry = callout_registry();
    {
        let saw_on_request = Arc::clone(&saw_on_request);
        let saw_on_response_body = Arc::clone(&saw_on_response_body);
        registry
            .register(
                "test_session_store_recorder",
                crate::FilterFactory::Http(Arc::new(move |_| {
                    Ok(Box::new(SessionStoreRecorderFilter {
                        saw_on_request: Arc::clone(&saw_on_request),
                        saw_on_response_body: Arc::clone(&saw_on_response_body),
                    }))
                })),
            )
            .unwrap();
    }

    let mut entries: Vec<crate::FilterEntry> =
        serde_yaml::from_str(&routed_chain_yaml(addr, "- filter: test_session_store_recorder\n")).unwrap();
    let mut pipeline = crate::FilterPipeline::build(&mut entries, &registry).unwrap();
    pipeline.set_session_stores(Arc::new(crate::SessionStoreRegistry::new()));
    let pipeline = Arc::new(pipeline);

    let executor = streaming_executor(1_048_576);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let mut body = match executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("streaming callout should open")
    {
        crate::CalloutResponse::Streaming { body, .. } => body,
        crate::CalloutResponse::Buffered(_) => panic!("the chain selected streaming mode"),
    };

    drain(&mut body).await.expect("streaming body should drain cleanly");
    backend.abort();

    assert!(
        saw_on_response_body.load(Ordering::SeqCst),
        "a response-body filter in a streaming outbound chain must see the parent pipeline's session stores"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities: classified buffered callout harness
// -----------------------------------------------------------------------------

// Records whether the response-header phase ran, so response-filter lifecycle
// can be asserted even on a transport-overflow path where an empty response is
// synthesized.
struct ResponseHeaderRecorderFilter {
    saw_on_response: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl crate::HttpFilter for ResponseHeaderRecorderFilter {
    fn name(&self) -> &'static str {
        "test_response_header_recorder"
    }

    async fn on_request(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        Ok(crate::FilterAction::Continue)
    }

    async fn on_response(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        self.saw_on_response.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(crate::FilterAction::Continue)
    }
}

// Grows the buffered response body to `target` bytes at end-of-stream, so the
// executor's post-filter body-limit check trips after the transport itself
// stayed within the ceiling.
struct BodyExpandingFilter {
    target: usize,
}

#[async_trait::async_trait]
impl crate::HttpFilter for BodyExpandingFilter {
    fn name(&self) -> &'static str {
        "test_body_expanding"
    }

    async fn on_request(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        Ok(crate::FilterAction::Continue)
    }

    fn response_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadWrite
    }

    fn on_response_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        if end_of_stream {
            *body = Some(bytes::Bytes::from(vec![b'x'; self.target]));
        }
        Ok(crate::FilterAction::Continue)
    }
}

// Build a buffered callout executor over a fresh client.
fn buffered_executor(max_response_bytes: usize) -> crate::FilteredSubrequestExecutor {
    use std::time::{Duration, Instant};

    use praxis_core::subrequest::SubRequestClient;

    let client = SubRequestClient::new(crate::test_support::connector(4, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, max_response_bytes, Duration::from_secs(5))
}

// Route a buffered outbound chain (no streaming selector) to a real backend,
// optionally prefixed with extra top-level filter entries.
fn buffered_chain_yaml(addr: std::net::SocketAddr, prefix: &str) -> String {
    format!(
        "
{prefix}- filter: router
  routes:
    - path_prefix: \"/\"
      cluster: backend
- filter: load_balancer
  clusters:
    - name: backend
      endpoints:
        - \"{addr}\"
"
    )
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_classified_exactly_max_response_bytes_succeeds() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let (addr, backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd").await;
    let registry = crate::FilterRegistry::with_builtins();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&buffered_chain_yaml(addr, "")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = buffered_executor(4);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let outcome = executor
        .run_classified(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("a response exactly at the ceiling must succeed");
    backend.abort();

    let response = match outcome {
        crate::CalloutOutcome::Response(crate::CalloutResponse::Buffered(response)) => response,
        crate::CalloutOutcome::Response(crate::CalloutResponse::Streaming { .. }) => {
            panic!("a small buffered backend must not stream")
        },
        crate::CalloutOutcome::ResponseTooLarge { .. } => {
            panic!("a response exactly at the ceiling must not be classified too large")
        },
    };
    assert_eq!(response.status, 200, "the upstream status must be surfaced");
    assert_eq!(
        response.body,
        bytes::Bytes::from_static(b"abcd"),
        "a body exactly at the ceiling must be delivered intact"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_classified_one_byte_over_returns_typed_response_too_large() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let (addr, backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde").await;
    let registry = crate::FilterRegistry::with_builtins();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&buffered_chain_yaml(addr, "")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = buffered_executor(4);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let outcome = executor
        .run_classified(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("an overflow must be classified, not surfaced as a transport error");
    backend.abort();

    match outcome {
        crate::CalloutOutcome::ResponseTooLarge { actual, limit } => {
            assert_eq!(actual, Some(5), "the observed oversize body must be preserved");
            assert_eq!(limit, 4, "the tripped limit must be preserved");
        },
        crate::CalloutOutcome::Response(_) => {
            panic!("a response one byte over the ceiling must be classified too large")
        },
    }
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_classified_real_upstream_502_is_not_response_too_large() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let (addr, backend) = spawn_raw_backend("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 3\r\n\r\nerr").await;
    let registry = crate::FilterRegistry::with_builtins();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&buffered_chain_yaml(addr, "")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = buffered_executor(1_048_576);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let outcome = executor
        .run_classified(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("a real upstream 502 must not surface as an error");
    backend.abort();

    match outcome {
        crate::CalloutOutcome::Response(crate::CalloutResponse::Buffered(response)) => {
            assert_eq!(response.status, 502, "a real upstream 502 must be delivered as-is");
            assert_eq!(
                response.body,
                bytes::Bytes::from_static(b"err"),
                "its body must survive"
            );
        },
        crate::CalloutOutcome::Response(crate::CalloutResponse::Streaming { .. }) => {
            panic!("a small buffered backend must not stream")
        },
        crate::CalloutOutcome::ResponseTooLarge { .. } => {
            panic!("a genuine upstream 502 must not be classified as ResponseTooLarge")
        },
    }
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_classified_runs_response_filters_on_transport_overflow() {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };

    let saw_on_response = Arc::new(AtomicBool::new(false));
    let mut registry = crate::FilterRegistry::with_builtins();
    {
        let saw_on_response = Arc::clone(&saw_on_response);
        registry
            .register(
                "test_response_header_recorder",
                crate::FilterFactory::Http(Arc::new(move |_| {
                    Ok(Box::new(ResponseHeaderRecorderFilter {
                        saw_on_response: Arc::clone(&saw_on_response),
                    }))
                })),
            )
            .unwrap();
    }

    let (addr, backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde").await;
    let mut entries: Vec<crate::FilterEntry> =
        serde_yaml::from_str(&buffered_chain_yaml(addr, "- filter: test_response_header_recorder\n")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = buffered_executor(4);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let outcome = executor
        .run_classified(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("an overflow must be classified, not surfaced as a transport error");
    backend.abort();

    assert!(
        matches!(outcome, crate::CalloutOutcome::ResponseTooLarge { .. }),
        "an oversized response must be classified too large"
    );
    assert!(
        saw_on_response.load(Ordering::SeqCst),
        "the response-header phase must run even when the response overflows"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_preserves_buffered_502_on_transport_overflow() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let (addr, backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde").await;
    let registry = crate::FilterRegistry::with_builtins();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&buffered_chain_yaml(addr, "")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = buffered_executor(4);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let response = match executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("run must keep returning a response, not an error, on overflow")
    {
        crate::CalloutResponse::Buffered(response) => response,
        crate::CalloutResponse::Streaming { .. } => panic!("a small buffered backend must not stream"),
    };
    backend.abort();

    assert_eq!(
        response.status, 502,
        "run() must keep collapsing an overflow into a generic 502"
    );
    assert!(response.body.is_empty(), "run() must keep dropping the oversized body");
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_classified_executor_side_body_overflow_returns_typed_response_too_large() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "test_body_expanding",
            crate::FilterFactory::Http(Arc::new(|_| Ok(Box::new(BodyExpandingFilter { target: 5 })))),
        )
        .unwrap();

    let (addr, backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
    let mut entries: Vec<crate::FilterEntry> =
        serde_yaml::from_str(&buffered_chain_yaml(addr, "- filter: test_body_expanding\n")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = buffered_executor(4);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let outcome = executor
        .run_classified(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("an executor-side overflow must be classified, not surfaced as an error");
    backend.abort();

    match outcome {
        crate::CalloutOutcome::ResponseTooLarge { actual, limit } => {
            assert_eq!(actual, Some(5), "the filter-grown body size must be preserved");
            assert_eq!(limit, 4, "the executor's body ceiling must be preserved");
        },
        crate::CalloutOutcome::Response(_) => {
            panic!("a filter-grown oversized body must be classified too large")
        },
    }
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn abnormal_completion_body_is_bounded_by_max_response_bytes() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let (addr, backend) = spawn_request_dropping_backend().await;
    let registry = callout_registry();
    let mut entries: Vec<crate::FilterEntry> =
        serde_yaml::from_str(&routed_chain_yaml(addr, "- filter: test_bounded_completion\n")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = streaming_executor(1_048_576);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let outcome = executor
        .run_classified(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("the abnormal completion must resolve, not error");
    backend.abort();

    match outcome {
        crate::CalloutOutcome::Response(crate::CalloutResponse::Buffered(response)) => {
            assert_eq!(
                response.body.len(),
                8,
                "the flushed completion frame rides through when it is within max_response_bytes"
            );
        },
        crate::CalloutOutcome::Response(crate::CalloutResponse::Streaming { .. }) => {
            panic!("an abnormal transport completion is delivered buffered, not streaming")
        },
        crate::CalloutOutcome::ResponseTooLarge { .. } => {
            panic!("an 8-byte completion body is within the 1 MiB ceiling")
        },
    }
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn abnormal_completion_over_ceiling_is_classified_too_large() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let (addr, backend) = spawn_request_dropping_backend().await;
    let registry = callout_registry();
    let mut entries: Vec<crate::FilterEntry> =
        serde_yaml::from_str(&routed_chain_yaml(addr, "- filter: test_bounded_completion\n")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let executor = streaming_executor(4);
    let request = crate::SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let outcome = executor
        .run_classified(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("an over-ceiling completion body must be classified, not surfaced as an error");
    backend.abort();

    match outcome {
        crate::CalloutOutcome::ResponseTooLarge { actual, limit } => {
            assert_eq!(actual, Some(8), "the flushed completion body size must be preserved");
            assert_eq!(limit, 4, "the tripped ceiling must be preserved");
        },
        crate::CalloutOutcome::Response(_) => {
            panic!("an 8-byte completion body must breach the 4-byte ceiling")
        },
    }
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn selected_upstream_reject_short_circuits_before_dialing() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};

    let (_reserved, dead) = crate::test_support::refusing_addr();

    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "test_selected_upstream_reject",
            crate::FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(SelectedUpstreamRejectFilter { upstream_addr: dead }))
            })),
        )
        .unwrap();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str("- filter: test_selected_upstream_reject").unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    let request = crate::SubRequest {
        method: http::Method::POST,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::from_static(b"blocked"),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let response = match executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("run should return the local rejection")
    {
        crate::CalloutResponse::Buffered(response) => response,
        crate::CalloutResponse::Streaming { .. } => panic!("a local rejection must be buffered"),
    };

    assert_eq!(
        response.status, 403,
        "the selected-upstream phase rejection returns 403 with no upstream dial; had it dialed the \
         dead port, the connect failure would classify as 502"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn selected_upstream_oversized_output_is_rejected_with_413() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};

    let (_reserved, dead) = crate::test_support::refusing_addr();

    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "test_selected_upstream_expand",
            crate::FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(SelectedUpstreamExpandFilter {
                    upstream_addr: dead,
                    output: b"OVERSIZED_OUTPUT_THAT_IS_DELIBERATELY_LONGER_THAN_THE_SIXTY_FOUR_BYTE_STREAM_BUFFER_LIMIT_XXXX",
                }))
            })),
        )
        .unwrap();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str("- filter: test_selected_upstream_expand").unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    let request = crate::SubRequest {
        method: http::Method::POST,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::from_static(b"tiny"),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let response = match executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("run should return the 413 rejection")
    {
        crate::CalloutResponse::Buffered(response) => response,
        crate::CalloutResponse::Streaming { .. } => panic!("a 413 rejection must be buffered"),
    };

    assert_eq!(
        response.status, 413,
        "adapted output over the effective limit is rejected with 413 before dialing"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities: selected-upstream body-phase re-pin and retained-state ceiling
// -----------------------------------------------------------------------------

// A malicious selected-upstream body filter that rewrites `ctx.upstream` during
// the body phase — after the pre-phase re-pin — to redirect a body already
// adapted for the pinned destination. The executor's post-phase re-pin must
// defeat it, one boundary later than the request-phase UpstreamHijackFilter.
struct SelectedUpstreamBodyHijackFilter {
    redirect_to: std::net::SocketAddr,
}

#[async_trait::async_trait]
impl crate::HttpFilter for SelectedUpstreamBodyHijackFilter {
    fn name(&self) -> &'static str {
        "test_selected_upstream_body_hijack"
    }

    // No-op: the staged upstream (seeded from extensions) is the pinned
    // destination; the rewrite happens later, in the body phase.
    async fn on_request(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        Ok(crate::FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> crate::BodyMode {
        crate::BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<bytes::Bytes>,
    ) -> Result<crate::SelectedUpstreamBodyOutcome, crate::FilterError> {
        ctx.upstream = Some(praxis_core::connectivity::Upstream {
            address: std::sync::Arc::from(self.redirect_to.to_string().as_str()),
            authority: None,
            connection: std::sync::Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });
        Ok(crate::SelectedUpstreamBodyOutcome::Continue)
    }
}

// Retained-state accounting mirroring the IRR's `IterationAccounting`: it caps
// the bytes retained in `IterationState`. Lets a unit test prove the executor
// enforces the ceiling at the selected-upstream body boundary like every other
// boundary, without reaching into the router's private accounting type.
struct IterationStateCeiling {
    max_state_bytes: usize,
}

impl super::RetainedStateAccounting for IterationStateCeiling {
    fn exceeds_limit(&self, extensions: &crate::RequestExtensions) -> bool {
        extensions
            .get::<crate::IterationState>()
            .is_some_and(|state| state.retained_bytes() > self.max_state_bytes)
    }
}

// Selects a fixed upstream in `on_request` and, during the selected-upstream body
// phase, inserts an oversized `IterationState` — the retained-state growth the
// executor's post-phase accounting check must reject with 413 before dialing.
struct SelectedUpstreamStateExpandFilter {
    upstream_addr: std::net::SocketAddr,
    accumulator_bytes: usize,
}

#[async_trait::async_trait]
impl crate::HttpFilter for SelectedUpstreamStateExpandFilter {
    fn name(&self) -> &'static str {
        "test_selected_upstream_state_expand"
    }

    async fn on_request(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        ctx.upstream = Some(praxis_core::connectivity::Upstream {
            address: std::sync::Arc::from(self.upstream_addr.to_string().as_str()),
            authority: None,
            connection: std::sync::Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });
        Ok(crate::FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> crate::BodyMode {
        crate::BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<bytes::Bytes>,
    ) -> Result<crate::SelectedUpstreamBodyOutcome, crate::FilterError> {
        let mut accumulator = std::collections::HashMap::new();
        accumulator.insert(
            "bloat".to_owned(),
            bytes::Bytes::from(vec![b'x'; self.accumulator_bytes]),
        );
        ctx.extensions.insert(crate::IterationState {
            original_request: praxis_core::subrequest::SubRequest {
                method: http::Method::POST,
                uri: http::Uri::from_static("/"),
                headers: HeaderMap::new(),
                body: bytes::Bytes::new(),
            },
            previous_response: None,
            accumulator,
            iteration: 0,
            max_iterations: 1,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(5),
            max_response_bytes: 1_048_576,
            depth: 0,
        });
        Ok(crate::SelectedUpstreamBodyOutcome::Continue)
    }
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn selected_upstream_phase_re_pins_staged_upstream_over_body_filter_rewrite() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};

    let (staged_addr, staged_backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nstaged").await;
    let (attacker_addr, attacker_backend) =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhijack").await;

    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "test_selected_upstream_body_hijack",
            crate::FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(SelectedUpstreamBodyHijackFilter {
                    redirect_to: attacker_addr,
                }))
            })),
        )
        .unwrap();
    let mut entries: Vec<crate::FilterEntry> =
        serde_yaml::from_str("- filter: test_selected_upstream_body_hijack").unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    let staged = super::StagedUpstream(praxis_core::connectivity::Upstream {
        address: Arc::from(staged_addr.to_string().as_str()),
        authority: None,
        connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        tls: None,
    });
    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(staged);

    let request = crate::SubRequest {
        method: http::Method::POST,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::from_static(b"adapted"),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let response = match executor
        .run(&pipeline, &request, extensions, deadline)
        .await
        .expect("run should dial the staged address and return its response")
    {
        crate::CalloutResponse::Buffered(response) => response,
        crate::CalloutResponse::Streaming { .. } => {
            panic!("a buffered outbound chain must not produce a streaming response")
        },
    };
    staged_backend.abort();
    attacker_backend.abort();

    assert_eq!(response.status, 200);
    assert_eq!(
        response.body,
        bytes::Bytes::from_static(b"staged"),
        "the executor must re-pin the staged address after the selected-upstream body phase, so a \
         body filter's `ctx.upstream` rewrite cannot redirect the callout to the attacker backend"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn selected_upstream_phase_enforces_retained_state_ceiling() {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};

    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let (backend_addr, backend) =
        spawn_capturing_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Arc::clone(&captured)).await;

    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "test_selected_upstream_state_expand",
            crate::FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(SelectedUpstreamStateExpandFilter {
                    upstream_addr: backend_addr,
                    accumulator_bytes: 4096,
                }))
            })),
        )
        .unwrap();
    let mut entries: Vec<crate::FilterEntry> =
        serde_yaml::from_str("- filter: test_selected_upstream_state_expand").unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor = crate::FilteredSubrequestExecutor::new(
        Box::new(IterationStateCeiling { max_state_bytes: 64 }),
        client,
        0,
        downstream,
        1_048_576,
        1_048_576,
        Duration::from_secs(5),
    );

    let request = crate::SubRequest {
        method: http::Method::POST,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::from_static(b"tiny"),
    };
    let deadline = Instant::now() + Duration::from_secs(5);

    let response = match executor
        .run(&pipeline, &request, crate::RequestExtensions::default(), deadline)
        .await
        .expect("run should return the 413 rejection")
    {
        crate::CalloutResponse::Buffered(response) => response,
        crate::CalloutResponse::Streaming { .. } => panic!("a 413 rejection must be buffered"),
    };
    backend.abort();

    assert_eq!(
        response.status, 413,
        "retained state grown past the ceiling during the selected-upstream body phase is \
         rejected with 413"
    );
    assert!(
        captured.lock().unwrap().is_empty(),
        "the ceiling must reject the oversized retained state BEFORE dialing: the upstream must \
         never be contacted, so a body-authenticated request cannot cross the wire before the \
         413. A non-empty capture means the executor dialed first and only rejected \
         post-transport"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities: binding restore
// -----------------------------------------------------------------------------

#[cfg(feature = "upstream-binding")]
/// Records the binding it sees, then replaces it with a child binding and
/// clears the freeze, optionally failing afterwards.
struct RebindChildFilter {
    seen: std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>>,
    fails: bool,
}

#[cfg(feature = "upstream-binding")]
#[async_trait::async_trait]
impl crate::HttpFilter for RebindChildFilter {
    fn name(&self) -> &'static str {
        "test_rebind_child"
    }

    async fn on_request(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
    ) -> Result<crate::FilterAction, crate::FilterError> {
        self.seen.lock().unwrap().push(ctx.bound_cluster().map(str::to_owned));
        ctx.extensions.insert(crate::extensions::BoundUpstream::new(
            std::sync::Arc::from("child"),
            None,
            None,
        ));
        ctx.extensions.remove::<crate::extensions::BoundUpstreamFrozen>();
        if self.fails {
            return Err("child step failed".to_owned().into());
        }
        Ok(crate::FilterAction::Continue)
    }
}

#[cfg(feature = "upstream-binding")]
/// A pipeline whose first filter rebinds, then routes to `addr`.
fn rebinding_pipeline(
    addr: std::net::SocketAddr,
    seen: &std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>>,
    fails: bool,
) -> std::sync::Arc<crate::FilterPipeline> {
    let mut registry = crate::FilterRegistry::with_builtins();
    let recorder = std::sync::Arc::clone(seen);
    registry
        .register(
            "test_rebind_child",
            crate::FilterFactory::Http(std::sync::Arc::new(move |_| {
                Ok(Box::new(RebindChildFilter {
                    seen: std::sync::Arc::clone(&recorder),
                    fails,
                }))
            })),
        )
        .unwrap();
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(&format!(
        r#"
- filter: test_rebind_child
- filter: router
  routes:
    - path_prefix: "/"
      cluster: backend
- filter: load_balancer
  clusters:
    - name: backend
      endpoints: ["{addr}"]
"#
    ))
    .unwrap();
    std::sync::Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap())
}

/// Request extensions carrying a frozen parent binding.
#[cfg(feature = "upstream-binding")]
fn frozen_parent_extensions() -> crate::RequestExtensions {
    let mut extensions = crate::RequestExtensions::default();
    extensions.insert(crate::extensions::BoundUpstream::new(
        std::sync::Arc::from("parent"),
        None,
        None,
    ));
    extensions.insert(crate::extensions::BoundUpstreamFrozen);
    extensions
}

#[cfg(feature = "upstream-binding")]
/// A callout executor over a test connector.
fn test_callout_executor() -> crate::FilteredSubrequestExecutor {
    let client = praxis_core::subrequest::SubRequestClient::new(crate::test_support::connector(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, std::time::Instant::now());
    crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, std::time::Duration::from_secs(5))
}
