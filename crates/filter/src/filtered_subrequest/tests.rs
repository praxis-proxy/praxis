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

// ---------------------------------------------------------------------------
// Public callout entry point (run)
// ---------------------------------------------------------------------------

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn run_returns_buffered_for_locally_produced_response() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};

    // A bound outbound chain that terminates locally with a fixed response, so
    // the executor never has to contact a real upstream.
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

    // Construct the executor through the deliberately small public surface an
    // application callout uses.
    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor = crate::FilteredSubrequestExecutor::for_callout(
        client,
        downstream,
        0,         // depth
        1_048_576, // 1 MiB per-response ceiling
        Duration::from_secs(5),
    );

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

// ---------------------------------------------------------------------------
// Test Utilities: session-store propagation recorder
// ---------------------------------------------------------------------------

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

    use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};

    let saw_on_request = Arc::new(AtomicBool::new(false));
    let saw_on_response_body = Arc::new(AtomicBool::new(false));
    let registry = recorder_registry(&saw_on_request, &saw_on_response_body);

    // The recorder observes the context, then a static response terminates the
    // chain locally so the executor never contacts an upstream.
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

    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
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

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn subrequest_binds_credentials_to_logical_authority_not_transport() {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};

    let captured = Arc::new(Mutex::new(Vec::new()));
    let (addr, backend) =
        spawn_capturing_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Arc::clone(&captured)).await;

    // The upstream's logical authority (`api.internal`) differs from its
    // transport endpoint (`127.0.0.1:<port>`). A credential bound to the logical
    // authority must be delivered; one bound to the transport host must not.
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

    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
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

    use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};

    let captured = Arc::new(Mutex::new(Vec::new()));
    let (addr, backend) =
        spawn_capturing_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Arc::clone(&captured)).await;

    // The cluster overrides the logical authority (`api.internal`); its transport
    // endpoint is `127.0.0.1:<port>`. Mirroring the normal proxy path's authority
    // override, the upstream must receive the logical authority as its Host — not
    // the transport address, and not a stale inbound Host.
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

    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
    let downstream = crate::SubrequestRuntime::new(None, false, None, Instant::now());
    let executor =
        crate::FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, Duration::from_secs(5));

    // A stale inbound Host must not survive an authority override.
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

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn subrequest_credential_injection_pins_host_to_credential_authority() {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};

    let captured = Arc::new(Mutex::new(Vec::new()));
    let (addr, backend) =
        spawn_capturing_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Arc::clone(&captured)).await;

    // No authority override: the credential is authorized against the transport
    // endpoint. A stale inbound Host must NOT survive to the upstream, or a
    // shared-vhost endpoint could route the injected secret to a different vhost
    // than the one the credential was authorized for.
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

    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
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

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn subrequest_unmatched_staged_credential_preserves_custom_host() {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};

    let captured = Arc::new(Mutex::new(Vec::new()));
    let (addr, backend) =
        spawn_capturing_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Arc::clone(&captured)).await;

    // No authority override: the logical authority equals the transport endpoint.
    // A credential is staged, but bound to a *different* authority that never
    // matches this destination, so nothing is injected. A caller-set Host that
    // selects a virtual host must survive untouched — pinning the Host to the
    // transport only when a secret is actually delivered, never for a staged
    // credential that matched nothing.
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

    let client = SubRequestClient::new(SubRequestConnector::new(1, None));
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

// ---------------------------------------------------------------------------
// Test Utilities: streaming callout harness
// ---------------------------------------------------------------------------

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
#[derive(Debug, PartialEq, Eq)]
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

    use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};

    let client = SubRequestClient::new(SubRequestConnector::new(4, None));
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

    // A ceiling below the upstream chunk size forces the body to reject it.
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

    // A 20-byte upstream body (hex chunk length 14), behind a chain whose
    // completion hook emits a 14-byte terminal event at EOF.
    let (addr, backend) = spawn_raw_backend(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n14\r\nAAAAAAAAAAAAAAAAAAAA\r\n0\r\n\r\n",
    )
    .await;
    let registry = callout_registry();
    let mut entries: Vec<crate::FilterEntry> =
        serde_yaml::from_str(&routed_chain_yaml(addr, "- filter: test_terminal_event\n")).unwrap();
    let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());

    // 20 bytes of body cannot fit under a 15-byte ceiling however the upstream
    // frames it, so some chunk must be rejected. A rejected chunk is never
    // emitted and so never advances `emitted_bytes` — leaving room for the
    // 14-byte completion event to pass the check afterwards. A stream that kept
    // running would therefore resume around the hole and hand the caller a body
    // with a gap in it instead of an error-terminated one.
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

    // Pull until the ceiling rejects a chunk, whatever framing the upstream used.
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

    // Chunked framing that promises a large chunk, then closes mid-payload.
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
    // The completion filter rejects at end-of-stream, so `suppress` (which runs
    // the completion lifecycle) fails.
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

    // Suppressing the body runs the completion lifecycle, which the guardrail
    // rejects, so `suppress` surfaces an error.
    let suppressed = body.suppress().await;
    assert!(
        suppressed.is_err(),
        "a completion-phase rejection must surface from suppress: {suppressed:?}"
    );

    // Despite the error, the caller-injected extension must survive the body's
    // inner->held transition so the parent request context can recover it.
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

    // The streaming harness needs the streaming selector plus the recorder.
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
