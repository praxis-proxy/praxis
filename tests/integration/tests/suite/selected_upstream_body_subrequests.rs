// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the selected-upstream request-body phase in the
//! filtered-subrequest / iterative_request_router path (#1138): the phase runs
//! after each step selects an upstream, its adapted body is what the step
//! forwards and frames, adaptation runs exactly once per step (no compounding),
//! rejections short-circuit before dialing, and selected-cluster metadata is
//! isolated across steps.

use std::sync::Arc;

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
    Rejection, SelectedUpstreamBodyOutcome,
};
use praxis_test_utils::{
    free_port, http_post, http_send, parse_body, parse_status, start_echo_backend, start_full_proxy_with_registry,
    start_header_echo_backend,
};

// -----------------------------------------------------------------------------
// Test Participant Filters (public API only)
// -----------------------------------------------------------------------------

/// Appends a fixed non-idempotent marker to the request body during the
/// selected-upstream phase (mirrors the #1191 append-marker participant).
struct AppendMarkerFilter;

#[async_trait::async_trait]
impl HttpFilter for AppendMarkerFilter {
    fn name(&self) -> &'static str {
        "test_su_append_marker"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        let mut bytes = body.as_ref().map_or_else(Vec::new, |b| b.to_vec());
        bytes.extend_from_slice(b"|adapted");
        *body = Some(Bytes::from(bytes));
        Ok(SelectedUpstreamBodyOutcome::Continue)
    }
}

/// Replaces the body with an oversized payload, exceeding a 64-byte StreamBuffer.
struct ExpandFilter;

#[async_trait::async_trait]
impl HttpFilter for ExpandFilter {
    fn name(&self) -> &'static str {
        "test_su_expand"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(64) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        *body = Some(Bytes::from_static(
            b"OVERSIZED_OUTPUT_THAT_IS_DELIBERATELY_LONGER_THAN_THE_SIXTY_FOUR_BYTE_STREAM_BUFFER_LIMIT_XXXX",
        ));
        Ok(SelectedUpstreamBodyOutcome::Continue)
    }
}

/// Rejects with 403 during the selected-upstream phase (read-only participant).
struct RejectFilter;

#[async_trait::async_trait]
impl HttpFilter for RejectFilter {
    fn name(&self) -> &'static str {
        "test_su_reject"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        Ok(SelectedUpstreamBodyOutcome::Reject(Rejection::status(403)))
    }
}

/// Rejects with 409 during the selected-upstream phase iff a selected-application
/// provider is visible — turning a cross-step metadata leak into an observable
/// status so a test can assert isolation through the public reader.
struct ProviderLeakGuardFilter;

#[async_trait::async_trait]
impl HttpFilter for ProviderLeakGuardFilter {
    fn name(&self) -> &'static str {
        "test_su_provider_leak_guard"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        if ctx.selected_application_provider().is_some() {
            return Ok(SelectedUpstreamBodyOutcome::Reject(Rejection::status(409)));
        }
        Ok(SelectedUpstreamBodyOutcome::Continue)
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

// `irr_yaml` in iterative_request_router.rs is private to that module; integration
// modules do not share private utilities, so this file builds its own IRR config
// strings inline (mirroring the config shapes in iterative_request_router.rs).

fn register(name: &'static str, make: fn() -> Box<dyn HttpFilter>) -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(name, FilterFactory::Http(Arc::new(move |_config| Ok(make()))))
        .unwrap();
    registry
}

#[test]
fn irr_step_adapts_body_and_forwards_adapted_bytes() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        initial_step: primary
        steps:
          - name: primary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: backend
              - filter: load_balancer
                clusters:
                  - name: backend
                    endpoints: ["127.0.0.1:{}"]
              - filter: test_su_append_marker
            on_result:
              - default: true
                done: true
"#,
        backend.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = register("test_su_append_marker", || Box::new(AppendMarkerFilter));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "hello");

    assert_eq!(status, 200);
    // Exactly one marker proves the phase ran once in the step and its adapted
    // output is what the step forwarded upstream.
    assert_eq!(body, "hello|adapted", "the step forwards the adapted body");
    assert_eq!(
        body.matches("|adapted").count(),
        1,
        "the phase runs exactly once per step"
    );
}

#[test]
fn irr_step_recomputes_content_length_and_strips_transfer_encoding() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        initial_step: primary
        steps:
          - name: primary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: backend
              - filter: load_balancer
                clusters:
                  - name: backend
                    endpoints: ["127.0.0.1:{}"]
              - filter: test_su_append_marker
            on_result:
              - default: true
                done: true
"#,
        backend.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = register("test_su_append_marker", || Box::new(AppendMarkerFilter));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    // Canonical "hello" is 5 bytes; adapted "hello|adapted" is 13 bytes.
    let raw = http_send(
        proxy.addr(),
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "chunked request with adapted body succeeds");
    let echoed = parse_body(&raw);
    let lines: Vec<&str> = echoed
        .lines()
        .filter(|l| l.trim_start().to_ascii_lowercase().starts_with("content-length:"))
        .collect();
    assert_eq!(lines.len(), 1, "exactly one content-length upstream, got:\n{echoed}");
    assert!(
        lines[0].to_ascii_lowercase().contains("13"),
        "content-length must reflect the adapted length (13), got {:?}",
        lines[0]
    );
    assert!(
        !echoed
            .to_ascii_lowercase()
            .lines()
            .any(|l| l.trim_start().starts_with("transfer-encoding:")),
        "transfer-encoding must not survive alongside the stamped content-length:\n{echoed}"
    );
}

#[test]
fn irr_adapts_each_step_input_exactly_once_without_compounding() {
    let backend_a = start_echo_backend();
    let backend_b = start_echo_backend();
    let proxy_port = free_port();
    // Step `primary` transitions to `secondary`; each step appends the marker to
    // its OWN input. `secondary`'s input is the original request body (the IRR
    // defaults the next iteration body to the original when no filter sets a next
    // body), so a correct implementation appends one marker per step and never
    // feeds a step's adapted output into the next. The final response is
    // `secondary`'s echoed body: exactly one marker proves no compounding.
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        initial_step: primary
        steps:
          - name: primary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: a
              - filter: load_balancer
                clusters:
                  - name: a
                    endpoints: ["127.0.0.1:{}"]
              - filter: test_su_append_marker
            on_result:
              - default: true
                next: secondary
          - name: secondary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: b
              - filter: load_balancer
                clusters:
                  - name: b
                    endpoints: ["127.0.0.1:{}"]
              - filter: test_su_append_marker
            on_result:
              - default: true
                done: true
"#,
        backend_a.port(),
        backend_b.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = register("test_su_append_marker", || Box::new(AppendMarkerFilter));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "hello");

    assert_eq!(status, 200);
    assert_eq!(
        body.matches("|adapted").count(),
        1,
        "each step adapts its own input exactly once; adaptation must not compound across steps (got {body:?})"
    );
}

#[test]
fn irr_step_does_not_observe_prior_step_provider() {
    let backend_a = start_echo_backend();
    let backend_b = start_echo_backend();
    let proxy_port = free_port();
    // `primary` selects a provider-tagged cluster; `secondary` selects an
    // untagged cluster and guards against observing any provider. If the tagged
    // provider leaked across the step boundary, `secondary` would reject with
    // 409. A 200 proves per-step isolation (the leak guard saw no provider).
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        initial_step: primary
        steps:
          - name: primary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: a
              - filter: load_balancer
                clusters:
                  - name: a
                    endpoints: ["127.0.0.1:{}"]
                    http:
                      application_provider: prova
            on_result:
              - default: true
                next: secondary
          - name: secondary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: b
              - filter: load_balancer
                clusters:
                  - name: b
                    endpoints: ["127.0.0.1:{}"]
              - filter: test_su_provider_leak_guard
            on_result:
              - default: true
                done: true
"#,
        backend_a.port(),
        backend_b.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = register("test_su_provider_leak_guard", || Box::new(ProviderLeakGuardFilter));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/echo", "hello");

    assert_eq!(
        status, 200,
        "the second step must not observe the first step's selected-application provider"
    );
}

#[test]
fn irr_step_reject_short_circuits_before_dialing() {
    let dead_backend = free_port();
    let proxy_port = free_port();
    // No backend on `dead_backend`: a dial would surface as 5xx. The phase
    // rejection returns 403 locally, proving it short-circuits before dialing.
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        initial_step: primary
        steps:
          - name: primary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: backend
              - filter: load_balancer
                clusters:
                  - name: backend
                    endpoints: ["127.0.0.1:{dead_backend}"]
              - filter: test_su_reject
            on_result:
              - default: true
                done: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = register("test_su_reject", || Box::new(RejectFilter));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/echo", "blocked");

    assert_eq!(status, 403, "the phase rejection returns 403, not a 5xx from a dial");
}

#[test]
fn irr_step_oversized_adapted_output_is_rejected_with_413() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        initial_step: primary
        steps:
          - name: primary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: backend
              - filter: load_balancer
                clusters:
                  - name: backend
                    endpoints: ["127.0.0.1:{}"]
              - filter: test_su_expand
            on_result:
              - default: true
                done: true
"#,
        backend.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = register("test_su_expand", || Box::new(ExpandFilter));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/echo", "tiny");

    assert_eq!(
        status, 413,
        "adapted output over the effective limit is rejected with 413"
    );
}

mod payload_child_limits {
    use std::{
        io::{BufRead as _, BufReader, Read as _, Write as _},
        net::{TcpListener, TcpStream},
        sync::{Arc, mpsc},
        thread,
        time::Duration,
    };

    use bytes::Bytes;
    use praxis_core::config::Config;
    use praxis_filter::{
        BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext, SelectedUpstreamBodyOutcome,
    };
    use praxis_test_utils::{
        free_port, http_send, parse_body, parse_status, read_h1_response, registry_with, start_echo_backend,
        start_full_proxy_with_registry, wait_for_tcp,
    };

    struct LargeMarker;

    /// A completed step can replace the next step's canonical request body.
    struct ReplaceNextBody;

    #[async_trait::async_trait]
    impl HttpFilter for ReplaceNextBody {
        fn name(&self) -> &'static str {
            "replace_next_body"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            ctx.extensions
                .insert(praxis_filter::NextIterationBody(Bytes::from(vec![b'y'; 8192])));
            Ok(FilterAction::Continue)
        }
    }

    #[async_trait::async_trait]
    impl HttpFilter for LargeMarker {
        fn name(&self) -> &'static str {
            "large_child_marker"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn selected_upstream_request_body_access(&self) -> BodyAccess {
            BodyAccess::ReadWrite
        }

        fn request_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer {
                max_bytes: Some(131_072),
            }
        }

        async fn on_selected_upstream_request_body(
            &self,
            _ctx: &mut HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
        ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
            let mut bytes = body.as_ref().map_or_else(Vec::new, |bytes| bytes.to_vec());
            bytes.extend_from_slice(b"|child");
            *body = Some(Bytes::from(bytes));
            Ok(SelectedUpstreamBodyOutcome::Continue)
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Response {
        ExactChunked,
        OverflowChunked,
        CloseDelimited,
        TruncatedLength,
    }

    /// Received child request bytes and whether an oversized response was cancelled.
    type ChildReceipt = (Vec<u8>, bool);
    /// The one-shot child's port, receipt channel and worker.
    type ChildHandle = (u16, mpsc::Receiver<ChildReceipt>, thread::JoinHandle<()>);

    fn child(response: Response) -> ChildHandle {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, received) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut reader = BufReader::new(stream);
            let mut length = None;
            loop {
                let mut line = String::new();
                assert_ne!(
                    reader.read_line(&mut line).unwrap(),
                    0,
                    "child request headers must complete"
                );
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    length = Some(value.trim().parse::<usize>().unwrap());
                }
            }
            let mut request = vec![0; length.unwrap()];
            reader.read_exact(&mut request).unwrap();
            match response {
                Response::ExactChunked | Response::OverflowChunked => {
                    reader
                        .get_mut()
                        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n400\r\n")
                        .unwrap();
                    reader.get_mut().write_all(&vec![b'r'; 1024]).unwrap();
                    if matches!(response, Response::ExactChunked) {
                        reader.get_mut().write_all(b"\r\n0\r\n\r\n").unwrap();
                    } else {
                        reader.get_mut().write_all(b"\r\n1\r\nz\r\n").unwrap();
                    }
                },
                Response::CloseDelimited => {
                    reader
                        .get_mut()
                        .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                        .unwrap();
                    reader.get_mut().write_all(&vec![b'r'; 1025]).unwrap();
                },
                Response::TruncatedLength => {
                    reader
                        .get_mut()
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9999\r\n\r\npartial")
                        .unwrap();
                },
            }
            reader.get_mut().flush().unwrap();
            let cancelled = if matches!(response, Response::OverflowChunked) {
                let mut byte = [0];
                match reader.read(&mut byte) {
                    Ok(0) => true,
                    Err(error) => matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                    ),
                    Ok(_) => false,
                }
            } else {
                false
            };
            sender.send((request, cancelled)).unwrap();
        });
        (port, received, worker)
    }

    fn yaml(proxy: u16, child: u16, probe: u16) -> String {
        format!(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        conditions:
          - when:
              headers:
                x-child: "yes"
        initial_step: child
        max_response_bytes: 1024
        steps:
          - name: child
            filters:
              - filter: router
                routes:
                  - path_prefix: "/probe"
                    cluster: probe
                  - path_prefix: "/"
                    cluster: child
              - filter: load_balancer
                clusters:
                  - name: child
                    endpoints: ["127.0.0.1:{child}"]
                  - name: probe
                    endpoints: ["127.0.0.1:{probe}"]
              - filter: large_child_marker
            on_result:
              - default: true
                done: true
"#
        )
    }

    fn post(addr: &str, body: &[u8]) -> (Option<u16>, Vec<u8>, bool) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            stream,
            "POST /echo HTTP/1.1\r\nHost: localhost\r\nX-Child: yes\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
        let mut output = Vec::new();
        let response = read_h1_response(&mut BufReader::new(stream), false, 4096, |chunk| {
            output.extend_from_slice(chunk);
            Ok(())
        });
        (
            response.status,
            output,
            response.completion.is_some() && response.abort.is_none(),
        )
    }

    fn probe(addr: &str) {
        let response = http_send(
            addr,
            "POST /probe HTTP/1.1\r\nHost: localhost\r\nX-Child: yes\r\nContent-Length: 5\r\nConnection: close\r\n\r\nclean",
        );
        assert_eq!(parse_status(&response), 200, "clean request should succeed");
        assert_eq!(
            parse_body(&response),
            "clean|child",
            "the probe must retain child adaptation"
        );
    }

    #[test]
    fn child_responses_are_bounded_and_never_complete_as_truncated_success() {
        for scenario in [
            Response::ExactChunked,
            Response::OverflowChunked,
            Response::CloseDelimited,
            Response::TruncatedLength,
        ] {
            let (child_port, received, worker) = child(scenario);
            let clean = start_echo_backend();
            let proxy_port = free_port();
            let config = Config::from_yaml(&yaml(proxy_port, child_port, clean.port())).unwrap();
            let registry = registry_with("large_child_marker", || Box::new(LargeMarker));
            let proxy = start_full_proxy_with_registry(&config, &registry);
            wait_for_tcp(proxy.addr());
            let request = vec![b'x'; 65_537];
            let (status, body, complete) = post(proxy.addr(), &request);
            let (received_body, cancelled) = received.recv_timeout(Duration::from_secs(8)).unwrap();
            worker.join().unwrap();
            let mut expected = request;
            expected.extend_from_slice(b"|child");
            assert_eq!(
                received_body, expected,
                "child received the full adapted request: {scenario:?}"
            );
            assert!(complete, "parent response must finish: {scenario:?}");
            if matches!(scenario, Response::ExactChunked) {
                assert_eq!(status, Some(200));
                assert_eq!(body, vec![b'r'; 1024]);
            } else {
                assert_eq!(status, Some(502), "child failure must propagate: {scenario:?}");
                assert_ne!(
                    body,
                    vec![b'r'; 1024],
                    "a truncated prefix cannot be a successful child response"
                );
            }
            if matches!(scenario, Response::OverflowChunked) {
                assert!(cancelled, "overflow must close the child's session");
            }
            probe(proxy.addr());
        }
    }

    #[test]
    fn large_adaptation_is_isolated_between_iterations() {
        check_iteration_payload(false);
        check_iteration_payload(true);
    }

    fn check_iteration_payload(replace_next: bool) {
        use praxis_test_utils::{PayloadSpec, start_counting_backend};

        let spec = PayloadSpec::padded(65_543, b"", b"|child", b'x').unwrap();
        let first = start_counting_backend(spec.clone(), "first", 70_000);
        let second_spec = if replace_next {
            PayloadSpec::padded(8198, b"", b"|child", b'y').unwrap()
        } else {
            spec
        };
        let second = start_counting_backend(second_spec, "second", 70_000);
        let proxy_port = free_port();
        let yaml = format!(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        initial_step: first
        max_iterations: 2
        steps:
          - name: first
            filters:
              - filter: router
                routes:
                  - path_prefix: /
                    cluster: first
              - filter: load_balancer
                clusters:
                  - name: first
                    endpoints: ["127.0.0.1:{}"]
              - filter: large_child_marker
            on_result:
              - default: true
                next: second
          - name: second
            filters:
              - filter: router
                routes:
                  - path_prefix: /
                    cluster: second
              - filter: load_balancer
                clusters:
                  - name: second
                    endpoints: ["127.0.0.1:{}"]
              - filter: large_child_marker
            on_result:
              - default: true
                done: true
"#,
            first.port, second.port
        );
        let yaml = if replace_next {
            yaml.replacen(
                "              - filter: large_child_marker\n            on_result:",
                "              - filter: large_child_marker\n              - filter: replace_next_body\n            on_result:",
                1,
            )
        } else {
            yaml
        };
        let config = Config::from_yaml(&yaml).unwrap();
        let mut registry = registry_with("large_child_marker", || Box::new(LargeMarker));
        registry
            .register(
                "replace_next_body",
                praxis_filter::FilterFactory::Http(Arc::new(|_| Ok(Box::new(ReplaceNextBody)))),
            )
            .unwrap();
        let proxy = start_full_proxy_with_registry(&config, &registry);
        wait_for_tcp(proxy.addr());
        let (status, body, complete) = post(proxy.addr(), &vec![b'x'; 65_537]);
        assert_eq!(status, Some(200), "both child steps must succeed");
        assert!(
            complete && body.is_empty(),
            "terminal response must complete with an empty body"
        );
        for (backend, expected_len) in [(first, 65_543), (second, if replace_next { 8198 } else { 65_543 })] {
            let receipt = backend.receipt.recv_timeout(Duration::from_secs(3)).unwrap();
            assert_eq!(
                receipt.bytes, expected_len,
                "child must receive its expected body length"
            );
            assert_eq!(
                receipt.verified_bytes, expected_len,
                "child must verify the entire body"
            );
            assert!(
                receipt.mismatch.is_none() && receipt.completion.is_some() && receipt.abort.is_none(),
                "child body and framing must complete: {receipt:?}"
            );
            backend.join();
        }
    }

    #[test]
    fn http2_child_overflow_terminates_after_receiving_adapted_body() {
        check_http2_overflow(false);
        check_http2_overflow(true);
    }

    fn check_http2_overflow(advertise_large_length: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let child_port = listener.local_addr().unwrap().port();
        let (sender, received) = mpsc::channel();
        let worker = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(Box::pin(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (socket, _) = Box::pin(listener.accept()).await.unwrap();
                let mut connection = Box::pin(h2::server::handshake(socket)).await.unwrap();
                let (request_tx, mut requests) = tokio::sync::mpsc::channel(1);
                let driver = tokio::spawn(Box::pin(async move {
                    while let Some(Ok(exchange)) = Box::pin(connection.accept()).await {
                        if request_tx.send(exchange).await.is_err() {
                            break;
                        }
                    }
                }));
                let (request, mut respond) = Box::pin(requests.recv()).await.unwrap();
                let mut request_body = request.into_body();
                let mut body = Vec::new();
                while let Some(chunk) = Box::pin(request_body.data()).await {
                    let chunk = chunk.unwrap();
                    body.extend_from_slice(&chunk);
                    request_body.flow_control().release_capacity(chunk.len()).unwrap();
                }
                let mut response = http::Response::builder().status(200);
                if advertise_large_length {
                    response = response.header(http::header::CONTENT_LENGTH, "5000");
                }
                let response = response.body(()).unwrap();
                let mut stream = respond.send_response(response, false).unwrap();
                stream.send_data(Bytes::from(vec![b'r'; 1024]), false).unwrap();
                stream.send_data(Bytes::from_static(b"z"), false).unwrap();
                let reset = Box::pin(tokio::time::timeout(
                    Duration::from_secs(5),
                    std::future::poll_fn(|cx| stream.poll_reset(cx)),
                ))
                .await;
                sender.send((body, reset)).unwrap();
                driver.abort();
            }));
        });
        let clean = start_echo_backend();
        let proxy_port = free_port();
        let yaml = yaml(proxy_port, child_port, clean.port()).replace(
            &format!("                  - name: child\n                    endpoints: [\"127.0.0.1:{child_port}\"]"),
            &format!("                  - name: child\n                    endpoints: [\"127.0.0.1:{child_port}\"]\n                    http:\n                      version: h2"),
        );
        assert!(yaml.contains("version: h2"), "child cluster must use HTTP/2");
        let config = Config::from_yaml(&yaml).unwrap();
        let registry = registry_with("large_child_marker", || Box::new(LargeMarker));
        let proxy = start_full_proxy_with_registry(&config, &registry);
        wait_for_tcp(proxy.addr());
        let request = vec![b'x'; 65_537];
        let (status, body, complete) = post(proxy.addr(), &request);
        assert_eq!(status, Some(502), "child response overflow must fail");
        assert!(
            complete && body != vec![b'r'; 1024],
            "parent must complete without forwarding truncated child data"
        );
        let (received_body, reset) = received.recv_timeout(Duration::from_secs(8)).unwrap();
        worker.join().unwrap();
        let mut expected = request;
        expected.extend_from_slice(b"|child");
        assert_eq!(
            received_body, expected,
            "child must receive the complete adapted request"
        );
        assert!(
            reset.is_ok(),
            "overflow must terminate the H2 stream or connection: {reset:?}"
        );
        probe(proxy.addr());
    }
}
