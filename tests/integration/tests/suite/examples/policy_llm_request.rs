// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End-to-end tests for OPA and CEL rules over the parsed inference request.

use std::{
    collections::HashMap,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
};
use praxis_test_utils::{
    BackendGuard, H1Completion, PayloadSpec, example_config_path, free_port, http_get, http_send, parse_body,
    parse_header, parse_status, patch_yaml, read_h1_response, start_counting_backend, start_echo_backend,
    start_full_proxy_with_registry, start_proxy, start_stateful_backend, wait_for_tcp,
};

use crate::guardrails::{inspection_proxy, post_to_spec_with_headers};

const FIXTURE_ISSUER: &str = "https://idp.example.com";
const FIXTURE_AUDIENCE: &str = "praxis-policy-example";
const FIXTURE_SECRET: &str = "REPLACE-WITH-A-PROPERLY-RANDOM-SHARED-SECRET-DO-NOT-COMMIT";

/// Response the probe backend returns to its first caller.
const FIRST_HIT: &str = "first-hit";

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Mint a JWT accepted by the fixture.
fn mint_fixture_jwt(subject: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    let claims = serde_json::json!({
        "iss": FIXTURE_ISSUER,
        "aud": FIXTURE_AUDIENCE,
        "sub": subject,
        "iat": now,
        "exp": now + 300,
    });
    super::jwt::hs256(&claims, None, FIXTURE_SECRET.as_bytes())
}

/// Load the inference example against the structured-input fixture.
fn load_example(proxy_port: u16, backend_port: u16, max_request_bytes: Option<usize>) -> Config {
    let praxis_yaml_path = example_config_path("security/policy-llm.yaml");
    let policy_yaml_path = format!("{}/fixtures/llm-request-policy.yaml", env!("CARGO_MANIFEST_DIR"));

    let raw = std::fs::read_to_string(&praxis_yaml_path).unwrap_or_else(|e| panic!("read {praxis_yaml_path}: {e}"));
    let mut yaml = raw.replace("/etc/praxis/llm-policy.yaml", &policy_yaml_path);
    if let Some(limit) = max_request_bytes {
        yaml = yaml.replace(
            "require_model: true",
            &format!("require_model: true\n          max_request_bytes: {limit}"),
        );
    }
    let port_map = HashMap::from([("127.0.0.1:3000", backend_port)]);
    let patched = patch_yaml(&yaml, proxy_port, &port_map);
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/policy-llm.yaml: {e}"))
}

/// Send an authenticated JSON `POST` and return the raw response.
fn post_json(addr: &str, path: &str, body: &str) -> String {
    let token = mint_fixture_jwt("agent");
    http_send(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Authorization: Bearer {token}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len(),
        ),
    )
}

/// A backend that answers [`FIRST_HIT`] only to the first request it sees.
fn start_probe_backend() -> BackendGuard {
    start_stateful_backend(vec![(200, FIRST_HIT.to_owned())])
}

/// Assert that nothing reached `backend` by claiming its first response.
fn assert_backend_untouched(backend: &BackendGuard) {
    let (status, body) = http_get(&format!("127.0.0.1:{}", backend.port()), "/", None);
    assert_eq!(
        (status, body.as_str()),
        (200, FIRST_HIT),
        "the probe must still hold its first response, so no request reached upstream",
    );
}

/// Assert an allowed request reached upstream byte for byte.
fn assert_forwarded_unchanged(path: &str, body: &str) {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let proxy = start_proxy(&load_example(proxy_port, backend.port(), None));

    let raw = post_json(proxy.addr(), path, body);
    assert_eq!(parse_status(&raw), 200, "raw response:\n{raw}");
    assert_eq!(parse_body(&raw), body, "upstream must receive the exact request bytes");
}

/// Assert a request is denied with 403 and never forwarded.
fn assert_denied_unforwarded(path: &str, body: &str) -> String {
    let backend = start_probe_backend();
    let proxy_port = free_port();
    let proxy = start_proxy(&load_example(proxy_port, backend.port(), None));

    let raw = post_json(proxy.addr(), path, body);
    assert_eq!(parse_status(&raw), 403, "raw response:\n{raw}");
    assert_backend_untouched(&backend);
    raw
}

/// A Chat Completions body for `model` whose tools are named `tools`.
fn chat_body(model: &str, tools: &[&str]) -> String {
    let tools: Vec<_> = tools
        .iter()
        .map(|name| serde_json::json!({"type": "function", "function": {"name": name}}))
        .collect();
    serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": "pay the invoice"}],
        "tools": tools,
    })
    .to_string()
}

/// A Chat Completions body for `model` using the legacy `functions` list.
fn legacy_functions_body(model: &str, functions: &[&str]) -> String {
    let functions: Vec<_> = functions.iter().map(|name| serde_json::json!({"name": name})).collect();
    serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": "pay the invoice"}],
        "functions": functions,
    })
    .to_string()
}

/// A Responses body whose `input` is one user message and whose tools are flat.
fn responses_body(tools: &[&str]) -> String {
    let tools: Vec<_> = tools
        .iter()
        .map(|name| serde_json::json!({"type": "function", "name": name}))
        .collect();
    serde_json::json!({
        "model": "responses-cel",
        "input": [{"role": "user", "content": [{"type": "input_text", "text": "pay the invoice"}]}],
        "tools": tools,
    })
    .to_string()
}

/// Responses tool history carrying `text` in each formerly skipped field.
fn responses_tool_history(text: &str) -> [serde_json::Value; 7] {
    [
        serde_json::json!({"type": "custom_tool_call_output", "call_id": "c1", "output": text}),
        serde_json::json!({
            "type": "mcp_call", "id": "mcp1", "name": "lookup", "server_label": "server",
            "arguments": "{}", "output": text,
        }),
        serde_json::json!({
            "type": "mcp_call", "id": "mcp1", "name": "lookup", "server_label": "server",
            "arguments": serde_json::json!({"q": text}).to_string(), "output": "result",
        }),
        serde_json::json!({"type": "file_search_call", "results": [{"text": text}]}),
        serde_json::json!({"type": "code_interpreter_call", "code": text}),
        serde_json::json!({"type": "code_interpreter_call", "outputs": [{"type": "logs", "logs": text}]}),
        serde_json::json!({"type": "mcp_list_tools", "tools": [{"name": "lookup", "description": text}]}),
    ]
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn large_inference_tail_is_authorized_by_policy_before_upstream() {
    let size = 1_048_700;
    let prefix = br#"{"padding":""#;
    let blocked_tail = br#"","model":"chat-cel","tools":[{"function":{"name":"transfer_funds"}}]}"#;
    let clean_tail = br#"","model":"chat-cel","tools":[{"function":{"name":"transfer_fundx"}}]}"#;
    let blocked = PayloadSpec::padded(size, prefix, blocked_tail, b'x').unwrap();
    let clean = PayloadSpec::padded(size, prefix, clean_tail, b'x').unwrap();
    let backend = start_counting_backend(clean.clone(), "inference", size);
    let proxy = inspection_proxy(&load_example(free_port(), backend.port, None));
    let token = mint_fixture_jwt("agent");
    let headers = format!("Authorization: Bearer {token}\r\nContent-Type: application/json\r\n");
    let path = "/v1/chat/completions";
    assert_eq!(
        post_to_spec_with_headers(proxy.addr(), path, &blocked, 16_384, &headers, || {
            assert!(matches!(
                backend.accepted.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
        }),
        Some(403)
    );
    assert!(matches!(backend.accepted.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert_eq!(
        post_to_spec_with_headers(proxy.addr(), path, &clean, 16_384, &headers, || {}),
        Some(200)
    );
    let receipt = backend.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(
        (receipt.bytes, receipt.verified_bytes, receipt.completion),
        (size, size, Some(H1Completion::ContentLength))
    );
    assert_eq!(receipt.mismatch, None);
    backend.join();
}

#[test]
fn inference_example_accepts_its_exact_default_limit_and_rejects_one_over() {
    let prefix = br#"{"padding":""#;
    let suffix = br#"","model":"chat-cel","tools":[]}"#;
    let exact = PayloadSpec::padded(10_485_760, prefix, suffix, b'x').unwrap();
    let over = PayloadSpec::padded(10_485_761, prefix, suffix, b'x').unwrap();
    let backend = start_counting_backend(exact.clone(), "inference-boundary", exact.len());
    let proxy = inspection_proxy(&load_example(free_port(), backend.port, None));
    let token = mint_fixture_jwt("agent");
    let headers = format!("Authorization: Bearer {token}\r\nContent-Type: application/json\r\n");
    let path = "/v1/chat/completions";
    assert_eq!(
        post_to_spec_with_headers(proxy.addr(), path, &over, 16_384, &headers, || {}),
        Some(413)
    );
    assert!(matches!(backend.accepted.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert_eq!(
        post_to_spec_with_headers(proxy.addr(), path, &exact, 16_384, &headers, || {
            assert!(matches!(
                backend.accepted.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
        }),
        Some(200)
    );
    let receipt = backend.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(
        (receipt.bytes, receipt.verified_bytes, receipt.completion),
        (exact.len(), exact.len(), Some(H1Completion::ContentLength))
    );
    assert_eq!(receipt.mismatch, None);
    backend.join();
}

#[test]
fn large_duplicate_and_malformed_inference_bodies_fail_for_different_reasons() {
    let padding = "x".repeat(900_000);
    let valid_duplicate = format!(r#"{{"model":"chat-cel","padding":"{padding}","mo\u0064el":"chat-opa"}}"#);
    let malformed_duplicate = format!(r#"{{"model":"chat-cel","padding":"{padding}","mo\u0064el":"chat-opa""#);
    let no_model = format!(r#"{{"padding":"{padding}"}}"#);
    let wrong_model = format!(r#"{{"padding":"{padding}","model":123}}"#);
    for (body, expected_status, expected_violation) in [
        (valid_duplicate, 400, "llm.duplicate_key"),
        (malformed_duplicate, 403, "llm.model_missing"),
        (no_model, 403, "llm.model_missing"),
        (wrong_model, 403, "llm.model_missing"),
    ] {
        let backend = start_probe_backend();
        let proxy = inspection_proxy(&load_example(free_port(), backend.port(), None));
        let raw = post_json(proxy.addr(), "/v1/chat/completions", &body);
        assert_eq!(parse_status(&raw), expected_status);
        assert_eq!(
            parse_header(&raw, "x-policy-violation").as_deref(),
            Some(expected_violation)
        );
        assert_backend_untouched(&backend);
    }
}

#[test]
fn large_ambiguous_json_rpc_and_model_is_denied_before_the_inference_route() {
    let size = 1_048_700;
    let ambiguous = PayloadSpec::padded(
        size,
        br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"},"padding":""#,
        br#"","model":"chat-cel"}"#,
        b'x',
    )
    .unwrap();
    let clean = PayloadSpec::padded(size, br#"{"padding":""#, br#"","model":"chat-cel","tools":[]}"#, b'x').unwrap();
    let backend = start_counting_backend(clean.clone(), "inference-control", size);
    let proxy = inspection_proxy(&load_example(free_port(), backend.port, None));
    let body = String::from_utf8(ambiguous.chunk(0, usize::try_from(size).unwrap())).unwrap();
    assert_eq!(body.len(), usize::try_from(size).unwrap());
    let denied = post_json(proxy.addr(), "/v1/chat/completions", &body);
    assert_eq!(parse_status(&denied), 403);
    assert_eq!(
        parse_header(&denied, "x-policy-violation").as_deref(),
        Some("llm.ambiguous_entity")
    );
    assert!(matches!(backend.accepted.try_recv(), Err(mpsc::TryRecvError::Empty)));

    let token = mint_fixture_jwt("agent");
    let headers = format!("Authorization: Bearer {token}\r\nContent-Type: application/json\r\n");
    assert_eq!(
        post_to_spec_with_headers(proxy.addr(), "/v1/chat/completions", &clean, 16_384, &headers, || {}),
        Some(200)
    );
    let receipt = backend.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(
        (receipt.bytes, receipt.verified_bytes, receipt.completion),
        (size, size, Some(H1Completion::ContentLength))
    );
    assert_eq!(receipt.mismatch, None);
    backend.join();
}

/// Configure a content-type gate with an explicit local denial for everything else.
fn gated_inference_config(port: u16, backend: u16, policy: &str) -> Config {
    Config::from_yaml(&format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 415
        body: unsupported
        conditions:
          - unless:
              headers:
                content-type: application/json
      - filter: policy
        config_path: "{policy}"
        llm:
          require_model: true
          provider: openai
        conditions:
          - when:
              headers:
                content-type: application/json
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:{backend}"]
insecure_options:
  allow_private_endpoints: true
  skip_pipeline_checks:
    conditional_security: true
"#
    ))
    .unwrap()
}

#[test]
fn gated_policy_rejects_overlong_model_and_excluded_content_type() {
    let directory = tempfile::TempDir::new().unwrap();
    let model = "m".repeat(256);
    let overlong = format!("{model}m");
    let original = std::fs::read_to_string(format!(
        "{}/fixtures/llm-request-policy.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let fixture = original.replace("  - llm: chat-cel\n", &format!("  - llm: {model}\n"));
    let policy_path = directory.path().join("long-model.yaml");
    std::fs::write(&policy_path, fixture).unwrap();
    let make = |chosen: &str, tool: &str| {
        let suffix = format!(r#"","model":"{chosen}","tools":[{{"function":{{"name":"{tool}"}}}}]}}"#);
        PayloadSpec::padded(1_048_000, br#"{"padding":""#, suffix.as_bytes(), b'x').unwrap()
    };
    let clean = make(&model, "lookup");
    let denied = make(&model, "transfer_funds");
    let invalid = make(&overlong, "lookup");
    let backend = start_counting_backend(clean.clone(), "gated-inference", clean.len());
    let config = gated_inference_config(free_port(), backend.port, policy_path.to_str().unwrap());
    let proxy = inspection_proxy(&config);
    for (payload, expected_missing) in [(&invalid, true), (&denied, false)] {
        let body = String::from_utf8(payload.chunk(0, usize::try_from(payload.len()).unwrap())).unwrap();
        let response = post_json(proxy.addr(), "/v1/chat/completions", &body);
        assert_eq!(parse_status(&response), 403);
        assert_eq!(
            parse_header(&response, "x-policy-violation").as_deref() == Some("llm.model_missing"),
            expected_missing
        );
        assert!(matches!(backend.accepted.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }
    let token = mint_fixture_jwt("agent");
    let excluded = format!("Authorization: Bearer {token}\r\nContent-Type: text/plain\r\nX-Model: {model}\r\n");
    assert_eq!(
        post_to_spec_with_headers(proxy.addr(), "/v1/chat/completions", &clean, 16_384, &excluded, || {}),
        Some(415)
    );
    assert!(matches!(backend.accepted.try_recv(), Err(mpsc::TryRecvError::Empty)));
    let included = format!("Authorization: Bearer {token}\r\nContent-Type: application/json\r\n");
    assert_eq!(
        post_to_spec_with_headers(proxy.addr(), "/v1/chat/completions", &clean, 16_384, &included, || {}),
        Some(200)
    );
    let receipt = backend.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(
        (
            receipt.bytes,
            receipt.verified_bytes,
            receipt.completion,
            receipt.mismatch
        ),
        (clean.len(), clean.len(), Some(H1Completion::ContentLength), None)
    );
    backend.join();
}

/// Test-only classifier: parse the complete JSON-RPC envelope to supply the
/// same metadata that a deployed protocol classifier supplies to policy.
struct PayloadMcpClassifier {
    calls: Arc<AtomicUsize>,
}

/// Each fixture owns its classifier counter, so tests can run concurrently.
fn payload_classifier_registry() -> (FilterRegistry, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "payload_mcp_classifier",
            FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(PayloadMcpClassifier {
                    calls: Arc::clone(&counter),
                }))
            })),
        )
        .unwrap();
    (registry, calls)
}

/// Start the custom-classifier fixture without forwarding an HTTP readiness probe.
fn start_mutation_proxy(config: &Config, registry: &FilterRegistry) -> praxis_test_utils::ProxyGuard {
    let proxy = start_full_proxy_with_registry(config, registry);
    wait_for_tcp(proxy.addr());
    proxy
}

#[async_trait::async_trait]
impl HttpFilter for PayloadMcpClassifier {
    fn name(&self) -> &'static str {
        "payload_mcp_classifier"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(2_097_152),
        }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        let value: serde_json::Value = serde_json::from_slice(body.as_deref().unwrap()).unwrap();
        assert_eq!(value["method"], "tools/call", "fixture must classify a tool call");
        assert_eq!(value["params"]["name"], "echo", "fixture must classify the echo tool");
        ctx.set_metadata("mcp.method", "tools/call");
        ctx.set_metadata("mcp.name", "echo");
        Ok(FilterAction::BodyDone)
    }
}

/// Make an authenticated, read-write policy with actual argument/result masks.
fn payload_mutation_policy(dir: &tempfile::TempDir) -> String {
    let fixture = std::fs::read_to_string(format!(
        "{}/fixtures/llm-request-policy.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let preamble = fixture.split_once("\nroutes:").unwrap().0;
    let path = dir.path().join("mutation-policy.yaml");
    std::fs::write(
        &path,
        format!(
            r#"{preamble}
routes:
  - tool: echo
    authorization:
      pre_invocation:
        - cel:
            expr: "args.stage == 'after'"
    args:
      ssn: "str | mask(2)"
    result:
      ssn: "str | mask(2)"
"#
        ),
    )
    .unwrap();
    path.to_string_lossy().into_owned()
}

/// Proxy configuration with a real policy and a test-only classifier.
fn payload_mutation_config(port: u16, backend: u16, policy: &str, policy_first: bool) -> Config {
    let rewrite = r#"      - filter: json_body
        request_replace:
          - pointer: /params/arguments/stage
            value: after
        max_body_bytes: 2097152
        on_invalid: reject
"#;
    let before = if policy_first { "" } else { rewrite };
    let after = if policy_first { rewrite } else { "" };
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: payload_mcp_classifier
{before}      - filter: policy
        config_path: "{policy}"
        body_access: read_write
        max_buffer_bytes: 2097152
{after}      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:{backend}"]
insecure_options:
  allow_private_endpoints: true
"#
    );
    Config::from_yaml(&yaml).unwrap()
}

#[test]
fn large_policy_mutations_preserve_http_framing_and_redact_both_directions() {
    for chunked in [false, true] {
        let directory = tempfile::TempDir::new().unwrap();
        let policy = payload_mutation_policy(&directory);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let backend_port = listener.local_addr().unwrap().port();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (observed_tx, observed_rx) = mpsc::channel();
        let backend = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            accepted_tx.send(()).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            let mut reader = BufReader::new(stream);
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(!line.is_empty());
                if line == "\r\n" {
                    break;
                }
                headers.push_str(&line);
            }
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            assert!(!headers.to_ascii_lowercase().contains("transfer-encoding:"));
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            observed_tx.send((length, body)).unwrap();
            let response = format!(
                r#"{{"jsonrpc":"2.0","id":1,"result":{{"structuredContent":{{"padding":"{}","ssn":"123-45-6789"}}}}}}"#,
                "x".repeat(900_000)
            );
            let stream = reader.get_mut();
            if chunked {
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                    response.len(),
                    response
                )
                .unwrap();
            } else {
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                )
                .unwrap();
            }
            response.len()
        });
        let (registry, calls) = payload_classifier_registry();
        let proxy = start_mutation_proxy(
            &payload_mutation_config(free_port(), backend_port, &policy, false),
            &registry,
        );
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"echo","arguments":{{"padding":"{}","ssn":"123-45-6789","stage":"before"}}}}}}"#,
            "x".repeat(900_000)
        );
        let token = mint_fixture_jwt("agent");
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        write!(stream, "POST /rpc HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", request.len()).unwrap();
        stream.write_all(&request.as_bytes()[..request.len() - 1]).unwrap();
        assert!(
            matches!(
                accepted_rx.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "no dispatch before EOS"
        );
        stream.write_all(&request.as_bytes()[request.len() - 1..]).unwrap();
        let mut response = Vec::new();
        let result = read_h1_response(&mut BufReader::new(stream), false, 2_097_152, |part| {
            response.extend_from_slice(part);
            Ok(())
        });
        assert_eq!(result.status, Some(200));
        assert!(result.completion.is_some());
        let (length, request_body) = observed_rx.recv_timeout(Duration::from_secs(30)).unwrap();
        assert_eq!(request_body.len(), length);
        assert!(!request_body.windows(11).any(|part| part == b"123-45-6789"));
        let parsed: serde_json::Value = serde_json::from_slice(&request_body).unwrap();
        assert_eq!(parsed["params"]["arguments"]["padding"], "x".repeat(900_000));
        assert_eq!(parsed["params"]["arguments"]["stage"], "after");
        assert_ne!(parsed["params"]["arguments"]["ssn"], "123-45-6789");
        let response_len = backend.join().unwrap();
        assert_eq!(response.len(), response_len);
        assert!(!response.windows(11).any(|part| part == b"123-45-6789"));
        let parsed: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(parsed["result"]["structuredContent"]["padding"], "x".repeat(900_000));
        assert_ne!(parsed["result"]["structuredContent"]["ssn"], "123-45-6789");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn policy_before_rewrite_denies_original_arguments_and_allows_a_clean_probe() {
    let directory = tempfile::TempDir::new().unwrap();
    let policy = payload_mutation_policy(&directory);
    // A valid upstream error is unchanged by result inspection. A plain-text
    // receipt would itself be rejected by this response-inspecting policy.
    let reply = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"complete"}}"#;
    let (backend_port, accepted, received, backend) = resize_backend();
    let (registry, calls) = payload_classifier_registry();
    let proxy = start_mutation_proxy(
        &payload_mutation_config(free_port(), backend_port, &policy, true),
        &registry,
    );
    let body = |stage: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"echo","arguments":{{"padding":"{}","ssn":"123-45-6789","stage":"{stage}"}}}}}}"#,
            "x".repeat(900_000)
        )
    };
    let denied = post_json(proxy.addr(), "/rpc", &body("before"));
    assert_eq!(parse_status(&denied), 200);
    let denied_json: serde_json::Value = serde_json::from_str(&parse_body(&denied)).unwrap();
    assert!(
        denied_json.get("error").is_some(),
        "policy must deny before the rewrite"
    );
    assert!(parse_header(&denied, "x-policy-violation").is_some());
    assert!(matches!(
        accepted.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    let allowed = post_json(proxy.addr(), "/rpc", &body("after"));
    assert_eq!(parse_status(&allowed), 200);
    assert_eq!(
        parse_body(&allowed),
        reply,
        "the denied request must not consume the backend response"
    );
    let (_headers, received_body) = received.recv_timeout(Duration::from_secs(30)).unwrap();
    let received_json: serde_json::Value = serde_json::from_slice(&received_body).unwrap();
    assert_eq!(received_json["params"]["arguments"]["stage"], "after");
    assert_eq!(received_json["params"]["arguments"]["padding"], "x".repeat(900_000));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    backend.join().unwrap();
}

/// A policy writer followed by an empty-body writer, to test their composition.
struct EmptyAfterPolicy {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl HttpFilter for EmptyAfterPolicy {
    fn name(&self) -> &'static str {
        "empty_after_policy"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream {
            let parsed: serde_json::Value = serde_json::from_slice(body.as_deref().unwrap()).unwrap();
            assert_eq!(
                parsed["params"]["arguments"]["secret"], "[REDACTED]",
                "policy must run before the empty writer"
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            *body = Some(Bytes::new());
        }
        Ok(FilterAction::Continue)
    }
}

/// Write a real tool policy that redacts or omits its `secret` argument.
fn resize_policy(dir: &tempfile::TempDir, operation: &str) -> String {
    let fixture = std::fs::read_to_string(format!(
        "{}/fixtures/llm-request-policy.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let preamble = fixture.split_once("\nroutes:").unwrap().0;
    let path = dir.path().join("resize-policy.yaml");
    std::fs::write(
        &path,
        format!(
            r#"{preamble}
routes:
  - tool: echo
    args:
      secret: "str | {operation}"
    result:
      secret: "str | redact"
"#
        ),
    )
    .unwrap();
    path.to_string_lossy().into_owned()
}

/// Configure the policy's real read-write path with a one-MiB input ceiling.
fn resize_policy_config(port: u16, backend: u16, policy: &str, empty: bool) -> Config {
    resize_policy_config_with_failure(port, backend, policy, empty, "closed")
}

/// Permit an explicit open-mode control only when the insecure override is set.
fn resize_policy_config_with_failure(port: u16, backend: u16, policy: &str, empty: bool, failure: &str) -> Config {
    let writer = if empty {
        "      - filter: empty_after_policy\n"
    } else {
        ""
    };
    let open_override = if failure == "open" {
        "  allow_open_security_filters: true\n"
    } else {
        ""
    };
    Config::from_yaml(&format!(
        r#"
body_limits:
  max_request_bytes: 1048576
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: payload_mcp_classifier
      - filter: policy
        config_path: "{policy}"
        body_access: read_write
        max_buffer_bytes: 1048576
        failure_mode: {failure}
{writer}      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:{backend}"]
insecure_options:
  allow_private_endpoints: true
{open_override}
"#
    ))
    .unwrap()
}

/// Produce an exact-length valid JSON-RPC body with the chosen secret length.
fn sized_policy_request(size: usize, secret_len: usize) -> String {
    let prefix = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"secret":""#;
    let middle = r#""}},"padding":""#;
    let suffix = r#""}"#;
    let filler = size - prefix.len() - middle.len() - suffix.len() - secret_len;
    let body = format!(
        "{prefix}{}{middle}{}{suffix}",
        "s".repeat(secret_len),
        "x".repeat(filler)
    );
    assert_eq!(
        body.len(),
        size,
        "generated policy request must have its requested size"
    );
    body
}

/// Backend endpoint, acceptance and request observations, and worker handle.
type ResizeBackend = (
    u16,
    mpsc::Receiver<()>,
    mpsc::Receiver<(String, Vec<u8>)>,
    std::thread::JoinHandle<()>,
);

/// Capture a complete Content-Length request before returning a small response.
fn resize_backend() -> ResizeBackend {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let (body_tx, body_rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        accepted_tx.send(()).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut reader = BufReader::new(stream);
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(!line.is_empty(), "request headers must finish before EOF");
            if line == "\r\n" {
                break;
            }
            headers.push_str(&line);
        }
        let lengths: Vec<usize> = headers
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .collect();
        assert_eq!(lengths.len(), 1, "{headers}");
        assert!(
            !headers.to_ascii_lowercase().contains("transfer-encoding:"),
            "resized request must not have conflicting transfer encoding"
        );
        let mut body = vec![0; lengths[0]];
        reader.read_exact(&mut body).unwrap();
        body_tx.send((headers, body)).unwrap();
        let reply = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"complete"}}"#;
        write!(
            reader.get_mut(),
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
            reply.len()
        )
        .unwrap();
    });
    (port, accepted_rx, body_rx, handle)
}

#[test]
fn policy_read_write_growth_shrink_omit_and_empty_writer_keep_framing() {
    for (label, operation, secret_len, size, empty) in [
        ("growth", "redact", 1, 1_048_544, false),
        ("shrink", "redact", 900_000, 1_048_576, false),
        ("empty_arguments", "omit", 64, 1_048_576, false),
        ("empty_body_writer", "redact", 1, 1_048_544, true),
    ] {
        let directory = tempfile::TempDir::new().unwrap();
        let policy = resize_policy(&directory, operation);
        let (backend_port, accepted, received, backend) = resize_backend();
        let (mut registry, classifier_calls) = payload_classifier_registry();
        let writer_calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&writer_calls);
        registry
            .register(
                "empty_after_policy",
                FilterFactory::Http(Arc::new(move |_| {
                    Ok(Box::new(EmptyAfterPolicy {
                        calls: Arc::clone(&counter),
                    }))
                })),
            )
            .unwrap();
        let proxy = start_mutation_proxy(
            &resize_policy_config(free_port(), backend_port, &policy, empty),
            &registry,
        );
        let input = sized_policy_request(size, secret_len);
        let expected: serde_json::Value = serde_json::from_str(&input).unwrap();
        let token = mint_fixture_jwt("agent");
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        write!(stream, "POST /rpc HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", input.len()).unwrap();
        stream.write_all(&input.as_bytes()[..input.len() - 1]).unwrap();
        assert!(
            matches!(
                accepted.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "{label}"
        );
        stream.write_all(&input.as_bytes()[input.len() - 1..]).unwrap();
        let mut reply = Vec::new();
        let response = read_h1_response(&mut BufReader::new(stream), false, 256, |chunk| {
            reply.extend_from_slice(chunk);
            Ok(())
        });
        assert_eq!(response.status, Some(200), "{label}: {response:?}");
        assert!(response.completion.is_some(), "{label}: {response:?}");
        assert_eq!(
            reply,
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"complete"}}"#
        );
        let (_headers, output) = received.recv_timeout(Duration::from_secs(30)).unwrap();
        assert_eq!(classifier_calls.load(Ordering::SeqCst), 1, "{label}");
        if empty {
            assert!(output.is_empty());
            assert_eq!(writer_calls.load(Ordering::SeqCst), 1);
        } else {
            let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(parsed["padding"], expected["padding"], "{label}");
            if operation == "omit" {
                assert_eq!(parsed["params"]["arguments"], serde_json::json!({}));
            } else {
                assert_eq!(parsed["params"]["arguments"]["secret"], "[REDACTED]");
            }
            assert_eq!(output.len() > input.len(), label == "growth", "{label}");
            assert_eq!(output.len() < input.len(), label != "growth", "{label}");
        }
        backend.join().unwrap();
    }
}

/// Send a small MCP call and collect the complete response framing and bytes.
fn policy_response_call(addr: &str) -> (praxis_test_utils::H1Response, Vec<u8>) {
    let body = sized_policy_request(256, 1);
    let token = mint_fixture_jwt("agent");
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(stream, "POST /rpc HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    let mut output = Vec::new();
    let response = read_h1_response(&mut BufReader::new(stream), false, 2_097_152, |part| {
        output.extend_from_slice(part);
        Ok(())
    });
    (response, output)
}

#[test]
fn response_rewrite_growth_fails_closed_then_clean_response_completes() {
    let directory = tempfile::TempDir::new().unwrap();
    let policy = resize_policy(&directory, "redact");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (length_tx, lengths) = mpsc::channel();
    let backend = std::thread::spawn(move || {
        for secret in ["s", "long synthetic secret"] {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            praxis_test_utils::read_http_request(&mut stream);
            let response = serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"padding":"x".repeat(900_000),"secret":secret}}}).to_string();
            length_tx.send(response.len()).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            )
            .unwrap();
        }
    });
    let (registry, calls) = payload_classifier_registry();
    let proxy = start_mutation_proxy(&resize_policy_config(free_port(), port, &policy, false), &registry);
    let (response, body) = policy_response_call(proxy.addr());
    let original_len = lengths.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(
        (response.status, response.completion, body.len()),
        (Some(200), Some(H1Completion::ContentLength), original_len)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["error"]["data"]["violation"],
        "gateway.response_rewrite_overflow"
    );
    assert!(parsed.get("result").is_none());
    assert!(!body.windows(b"\"secret\"".len()).any(|part| part == b"\"secret\""));
    let (response, body) = policy_response_call(proxy.addr());
    let clean_len = lengths.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(
        (response.status, response.completion, body.len()),
        (Some(200), Some(H1Completion::ContentLength), clean_len)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["result"]["structuredContent"]["secret"], "[REDACTED]");
    assert_eq!(parsed["result"]["structuredContent"]["padding"], "x".repeat(900_000));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    backend.join().unwrap();
}

#[test]
fn invalid_or_uninspectable_tool_responses_do_not_escape_closed_policy() {
    let directory = tempfile::TempDir::new().unwrap();
    let policy = resize_policy(&directory, "redact");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let valid = serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"padding":"x".repeat(900_000),"secret":"confidential-marker"}}}).to_string();
    let mut truncated = valid.as_bytes().to_vec();
    truncated.pop();
    let mut junk = valid.as_bytes().to_vec();
    junk.push(b'!');
    let mut invalid_utf8 = valid.into_bytes();
    *invalid_utf8.get_mut(1_000).unwrap() = 0xFF;
    let marker = format!("{}confidential-marker", "x".repeat(900_000));
    let scalar = serde_json::to_vec(&marker).unwrap();
    let array = serde_json::to_vec(&serde_json::json!([marker])).unwrap();
    let object = serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":1,"message":marker})).unwrap();
    let fake_error =
        serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"message":marker}})).unwrap();
    let error = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"upstream error"}}"#.to_vec();
    let payloads = vec![
        truncated,
        junk,
        invalid_utf8,
        scalar,
        array,
        object,
        fake_error,
        error.clone(),
    ];
    let backend = std::thread::spawn(move || {
        for payload in payloads {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            praxis_test_utils::read_http_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            )
            .unwrap();
            stream.write_all(&payload).unwrap();
        }
    });
    let (registry, calls) = payload_classifier_registry();
    let proxy = start_mutation_proxy(&resize_policy_config(free_port(), port, &policy, false), &registry);
    for variant in [
        "truncated",
        "trailing garbage",
        "invalid UTF-8",
        "scalar",
        "array",
        "object",
        "fake error",
    ] {
        let (response, body) = policy_response_call(proxy.addr());
        assert!(
            response.status != Some(200) || response.completion.is_none(),
            "{variant}: {response:?}"
        );
        assert!(
            !body
                .windows(b"confidential-marker".len())
                .any(|part| part == b"confidential-marker"),
            "{variant}"
        );
    }
    let (response, body) = policy_response_call(proxy.addr());
    assert_eq!(
        (response.status, response.completion),
        (Some(200), Some(H1Completion::ContentLength))
    );
    assert_eq!(body, error, "a valid JSON-RPC error remains untouched");
    assert_eq!(calls.load(Ordering::SeqCst), 8);
    backend.join().unwrap();
}

#[test]
fn malformed_tool_response_passes_only_when_policy_failure_mode_is_open() {
    let directory = tempfile::TempDir::new().unwrap();
    let policy = resize_policy(&directory, "redact");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let malformed = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"structuredContent":{{"padding":"{}","secret":"synthetic-marker"}}}}"#,
        "x".repeat(900_000)
    )
    .into_bytes();
    let upstream = malformed.clone();
    let backend = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        praxis_test_utils::read_http_request(&mut stream);
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            upstream.len()
        )
        .unwrap();
        stream.write_all(&upstream).unwrap();
    });
    let (registry, calls) = payload_classifier_registry();
    let proxy = start_mutation_proxy(
        &resize_policy_config_with_failure(free_port(), port, &policy, false, "open"),
        &registry,
    );
    let (response, body) = policy_response_call(proxy.addr());
    assert_eq!(
        (response.status, response.completion),
        (Some(200), Some(H1Completion::ContentLength))
    );
    assert_eq!(body, malformed, "operator-opted fail-open forwards the original body");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    backend.join().unwrap();
}

#[test]
fn a_cel_rule_denies_a_forbidden_second_tool_before_upstream() {
    assert_denied_unforwarded(
        "/v1/chat/completions",
        &chat_body("chat-cel", &["lookup", "transfer_funds"]),
    );
}

#[test]
fn an_opa_rule_denies_a_forbidden_second_tool_before_upstream() {
    assert_denied_unforwarded(
        "/v1/chat/completions",
        &chat_body("chat-opa", &["lookup", "transfer_funds"]),
    );
}

#[test]
fn a_cel_rule_forwards_permitted_tools_unchanged() {
    assert_forwarded_unchanged("/v1/chat/completions", &chat_body("chat-cel", &["lookup", "weather"]));
}

#[test]
fn an_opa_rule_forwards_permitted_tools_unchanged() {
    assert_forwarded_unchanged("/v1/chat/completions", &chat_body("chat-opa", &["lookup", "weather"]));
}

#[test]
fn a_responses_request_is_authorized_on_its_input_and_forwarded_unchanged() {
    assert_forwarded_unchanged("/v1/responses", &responses_body(&["lookup"]));
}

#[test]
fn a_responses_request_with_a_forbidden_tool_is_denied_before_upstream() {
    assert_denied_unforwarded("/v1/responses", &responses_body(&["lookup", "transfer_funds"]));
}

#[test]
fn responses_tool_history_is_subject_to_prompt_rules() {
    for text in ["SECRET-MARKER", "permitted text"] {
        for item in responses_tool_history(text) {
            let body = serde_json::json!({"model": "responses-prompt", "input": [item]}).to_string();
            if text == "SECRET-MARKER" {
                let raw = assert_denied_unforwarded("/v1/responses", &body);
                assert!(!raw.contains(text), "the denial must not echo tool history: {raw}");
            } else {
                assert_forwarded_unchanged("/v1/responses", &body);
            }
        }
    }
}

#[test]
fn a_messages_field_cannot_hide_responses_input_from_prompt_rules() {
    for messages in [serde_json::Value::Null, serde_json::json!([])] {
        let denied = serde_json::json!({"model": "responses-prompt", "messages": messages, "input": "SECRET-MARKER"})
            .to_string();
        assert_denied_unforwarded("/v1/responses", &denied);
    }
}

#[test]
fn a_denial_does_not_echo_request_content() {
    for model in ["chat-cel", "chat-opa"] {
        let body = serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": "SECRET-MARKER"}],
            "tools": [
                {"type": "function", "function": {"name": "lookup", "description": "SECRET-MARKER"}},
                {"type": "function", "function": {"name": "transfer_funds", "description": "SECRET-MARKER"}},
            ],
        })
        .to_string();
        let raw = assert_denied_unforwarded("/v1/chat/completions", &body);

        let violation = parse_header(&raw, "x-policy-violation");
        assert!(
            violation.is_some(),
            "a denial must name its violation; raw response:\n{raw}"
        );
        assert!(
            !violation.unwrap_or_default().contains("SECRET-MARKER"),
            "the violation header must not carry request content",
        );
        assert!(
            !parse_body(&raw).contains("SECRET-MARKER"),
            "the {model} denial body must not carry request content; raw response:\n{raw}",
        );
        assert!(!raw.contains("SECRET-MARKER"), "raw response:\n{raw}");
    }
}

#[test]
fn a_disconnected_inference_body_does_not_reach_upstream_or_affect_the_next_request() {
    let backend = start_probe_backend();
    let proxy_port = free_port();
    let proxy = start_proxy(&load_example(proxy_port, backend.port(), None));
    let token = mint_fixture_jwt("agent");

    let mut stream = TcpStream::connect(proxy.addr()).expect("connect to proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let partial_request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 100000\r\n\
         Connection: close\r\n\
         \r\n\
         {{\"model\":\"chat-cel\"",
    );
    stream
        .write_all(partial_request.as_bytes())
        .expect("send partial request body");
    stream
        .shutdown(Shutdown::Write)
        .expect("disconnect during body buffering");
    let mut response = Vec::new();
    let _read = stream.read_to_end(&mut response);
    drop(stream);

    let allowed = post_json(
        proxy.addr(),
        "/v1/chat/completions",
        &chat_body("chat-cel", &["lookup"]),
    );
    assert_eq!(
        parse_status(&allowed),
        200,
        "the next request must be admitted: {allowed}"
    );
    assert_eq!(
        parse_body(&allowed),
        FIRST_HIT,
        "the canceled request must not consume the backend's first response",
    );
}

#[test]
fn an_oversized_body_is_rejected_before_policy_or_upstream() {
    let backend = start_probe_backend();
    let proxy_port = free_port();
    let proxy = start_proxy(&load_example(proxy_port, backend.port(), Some(256)));

    let padding = "x".repeat(1024);
    let body = serde_json::json!({
        "model": "chat-cel",
        "messages": [{"role": "user", "content": padding}],
    })
    .to_string();
    let raw = post_json(proxy.addr(), "/v1/chat/completions", &body);

    assert_eq!(parse_status(&raw), 413, "raw response:\n{raw}");
    assert_backend_untouched(&backend);
}

#[test]
fn legacy_functions_are_guarded_like_tools() {
    for model in ["chat-cel", "chat-opa"] {
        assert_denied_unforwarded(
            "/v1/chat/completions",
            &legacy_functions_body(model, &["lookup", "transfer_funds"]),
        );
        assert_forwarded_unchanged(
            "/v1/chat/completions",
            &legacy_functions_body(model, &["lookup", "weather"]),
        );
    }
}

#[test]
fn a_body_repeating_a_key_is_rejected_before_policy_or_upstream() {
    for body in [
        r#"{"model":"chat-cel","tools":[{"type":"function","function":{"name":"transfer_funds"}}],"tools":[]}"#,
        r#"{"model":"chat-opa","tools":[{"type":"function","function":{"name":"lookup","name":"transfer_funds"}}]}"#,
        r#"{"model":"chat-cel","model":"chat-opa","messages":[]}"#,
        r#"{"model":"chat-cel","MODEL":"chat-opa","messages":[]}"#,
        r#"{"model":"chat-cel","tools":[],"Tools":[{"type":"function","function":{"name":"transfer_funds"}}]}"#,
    ] {
        let backend = start_probe_backend();
        let proxy_port = free_port();
        let proxy = start_proxy(&load_example(proxy_port, backend.port(), None));

        let raw = post_json(proxy.addr(), "/v1/chat/completions", body);
        assert_eq!(parse_status(&raw), 400, "body {body}; raw response:\n{raw}");
        assert_eq!(
            parse_header(&raw, "x-policy-violation").as_deref(),
            Some("llm.duplicate_key"),
            "raw response:\n{raw}",
        );
        assert!(
            !parse_body(&raw).contains("transfer_funds"),
            "the rejection must not echo request content; raw response:\n{raw}",
        );
        assert_backend_untouched(&backend);
    }
}
