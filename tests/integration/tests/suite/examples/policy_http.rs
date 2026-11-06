// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration test for the experimental generic-HTTP policy
//! authorization example (`examples/configs/security/policy-http.yaml`).
//!
//! Exercises the `policy` filter in its pure-L7 (`http_global`) shape
//! end-to-end against the policy's `global` block (admit only GET). Three cases
//! prove the full chain:
//!
//! * **Allow** — GET with a valid HS256 JWT resolves identity, the global policy admits GET, and the request reaches
//!   the backend (HTTP 200).
//! * **Deny (authz)** — POST with a valid JWT is denied by the global policy; the `denyWith` produces a plain HTTP 403
//!   with the custom body + header (not a JSON-RPC envelope).
//! * **Deny (identity)** — a request with no `Authorization` header is rejected at the identity gate (HTTP 401).
//!
//! Together these exercise the request-line attributes, the structured
//! denyWith carrier, the non-entity authz path, and the pure-L7
//! (`http_global`) deny mapping.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_status, patch_yaml, start_backend_with_shutdown, start_proxy,
};

// Identity parameters mirrored from
// `tests/integration/fixtures/http-policy.yaml`.
const FIXTURE_ISSUER: &str = "https://idp.example.com";
const FIXTURE_AUDIENCE: &str = "praxis-policy-example";
const FIXTURE_SECRET: &str = "REPLACE-WITH-A-PROPERLY-RANDOM-SHARED-SECRET-DO-NOT-COMMIT";

/// Mint an HS256 JWT accepted by the fixture's `jwt-user` plugin.
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

/// Load the policy-http example, rewrite the operator `config_path` to
/// the in-repo fixture, and patch ports.
#[expect(clippy::needless_pass_by_value, reason = "callers construct the map inline")]
fn load_example(proxy_port: u16, port_map: HashMap<&str, u16>) -> Config {
    let praxis_yaml_path = example_config_path("security/policy-http.yaml");
    let policy_yaml_path = format!("{}/fixtures/http-policy.yaml", env!("CARGO_MANIFEST_DIR"));

    let raw = std::fs::read_to_string(&praxis_yaml_path).unwrap_or_else(|e| panic!("read {praxis_yaml_path}: {e}"));
    let with_policy = raw.replace("/etc/praxis/http-policy.yaml", &policy_yaml_path);
    let patched = patch_yaml(&with_policy, proxy_port, &port_map);
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/policy-http.yaml: {e}"))
}

fn backend_map(port: u16) -> HashMap<&'static str, u16> {
    HashMap::from([("127.0.0.1:3000", port)])
}

#[test]
fn policy_http_get_with_valid_jwt_passes_through() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("alice");
    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET /widgets HTTP/1.1\r\n\
             Host: localhost\r\n\
             Authorization: Bearer {token}\r\n\
             Connection: close\r\n\
             \r\n",
        ),
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "GET with a valid JWT should be admitted by the global policy and reach the backend;\n{raw}",
    );
    assert!(
        raw.contains("ok"),
        "backend body should reach the client on allow;\n{raw}"
    );
}

#[test]
fn policy_http_post_denied_with_custom_response() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    // Valid identity, but POST is denied by the global policy (GET-only).
    let token = mint_fixture_jwt("alice");
    let body = "{}";
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST /widgets HTTP/1.1\r\n\
             Host: localhost\r\n\
             Authorization: Bearer {token}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len(),
        ),
    );

    assert_eq!(
        parse_status(&raw),
        403,
        "POST should be denied by the global policy with the custom denyWith status;\n{raw}",
    );
    let lower = raw.to_lowercase();
    assert!(
        lower.contains("x-authz-denied: method-not-allowed"),
        "custom denyWith header expected;\n{raw}"
    );
    assert!(
        raw.contains("only GET is permitted"),
        "custom denyWith body expected;\n{raw}"
    );
    assert!(
        lower.contains("x-policy-violation:"),
        "violation code header expected;\n{raw}"
    );
}

#[test]
fn policy_http_missing_authorization_rejects_401() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /widgets HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n",
    );

    assert_eq!(
        parse_status(&raw),
        401,
        "a request with no Authorization should hit the identity gate;\n{raw}",
    );
    assert!(
        raw.to_lowercase().contains("www-authenticate: bearer"),
        "401 must carry WWW-Authenticate;\n{raw}",
    );
}

#[test]
fn policy_http_large_opaque_get_streams_after_authorization() {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        time::Duration,
    };

    use praxis_test_utils::{PayloadSpec, read_h1_response, start_counting_backend, start_full_proxy, wait_for_tcp};

    let spec = PayloadSpec::binary(10_485_760, 27);
    let backend = start_counting_backend(spec.clone(), "policy-http", spec.len());
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port));
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let token = mint_fixture_jwt("alice");
    let mut stream = TcpStream::connect(proxy.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(stream, "GET /widgets HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", spec.len()).unwrap();
    let initial = spec.chunk(0, 65_536);
    stream.write_all(&initial).unwrap();
    stream.flush().unwrap();
    backend
        .first_byte
        .recv_timeout(Duration::from_secs(10))
        .expect("authorized stream must reach the backend before the rest is sent");
    send_payload_tail(&mut stream, &spec, u64::try_from(initial.len()).unwrap());
    let response = read_h1_response(&mut BufReader::new(stream), false, 0, |_| Ok(()));
    assert_eq!(response.status, Some(200));
    assert!(response.completion.is_some(), "response must complete: {response:?}");
    let receipt = backend.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(receipt.bytes, spec.len());
    assert_eq!(receipt.verified_bytes, spec.len());
    assert_eq!(receipt.mismatch, None);
    assert!(receipt.completion.is_some());
    assert_eq!(receipt.abort, None);
    backend.join();
}

#[test]
fn policy_http_denies_large_header_only_requests_without_upstream_dispatch() {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        sync::mpsc::TryRecvError,
        time::Duration,
    };

    use praxis_test_utils::{PayloadSpec, read_h1_response, start_counting_backend, start_full_proxy, wait_for_tcp};

    for (method, credential, expected_status) in [("GET", false, 401), ("POST", true, 403)] {
        let spec = PayloadSpec::binary(10_485_760, 81);
        let backend = start_counting_backend(spec, "denied", 10_485_760);
        let proxy_port = free_port();
        let config = load_example(proxy_port, backend_map(backend.port));
        let proxy = start_full_proxy(&config);
        wait_for_tcp(proxy.addr());
        let authorization = if credential {
            format!("Authorization: Bearer {}\r\n", mint_fixture_jwt("alice"))
        } else {
            String::new()
        };
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(stream, "{method} /widgets HTTP/1.1\r\nHost: localhost\r\n{authorization}Content-Length: 10485760\r\nConnection: close\r\n\r\n").unwrap();
        stream.flush().unwrap();
        let mut body = Vec::new();
        let response = read_h1_response(&mut BufReader::new(stream), false, 65_536, |chunk| {
            body.extend_from_slice(chunk);
            Ok(())
        });
        assert_eq!(response.status, Some(expected_status));
        assert!(
            response.completion.is_some(),
            "denial must complete without waiting for body: {response:?}"
        );
        if expected_status == 401 {
            assert!(response.headers.iter().any(|(name, value)| name == "www-authenticate" && value.to_ascii_lowercase().starts_with("bearer")));
        } else {
            assert!(
                body.windows(b"only GET is permitted".len())
                    .any(|window| window == b"only GET is permitted")
            );
        }
        assert!(matches!(backend.accepted.try_recv(), Err(TryRecvError::Empty)));
        backend.join();
    }
}

#[test]
fn policy_http_preread_authorizes_on_first_chunk_without_repeating_admission() {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        sync::{
            Arc,
            mpsc::{self, TryRecvError},
        },
        time::Duration,
    };

    use praxis_filter::{FilterFactory, FilterRegistry};
    use praxis_test_utils::{
        PayloadSpec, read_h1_response, start_counting_backend, start_full_proxy_with_registry, wait_for_tcp,
    };

    let spec = PayloadSpec::binary(1_048_576, 52);
    let backend = start_counting_backend(spec.clone(), "protected", spec.len());
    let proxy_port = free_port();
    let mut config = load_example(proxy_port, backend_map(backend.port));
    let observer = serde_yaml::from_str("filter: policy_body_probe").unwrap();
    config.filter_chains[0].filters.insert(1, observer);
    let (events, observed) = mpsc::channel();
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "policy_body_probe",
            FilterFactory::Http(Arc::new(move |_| {
                let filter: Box<dyn praxis_filter::HttpFilter> = Box::new(PolicyBodyProbe { events: events.clone() });
                Ok(filter)
            })),
        )
        .unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);
    wait_for_tcp(proxy.addr());

    for (method, credential, expected) in [("GET", false, 401), ("POST", true, 403)] {
        let auth = if credential {
            format!("Authorization: Bearer {}\r\n", mint_fixture_jwt("alice"))
        } else {
            String::new()
        };
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            stream,
            "{method} /widgets HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n",
            spec.len()
        )
        .unwrap();
        stream.write_all(&spec.chunk(0, 1)).unwrap();
        stream.flush().unwrap();
        let response = read_h1_response(&mut BufReader::new(stream), false, 65_536, |_| Ok(()));
        assert_eq!(response.status, Some(expected));
        assert!(response.completion.is_some());
        assert!(
            matches!(observed.try_recv(), Err(TryRecvError::Empty)),
            "denied requests must not reach the downstream body observer"
        );
        assert!(matches!(backend.accepted.try_recv(), Err(TryRecvError::Empty)));
    }

    let token = mint_fixture_jwt("alice");
    let mut stream = TcpStream::connect(proxy.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(stream, "GET /widgets HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", spec.len()).unwrap();
    stream.write_all(&spec.chunk(0, 1)).unwrap();
    stream.flush().unwrap();
    assert_eq!(
        observed.recv_timeout(Duration::from_secs(10)).unwrap(),
        PolicyProbeEvent::Body {
            subject: Some("alice".to_owned()),
            end_of_stream: false
        }
    );
    assert!(matches!(backend.accepted.try_recv(), Err(TryRecvError::Empty)));
    send_payload_tail(&mut stream, &spec, 1);
    let response = read_h1_response(&mut BufReader::new(stream), false, 0, |_| Ok(()));
    assert_eq!(response.status, Some(200));
    assert!(response.completion.is_some());
    assert_eq!(
        observed.recv_timeout(Duration::from_secs(10)).unwrap(),
        PolicyProbeEvent::Headers { subject: None },
        "policy must not re-publish identity during the later header phase"
    );
    assert!(
        matches!(observed.try_recv(), Err(TryRecvError::Empty)),
        "the body probe should complete once"
    );
    let receipt = backend.receipt.recv_timeout(Duration::from_secs(20)).unwrap();
    assert_eq!(receipt.bytes, spec.len());
    assert_eq!(receipt.verified_bytes, spec.len());
    assert_eq!(receipt.mismatch, None);
    assert!(receipt.completion.is_some());
    assert_eq!(receipt.abort, None);
    backend.join();
}

/// Observer events used to verify body-first identity admission and re-entry.
#[derive(Debug, Eq, PartialEq)]
enum PolicyProbeEvent {
    /// Identity visible to the first body callback.
    Body {
        subject: Option<String>,
        end_of_stream: bool,
    },
    /// Identity visible when request headers are subsequently processed.
    Headers { subject: Option<String> },
}

/// Forces a pre-read and observes the policy's public identity projection.
struct PolicyBodyProbe {
    /// Delivers callback observations to the test.
    events: std::sync::mpsc::Sender<PolicyProbeEvent>,
}

#[async_trait::async_trait]
impl praxis_filter::HttpFilter for PolicyBodyProbe {
    fn name(&self) -> &'static str {
        "policy_body_probe"
    }

    fn request_body_access(&self) -> praxis_filter::BodyAccess {
        praxis_filter::BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> praxis_filter::BodyMode {
        praxis_filter::BodyMode::StreamBuffer {
            max_bytes: Some(2_097_152),
        }
    }

    async fn on_request(
        &self,
        ctx: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        let subject = ctx
            .extensions
            .get::<praxis_filter::AuthenticatedIdentity>()
            .map(|identity| identity.subject_id().to_owned());
        self.events.send(PolicyProbeEvent::Headers { subject }).unwrap();
        Ok(praxis_filter::FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut praxis_filter::HttpFilterContext<'_>,
        _body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        let subject = ctx
            .extensions
            .remove::<praxis_filter::AuthenticatedIdentity>()
            .map(|identity| identity.subject_id().to_owned());
        self.events
            .send(PolicyProbeEvent::Body { subject, end_of_stream })
            .unwrap();
        Ok(praxis_filter::FilterAction::BodyDone)
    }
}

/// Write the remaining generated request bytes after an explicitly sent prefix.
fn send_payload_tail(stream: &mut std::net::TcpStream, spec: &praxis_test_utils::PayloadSpec, mut offset: u64) {
    use std::io::Write as _;
    while offset < spec.len() {
        let chunk = spec.chunk(offset, 65_536);
        stream.write_all(&chunk).unwrap();
        offset += u64::try_from(chunk.len()).unwrap();
    }
}
