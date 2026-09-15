// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! A retried upstream attempt must carry the body a `ReadWrite` request-body
//! filter rewrote during the `StreamBuffer` pre-read.
//!
//! Pingora replays the original downstream body on every attempt, and
//! `apply_mutated_content_length` frames every attempt with the rewritten
//! length, so the request-body hooks have to re-run per attempt. They stopped
//! doing so from the second retry onward, because `body_done` marks set on one
//! attempt were carried into the next: the replayed body then went upstream
//! unfiltered under a `Content-Length` describing the filtered one — a
//! truncated body when the rewrite shrank it, a short write when it grew.

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext};
use praxis_test_utils::{free_port, http_send, parse_status, registry_with, start_proxy_with_registry};

// -----------------------------------------------------------------------------
// Payloads
// -----------------------------------------------------------------------------

/// What the client sends: carries a secret an APL `redact()` would strip.
const ORIGINAL: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payroll","arguments":{"ssn":"111-22-3333"}}}"#;

/// A rewrite that shrinks the body.
const SHRUNK: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payroll","arguments":{}}}"#;

/// A rewrite that grows past the original length.
const GROWN: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payroll","arguments":{"ssn":"[REDACTED-BY-PPE-XXXXXXXXXXXXXXXXXXXX]"}}}"#;

// -----------------------------------------------------------------------------
// Filters
// -----------------------------------------------------------------------------

/// Stands in for `policy` under `body_access: read_write` applying a field
/// mutator: buffers the request body and replaces it at end-of-stream.
macro_rules! rewriting_filter {
    ($ty:ident, $name:literal, $access:expr, $out:expr) => {
        struct $ty;

        #[async_trait]
        impl HttpFilter for $ty {
            fn name(&self) -> &'static str {
                $name
            }

            fn request_body_access(&self) -> BodyAccess {
                $access
            }

            fn request_body_mode(&self) -> BodyMode {
                BodyMode::StreamBuffer {
                    max_bytes: Some(65_536),
                }
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
                if !end_of_stream {
                    return Ok(FilterAction::Continue);
                }
                let out: Option<&'static str> = $out;
                if let Some(out) = out
                    && body.as_ref().is_some_and(|b| !b.is_empty())
                {
                    *body = Some(Bytes::from_static(out.as_bytes()));
                }
                // Signalling BodyDone is what made the next attempt skip this
                // filter before the per-attempt reset landed.
                Ok(FilterAction::BodyDone)
            }
        }
    };
}

rewriting_filter!(BodyShrinker, "body_shrinker", BodyAccess::ReadWrite, Some(SHRUNK));
rewriting_filter!(BodyGrower, "body_grower", BodyAccess::ReadWrite, Some(GROWN));
rewriting_filter!(BodyObserver, "body_observer", BodyAccess::ReadOnly, None);

// -----------------------------------------------------------------------------
// Capturing backend
// -----------------------------------------------------------------------------

/// One upstream attempt as it arrived on the wire.
#[derive(Clone)]
struct Attempt {
    /// The `Content-Length` the proxy stamped on this attempt.
    content_length: Option<usize>,
    /// Every body byte written, drained until idle rather than truncated at
    /// `Content-Length`, so the two can be compared.
    body: Vec<u8>,
}

type Captures = Arc<Mutex<Vec<Attempt>>>;

fn header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn read_attempt(stream: &mut TcpStream) -> Option<(String, Attempt)> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];

    let header_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            },
        }
    };

    let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let path = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or_default()
        .to_owned();
    let content_length = header(&headers, "content-length").and_then(|v| v.parse::<usize>().ok());

    stream.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }

    Some((
        path,
        Attempt {
            content_length,
            body: buf[header_end..].to_vec(),
        },
    ))
}

/// Record every `/mcp` attempt, then answer with `status`.
fn start_capturing_backend(captures: &Captures, status: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let captures = Arc::clone(captures);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let captures = Arc::clone(&captures);
            thread::spawn(move || {
                let mut stream = stream;
                while let Some((path, attempt)) = read_attempt(&mut stream) {
                    if path == "/mcp" {
                        captures.lock().unwrap().push(attempt);
                    }
                    let response = if status == 200 {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_owned()
                    } else {
                        format!("HTTP/1.1 {status} Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                    };
                    if stream.write_all(response.as_bytes()).is_err() {
                        break;
                    }
                    let _flush = stream.flush();
                }
            });
        }
    });

    port
}

// -----------------------------------------------------------------------------
// Scenario
// -----------------------------------------------------------------------------

fn config_yaml(proxy_port: u16, filter: &str, endpoints: &[u16]) -> String {
    let endpoint_lines = endpoints
        .iter()
        .map(|p| format!("              - \"127.0.0.1:{p}\""))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: {filter}
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
{endpoint_lines}
            retry_policy:
              max_retries: 3
              retriable_status_codes: [503]
              allow_non_idempotent: true
              backoff:
                base_interval_ms: 1
                max_interval_ms: 2
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// Drive `requests` POSTs through `failing` 503 endpoints onto a healthy one,
/// returning every upstream attempt in arrival order.
fn run(filter_name: &'static str, make: fn() -> Box<dyn HttpFilter>, failing: usize, requests: usize) -> Vec<Attempt> {
    let captures: Captures = Arc::new(Mutex::new(Vec::new()));
    let mut endpoints: Vec<u16> = (0..failing).map(|_| start_capturing_backend(&captures, 503)).collect();
    endpoints.push(start_capturing_backend(&captures, 200));

    let proxy_port = free_port();
    let config = Config::from_yaml(&config_yaml(proxy_port, filter_name, &endpoints)).unwrap();
    let registry = registry_with(filter_name, make);
    let proxy = start_proxy_with_registry(&config, &registry);

    for k in 0..requests {
        let raw = http_send(
            proxy.addr(),
            &format!(
                "POST /mcp HTTP/1.1\r\nHost: localhost\r\nX-Req-N: {k}\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{ORIGINAL}",
                ORIGINAL.len(),
            ),
        );
        assert_eq!(
            parse_status(&raw),
            200,
            "request {k} should end on the healthy endpoint"
        );
    }

    thread::sleep(Duration::from_millis(300));
    let attempts = captures.lock().unwrap().clone();
    drop(proxy);
    attempts
}

/// Every attempt must frame exactly what it wrote, and write `expected`.
fn assert_every_attempt_carries(attempts: &[Attempt], expected: &str) {
    for (i, a) in attempts.iter().enumerate() {
        assert_eq!(
            a.content_length,
            Some(a.body.len()),
            "attempt {}: Content-Length {:?} must equal the {} bytes written",
            i + 1,
            a.content_length,
            a.body.len(),
        );
        assert_eq!(
            String::from_utf8_lossy(&a.body),
            expected,
            "attempt {}: upstream received the wrong body",
            i + 1,
        );
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn chained_retries_keep_a_shrinking_body_rewrite() {
    // Two 503 endpoints, so some requests reach a third attempt — the point
    // at which the carried-over body_done marks used to skip the rewriter.
    let attempts = run("body_shrinker", || Box::new(BodyShrinker), 2, 8);
    assert!(attempts.len() > 8, "expected retries beyond the 8 initial attempts");
    assert_every_attempt_carries(&attempts, SHRUNK);
}

#[test]
fn chained_retries_keep_a_growing_body_rewrite() {
    let attempts = run("body_grower", || Box::new(BodyGrower), 2, 8);
    assert!(attempts.len() > 8, "expected retries beyond the 8 initial attempts");
    assert_every_attempt_carries(&attempts, GROWN);
}

#[test]
fn a_single_retry_keeps_a_body_rewrite() {
    let attempts = run("body_shrinker", || Box::new(BodyShrinker), 1, 4);
    assert!(attempts.len() > 4, "expected a retry for every request");
    assert_every_attempt_carries(&attempts, SHRUNK);
}

#[test]
fn chained_retries_leave_an_unrewritten_body_alone() {
    let attempts = run("body_observer", || Box::new(BodyObserver), 2, 8);
    assert!(attempts.len() > 8, "expected retries beyond the 8 initial attempts");
    assert_every_attempt_carries(&attempts, ORIGINAL);
}
