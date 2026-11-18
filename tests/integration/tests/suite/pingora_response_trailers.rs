// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Wire regressions for final body and trailer dispatch across the HTTP adapters.

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use bytes::Bytes;
#[cfg(feature = "pingora")]
use pingora_core::protocols::http::compression::Algorithm;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyRequirement, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter,
    HttpFilterContext, Rejection,
};
use praxis_test_utils::{
    H2Response, free_port, http_send, parse_header, parse_status, read_h2_response, start_full_proxy_with_registry,
    wait_for_tcp,
};

#[derive(Clone, Copy)]
enum ProbeMode {
    Pass,
    Observe,
    NoEof,
    Error,
    ErrorNoEof,
    Convert,
    FailAtEof,
    RejectAtEof,
    FailAtEofWithoutTrailer,
    GrpcReject,
    GrpcRejectStringLength,
    GrpcRejectMapLength,
    GrpcRejectConflictingLengths,
}

struct TrailerProbe {
    eof_seen: Arc<AtomicBool>,
    mode: ProbeMode,
}

#[async_trait::async_trait]
impl HttpFilter for TrailerProbe {
    fn name(&self) -> &'static str {
        "test_pingora_trailer_probe"
    }

    fn response_body_access(&self) -> BodyAccess {
        if matches!(self.mode, ProbeMode::Observe) {
            BodyAccess::ReadOnly(BodyRequirement::Optional)
        } else {
            BodyAccess::ReadWrite(BodyRequirement::Optional)
        }
    }

    fn response_trailer_access(&self) -> bool {
        !matches!(self.mode, ProbeMode::Observe | ProbeMode::FailAtEofWithoutTrailer)
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if matches!(
            self.mode,
            ProbeMode::GrpcReject
                | ProbeMode::GrpcRejectStringLength
                | ProbeMode::GrpcRejectMapLength
                | ProbeMode::GrpcRejectConflictingLengths
        ) {
            let mut rejection = Rejection::status(200)
                .with_header("grpc-status", "7")
                .with_header("grpc-message", "denied")
                .with_header("x-safe", "kept")
                .with_header("x-duplicate", "first")
                .with_header("x-duplicate", "second")
                .with_header("te", "trailers")
                .with_header("x-praxis-secret", "hidden")
                .with_header("x-ext-protocol-secret", "hidden")
                .with_header("x-ext-agent-secret", "hidden");
            if matches!(
                self.mode,
                ProbeMode::GrpcRejectStringLength | ProbeMode::GrpcRejectConflictingLengths
            ) {
                rejection.headers.push(("Content-Length".to_owned(), "19".to_owned()));
            }
            let mut headers = http::HeaderMap::new();
            for name in ["x-praxis-map", "x-ext-protocol-map", "x-ext-agent-map", "te"] {
                headers.insert(name, http::HeaderValue::from_static("hidden"));
            }
            headers.insert("x-map-safe", http::HeaderValue::from_static("kept"));
            headers.insert("x-map-opaque", http::HeaderValue::from_bytes(b"\x80kept").unwrap());
            headers.append("x-duplicate", http::HeaderValue::from_static("third"));
            headers.append("x-duplicate", http::HeaderValue::from_static("fourth"));
            if matches!(self.mode, ProbeMode::GrpcRejectMapLength) {
                headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("19"));
            } else if matches!(self.mode, ProbeMode::GrpcRejectConflictingLengths) {
                headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("0"));
            }
            rejection.header_map = Some(Box::new(headers));
            return Ok(FilterAction::Reject(rejection));
        }
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream {
            self.eof_seen.store(true, Ordering::SeqCst);
            if matches!(self.mode, ProbeMode::FailAtEof | ProbeMode::FailAtEofWithoutTrailer) {
                return Err("synthetic EOF rejected".to_owned().into());
            }
            if matches!(self.mode, ProbeMode::RejectAtEof) {
                return Ok(FilterAction::Reject(Rejection::status(451)));
            }
            if !matches!(self.mode, ProbeMode::Observe | ProbeMode::NoEof | ProbeMode::ErrorNoEof) {
                *body = Some(Bytes::from_static(b"tail"));
            }
        }
        Ok(FilterAction::Continue)
    }

    fn on_response_trailers(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        trailers: &mut http::HeaderMap,
    ) -> Result<Option<Bytes>, FilterError> {
        match self.mode {
            ProbeMode::Pass
            | ProbeMode::Observe
            | ProbeMode::NoEof
            | ProbeMode::FailAtEof
            | ProbeMode::RejectAtEof
            | ProbeMode::FailAtEofWithoutTrailer
            | ProbeMode::GrpcReject
            | ProbeMode::GrpcRejectStringLength
            | ProbeMode::GrpcRejectMapLength
            | ProbeMode::GrpcRejectConflictingLengths => Ok(None),
            ProbeMode::Convert => Ok(Some(Bytes::from_static(b"converted"))),
            ProbeMode::Error | ProbeMode::ErrorNoEof => {
                trailers.insert("x-partial", http::HeaderValue::from_static("leak"));
                Err("trailer probe failed after mutation".to_owned().into())
            },
        }
    }
}

#[test]
#[cfg(feature = "pingora")]
fn trailer_collision_resets_h2_downstream() {
    for filter in ["json", "pass", "error"] {
        let body = if filter == "json" {
            Bytes::from_static(br#"{"public":1,"internal":2}"#)
        } else {
            Bytes::from_static(b"original")
        };
        let backend = H2TrailerBackend::start(body, false, true);
        let proxy_port = free_port();
        let eof_seen = Arc::new(AtomicBool::new(false));
        let registry = registry_with_eof(&eof_seen);
        let config = Config::from_yaml(&proxy_yaml(proxy_port, backend.port, filter)).unwrap();
        let proxy = start_full_proxy_with_registry(&config, &registry);
        let (response, _body) = h2_exchange(proxy.addr(), false);
        assert_trailer_eof_observed(&backend, &eof_seen);
        assert!(
            !response.end_stream,
            "{filter}: colliding outputs cannot complete: {response:?}"
        );
        assert!(response.reset.is_some(), "{filter}: expected H2 reset: {response:?}");
        assert!(response.trailers.is_none(), "{filter}: no success trailers after reset");
    }
}

#[test]
#[cfg(feature = "pingora")]
fn trailer_collision_after_client_data_resets_h2_downstream() {
    let gate = Arc::new(AtomicBool::new(false));
    let backend = H2TrailerBackend::start_gated(Bytes::from_static(b"original"), false, true, Some(Arc::clone(&gate)));
    let proxy_port = free_port();
    let eof_seen = Arc::new(AtomicBool::new(false));
    let registry = registry_with_eof(&eof_seen);
    let config = Config::from_yaml(&proxy_yaml(proxy_port, backend.port, "pass")).unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);
    let observed_prefix = (gate, Bytes::from_static(b"original"));
    let (response, body) = h2_exchange_with_gate(proxy.addr(), false, Some(&observed_prefix));
    assert_trailer_eof_observed(&backend, &eof_seen);
    assert_eq!(response.status, Some(200));
    assert_eq!(
        body, b"original",
        "initial DATA must arrive before backend releases trailers"
    );
    assert!(!response.end_stream, "late trailer collision cannot complete");
    assert!(response.reset.is_some(), "late collision must reset: {response:?}");
    assert!(response.trailers.is_none());
}

#[test]
#[cfg(feature = "pingora")]
fn trailer_collision_aborts_http1_response_without_success_terminator() {
    for filter in ["pass", "error"] {
        assert_http1_trailer_abort(filter, true);
    }
}

#[test]
#[cfg(feature = "pingora")]
fn synthetic_eof_failure_aborts_http1_response() {
    for filter in ["fail", "reject", "fail_without_trailer"] {
        assert_http1_trailer_abort(filter, filter != "fail_without_trailer");
    }
}

/// Commit a DATA prefix before releasing upstream trailers, then require an
/// incomplete HTTP/1 response and an unusable downstream connection.
#[cfg(feature = "pingora")]
fn assert_http1_trailer_abort(filter: &str, has_trailer: bool) {
    let gate = Arc::new(AtomicBool::new(false));
    let backend = H2TrailerBackend::start_gated(
        Bytes::from_static(b"original"),
        false,
        has_trailer,
        Some(Arc::clone(&gate)),
    );
    let eof_seen = Arc::new(AtomicBool::new(false));
    let registry = registry_with_eof(&eof_seen);
    let config = Config::from_yaml(&proxy_yaml(free_port(), backend.port, filter)).unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);
    wait_for_tcp(proxy.addr());
    let mut stream = TcpStream::connect(proxy.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
    let head = read_http1_head(&mut stream);
    assert_eq!(head.status, 200, "{filter}: response head must be committed");
    let mut body = Vec::new();
    let mut chunk = [0_u8; 512];
    while !body.windows(b"original".len()).any(|part| part == b"original") {
        let count = stream.read(&mut chunk).expect("read committed HTTP/1 DATA prefix");
        assert_ne!(count, 0, "{filter}: response ended before DATA prefix");
        body.extend_from_slice(&chunk[..count]);
    }
    gate.store(true, Ordering::SeqCst);
    if let Err(error) = stream.read_to_end(&mut body) {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset,
            "{filter}: abort must close or reset the HTTP/1 connection"
        );
    }
    assert_trailer_eof_observed(&backend, &eof_seen);
    let wire_body = String::from_utf8_lossy(&body).to_ascii_lowercase();
    assert!(wire_body.contains("original"), "{filter}: DATA prefix: {wire_body}");
    assert!(
        !wire_body.contains("\r\nx-end: done\r\n"),
        "{filter}: abort must not forward success trailers: {wire_body}"
    );
    assert_incomplete_http1_body(&head.headers, &body, filter);
    if stream
        .write_all(b"GET /again HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .is_ok()
    {
        assert!(
            !matches!(stream.read(&mut chunk), Ok(count) if count > 0),
            "{filter}: aborted connection must not answer a second request"
        );
    }
}

/// A committed success must advertise a body length that the aborted bytes
/// fail to fulfill. A close-delimited body would look like a clean response.
#[cfg(feature = "pingora")]
fn assert_incomplete_http1_body(headers: &http::HeaderMap, body: &[u8], filter: &str) {
    let encodings = headers
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .collect::<Vec<_>>();
    let lengths = headers.get_all(http::header::CONTENT_LENGTH).iter().collect::<Vec<_>>();
    let chunked = matches!(encodings.as_slice(), [encoding] if encoding.as_bytes().eq_ignore_ascii_case(b"chunked"));
    let length = match lengths.as_slice() {
        [length] => length.to_str().ok().and_then(|value| value.parse::<usize>().ok()),
        _ => None,
    };
    assert!(
        (chunked && lengths.is_empty() && !chunked_body_complete(body))
            || (encodings.is_empty() && length.is_some_and(|expected| body.len() < expected)),
        "{filter}: closed response must have incomplete chunked or fixed-length framing, headers: {headers:?}, body: {body:?}"
    );
}

/// Recognize a complete chunked message, including its terminal trailer block.
#[cfg(feature = "pingora")]
fn chunked_body_complete(mut remaining: &[u8]) -> bool {
    loop {
        let Some(line_end) = remaining.windows(2).position(|part| part == b"\r\n") else {
            return false;
        };
        let size_text = remaining[..line_end].split(|byte| *byte == b';').next().unwrap();
        let Ok(size_text) = std::str::from_utf8(size_text) else {
            return false;
        };
        let Ok(size) = usize::from_str_radix(size_text, 16) else {
            return false;
        };
        remaining = &remaining[line_end + 2..];
        if size == 0 {
            loop {
                let Some(trailer_end) = remaining.windows(2).position(|part| part == b"\r\n") else {
                    return false;
                };
                if trailer_end == 0 {
                    return true;
                }
                remaining = &remaining[trailer_end + 2..];
            }
        }
        let Some(after_chunk) = remaining.get(size..) else {
            return false;
        };
        if !after_chunk.starts_with(b"\r\n") {
            return false;
        }
        remaining = &after_chunk[2..];
    }
}

#[test]
fn trailer_none_without_eof_bytes_preserves_upstream_trailers() {
    for filter in ["no_eof", "error_no_eof"] {
        let backend = H2TrailerBackend::start(Bytes::from_static(b"original"), false, true);
        let proxy_port = free_port();
        let registry = registry();
        let config = Config::from_yaml(&proxy_yaml(proxy_port, backend.port, filter)).unwrap();
        let proxy = start_full_proxy_with_registry(&config, &registry);
        let (response, body) = h2_exchange(proxy.addr(), false);
        assert_eq!(response.status, Some(200));
        assert_eq!(body, b"original");
        assert!(response.end_stream, "{filter}: unchanged trailers must complete");
        let trailers = response.trailers.unwrap();
        assert_eq!(trailers.get("x-end"), Some(&http::HeaderValue::from_static("done")));
        assert!(
            !trailers.contains_key("x-partial"),
            "{filter}: failed trailer edits must be restored"
        );
    }
}

#[test]
fn empty_trailers_allow_final_eof_body() {
    let backend = H2TrailerBackend::start(Bytes::from_static(b"original"), false, false);
    let proxy_port = free_port();
    let registry = registry();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, backend.port, "pass")).unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);
    let (response, body) = h2_exchange(proxy.addr(), false);
    assert_eq!(response.status, Some(200));
    assert_eq!(body, b"originaltail");
    assert!(response.end_stream, "empty trailers may become final body DATA");
    assert!(response.trailers.as_ref().is_none_or(http::HeaderMap::is_empty));
}

#[test]
fn json_body_with_empty_trailers_delivers_rewrite() {
    let original = br#"{"public":1,"internal":2}"#;
    let backend = H2TrailerBackend::start(Bytes::from_static(original), false, false);
    let proxy_port = free_port();
    let registry = registry();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, backend.port, "json")).unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);
    let (response, body) = h2_exchange(proxy.addr(), false);
    let mut expected = b"{\"public\":1}".to_vec();
    expected.resize(original.len(), b' ');
    assert_eq!(response.status, Some(200));
    assert_eq!(body, expected, "JSON rewrite and padding must reach the client");
    assert!(response.end_stream);
    assert!(response.trailers.as_ref().is_none_or(http::HeaderMap::is_empty));
}

#[test]
#[cfg(feature = "pingora")]
fn deliberate_trailer_conversion_keeps_ordered_body() {
    for (filter, compressed) in [("convert", false), ("compressed_convert", true)] {
        let backend = H2TrailerBackend::start(Bytes::from_static(b"original"), false, true);
        let proxy_port = free_port();
        let registry = registry();
        let config = Config::from_yaml(&proxy_yaml(proxy_port, backend.port, filter)).unwrap();
        let proxy = start_full_proxy_with_registry(&config, &registry);
        let (response, wire_body) = h2_exchange(proxy.addr(), compressed);
        assert_eq!(response.status, Some(200));
        assert!(
            response.end_stream,
            "{filter}: converted body must complete: {response:?}"
        );
        assert!(
            response.trailers.is_none(),
            "{filter}: conversion deliberately replaces trailers"
        );
        let body = if compressed {
            assert_eq!(
                response
                    .headers
                    .as_ref()
                    .and_then(|headers| headers.get("content-encoding")),
                Some(&http::HeaderValue::from_static("gzip"))
            );
            Algorithm::Gzip
                .decompressor(true)
                .unwrap()
                .encode(&wire_body, true)
                .unwrap()
                .to_vec()
        } else {
            wire_body
        };
        assert_eq!(
            body, b"originaltailconverted",
            "{filter}: body order and one compression pass"
        );
    }
}

#[test]
fn synthetic_eof_failure_resets_h2_downstream() {
    for filter in ["fail", "reject", "fail_without_trailer"] {
        let backend = H2TrailerBackend::start(Bytes::from_static(b"original"), false, true);
        let proxy_port = free_port();
        let eof_seen = Arc::new(AtomicBool::new(false));
        let registry = registry_with_eof(&eof_seen);
        let config = Config::from_yaml(&proxy_yaml(proxy_port, backend.port, filter)).unwrap();
        let proxy = start_full_proxy_with_registry(&config, &registry);
        let (response, _body) = h2_exchange(proxy.addr(), false);
        assert_trailer_eof_observed(&backend, &eof_seen);
        assert!(!response.end_stream, "{filter}: failed EOS cannot complete");
        assert!(response.reset.is_some(), "{filter}: expected H2 reset: {response:?}");
        assert!(
            response.trailers.is_none(),
            "{filter}: successful trailers cannot follow reset"
        );
    }
}

#[test]
#[cfg(feature = "pingora")]
fn trailer_collision_with_fixed_length_resets_h2_downstream() {
    let backend = H2TrailerBackend::start(Bytes::from_static(b"original"), true, true);
    let proxy_port = free_port();
    let eof_seen = Arc::new(AtomicBool::new(false));
    let registry = registry_with_eof(&eof_seen);
    let config = Config::from_yaml(&proxy_yaml(proxy_port, backend.port, "pass")).unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);
    let (response, _body) = h2_exchange(proxy.addr(), false);
    assert_trailer_eof_observed(&backend, &eof_seen);
    assert!(
        !response.end_stream,
        "fixed Content-Length must not hide discarded EOF bytes"
    );
    assert!(
        response.reset.is_some(),
        "fixed framing must abort instead of silently truncating"
    );
    assert!(response.trailers.is_none());
}

#[test]
#[cfg(feature = "hyper")]
fn hyper_preserves_synthetic_eof_bytes_and_trailers() {
    for (filter, gated) in [
        ("pass", false),
        ("pass", true),
        ("error", false),
        ("error", true),
        ("convert", false),
        ("convert", true),
        ("json", false),
    ] {
        assert_hyper_final_outputs(filter, gated);
    }
}

/// Require real EOF execution and exact outputs with both immediate and paused producers.
#[cfg(feature = "hyper")]
fn assert_hyper_final_outputs(filter: &str, gated: bool) {
    let original = if filter == "json" {
        Bytes::from_static(br#"{"public":1,"internal":2}"#)
    } else {
        Bytes::from_static(b"original")
    };
    let gate = gated.then(|| Arc::new(AtomicBool::new(false)));
    let backend = H2TrailerBackend::start_gated(original.clone(), false, true, gate.clone());
    let eof_seen = Arc::new(AtomicBool::new(false));
    let registry = registry_with_eof(&eof_seen);
    let config = Config::from_yaml(&proxy_yaml(free_port(), backend.port, filter)).unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);
    let observed_prefix = gate.map(|gate| (gate, original.clone()));
    let (response, body) = h2_exchange_with_gate(proxy.addr(), false, observed_prefix.as_ref());
    assert_trailer_eof_observed(&backend, &eof_seen);
    assert_eq!(
        response.status,
        Some(200),
        "{filter}: successful response status survives"
    );
    assert!(
        response.end_stream,
        "{filter}: Hyper can deliver final DATA followed by trailers: {response:?}"
    );
    assert_eq!(response.reset, None, "{filter}: neither reset nor timeout is success");
    assert_eq!(
        body,
        hyper_expected_body(filter, original.len()),
        "{filter}: exact body order"
    );
    let expected_trailers = (filter != "convert").then(|| {
        http::HeaderMap::from_iter([(
            http::HeaderName::from_static("x-end"),
            http::HeaderValue::from_static("done"),
        )])
    });
    assert_eq!(
        response.trailers, expected_trailers,
        "{filter}: forwarding restores trailers; conversion replaces them"
    );
}

/// Expected output for each independently observable Hyper trailer outcome.
#[cfg(feature = "hyper")]
fn hyper_expected_body(filter: &str, original_len: usize) -> Vec<u8> {
    match filter {
        "pass" | "error" => b"originaltail".to_vec(),
        "convert" => b"originaltailconverted".to_vec(),
        "json" => {
            let mut expected = b"{\"public\":1}".to_vec();
            expected.resize(original_len, b' ');
            expected
        },
        other => panic!("unknown Hyper trailer test: {other}"),
    }
}

#[test]
fn preformatted_grpc_rejection_strips_reserved_headers() {
    for filter in [
        "grpc_reject",
        "grpc_reject_string_length",
        "grpc_reject_map_length",
        "grpc_reject_conflicting_lengths",
        "static_grpc",
    ] {
        assert_preformatted_grpc_rejection_headers(filter);
    }
}

#[test]
fn preformatted_grpc_rejection_keeps_http1_connection_usable() {
    for filter in [
        "grpc_reject",
        "grpc_reject_string_length",
        "grpc_reject_map_length",
        "grpc_reject_conflicting_lengths",
        "static_grpc",
    ] {
        let registry = registry();
        let config = Config::from_yaml(&proxy_yaml(free_port(), free_port(), filter)).unwrap();
        let proxy = start_full_proxy_with_registry(&config, &registry);
        wait_for_tcp(proxy.addr());
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        for method in ["GET", "HEAD", "GET"] {
            write!(stream, "{method} / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            let response = read_http1_head(&mut stream);
            assert_eq!(response.status, 200, "{filter}, {method} request");
            assert_eq!(response.headers.get("grpc-status").unwrap(), "7");
            assert_eq!(response.headers.get("grpc-message").unwrap(), "denied");
            assert_eq!(response.headers.get("x-safe").unwrap(), "kept");
            assert_eq!(response.headers.get("x-map-safe").unwrap(), "kept");
            if method == "GET" {
                read_empty_http1_body(&mut stream, &response.headers, filter);
            }
            for name in [
                "te",
                "x-praxis-secret",
                "x-ext-protocol-secret",
                "x-ext-agent-secret",
                "x-praxis-map",
                "x-ext-protocol-map",
                "x-ext-agent-map",
            ] {
                assert!(!response.headers.contains_key(name), "{filter}: {name} must not escape");
            }
            if filter.starts_with("grpc_reject") {
                assert_eq!(response.headers.get("x-map-opaque").unwrap().as_bytes(), b"\x80kept");
                assert_eq!(
                    response
                        .headers
                        .get_all("x-duplicate")
                        .iter()
                        .map(http::HeaderValue::as_bytes)
                        .collect::<Vec<_>>(),
                    [
                        b"first".as_slice(),
                        b"second".as_slice(),
                        b"third".as_slice(),
                        b"fourth".as_slice()
                    ],
                    "{filter}: duplicate order across both header representations"
                );
            }
        }
    }
}

/// Read exactly one response head without losing non-UTF-8 header values or
/// consuming body bytes on the persistent connection.
fn read_http1_head(stream: &mut TcpStream) -> Http1Head {
    let mut raw = Vec::new();
    while !raw.ends_with(b"\r\n\r\n") {
        let mut byte = [0_u8];
        stream.read_exact(&mut byte).expect("complete HTTP/1 response head");
        raw.push(byte[0]);
        assert!(raw.len() <= 16_384, "HTTP/1 response head exceeded 16 KiB");
    }
    let mut lines = raw.split(|byte| *byte == b'\n');
    let status_line = lines.next().unwrap();
    let status = std::str::from_utf8(status_line)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut headers = http::HeaderMap::new();
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let colon = line.iter().position(|byte| *byte == b':').unwrap();
        let name = http::HeaderName::from_bytes(&line[..colon]).unwrap();
        let value = http::HeaderValue::from_bytes(line[colon + 1..].trim_ascii()).unwrap();
        headers.append(name, value);
    }
    Http1Head { status, headers }
}

/// Consume one unambiguously empty HTTP/1 body before reusing its connection.
fn read_empty_http1_body(stream: &mut TcpStream, headers: &http::HeaderMap, filter: &str) {
    let lengths = headers.get_all(http::header::CONTENT_LENGTH).iter().collect::<Vec<_>>();
    let encodings = headers
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .collect::<Vec<_>>();
    match (lengths.as_slice(), encodings.as_slice()) {
        ([length], []) => assert_eq!(length.as_bytes(), b"0", "{filter}: empty body length"),
        ([], [encoding]) if encoding.as_bytes().eq_ignore_ascii_case(b"chunked") => {
            let size = read_http1_line(stream);
            let digits = size.split(|byte| *byte == b';').next().unwrap();
            assert_eq!(digits, b"0", "{filter}: chunked rejection must have no DATA");
            loop {
                if read_http1_line(stream).is_empty() {
                    break;
                }
            }
        },
        _ => panic!("{filter}: ambiguous empty-body framing: {headers:?}"),
    }
}

/// Read one CRLF-terminated framing line without consuming the next response.
fn read_http1_line(stream: &mut TcpStream) -> Vec<u8> {
    let mut line = Vec::new();
    while !line.ends_with(b"\r\n") {
        let mut byte = [0_u8];
        stream.read_exact(&mut byte).expect("complete HTTP/1 framing line");
        line.push(byte[0]);
        assert!(line.len() <= 16_384, "HTTP/1 framing line exceeded 16 KiB");
    }
    line.truncate(line.len() - 2);
    line
}

/// HTTP/1 response head with byte-preserving fields.
struct Http1Head {
    /// HTTP response status.
    status: u16,
    /// All received fields, including duplicate and opaque values.
    headers: http::HeaderMap,
}

fn assert_preformatted_grpc_rejection_headers(filter: &str) {
    let proxy_port = free_port();
    let registry = registry();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, free_port(), filter)).unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "{filter}: H1 gRPC rejection uses HTTP 200");
    assert_eq!(
        parse_header(&raw, "grpc-status").as_deref(),
        Some("7"),
        "{filter}: H1 gRPC status must survive"
    );
    assert_eq!(
        parse_header(&raw, "grpc-message").as_deref(),
        Some("denied"),
        "{filter}: H1 gRPC message must survive"
    );
    assert_eq!(
        parse_header(&raw, "x-safe").as_deref(),
        Some("kept"),
        "{filter}: H1 safe headers must survive"
    );
    assert_eq!(
        parse_header(&raw, "x-map-safe").as_deref(),
        Some("kept"),
        "{filter}: H1 map headers must survive"
    );
    for name in [
        "te",
        "x-praxis-secret",
        "x-ext-protocol-secret",
        "x-ext-agent-secret",
        "x-praxis-map",
        "x-ext-protocol-map",
        "x-ext-agent-map",
    ] {
        assert!(
            parse_header(&raw, name).is_none(),
            "{filter}: H1 {name} must be stripped"
        );
    }
    let (response, body) = h2_exchange(proxy.addr(), false);
    assert_eq!(response.status, Some(200), "{filter}: H2 gRPC rejection uses HTTP 200");
    assert!(response.end_stream, "{filter}: H2 rejection must complete cleanly");
    assert!(body.is_empty(), "{filter}: H2 rejection has no DATA payload");
    let headers = response.headers.unwrap();
    assert!(
        !headers.contains_key(http::header::CONTENT_LENGTH),
        "{filter}: H2 END_STREAM must not inherit a filter length"
    );
    for name in [
        "te",
        "x-praxis-secret",
        "x-ext-protocol-secret",
        "x-ext-agent-secret",
        "x-praxis-map",
        "x-ext-protocol-map",
        "x-ext-agent-map",
    ] {
        assert!(!headers.contains_key(name), "{filter}: H2 {name} must be stripped");
    }
    assert_eq!(
        headers.get("grpc-status").unwrap(),
        "7",
        "{filter}: H2 gRPC status must survive"
    );
    assert_eq!(
        headers.get("grpc-message").unwrap(),
        "denied",
        "{filter}: H2 gRPC message must survive"
    );
    assert_eq!(
        headers.get("x-safe").unwrap(),
        "kept",
        "{filter}: H2 safe headers must survive"
    );
    assert_eq!(
        headers.get("x-map-safe").unwrap(),
        "kept",
        "{filter}: H2 map headers must survive"
    );
    if filter.starts_with("grpc_reject") {
        assert_eq!(
            headers.get("x-map-opaque").unwrap().as_bytes(),
            b"\x80kept",
            "H2 opaque values stay intact"
        );
        assert_eq!(
            headers
                .get_all("x-duplicate")
                .iter()
                .map(http::HeaderValue::as_bytes)
                .collect::<Vec<_>>(),
            [
                b"first".as_slice(),
                b"second".as_slice(),
                b"third".as_slice(),
                b"fourth".as_slice()
            ],
            "H2 retains duplicates from both representations in append order"
        );
    }
}

fn registry() -> FilterRegistry {
    registry_with_eof(&Arc::new(AtomicBool::new(false)))
}

fn registry_with_eof(eof_seen: &Arc<AtomicBool>) -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    for (name, mode) in [
        ("test_trailer_pass", ProbeMode::Pass),
        ("test_trailer_observe", ProbeMode::Observe),
        ("test_trailer_no_eof", ProbeMode::NoEof),
        ("test_trailer_error", ProbeMode::Error),
        ("test_trailer_error_no_eof", ProbeMode::ErrorNoEof),
        ("test_trailer_convert", ProbeMode::Convert),
        ("test_trailer_fail", ProbeMode::FailAtEof),
        ("test_trailer_reject", ProbeMode::RejectAtEof),
        ("test_trailer_fail_without", ProbeMode::FailAtEofWithoutTrailer),
        ("test_trailer_grpc_reject", ProbeMode::GrpcReject),
        (
            "test_trailer_grpc_reject_string_length",
            ProbeMode::GrpcRejectStringLength,
        ),
        ("test_trailer_grpc_reject_map_length", ProbeMode::GrpcRejectMapLength),
        (
            "test_trailer_grpc_reject_conflicting_lengths",
            ProbeMode::GrpcRejectConflictingLengths,
        ),
    ] {
        let eof_seen = Arc::clone(eof_seen);
        registry
            .register(
                name,
                FilterFactory::Http(Arc::new(move |_| {
                    Ok(Box::new(TrailerProbe {
                        eof_seen: Arc::clone(&eof_seen),
                        mode,
                    }))
                })),
            )
            .unwrap();
    }
    registry
}

fn proxy_yaml(proxy_port: u16, backend_port: u16, filter: &str) -> String {
    let selected = match filter {
        "json" => {
            "- filter: json_body\n        response_remove: [/internal]\n        on_invalid: reject\n      - filter: test_trailer_observe"
        },
        "pass" => "- filter: test_trailer_pass",
        "no_eof" => "- filter: test_trailer_no_eof",
        "error" => "- filter: test_trailer_error",
        "error_no_eof" => "- filter: test_trailer_error_no_eof",
        "convert" => "- filter: test_trailer_convert",
        "compressed_convert" => {
            "- filter: compression\n        level: 6\n        min_size_bytes: 1\n      - filter: test_trailer_convert"
        },
        "fail" => "- filter: test_trailer_fail",
        "reject" => "- filter: test_trailer_reject",
        "fail_without_trailer" => "- filter: test_trailer_fail_without",
        "grpc_reject" => "- filter: test_trailer_grpc_reject",
        "grpc_reject_string_length" => "- filter: test_trailer_grpc_reject_string_length",
        "grpc_reject_map_length" => "- filter: test_trailer_grpc_reject_map_length",
        "grpc_reject_conflicting_lengths" => "- filter: test_trailer_grpc_reject_conflicting_lengths",
        "static_grpc" => {
            "- filter: static_response\n        status: 200\n        headers:\n          - {name: grpc-status, value: '7'}\n          - {name: grpc-message, value: denied}\n          - {name: x-safe, value: kept}\n          - {name: x-map-safe, value: kept}\n          - {name: x-praxis-secret, value: hidden}\n          - {name: x-ext-protocol-secret, value: hidden}\n          - {name: x-ext-agent-secret, value: hidden}"
        },
        other => panic!("unknown probe filter: {other}"),
    };
    let upstream = if filter == "static_grpc" {
        String::new()
    } else {
        format!(
            "\n      - filter: router\n        routes:\n          - path_prefix: '/'\n            cluster: backend\n      - filter: load_balancer\n        clusters:\n          - name: backend\n            endpoints: ['127.0.0.1:{backend_port}']\n            http:\n              version: h2"
        )
    };
    format!(
        "listeners:\n  - name: web\n    address: '127.0.0.1:{proxy_port}'\n    filter_chains: [main]\n\
         insecure_options:\n  allow_private_endpoints: true\n  allow_private_upstreams: true\n\
         filter_chains:\n  - name: main\n    filters:\n      {selected}{upstream}\n"
    )
}

fn h2_exchange(addr: &str, gzip: bool) -> (H2Response, Vec<u8>) {
    h2_exchange_with_gate(addr, gzip, None)
}

fn h2_exchange_with_gate(addr: &str, gzip: bool, gate: Option<&(Arc<AtomicBool>, Bytes)>) -> (H2Response, Vec<u8>) {
    wait_for_tcp(addr);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), Box::pin(h2_exchange_async(addr, gzip, gate)))
            .await
            .unwrap()
    })
}

/// Keep connection setup separate from response polling while the runtime owns the driver.
async fn connect_h2_client(addr: &str) -> h2::client::SendRequest<Bytes> {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (client, connection) = Box::pin(h2::client::handshake(stream)).await.unwrap();
    tokio::spawn(async move {
        let _result = connection.await;
    });
    client
}

/// Observe DATA and release the backend gate only after receiving the exact prefix.
async fn h2_exchange_async(addr: &str, gzip: bool, gate: Option<&(Arc<AtomicBool>, Bytes)>) -> (H2Response, Vec<u8>) {
    let mut client = Box::pin(connect_h2_client(addr)).await;
    let mut request = http::Request::builder()
        .uri("http://localhost/")
        .header("host", "localhost");
    if gzip {
        request = request.header("accept-encoding", "gzip");
    }
    let request = request.body(()).unwrap();
    let (response_future, _send) = client.send_request(request, true).unwrap();
    let mut body = Vec::new();
    let response = read_h2_response(response_future.await, 1024, |chunk| {
        body.extend_from_slice(chunk);
        if let Some((gate, expected)) = gate
            && body.as_slice() == expected.as_ref()
        {
            gate.store(true, Ordering::SeqCst);
        }
        Ok(())
    })
    .await;
    (response, body)
}

fn assert_trailer_eof_observed(backend: &H2TrailerBackend, eof_seen: &AtomicBool) {
    assert!(
        backend.trailers_sent.load(Ordering::SeqCst),
        "the backend must successfully emit trailers, not terminate because its fixture failed"
    );
    assert!(
        eof_seen.load(Ordering::SeqCst),
        "the intended synthetic EOF hook must run before the reset is accepted"
    );
}

struct H2TrailerBackend {
    port: u16,
    running: Arc<AtomicBool>,
    trailers_sent: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

/// Response framing and synchronization shared by each owned backend connection.
#[derive(Clone)]
struct H2TrailerResponse {
    body: Bytes,
    fixed_length: bool,
    has_trailer: bool,
    gate: Option<Arc<AtomicBool>>,
    trailers_sent: Arc<AtomicBool>,
}

impl H2TrailerBackend {
    fn start(body: Bytes, fixed_length: bool, has_trailer: bool) -> Self {
        Self::start_gated(body, fixed_length, has_trailer, None)
    }

    fn start_gated(body: Bytes, fixed_length: bool, has_trailer: bool, gate: Option<Arc<AtomicBool>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let trailers_sent = Arc::new(AtomicBool::new(false));
        let response = H2TrailerResponse {
            body,
            fixed_length,
            has_trailer,
            gate,
            trailers_sent: Arc::clone(&trailers_sent),
        };
        let worker = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let mut connections = tokio::task::JoinSet::new();
                while worker_running.load(Ordering::SeqCst) {
                    tokio::select! {
                        accepted = tokio::time::timeout(Duration::from_millis(50), listener.accept()) => {
                            match accepted {
                                Ok(Ok((stream, _))) => {
                                    connections.spawn(serve_h2(stream, response.clone()));
                                },
                                Ok(Err(error)) => panic!("H2 test backend accept failed: {error}"),
                                Err(_) => {},
                            }
                        },
                        Some(joined) = connections.join_next(), if !connections.is_empty() => {
                            joined.expect("H2 fixture task must not fail");
                        },
                    }
                }
                connections.shutdown().await;
            });
        });
        Self {
            port,
            running,
            trailers_sent,
            worker: Some(worker),
        }
    }
}

impl Drop for H2TrailerBackend {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let joined = worker.join();
            if !thread::panicking() {
                joined.expect("H2 fixture worker must not fail");
            }
        }
    }
}

async fn serve_h2(stream: tokio::net::TcpStream, response: H2TrailerResponse) {
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    let Some(Ok((_request, respond))) = connection.accept().await else {
        return;
    };
    let drive = async {
        if let Some(Ok(_)) = connection.accept().await {
            panic!("unexpected second request to the H2 trailer fixture");
        }
    };
    tokio::pin!(drive);
    tokio::select! {
        () = serve_h2_response(respond, response) => drive.await,
        () = &mut drive => {},
    }
}

async fn serve_h2_response(mut respond: h2::server::SendResponse<Bytes>, fixture: H2TrailerResponse) {
    let mut response = http::Response::builder()
        .status(200)
        .header("content-type", "application/json");
    if fixture.fixed_length {
        response = response.header("content-length", fixture.body.len().to_string());
    }
    let response = response.body(()).expect("build H2 fixture response");
    let mut send = respond.send_response(response, false).expect("send H2 fixture headers");
    send.send_data(fixture.body, false).expect("send H2 fixture DATA");
    if let Some(gate) = fixture.gate {
        let wait = async {
            while !gate.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(3), wait)
            .await
            .expect("client must observe the exact DATA prefix before trailers");
    }
    let mut trailers = http::HeaderMap::new();
    if fixture.has_trailer {
        trailers.insert("x-end", http::HeaderValue::from_static("done"));
    }
    send.send_trailers(trailers).expect("send H2 fixture trailers");
    fixture.trailers_sent.store(true, Ordering::SeqCst);
}
