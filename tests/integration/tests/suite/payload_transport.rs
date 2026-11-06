// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Byte and framing observations at the proxy transport boundary.

mod buffer_ceiling;
#[cfg(target_os = "linux")]
mod campaigns;

use std::{
    io::{BufReader, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{
    BackendReceipt, CountingBackend, H1Completion, H1Response, PayloadResponseFraming, PayloadSpec, free_port,
    read_h1_response, start_backend_with_shutdown, start_counting_backend, start_payload_response_backend,
};

/// Long enough for MiB-scale local transfers, while bounding stalled peers.
const DEADLINE: Duration = Duration::from_secs(30);
/// A deterministic byte generator seed for transport cases.
const SEED: u64 = 0x004E_3031;

/// Configure a body-independent route, a second route and a clean probe.
fn transport_config(port: u16, backends: (u16, u16, u16), limits: &str, guard: &str) -> Config {
    let (selected, other, probe) = backends;
    let yaml = format!(
        r#"
{limits}
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
{guard}
      - filter: router
        routes:
          - path_prefix: "/probe"
            cluster: probe
          - path_prefix: "/other"
            cluster: other
          - path_prefix: "/host"
            host: selected.local
            cluster: selected
          - path_prefix: "/host"
            cluster: other
          - path_prefix: "/trailer"
            headers: {{x-praxis-model: trusted}}
            cluster: other
          - path_prefix: "/trailer"
            cluster: selected
          - path_prefix: "/header"
            headers: {{x-destination: selected}}
            cluster: selected
          - path_prefix: "/header"
            cluster: other
          - path_prefix: "/"
            cluster: selected
      - filter: load_balancer
        clusters:
          - name: selected
            endpoints: ["127.0.0.1:{selected}"]
          - name: other
            endpoints: ["127.0.0.1:{other}"]
          - name: probe
            endpoints: ["127.0.0.1:{probe}"]
insecure_options:
  allow_private_endpoints: true
  allow_unbounded_body: true
"#
    );
    Config::from_yaml(&yaml).unwrap()
}

/// Start without an HTTP readiness request, which would consume a one-shot backend.
fn start_transport(config: &Config) -> praxis_test_utils::ProxyGuard {
    let proxy = praxis_test_utils::start_full_proxy(config);
    praxis_test_utils::wait_for_tcp(proxy.addr());
    proxy
}

/// Start a custom-filter proxy without contacting its one-shot backend.
fn start_transport_with_registry(
    config: &Config,
    registry: &praxis_filter::FilterRegistry,
) -> praxis_test_utils::ProxyGuard {
    let proxy = praxis_test_utils::start_full_proxy_with_registry(config, registry);
    praxis_test_utils::wait_for_tcp(proxy.addr());
    proxy
}

/// Connect with finite deadlines for writes and reads.
fn connect(address: &str) -> TcpStream {
    let stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(DEADLINE)).unwrap();
    stream.set_write_timeout(Some(DEADLINE)).unwrap();
    stream
}

/// Read a small response, preserving its completion separately from its status.
fn response(stream: TcpStream) -> H1Response {
    read_h1_response(&mut BufReader::new(stream), false, 65_536, |_| Ok(()))
}

/// Confirm a rejected or completed request did not prevent a subsequent request.
fn probe(address: &str) {
    let mut stream = connect(address);
    stream
        .write_all(b"GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut body = Vec::new();
    let observed = read_h1_response(&mut BufReader::new(stream), false, 100, |chunk| {
        body.extend_from_slice(chunk);
        Ok(())
    });
    assert_eq!(observed.status, Some(200), "probe status: {observed:?}");
    assert_eq!(
        observed.completion,
        Some(H1Completion::ContentLength),
        "probe response must complete"
    );
    assert_eq!(body, b"probe", "probe body must reach the client");
}

/// Write a generated content body in bounded pieces, returning socket-written bytes.
fn write_payload<W: std::io::Write>(stream: &mut W, spec: &PayloadSpec, chunk_size: usize, chunked: bool) -> u64 {
    let written = write_payload_chunks(stream, spec, chunk_size, chunked);
    if chunked && written == spec.len() {
        let _result = stream.write_all(b"0\r\n\r\n");
    }
    written
}

/// End an otherwise identical chunked upload with an explicit ordinary trailer.
fn write_payload_with_trailer<W: std::io::Write>(stream: &mut W, spec: &PayloadSpec, chunk_size: usize) -> u64 {
    let written = write_payload_chunks(stream, spec, chunk_size, true);
    if written == spec.len() {
        stream.write_all(b"0\r\nX-Trailer: done\r\n\r\n").unwrap();
    }
    written
}

/// Write content and per-chunk framing without producing an end marker.
fn write_payload_chunks<W: std::io::Write>(
    stream: &mut W,
    spec: &PayloadSpec,
    chunk_size: usize,
    chunked: bool,
) -> u64 {
    let mut written = 0;
    while written < spec.len() {
        let chunk = spec.chunk(written, chunk_size);
        if chunked && write!(stream, "{:x};note=boundary\r\n", chunk.len()).is_err() {
            break;
        }
        if stream.write_all(&chunk).is_err() {
            break;
        }
        written += chunk.len() as u64;
        if chunked && stream.write_all(b"\r\n").is_err() {
            break;
        }
    }
    written
}

/// The Hyper H1 upstream must not see a cleanly completed rejected upload.
#[cfg(feature = "hyper")]
fn assert_aborted_trailer_upload(backend: &CountingBackend, spec: &PayloadSpec, preread: bool) {
    backend.accepted.recv_timeout(DEADLINE).unwrap();
    let receipt = backend.receipt.recv_timeout(DEADLINE).unwrap();
    assert_eq!(
        receipt.completion, None,
        "rejected trailers cannot end upstream cleanly: {receipt:?}"
    );
    assert!(
        receipt.abort.is_some(),
        "the upstream request must be aborted: {receipt:?}"
    );
    assert!(
        receipt.bytes <= spec.len(),
        "upstream cannot receive excess content: {receipt:?}"
    );
    assert_eq!(
        receipt.verified_bytes, receipt.bytes,
        "any streamed prefix must match: {receipt:?}"
    );
    assert_eq!(
        receipt.mismatch, None,
        "rejected upload must not mutate its prefix: {receipt:?}"
    );
    assert!(
        receipt.trailers.is_empty(),
        "no request trailers reach the H1 upstream: {receipt:?}"
    );
    if preread {
        assert_eq!(
            receipt.bytes, 0,
            "retained trailers are refused before sending the body: {receipt:?}"
        );
        assert_eq!(
            receipt.first_byte, None,
            "pre-read body must not start upstream: {receipt:?}"
        );
    }
}

/// Verify the complete backend's independent binary observation.
fn assert_receipt(backend: &CountingBackend, spec: &PayloadSpec) -> BackendReceipt {
    let receipt = backend.receipt.recv_timeout(DEADLINE).unwrap();
    assert_eq!(receipt.bytes, spec.len(), "{receipt:?}");
    assert_eq!(receipt.verified_bytes, spec.len(), "{receipt:?}");
    assert_eq!(receipt.mismatch, None, "{receipt:?}");
    assert!(receipt.completion.is_some(), "{receipt:?}");
    assert_eq!(receipt.abort, None, "{receipt:?}");
    receipt
}

/// A routed opaque request and an unselected-backend ledger.
fn opaque_upload(spec: &PayloadSpec, limits: &str, method: &str, chunked: bool, route: &str) {
    opaque_upload_with_headers(
        spec,
        limits,
        chunked,
        UploadRequest {
            method,
            route,
            headers: "Content-Type: application/octet-stream\r\n",
        },
    );
}

/// Request metadata for an opaque upload.
#[derive(Clone, Copy)]
struct UploadRequest<'a> {
    /// Request method.
    method: &'a str,
    /// Route selected by request metadata.
    route: &'a str,
    /// Explicit media and encoding headers.
    headers: &'a str,
}

/// Upload an opaque representation with its explicit media and encoding headers.
fn opaque_upload_with_headers(spec: &PayloadSpec, limits: &str, chunked: bool, request: UploadRequest<'_>) {
    let UploadRequest { method, route, headers } = request;
    let selected = start_counting_backend(spec.clone(), "selected", spec.len());
    let other = start_counting_backend(spec.clone(), "other", spec.len());
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(free_port(), (selected.port, other.port, health.port()), limits, "");
    let proxy = start_transport(&config);
    let mut stream = connect(proxy.addr());
    let framing = if chunked {
        "Transfer-Encoding: chunked".to_owned()
    } else {
        format!("Content-Length: {}", spec.len())
    };
    let host = if route == "host" { "selected.local" } else { "localhost" };
    write!(stream, "{method} /{route} HTTP/1.1\r\nHost: {host}\r\nX-Destination: selected\r\n{headers}{framing}\r\nConnection: close\r\n\r\n").unwrap();
    assert_eq!(
        write_payload(&mut stream, spec, 16_384, chunked),
        spec.len(),
        "client must write the complete upload"
    );
    let observed = response(stream);
    assert_eq!(observed.status, Some(200), "{observed:?}");
    assert_eq!(
        observed.completion,
        Some(H1Completion::ContentLength),
        "upload response must complete"
    );
    assert_receipt(&selected, spec);
    assert!(
        matches!(other.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
        "the other route was contacted"
    );
    probe(proxy.addr());
    selected.join();
    other.join();
}

#[test]
fn opaque_binary_and_malformed_json_are_forwarded_intact() {
    opaque_upload(&PayloadSpec::binary(1_048_576, SEED), "", "POST", false, "upload");
    let malformed = PayloadSpec::padded(65_537, b"{\"broken\":\"", b"", b'x').unwrap();
    opaque_upload(&malformed, "", "PUT", true, "header");
}

#[test]
fn opaque_content_types_and_gzip_encoding_preserve_bytes() {
    let plain = PayloadSpec::padded(65_537, b"plain ", b" end", b'a').unwrap();
    opaque_upload_with_headers(
        &plain,
        "",
        false,
        UploadRequest {
            method: "POST",
            route: "upload",
            headers: "Content-Type: text/plain\r\n",
        },
    );
    let json = PayloadSpec::padded(65_537, br#"{"message":""#, br#""}"#, b'a').unwrap();
    opaque_upload_with_headers(
        &json,
        "",
        false,
        UploadRequest {
            method: "POST",
            route: "header",
            headers: "Content-Type: application/json\r\n",
        },
    );
    let multipart = PayloadSpec::padded(
        65_537,
        b"--B\r\nContent-Disposition: form-data; name=\"part\"\r\n\r\n",
        b"\r\n--B--\r\n",
        b'z',
    )
    .unwrap();
    opaque_upload_with_headers(
        &multipart,
        "",
        true,
        UploadRequest {
            method: "PUT",
            route: "host",
            headers: "Content-Type: multipart/form-data; boundary=B\r\n",
        },
    );
    let gzip = include_bytes!("../../../security/fixtures/gzip_1mb_zeros.gz");
    let compressed = PayloadSpec::padded(gzip.len() as u64, gzip, b"", 0).unwrap();
    opaque_upload_with_headers(
        &compressed,
        "",
        false,
        UploadRequest {
            method: "POST",
            route: "upload",
            headers: "Content-Type: application/octet-stream\r\nContent-Encoding: gzip\r\n",
        },
    );
}

#[test]
fn opaque_upload_at_default_10_mib_limit_is_complete() {
    opaque_upload(&PayloadSpec::binary(10_485_759, SEED), "", "POST", false, "upload");
    opaque_upload(&PayloadSpec::binary(10_485_760, SEED), "", "POST", false, "upload");
}

#[test]
#[ignore = "scheduled: transfers a 64 MiB request"]
fn scheduled_opaque_upload_at_64_mib_limit() {
    opaque_upload(
        &PayloadSpec::binary(67_108_863, SEED),
        "body_limits:\n  max_request_bytes: 67108864",
        "POST",
        false,
        "header",
    );
    opaque_upload(
        &PayloadSpec::binary(67_108_864, SEED),
        "body_limits:\n  max_request_bytes: 67108864",
        "PUT",
        false,
        "host",
    );
}

#[test]
#[ignore = "scheduled: transfers a 256 MiB request with an explicit unbounded override"]
fn scheduled_unbounded_opaque_upload_256_mib() {
    opaque_upload(
        &PayloadSpec::binary(268_435_456, SEED),
        "body_limits:\n  max_buffer_bytes: 268435456\n  max_request_bytes: null\n  max_response_bytes: 1024",
        "POST",
        false,
        "upload",
    );
}

/// Assert a rejected upload cannot complete on the selected backend.
fn assert_rejected_receipt(backend: &CountingBackend, limit: u64) {
    if backend.accepted.recv_timeout(Duration::from_millis(200)).is_ok() {
        let receipt: BackendReceipt = backend.receipt.recv_timeout(DEADLINE).unwrap();
        assert!(
            receipt.bytes <= limit,
            "overflow crossed the backend boundary: {receipt:?}"
        );
        assert_eq!(receipt.mismatch, None, "{receipt:?}");
        assert_eq!(
            receipt.completion, None,
            "a rejected upload must not complete: {receipt:?}"
        );
        assert!(receipt.abort.is_some(), "{receipt:?}");
    }
}

/// Cross an input limit in fixed or chunked framing, then send a clean probe.
fn upload_over_limit(limit: u64, length: u64, chunked: bool, limits: &str) {
    upload_over_limit_with_chunk(limit, length, chunked, limits, 4096);
}

/// Vary the client write schedule without assuming proxy callback boundaries.
fn upload_over_limit_with_chunk(limit: u64, length: u64, chunked: bool, limits: &str, chunk_size: usize) {
    let spec = PayloadSpec::binary(length, SEED);
    let selected = start_counting_backend(spec.clone(), "selected", length);
    let other = start_counting_backend(spec.clone(), "other", length);
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(free_port(), (selected.port, other.port, health.port()), limits, "");
    let proxy = start_transport(&config);
    let mut stream = connect(proxy.addr());
    let framing = if chunked {
        "Transfer-Encoding: chunked".to_owned()
    } else {
        format!("Content-Length: {length}")
    };
    write!(
        stream,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\n{framing}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let written = write_payload(&mut stream, &spec, chunk_size, chunked);
    let observed = response(stream);
    assert_eq!(observed.status, Some(413), "written={written}; {observed:?}");
    assert!(
        matches!(other.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
        "over-limit upload must not reach the other backend"
    );
    probe(proxy.addr());
    assert_rejected_receipt(&selected, limit);
    selected.join();
    other.join();
}

#[test]
fn fixed_and_chunked_limits_count_content_bytes() {
    let limits = "body_limits:\n  max_request_bytes: 65536";
    opaque_upload(&PayloadSpec::binary(65_535, SEED), limits, "POST", false, "host");
    opaque_upload(&PayloadSpec::binary(65_536, SEED), limits, "PUT", true, "header");
    upload_over_limit_with_chunk(65_536, 65_537, false, limits, 65_537);
    upload_over_limit(65_536, 65_537, false, limits);
    upload_over_limit(65_536, 65_537, true, limits);
}

#[test]
fn default_limit_rejects_the_next_content_byte() {
    upload_over_limit(10_485_760, 10_485_761, false, "");
}

#[test]
#[ignore = "scheduled: crosses the 64 MiB limit"]
fn scheduled_64_mib_limit_rejects_the_next_content_byte() {
    upload_over_limit(
        67_108_864,
        67_108_865,
        false,
        "body_limits:\n  max_request_bytes: 67108864",
    );
}

/// Observe a generated response; signal the source only once the proxy has
/// delivered the complete initial prefix to the client.
fn generated_response(
    length: u64,
    ceiling: Option<u64>,
    request_ceiling: &str,
    framing: PayloadResponseFraming,
    completes: bool,
) {
    generated_response_spec(
        &PayloadSpec::binary(length, SEED),
        ceiling,
        request_ceiling,
        framing,
        completes,
    );
}

/// Verify any generated response representation while coordinating its prefix.
fn generated_response_spec(
    spec: &PayloadSpec,
    ceiling: Option<u64>,
    request_ceiling: &str,
    framing: PayloadResponseFraming,
    completes: bool,
) {
    let length = spec.len();
    let prefix = 4096_u64.min(length / 2);
    let mut source = start_payload_response_backend(spec.clone(), framing, Some(prefix));
    let other = start_counting_backend(PayloadSpec::binary(0, SEED), "other", 0);
    let health = start_backend_with_shutdown("probe");
    let response_ceiling = ceiling.map_or_else(|| "null".to_owned(), |value| value.to_string());
    let limits =
        format!("body_limits:\n  max_request_bytes: {request_ceiling}\n  max_response_bytes: {response_ceiling}");
    let config = transport_config(free_port(), (source.port, other.port, health.port()), &limits, "");
    let proxy = start_transport(&config);
    let mut stream = connect(proxy.addr());
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut checked = 0;
    let mut resumed = false;
    let observed = read_h1_response(&mut BufReader::new(stream), false, length, |bytes| {
        assert_eq!(
            spec.mismatch(checked, bytes),
            None,
            "response mismatch at offset {checked}"
        );
        checked += bytes.len() as u64;
        if checked >= prefix && !resumed {
            assert_eq!(
                source.prefix_written.recv_timeout(DEADLINE).unwrap(),
                prefix,
                "backend must pause after the prefix"
            );
            source.resume();
            resumed = true;
        }
        Ok(())
    });
    assert_eq!(observed.status, Some(200), "{observed:?}");
    assert!(resumed, "prefix did not reach the client before the tail was permitted");
    assert_eq!(
        observed.body_bytes, checked,
        "response byte count must match verified bytes"
    );
    if completes {
        assert_eq!(checked, length, "{observed:?}");
        let expected = match framing {
            PayloadResponseFraming::Fixed => H1Completion::ContentLength,
            PayloadResponseFraming::Chunked => H1Completion::Chunked,
            PayloadResponseFraming::Close => {
                if observed
                    .headers
                    .iter()
                    .any(|(name, value)| name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked"))
                {
                    H1Completion::Chunked
                } else if observed.headers.iter().any(|(name, _)| name == "content-length") {
                    H1Completion::ContentLength
                } else {
                    H1Completion::CloseDelimited
                }
            },
        };
        assert_eq!(observed.completion, Some(expected), "{observed:?}");
    } else {
        assert!(checked <= ceiling.unwrap(), "{observed:?}");
        assert!(
            checked < length,
            "overflow must not deliver a complete response: {observed:?}"
        );
        assert_eq!(
            observed.completion, None,
            "overflow must not complete framed response: {observed:?}"
        );
        assert!(observed.abort.is_some(), "{observed:?}");
    }
    let receipt = source.receipt.recv_timeout(DEADLINE).unwrap();
    assert!(receipt.written_bytes >= prefix, "{receipt:?}");
    if completes {
        assert!(receipt.complete, "{receipt:?}");
    }
    probe(proxy.addr());
    source.join();
    other.join();
}

#[test]
fn fixed_and_chunked_responses_stream_and_enforce_the_ceiling() {
    for framing in [PayloadResponseFraming::Fixed, PayloadResponseFraming::Chunked] {
        generated_response(65_536, Some(65_536), "65536", framing, true);
        generated_response(131_072, Some(65_536), "null", framing, false);
    }
}

#[test]
fn chunked_response_content_may_contain_terminal_chunk_lookalikes() {
    let spec = PayloadSpec::padded(65_536, b"binary\0\xff\r\n0\r\n\r\n", b"tail", b'x').unwrap();
    generated_response_spec(&spec, Some(65_536), "65536", PayloadResponseFraming::Chunked, true);
}

#[test]
fn close_delimited_response_streams_without_whole_body_buffering() {
    generated_response(1_048_576, Some(1_048_576), "65536", PayloadResponseFraming::Close, true);
}

/// Header-only filtering never asks the pipeline to inspect the body.
const HEADER_GUARD: &str = "      - filter: guardrails\n        rules:\n          - target: header\n            name: X-Bad\n            contains: evil";

#[test]
fn header_guard_forwards_opaque_body_but_rejects_before_upload() {
    let spec = PayloadSpec::padded(1_048_576, b"{\"text\":\"evil 123-45-6789 ", b"", b'x').unwrap();
    let selected = start_counting_backend(spec.clone(), "selected", spec.len());
    let other = start_counting_backend(spec.clone(), "other", spec.len());
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(
        free_port(),
        (selected.port, other.port, health.port()),
        "body_limits:\n  max_request_bytes: null",
        HEADER_GUARD,
    );
    let proxy = start_transport(&config);

    for expect in ["", "Expect: 100-continue\r\n"] {
        let mut blocked = connect(proxy.addr());
        write!(blocked, "POST / HTTP/1.1\r\nHost: localhost\r\nX-Bad: evil\r\nContent-Length: 1073741824\r\n{expect}Connection: close\r\n\r\n").unwrap();
        let rejected = response(blocked);
        assert_eq!(rejected.status, Some(403), "{rejected:?}");
        assert!(rejected.completion.is_some(), "{rejected:?}");
        assert!(
            matches!(selected.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
            "header rejection dispatched upstream"
        );
        assert!(matches!(
            other.accepted.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
    }

    let mut clean = connect(proxy.addr());
    write!(
        clean,
        "POST / HTTP/1.1\r\nHost: localhost\r\nX-Bad: safe\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        spec.len()
    )
    .unwrap();
    assert_eq!(write_payload(&mut clean, &spec, 16_384, false), spec.len());
    let accepted = response(clean);
    assert_eq!(accepted.status, Some(200), "{accepted:?}");
    assert_receipt(&selected, &spec);
    assert!(matches!(
        other.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    probe(proxy.addr());
    selected.join();
    other.join();
}

#[test]
fn truncated_huge_length_does_not_complete_upstream() {
    for declared in [1_073_741_824_u64, u64::MAX] {
        let spec = PayloadSpec::binary(1, SEED);
        let selected = start_counting_backend(spec.clone(), "selected", 8);
        let other = start_counting_backend(spec.clone(), "other", 8);
        let health = start_backend_with_shutdown("probe");
        let limits = "body_limits:\n  max_request_bytes: null\n  max_response_bytes: 1024";
        let config = transport_config(free_port(), (selected.port, other.port, health.port()), limits, "");
        let proxy = start_transport(&config);
        let mut stream = connect(proxy.addr());
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let _result = stream.write_all(&spec.chunk(0, 1));
        drop(stream);
        probe(proxy.addr());
        assert_rejected_receipt(&selected, 1);
        assert!(matches!(
            other.accepted.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        selected.join();
        other.join();
    }
}

#[test]
#[ignore = "scheduled: transfers an unbounded response larger than 64 MiB"]
fn scheduled_unbounded_response_keeps_request_ceiling() {
    generated_response(67_108_865, None, "64", PayloadResponseFraming::Fixed, true);
    upload_over_limit(
        64,
        65,
        false,
        "body_limits:\n  max_request_bytes: 64\n  max_response_bytes: null",
    );
}

/// Select whether the upload ends on its last data frame or an empty frame.
#[derive(Clone, Copy)]
enum H2End {
    /// End the stream on the last data frame.
    FinalData,
    /// Follow the data with an empty end-of-stream frame.
    EmptyFrame,
}

/// Bulk upload, bulk response and independent control response observations.
type H2Exchange = (
    praxis_test_utils::H2Upload,
    praxis_test_utils::H2Response,
    praxis_test_utils::H2Response,
    Vec<u8>,
);

/// Drive both streams concurrently on an already established H2 connection.
async fn observe_h2_upload(
    client: &mut h2::client::SendRequest<bytes::Bytes>,
    spec: &PayloadSpec,
    declared_length: bool,
    ending: H2End,
) -> H2Exchange {
    let mut request = http::Request::post("/upload").header("host", "localhost");
    if declared_length {
        request = request.header("content-length", spec.len().to_string());
    }
    let (response_future, mut sender) = client.send_request(request.body(()).unwrap(), false).unwrap();
    let control = http::Request::get("/probe")
        .header("host", "localhost")
        .body(())
        .unwrap();
    let (control_future, _) = client.send_request(control, true).unwrap();
    let upload_future = Box::pin(async {
        if matches!(ending, H2End::EmptyFrame) {
            send_h2_data_nonfinal(&mut sender, spec).await;
            sender.send_data(bytes::Bytes::new(), true).unwrap();
            praxis_test_utils::H2Upload {
                queued_bytes: spec.len(),
                end_stream: true,
                reset: None,
                abort: None,
            }
        } else {
            praxis_test_utils::send_h2_payload(&mut sender, spec, 4096).await
        }
    });
    let response_observation =
        Box::pin(async { praxis_test_utils::read_h2_response(response_future.await, 65_536, |_| Ok(())).await });
    let mut control_body = Vec::new();
    let control_observation = Box::pin(async {
        praxis_test_utils::read_h2_response(control_future.await, 100, |bytes| {
            control_body.extend_from_slice(bytes);
            Ok(())
        })
        .await
    });
    let (upload, observed, control) = tokio::join!(upload_future, response_observation, control_observation);
    (upload, observed, control, control_body)
}

/// Run one HTTP/2 upload alongside an independent control stream.
fn h2_upload(length: u64, declared_length: bool, succeeds: bool, ending: H2End) {
    let spec = PayloadSpec::binary(length, SEED);
    let selected = start_counting_backend(spec.clone(), "selected", length);
    let other = start_counting_backend(spec.clone(), "other", length);
    let health = start_backend_with_shutdown("probe");
    let limits = "body_limits:\n  max_request_bytes: 65536";
    let config = transport_config(free_port(), (selected.port, other.port, health.port()), limits, "");
    let proxy = start_transport(&config);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(
            DEADLINE,
            Box::pin(async {
                let stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
                let (mut client, connection) = Box::pin(h2::client::handshake(stream)).await.unwrap();
                let driver = tokio::spawn(Box::pin(async move {
                    let _result = connection.await;
                }));
                let (upload, observed, control, control_body) =
                    Box::pin(observe_h2_upload(&mut client, &spec, declared_length, ending)).await;
                assert_eq!(control.status, Some(200), "independent control: {control:?}");
                assert!(control.end_stream, "independent control: {control:?}");
                assert_eq!(control_body, b"probe", "independent control must return its body");
                if succeeds {
                    assert_eq!(upload.queued_bytes, length, "{upload:?}");
                    assert!(upload.end_stream, "{upload:?}");
                    assert_eq!(observed.status, Some(200), "{observed:?}");
                    assert!(observed.end_stream, "{observed:?}");
                } else {
                    assert_eq!(observed.status, Some(413), "upload={upload:?}, response={observed:?}");
                    assert!(observed.end_stream, "{observed:?}");
                }
                driver.abort();
            }),
        )
        .await
        .expect("H2 streams must complete within the test deadline");
    });
    if succeeds {
        assert_receipt(&selected, &spec);
    } else {
        assert_rejected_receipt(&selected, 65_536);
    }
    assert!(
        matches!(other.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
        "HTTP/2 upload must not reach the other backend"
    );
    probe(proxy.addr());
    selected.join();
    other.join();
}

#[test]
fn h2_data_limits_preserve_independent_stream_progress() {
    h2_upload(65_535, true, true, H2End::EmptyFrame);
    h2_upload(65_536, false, true, H2End::FinalData);
    h2_upload(65_537, false, false, H2End::FinalData);
    h2_upload(65_537, true, false, H2End::FinalData);
}

#[test]
fn keepalive_requests_get_independent_limits_and_close_safely_after_overflow() {
    use std::io::Read as _;

    let echo = praxis_test_utils::start_echo_backend();
    let other = start_counting_backend(PayloadSpec::binary(0, SEED), "other", 0);
    let health = start_backend_with_shutdown("probe");
    let limits = "body_limits:\n  max_request_bytes: 64";
    let config = transport_config(free_port(), (echo.port(), other.port, health.port()), limits, "");
    let proxy = start_transport(&config);
    let mut connection = BufReader::new(connect(proxy.addr()));
    let payload = "x".repeat(63);
    for _ in 0..2 {
        write!(
            connection.get_mut(),
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 63\r\n\r\n{payload}"
        )
        .unwrap();
        let mut body = Vec::new();
        let observed = read_h1_response(&mut connection, false, 128, |part| {
            body.extend_from_slice(part);
            Ok(())
        });
        assert_eq!(observed.status, Some(200), "{observed:?}");
        assert_eq!(observed.completion, Some(H1Completion::ContentLength));
        assert_eq!(body, payload.as_bytes());
    }
    write!(connection.get_mut(), "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n41\r\n{}\r\n0\r\n\r\nGET /probe HTTP/1.1\r\nHost: localhost\r\n\r\n", "y".repeat(65)).unwrap();
    let rejected = read_h1_response(&mut connection, false, 1024, |_| Ok(()));
    assert_eq!(rejected.status, Some(413), "{rejected:?}");
    let mut extra = [0_u8; 1];
    match connection.read(&mut extra) {
        Ok(0) => {},
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {},
        result => panic!("overflow connection must close without interpreting a pipelined request: {result:?}"),
    }
    probe(proxy.addr());
    assert!(matches!(
        other.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    other.join();
}

#[test]
fn head_and_not_modified_hypothetical_lengths_do_not_poison_next_response() {
    no_body_then_probe("HEAD", "200 OK", 200);
    no_body_then_probe("GET", "304 Not Modified", 304);
}

/// Send a no-body response and verify the next response on the same connection.
fn no_body_then_probe(method: &str, status: &'static str, expected: u16) {
    let (port, worker) = praxis_test_utils::spawn_raw_http_backend(move |mut stream| {
        praxis_test_utils::read_http_request(&mut stream);
        let validator = if status.starts_with("304") {
            "ETag: \"payload-metadata\"\r\n"
        } else {
            ""
        };
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: text/event-stream\r\nContent-Length: 1073741824\r\n{validator}Connection: close\r\n\r\n"
        )
        .unwrap();
    });
    let other = start_counting_backend(PayloadSpec::binary(0, SEED), "other", 0);
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(free_port(), (port, other.port, health.port()), "", "");
    let proxy = start_transport(&config);
    let mut connection = BufReader::new(connect(proxy.addr()));
    let conditional = if expected == 304 {
        "If-None-Match: \"payload-metadata\"\r\n"
    } else {
        ""
    };
    write!(
        connection.get_mut(),
        "{method} / HTTP/1.1\r\nHost: localhost\r\n{conditional}\r\n"
    )
    .unwrap();
    let head = read_h1_response(&mut connection, method == "HEAD", 0, |_| Ok(()));
    assert_eq!(head.status, Some(expected), "{head:?}");
    assert_eq!(
        head.completion,
        Some(H1Completion::Headers),
        "bodyless response must end with its headers"
    );
    assert_eq!(head.body_bytes, 0, "bodyless response must have no content");
    assert!(
        head.headers
            .iter()
            .any(|(name, value)| name == "content-length" && value == "1073741824"),
        "hypothetical content length must be retained: {head:?}"
    );
    connection
        .get_mut()
        .write_all(b"GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut bytes = Vec::new();
    let next = read_h1_response(&mut connection, false, 100, |part| {
        bytes.extend_from_slice(part);
        Ok(())
    });
    assert_eq!(next.status, Some(200), "{next:?}");
    assert_eq!(
        next.completion,
        Some(H1Completion::ContentLength),
        "following probe must complete"
    );
    assert_eq!(bytes, b"probe", "following probe body must be intact");
    worker.join().unwrap();
    other.join();
}

/// Shared EOS callback lengths and mismatch positions.
type PreReadObservations = std::sync::Arc<std::sync::Mutex<Vec<(usize, Option<u64>)>>>;

/// Records the EOS callback and verifies the bytes delivered to pre-read.
struct PreReadProbe {
    /// Expected complete byte sequence.
    spec: PayloadSpec,
    /// EOS callback lengths and mismatch positions.
    observations: PreReadObservations,
}

#[async_trait::async_trait]
impl praxis_filter::HttpFilter for PreReadProbe {
    fn name(&self) -> &'static str {
        "payload_preread_probe"
    }

    async fn on_request(
        &self,
        _ctx: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        Ok(praxis_filter::FilterAction::Continue)
    }

    fn request_body_access(&self) -> praxis_filter::BodyAccess {
        praxis_filter::BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> praxis_filter::BodyMode {
        praxis_filter::BodyMode::StreamBuffer {
            max_bytes: Some(1_048_576),
        }
    }

    async fn on_request_body(
        &self,
        _ctx: &mut praxis_filter::HttpFilterContext<'_>,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        if end_of_stream && body.as_ref().is_some_and(|data| !data.is_empty()) {
            let data = body.as_deref().unwrap_or_default();
            self.observations
                .lock()
                .unwrap()
                .push((data.len(), self.spec.mismatch(0, data)));
        }
        Ok(praxis_filter::FilterAction::Continue)
    }
}

/// Construct a pre-read registry with a per-test binary oracle.
fn preread_registry(spec: &PayloadSpec, observations: &PreReadObservations) -> praxis_filter::FilterRegistry {
    let spec = spec.clone();
    let observations = std::sync::Arc::clone(observations);
    let mut registry = praxis_filter::FilterRegistry::with_builtins();
    registry
        .register(
            "payload_preread_probe",
            praxis_filter::FilterFactory::Http(std::sync::Arc::new(move |_| {
                Ok(Box::new(PreReadProbe {
                    spec: spec.clone(),
                    observations: std::sync::Arc::clone(&observations),
                }))
            })),
        )
        .unwrap();
    registry
}

#[test]
fn fragmented_mib_preread_preserves_bytes_eos_and_trailer_framing() {
    let spec = PayloadSpec::binary(1_048_576, SEED);
    let selected = start_counting_backend(spec.clone(), "selected", spec.len());
    let other = start_counting_backend(spec.clone(), "other", spec.len());
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(
        free_port(),
        (selected.port, other.port, health.port()),
        "",
        "      - filter: payload_preread_probe",
    );
    let observations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let registry = preread_registry(&spec, &observations);
    let proxy = start_transport_with_registry(&config, &registry);
    let mut stream = connect(proxy.addr());
    stream.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer\r\nConnection: close\r\n\r\n").unwrap();
    assert_eq!(write_payload_with_trailer(&mut stream, &spec, 4096), spec.len());
    let result = response(stream);
    #[cfg(feature = "pingora")]
    {
        assert_eq!(result.status, Some(200), "{result:?}");
        let receipt = assert_receipt(&selected, &spec);
        assert!(
            receipt.trailers.is_empty(),
            "Pingora consumes request trailers: {receipt:?}"
        );
    }
    #[cfg(feature = "hyper")]
    {
        assert_eq!(
            result.status,
            Some(400),
            "H1 upstream cannot carry request trailers: {result:?}"
        );
        assert!(
            result.completion.is_some() && result.abort.is_none(),
            "rejection must complete: {result:?}"
        );
        assert_aborted_trailer_upload(&selected, &spec, true);
    }
    assert_eq!(
        *observations.lock().unwrap(),
        vec![(1_048_576, None)],
        "pre-read must receive exactly one complete EOS"
    );
    assert!(matches!(
        other.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    selected.join();
    other.join();
}

/// Pre-read extraction and body scanning share a finite global input ceiling.
const INSPECTION_FILTERS: &str = "      - filter: json_body_field\n        field: model\n        header: x-praxis-model\n        max_body_bytes: 65536\n      - filter: guardrails\n        rules:\n          - target: body\n            contains: 123-45-6789";

#[test]
fn oversized_malformed_json_is_rejected_before_the_unread_pii_tail() {
    let spec = PayloadSpec::padded(
        131_072,
        br#"{"model":"blue","padding":""#,
        br#"","pii":"123-45-6789"#,
        b'x',
    )
    .unwrap();
    let selected = start_counting_backend(spec.clone(), "selected", spec.len());
    let other = start_counting_backend(spec.clone(), "other", spec.len());
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(
        free_port(),
        (selected.port, other.port, health.port()),
        "body_limits:\n  max_request_bytes: 65536",
        INSPECTION_FILTERS,
    );
    let proxy = start_transport(&config);
    let mut stream = connect(proxy.addr());
    stream
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
        .unwrap();
    let crossing = spec.chunk(0, 65_537);
    write!(stream, "{:x}\r\n", crossing.len()).unwrap();
    stream.write_all(&crossing).unwrap();
    stream.write_all(b"\r\n").unwrap();
    // The PII-bearing malformed suffix and terminating chunk remain unsent.
    let observed = response(stream);
    assert_eq!(observed.status, Some(413), "{observed:?}");
    assert!(observed.completion.is_some(), "{observed:?}");
    assert!(
        matches!(selected.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
        "pre-read rejection dispatched upstream"
    );
    assert!(matches!(
        other.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    probe(proxy.addr());
    selected.join();
    other.join();
}

#[test]
fn within_limit_malformed_and_pii_controls_exercise_distinct_decisions() {
    let malformed = PayloadSpec::padded(1024, br#"{"model":"blue","padding":""#, b"", b'x').unwrap();
    let selected = start_counting_backend(malformed.clone(), "selected", malformed.len());
    let other = start_counting_backend(malformed.clone(), "other", malformed.len());
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(
        free_port(),
        (selected.port, other.port, health.port()),
        "body_limits:\n  max_request_bytes: 65536",
        INSPECTION_FILTERS,
    );
    let proxy = start_transport(&config);
    let mut stream = connect(proxy.addr());
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        malformed.len()
    )
    .unwrap();
    assert_eq!(write_payload(&mut stream, &malformed, 257, false), malformed.len());
    let observed = response(stream);
    assert_eq!(
        observed.status,
        Some(200),
        "malformed JSON continues by configuration: {observed:?}"
    );
    assert_receipt(&selected, &malformed);
    selected.join();
    other.join();

    let pii = br#"{"model":"blue","pii":"123-45-6789"}"#;
    let selected = start_counting_backend(PayloadSpec::binary(1, SEED), "selected", 1);
    let other = start_counting_backend(PayloadSpec::binary(1, SEED), "other", 1);
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(
        free_port(),
        (selected.port, other.port, health.port()),
        "body_limits:\n  max_request_bytes: 65536",
        INSPECTION_FILTERS,
    );
    let proxy = start_transport(&config);
    let mut stream = connect(proxy.addr());
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        pii.len()
    )
    .unwrap();
    stream.write_all(pii).unwrap();
    let observed = response(stream);
    assert_eq!(
        observed.status,
        Some(403),
        "within-limit PII must trigger the guard: {observed:?}"
    );
    assert!(matches!(
        selected.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    assert!(matches!(
        other.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    probe(proxy.addr());
    selected.join();
    other.join();
}

/// Send generated HTTP/2 DATA under flow control without ending the stream.
async fn send_h2_data_nonfinal(stream: &mut h2::SendStream<bytes::Bytes>, spec: &PayloadSpec) {
    let mut offset = 0_u64;
    while offset < spec.len() {
        let desired = (spec.len() - offset).min(4096) as usize;
        stream.reserve_capacity(desired);
        let capacity = if stream.capacity() > 0 {
            stream.capacity()
        } else {
            std::future::poll_fn(|cx| stream.poll_capacity(cx))
                .await
                .unwrap()
                .unwrap()
        };
        if capacity == 0 {
            continue;
        }
        let chunk = spec.chunk(offset, desired.min(capacity));
        offset += chunk.len() as u64;
        stream.send_data(bytes::Bytes::from(chunk), false).unwrap();
    }
}

/// Finish a generated upload with a trailer block rather than DATA EOS.
async fn send_h2_trailers(stream: &mut h2::SendStream<bytes::Bytes>, spec: &PayloadSpec) {
    send_h2_data_nonfinal(stream, spec).await;
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-trailer", http::HeaderValue::from_static("done"));
    stream.send_trailers(trailers).unwrap();
}

#[test]
fn h2_fragmented_mib_preread_ends_with_trailers_and_one_eos() {
    let spec = PayloadSpec::binary(1_048_576, SEED);
    let selected = start_counting_backend(spec.clone(), "selected", spec.len());
    let other = start_counting_backend(spec.clone(), "other", spec.len());
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(
        free_port(),
        (selected.port, other.port, health.port()),
        "",
        "      - filter: payload_preread_probe",
    );
    let observations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let registry = preread_registry(&spec, &observations);
    let proxy = start_transport_with_registry(&config, &registry);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(DEADLINE, async {
            let stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
            let (mut client, connection) = h2::client::handshake(stream).await.unwrap();
            let driver = tokio::spawn(async move {
                let _result = connection.await;
            });
            let request = http::Request::post("/").header("host", "localhost").body(()).unwrap();
            let (response, mut sender) = client.send_request(request, false).unwrap();
            let ((), observed) = tokio::join!(send_h2_trailers(&mut sender, &spec), async {
                praxis_test_utils::read_h2_response(response.await, 1024, |_| Ok(())).await
            });
            #[cfg(feature = "pingora")]
            assert_eq!(observed.status, Some(200), "{observed:?}");
            #[cfg(feature = "hyper")]
            assert_eq!(
                observed.status,
                Some(400),
                "H1 upstream cannot carry request trailers: {observed:?}"
            );
            assert!(observed.end_stream, "{observed:?}");
            driver.abort();
        })
        .await
        .expect("H2 pre-read upload deadline");
    });
    #[cfg(feature = "pingora")]
    {
        let receipt = assert_receipt(&selected, &spec);
        assert!(
            receipt.trailers.is_empty(),
            "Pingora consumes request trailers: {receipt:?}"
        );
    }
    #[cfg(feature = "hyper")]
    assert_aborted_trailer_upload(&selected, &spec, true);
    assert_eq!(*observations.lock().unwrap(), vec![(1_048_576, None)]);
    assert!(matches!(
        other.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    selected.join();
    other.join();
}

/// Exercise ordered event delivery before EOS and optional finite overflow.
fn sse_events(unbounded: bool) {
    let events = (0..8).map(|index| format!("data: {index:06}\n\n")).collect::<Vec<_>>();
    let event_len = events[0].len();
    let expected = events.concat().into_bytes();
    let backend_events = events.clone();
    let (advance, wait) = std::sync::mpsc::channel();
    let accepted_events = if unbounded { events.len() } else { 4 };
    let (port, worker) = praxis_test_utils::spawn_raw_http_backend(move |mut stream| {
        praxis_test_utils::read_http_request(&mut stream);
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            backend_events.iter().map(String::len).sum::<usize>()
        )
        .unwrap();
        for (index, event) in backend_events.iter().enumerate() {
            if stream.write_all(event.as_bytes()).is_err() {
                break;
            }
            stream.flush().unwrap();
            if index < accepted_events {
                wait.recv_timeout(Duration::from_secs(5))
                    .unwrap_or_else(|error| panic!("event index={index}, unbounded={unbounded}: {error}"));
                std::thread::sleep(Duration::from_millis(10));
            } else {
                break;
            }
        }
    });
    let other = start_counting_backend(PayloadSpec::binary(0, SEED), "other", 0);
    let health = start_backend_with_shutdown("probe");
    let response_limit = if unbounded {
        "null".to_owned()
    } else {
        (event_len * accepted_events).to_string()
    };
    let limits = format!("body_limits:\n  max_response_bytes: {response_limit}");
    let config = transport_config(free_port(), (port, other.port, health.port()), &limits, "");
    let proxy = start_transport(&config);
    let mut stream = connect(proxy.addr());
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut bytes = Vec::new();
    let mut acknowledged = 0;
    let result = read_h1_response(&mut BufReader::new(stream), false, expected.len() as u64, |part| {
        bytes.extend_from_slice(part);
        while acknowledged < accepted_events && bytes.len() >= (acknowledged + 1) * event_len {
            assert_eq!(
                &bytes[..(acknowledged + 1) * event_len],
                &expected[..(acknowledged + 1) * event_len],
                "SSE event prefix must arrive in order before acknowledging event {acknowledged}"
            );
            advance.send(()).unwrap_or_else(|error| {
                panic!("client acknowledged event index={acknowledged}, unbounded={unbounded}: {error}")
            });
            acknowledged += 1;
        }
        Ok(())
    });
    assert_eq!(result.status, Some(200), "{result:?}");
    assert_eq!(
        acknowledged, accepted_events,
        "all allowed events must be delivered before EOS"
    );
    if unbounded {
        assert_eq!(bytes, expected, "unbounded SSE stream must deliver every event");
        #[cfg(feature = "pingora")]
        let expected_completion = H1Completion::Chunked;
        #[cfg(feature = "hyper")]
        let expected_completion = H1Completion::ContentLength;
        assert_eq!(
            result.completion,
            Some(expected_completion),
            "unbounded SSE response must complete with the adapter's framing"
        );
    } else {
        assert_eq!(
            bytes,
            expected[..accepted_events * event_len],
            "limited SSE stream must deliver exactly the allowed prefix"
        );
        assert_eq!(result.completion, None, "{result:?}");
        assert!(result.abort.is_some(), "{result:?}");
    }
    worker.join().unwrap();
    probe(proxy.addr());
    other.join();
}

#[test]
fn sse_events_arrive_incrementally_and_finite_streams_stop_at_limit() {
    sse_events(true);
    sse_events(false);
}

#[test]
fn chunk_extensions_and_reserved_trailers_do_not_change_body_budget_or_route() {
    for reserved_trailers in [false, true] {
        chunk_extensions_at_body_limit(reserved_trailers);
    }
}

/// The successful control rules out a framing rejection before the reserved trailer.
fn chunk_extensions_at_body_limit(reserved_trailers: bool) {
    let spec = PayloadSpec::padded(32_768, b"binary\0\xff\r\n0\r\n\r\n", b"end", b'x').unwrap();
    let selected = start_counting_backend(spec.clone(), "selected", spec.len());
    let other = start_counting_backend(spec.clone(), "other", spec.len());
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(
        free_port(),
        (selected.port, other.port, health.port()),
        "body_limits:\n  max_request_bytes: 32768",
        "",
    );
    let proxy = start_transport(&config);
    let mut stream = connect(proxy.addr());
    stream.write_all(b"POST /trailer HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTrailer: X-Praxis-Model\r\nConnection: close\r\n\r\n").unwrap();
    // Hyper caps cumulative chunk-extension bytes at 16 KiB. Eight 1 KiB
    // extensions leave room for their names while still exceeding the body limit
    // if the proxy mistakenly counts framing as content.
    let extension = "x".repeat(1024);
    let mut offset = 0;
    while offset < spec.len() {
        let chunk = spec.chunk(offset, 4096);
        write!(stream, "{:x};padding={extension}\r\n", chunk.len()).unwrap();
        stream.write_all(&chunk).unwrap();
        stream.write_all(b"\r\n").unwrap();
        offset += chunk.len() as u64;
    }
    let ending = if reserved_trailers {
        b"0\r\nX-Praxis-Model: trusted\r\nX-Ordinary: done\r\n\r\n".as_slice()
    } else {
        b"0\r\n\r\n".as_slice()
    };
    stream.write_all(ending).unwrap();
    let result = response(stream);
    assert!(
        result.completion.is_some() && result.abort.is_none(),
        "response must complete: {result:?}"
    );
    #[cfg(feature = "pingora")]
    {
        assert_eq!(result.status, Some(200), "{result:?}");
        let receipt = assert_receipt(&selected, &spec);
        assert!(
            receipt.trailers.is_empty(),
            "Pingora consumes request trailers: {receipt:?}"
        );
    }
    #[cfg(feature = "hyper")]
    {
        assert_eq!(
            result.status,
            Some(if reserved_trailers { 400 } else { 200 }),
            "only the reserved trailer must cause rejection: {result:?}"
        );
        if reserved_trailers {
            assert_aborted_trailer_upload(&selected, &spec, false);
        } else {
            assert_receipt(&selected, &spec);
        }
    }
    assert!(
        matches!(
            other.accepted.recv_timeout(Duration::from_millis(200)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ),
        "trailer must not select a header-based route"
    );
    probe(proxy.addr());
    selected.join();
    other.join();
}

#[test]
fn bounded_invalid_length_corpus_cannot_dispatch_a_sentinel() {
    // Stable corpus IDs preserve the exact bytes used in each run.
    let corpus = [
        ("duplicate-length", "Content-Length: 4\r\nContent-Length: 5\r\n"),
        ("overflow-length", "Content-Length: 18446744073709551616\r\n"),
        ("negative-length", "Content-Length: -1\r\n"),
        ("empty-length", "Content-Length: \r\n"),
    ];
    for (seed, framing) in corpus {
        let selected = start_counting_backend(PayloadSpec::binary(0, SEED), "selected", 1);
        let other = start_counting_backend(PayloadSpec::binary(0, SEED), "sentinel", 1);
        let health = start_backend_with_shutdown("probe");
        let config = transport_config(free_port(), (selected.port, other.port, health.port()), "", "");
        let proxy = start_transport(&config);
        let mut stream = connect(proxy.addr());
        write!(stream, "POST / HTTP/1.1\r\nHost: localhost\r\n{framing}Connection: close\r\n\r\nGET /other HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let result = response(stream);
        assert_eq!(result.status, Some(400), "corpus={seed}: {result:?}");
        assert!(
            matches!(selected.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
            "corpus={seed} forwarded invalid framing"
        );
        assert!(
            matches!(other.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
            "corpus={seed} dispatched the sentinel"
        );
        probe(proxy.addr());
        selected.join();
        other.join();
    }
}

/// Connect HTTP/1 over TLS using the generated test CA.
fn tls_stream(
    address: &str,
    client: &std::sync::Arc<rustls::ClientConfig>,
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let session = rustls::ClientConnection::new(std::sync::Arc::clone(client), name).unwrap();
    rustls::StreamOwned::new(session, connect(address))
}

#[test]
fn tls_ingress_preserves_near_default_limit_bytes_and_rejection() {
    let certificates = praxis_test_utils::TestCertificates::generate();
    let client = certificates.raw_tls_client_config();
    for length in [10_485_760_u64, 10_485_761] {
        let spec = PayloadSpec::binary(length, SEED);
        let selected = start_counting_backend(spec.clone(), "selected", length);
        let health = start_backend_with_shutdown("probe");
        let port = free_port();
        let yaml = format!(
            r#"
listeners:
  - name: secure
    address: "127.0.0.1:{port}"
    filter_chains: [main]
    tls:
      certificates:
        - cert_path: "{}"
          key_path: "{}"
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: /probe
            cluster: probe
          - path_prefix: /
            cluster: selected
      - filter: load_balancer
        clusters:
          - name: selected
            endpoints: ["127.0.0.1:{}"]
          - name: probe
            endpoints: ["127.0.0.1:{}"]
insecure_options:
  allow_private_endpoints: true
"#,
            certificates.cert_path.display(),
            certificates.key_path.display(),
            selected.port,
            health.port()
        );
        let config = Config::from_yaml(&yaml).unwrap();
        let proxy = praxis_test_utils::start_tls_proxy_no_wait(&config);
        praxis_test_utils::wait_for_tcp(proxy.addr());
        let mut stream = tls_stream(proxy.addr(), &client);
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let written = if length == 10_485_760 {
            write_payload(&mut stream, &spec, 16_384, false)
        } else {
            0
        };
        stream.flush().unwrap();
        let mut body = Vec::new();
        let observed = read_h1_response(&mut BufReader::new(stream), false, 65_536, |part| {
            body.extend_from_slice(part);
            Ok(())
        });
        if length == 10_485_760 {
            assert_eq!(written, length);
            assert_eq!(observed.status, Some(200), "{observed:?}");
            assert_receipt(&selected, &spec);
        } else {
            assert_eq!(
                written, 0,
                "oversized declaration must be tested before uploading content"
            );
            assert_eq!(observed.status, Some(413), "{observed:?}");
            assert_eq!(observed.completion, Some(H1Completion::ContentLength), "{observed:?}");
            assert_eq!(
                body.as_slice(),
                br#"{"error":"request body too large"}"#,
                "413 body must be complete"
            );
            assert!(
                matches!(
                    selected.accepted.recv_timeout(Duration::from_millis(200)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ),
                "oversized declaration must be rejected before selecting an upstream"
            );
        }
        let mut clean = tls_stream(proxy.addr(), &client);
        clean
            .write_all(b"GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        clean.flush().unwrap();
        let mut body = Vec::new();
        let control = read_h1_response(&mut BufReader::new(clean), false, 100, |part| {
            body.extend_from_slice(part);
            Ok(())
        });
        assert_eq!(control.status, Some(200), "{control:?}");
        assert_eq!(body, b"probe");
        assert!(control.completion.is_some());
        selected.join();
    }
}

#[test]
fn early_upstream_reply_cancels_the_unread_upload_without_a_late_413() {
    use std::io::Read as _;

    let (port, worker) = praxis_test_utils::spawn_raw_http_backend(|mut stream| {
        stream.set_read_timeout(Some(DEADLINE)).unwrap();
        let mut header = Vec::new();
        let mut byte = [0_u8; 1];
        while !header.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() <= 65_536);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nearly")
            .unwrap();
    });
    let other = start_counting_backend(PayloadSpec::binary(0, SEED), "other", 0);
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(
        free_port(),
        (port, other.port, health.port()),
        "body_limits:\n  max_request_bytes: 16",
        "",
    );
    let proxy = start_transport(&config);
    let mut stream = connect(proxy.addr());
    stream
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\ntiny\r\n")
        .unwrap();
    let mut body = Vec::new();
    let observed = read_h1_response(&mut BufReader::new(stream), false, 100, |part| {
        body.extend_from_slice(part);
        Ok(())
    });
    assert_eq!(
        observed.status,
        Some(200),
        "only four content bytes were sent before the reply: {observed:?}"
    );
    assert_eq!(observed.completion, Some(H1Completion::ContentLength));
    assert_eq!(body, b"early");
    worker.join().unwrap();
    probe(proxy.addr());
    assert!(matches!(
        other.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    other.join();
}

#[test]
fn h2_reset_during_preread_does_not_dispatch_or_stop_control_stream() {
    let spec = PayloadSpec::binary(1_048_576, SEED);
    let selected = start_counting_backend(spec.clone(), "selected", spec.len());
    let other = start_counting_backend(spec.clone(), "other", spec.len());
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(
        free_port(),
        (selected.port, other.port, health.port()),
        "",
        "      - filter: payload_preread_probe",
    );
    let observations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let registry = preread_registry(&spec, &observations);
    let proxy = start_transport_with_registry(&config, &registry);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(DEADLINE, async {
            let stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
            let (mut client, connection) = h2::client::handshake(stream).await.unwrap();
            let driver = tokio::spawn(async move {
                let _result = connection.await;
            });
            let request = http::Request::post("/").header("host", "localhost").body(()).unwrap();
            let (_response, mut body) = client.send_request(request, false).unwrap();
            body.send_data(bytes::Bytes::from(spec.chunk(0, 4096)), false).unwrap();
            body.send_reset(h2::Reason::CANCEL);
            let control = http::Request::get("/probe")
                .header("host", "localhost")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(control, true).unwrap();
            let mut bytes = Vec::new();
            let observed = praxis_test_utils::read_h2_response(response.await, 100, |part| {
                bytes.extend_from_slice(part);
                Ok(())
            })
            .await;
            assert_eq!(observed.status, Some(200), "{observed:?}");
            assert!(observed.end_stream, "{observed:?}");
            assert_eq!(bytes, b"probe");
            driver.abort();
        })
        .await
        .expect("reset and independent control must finish");
    });
    assert!(observations.lock().unwrap().is_empty(), "a reset has no buffered EOS");
    assert!(
        matches!(selected.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
        "reset pre-read dispatched upstream"
    );
    assert!(matches!(
        other.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    selected.join();
    other.join();
}

#[test]
#[ignore = "scheduled: transfers a 1 GiB request with an explicit unbounded override"]
fn scheduled_unbounded_opaque_upload_one_gib() {
    opaque_upload(
        &PayloadSpec::binary(1_073_741_824, SEED),
        "body_limits:\n  max_buffer_bytes: 1073741824\n  max_request_bytes: null\n  max_response_bytes: 1024",
        "POST",
        false,
        "upload",
    );
}

#[test]
#[ignore = "scheduled: transfers a 256 MiB generated response"]
fn scheduled_unbounded_opaque_response_256_mib() {
    generated_response(268_435_456, None, "1024", PayloadResponseFraming::Chunked, true);
}

#[test]
fn h2_content_length_mismatch_is_stream_error_with_control_progress() {
    let spec = PayloadSpec::binary(4, SEED);
    let selected = start_counting_backend(spec.clone(), "selected", spec.len());
    let other = start_counting_backend(spec.clone(), "other", spec.len());
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(
        free_port(),
        (selected.port, other.port, health.port()),
        "",
        "      - filter: payload_preread_probe",
    );
    let observations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let registry = preread_registry(&spec, &observations);
    let proxy = start_transport_with_registry(&config, &registry);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(DEADLINE, async {
            let stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
            let (mut client, connection) = h2::client::handshake(stream).await.unwrap();
            let driver = tokio::spawn(async move {
                let _result = connection.await;
            });
            let request = http::Request::post("/")
                .header("host", "localhost")
                .header("content-length", "5")
                .body(())
                .unwrap();
            let (affected, mut body) = client.send_request(request, false).unwrap();
            body.send_data(bytes::Bytes::from(spec.chunk(0, 4)), true).unwrap();
            let control = http::Request::get("/probe")
                .header("host", "localhost")
                .body(())
                .unwrap();
            let (control, _) = client.send_request(control, true).unwrap();
            let mut bytes = Vec::new();
            let (affected, control) = tokio::join!(
                async { praxis_test_utils::read_h2_response(affected.await, 1024, |_| Ok(())).await },
                async {
                    praxis_test_utils::read_h2_response(control.await, 100, |part| {
                        bytes.extend_from_slice(part);
                        Ok(())
                    })
                    .await
                },
            );
            assert_eq!(affected.status, None, "mismatched stream cannot complete: {affected:?}");
            assert_eq!(affected.reset, Some(h2::Reason::PROTOCOL_ERROR), "{affected:?}");
            assert!(!affected.end_stream, "{affected:?}");
            assert_eq!(control.status, Some(200), "independent control: {control:?}");
            assert!(control.end_stream, "{control:?}");
            assert_eq!(bytes, b"probe");
            driver.abort();
        })
        .await
        .expect("mismatched stream and control must finish");
    });
    assert!(matches!(
        selected.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    assert!(matches!(
        other.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    selected.join();
    other.join();
}

/// Collect a TLS upstream's request without buffering its body.
fn tls_backend_receipt(
    listener: &std::net::TcpListener,
    server: std::sync::Arc<rustls::ServerConfig>,
    spec: &PayloadSpec,
) -> Option<(u64, Option<u64>, bool)> {
    use std::io::Read as _;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return None,
            Err(error) => panic!("TLS backend accept: {error}"),
        }
    };
    socket.set_read_timeout(Some(DEADLINE)).unwrap();
    socket.set_write_timeout(Some(DEADLINE)).unwrap();
    let session = rustls::ServerConnection::new(server).unwrap();
    let mut stream = rustls::StreamOwned::new(session, socket);
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).is_err() {
            return Some((0, None, false));
        }
        header.push(byte[0]);
        assert!(
            header.len() <= 65_536,
            "TLS backend request headers must remain bounded"
        );
    }
    let headers = String::from_utf8(header).unwrap();
    let length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<u64>().unwrap())
        })
        .expect("fixed-length request must retain its content length");
    assert_eq!(
        length,
        spec.len(),
        "TLS backend must receive the declared upload length"
    );
    let mut count = 0_u64;
    let mut mismatch = None;
    let mut buffer = vec![0_u8; 16_384];
    while count < length {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if mismatch.is_none() {
                    mismatch = spec.mismatch(count, &buffer[..read]);
                }
                count += read as u64;
            },
        }
    }
    let complete = count == length && mismatch.is_none();
    if complete {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        stream.flush().unwrap();
    }
    Some((count, mismatch, complete))
}

#[test]
fn tls_upstream_preserves_near_default_limit_and_abort() {
    let certificates = praxis_test_utils::TestCertificates::generate();
    let cert_pem = std::fs::read(&certificates.cert_path).unwrap();
    let key_pem = std::fs::read(&certificates.key_path).unwrap();
    let (chain, key) = praxis_test_utils::parse_cert_chain_and_key(&cert_pem, &key_pem);
    let server = std::sync::Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
    );
    for length in [10_485_760_u64, 10_485_761] {
        let spec = PayloadSpec::binary(length, SEED);
        let (listener, backend_port) = praxis_test_utils::bind_unique_port();
        listener.set_nonblocking(true).unwrap();
        let backend_spec = spec.clone();
        let server_config = std::sync::Arc::clone(&server);
        let worker = std::thread::spawn(move || tls_backend_receipt(&listener, server_config, &backend_spec));
        let health = start_backend_with_shutdown("probe");
        let port = free_port();
        let yaml = format!(
            r#"
listeners:
  - name: plain
    address: "127.0.0.1:{port}"
    filter_chains: [main]
runtime:
  upstream_ca_file: "{}"
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: /probe
            cluster: probe
          - path_prefix: /
            cluster: selected
      - filter: load_balancer
        clusters:
          - name: selected
            tls:
              sni: localhost
            endpoints: ["127.0.0.1:{backend_port}"]
          - name: probe
            endpoints: ["127.0.0.1:{}"]
insecure_options:
  allow_private_endpoints: true
"#,
            certificates.ca_cert_path.display(),
            health.port()
        );
        let proxy = start_transport(&Config::from_yaml(&yaml).unwrap());
        let mut stream = connect(proxy.addr());
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let written = write_payload(&mut stream, &spec, 16_384, false);
        let observed = response(stream);
        let receipt = worker.join().unwrap();
        if length == 10_485_760 {
            assert_eq!(written, length);
            assert_eq!(observed.status, Some(200), "{observed:?}");
            assert_eq!(receipt, Some((length, None, true)));
        } else {
            assert_eq!(observed.status, Some(413), "{observed:?}");
            if let Some((bytes, mismatch, complete)) = receipt {
                assert!(bytes <= 10_485_760);
                assert_eq!(mismatch, None);
                assert!(!complete);
            }
        }
        probe(proxy.addr());
    }
}

#[test]
fn malformed_and_overflowing_chunk_sizes_cannot_dispatch_a_sentinel() {
    for (seed, size) in [("nonhex", "xyz"), ("overflow", "10000000000000000")] {
        let spec = PayloadSpec::padded(1, b"a", b"", b'x').unwrap();
        let selected = start_counting_backend(spec.clone(), "selected", 4);
        let other = start_counting_backend(spec, "sentinel", 4);
        let health = start_backend_with_shutdown("probe");
        let config = transport_config(free_port(), (selected.port, other.port, health.port()), "", "");
        let proxy = start_transport(&config);
        let mut stream = connect(proxy.addr());
        write!(stream, "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\na\r\n{size}\r\nGET /other HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let result = response(stream);
        assert_eq!(result.status, Some(400), "corpus={seed}: {result:?}");
        assert_rejected_receipt(&selected, 1);
        assert!(
            matches!(other.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
            "corpus={seed} dispatched a sentinel"
        );
        probe(proxy.addr());
        selected.join();
        other.join();
    }
}

#[test]
fn h2_over_tls_upload_enforces_limit_with_control_stream() {
    let certificates = praxis_test_utils::TestCertificates::generate();
    let client_config = certificates.client_config();
    for length in [65_536_u64, 65_537] {
        let spec = PayloadSpec::binary(length, SEED);
        let selected = start_counting_backend(spec.clone(), "selected", length);
        let health = start_backend_with_shutdown("probe");
        let port = free_port();
        let yaml = format!(
            r#"
body_limits:
  max_request_bytes: 65536
listeners:
  - name: secure
    address: "127.0.0.1:{port}"
    filter_chains: [main]
    tls:
      certificates:
        - cert_path: "{}"
          key_path: "{}"
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: /probe
            cluster: probe
          - path_prefix: /
            cluster: selected
      - filter: load_balancer
        clusters:
          - name: selected
            endpoints: ["127.0.0.1:{}"]
          - name: probe
            endpoints: ["127.0.0.1:{}"]
insecure_options:
  allow_private_endpoints: true
"#,
            certificates.cert_path.display(),
            certificates.key_path.display(),
            selected.port,
            health.port()
        );
        let config = Config::from_yaml(&yaml).unwrap();
        let proxy = praxis_test_utils::start_tls_proxy_no_wait(&config);
        praxis_test_utils::wait_for_tcp(proxy.addr());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            tokio::time::timeout(DEADLINE, async {
                let socket = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
                let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::clone(&client_config));
                let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
                let tls = connector.connect(server_name, socket).await.unwrap();
                let (mut client, connection) = h2::client::handshake(tls).await.unwrap();
                let driver = tokio::spawn(async move {
                    let _result = connection.await;
                });
                let request = http::Request::post("/").header("host", "localhost").body(()).unwrap();
                let (response, mut sender) = client.send_request(request, false).unwrap();
                let control = http::Request::get("/probe")
                    .header("host", "localhost")
                    .body(())
                    .unwrap();
                let (control, _) = client.send_request(control, true).unwrap();
                let mut control_bytes = Vec::new();
                let (upload, observed, control) = tokio::join!(
                    praxis_test_utils::send_h2_payload(&mut sender, &spec, 4096),
                    async { praxis_test_utils::read_h2_response(response.await, 1024, |_| Ok(())).await },
                    async {
                        praxis_test_utils::read_h2_response(control.await, 100, |part| {
                            control_bytes.extend_from_slice(part);
                            Ok(())
                        })
                        .await
                    },
                );
                let expected = if length == 65_536 { 200 } else { 413 };
                assert_eq!(observed.status, Some(expected), "upload={upload:?}; {observed:?}");
                assert!(observed.end_stream, "{observed:?}");
                assert_eq!(control.status, Some(200), "{control:?}");
                assert!(control.end_stream);
                assert_eq!(control_bytes, b"probe");
                driver.abort();
            })
            .await
            .expect("H2 TLS streams must finish");
        });
        if length == 65_536 {
            assert_receipt(&selected, &spec);
        } else {
            assert_rejected_receipt(&selected, 65_536);
        }
        selected.join();
    }
}

#[test]
fn h2_response_overflow_resets_only_affected_stream_after_prefix() {
    let spec = PayloadSpec::binary(131_072, SEED);
    let mut source = start_payload_response_backend(spec.clone(), PayloadResponseFraming::Fixed, Some(4096));
    let other = start_counting_backend(PayloadSpec::binary(0, SEED), "other", 0);
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(
        free_port(),
        (source.port, other.port, health.port()),
        "body_limits:\n  max_response_bytes: 65536",
        "",
    );
    let proxy = start_transport(&config);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(DEADLINE, async {
            let socket = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
            let (mut client, connection) = h2::client::handshake(socket).await.unwrap();
            let driver = tokio::spawn(async move {
                let _result = connection.await;
            });
            let request = http::Request::get("/").header("host", "localhost").body(()).unwrap();
            let (response, _) = client.send_request(request, true).unwrap();
            let control = http::Request::get("/probe")
                .header("host", "localhost")
                .body(())
                .unwrap();
            let (control, _) = client.send_request(control, true).unwrap();
            let mut count = 0;
            let mut resumed = false;
            let mut control_bytes = Vec::new();
            let (observed, control) = tokio::join!(
                async {
                    praxis_test_utils::read_h2_response(response.await, spec.len(), |part| {
                        assert_eq!(spec.mismatch(count, part), None);
                        count += part.len() as u64;
                        if count >= 4096 && !resumed {
                            assert_eq!(source.prefix_written.recv_timeout(DEADLINE).unwrap(), 4096);
                            source.resume();
                            resumed = true;
                        }
                        Ok(())
                    })
                    .await
                },
                async {
                    praxis_test_utils::read_h2_response(control.await, 100, |part| {
                        control_bytes.extend_from_slice(part);
                        Ok(())
                    })
                    .await
                },
            );
            assert_eq!(observed.status, Some(200), "{observed:?}");
            assert!(resumed);
            assert_eq!(observed.body_bytes, count);
            assert!(count <= 65_536 && count < spec.len());
            assert!(!observed.end_stream, "{observed:?}");
            assert!(
                observed.reset.is_some(),
                "the oversized response must reset the stream: {observed:?}"
            );
            assert_eq!(control.status, Some(200), "{control:?}");
            assert!(control.end_stream);
            assert_eq!(control_bytes, b"probe");
            driver.abort();
        })
        .await
        .expect("H2 response overflow deadline");
    });
    let receipt = source.receipt.recv_timeout(DEADLINE).unwrap();
    assert!(receipt.written_bytes >= 4096, "{receipt:?}");
    assert!(matches!(
        other.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    probe(proxy.addr());
    source.join();
    other.join();
}

#[test]
fn generated_length_overflow_mutations_keep_sentinel_isolated() {
    for seed in 0..8_u64 {
        let selected = start_counting_backend(PayloadSpec::binary(0, SEED), "selected", 1);
        let other = start_counting_backend(PayloadSpec::binary(0, SEED), "sentinel", 1);
        let health = start_backend_with_shutdown("probe");
        let config = transport_config(free_port(), (selected.port, other.port, health.port()), "", "");
        let proxy = start_transport(&config);
        let mut stream = connect(proxy.addr());
        let header = if seed % 2 == 0 {
            "Content-Length"
        } else {
            "cOnTeNt-LeNgTh"
        };
        let wire = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\n{header}: 18446744073709551616{seed:02}\r\nConnection: close\r\n\r\nGET /other HTTP/1.1\r\nHost: localhost\r\nX-Seed: {seed}\r\n\r\n"
        );
        stream.write_all(wire.as_bytes()).unwrap();
        let result = response(stream);
        assert_eq!(result.status, Some(400), "seed={seed}: {result:?}");
        assert!(
            matches!(selected.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
            "seed={seed} dispatched invalid request"
        );
        assert!(
            matches!(other.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
            "seed={seed} dispatched sentinel"
        );
        probe(proxy.addr());
        selected.join();
        other.join();
    }
}

#[test]
fn truncated_fixed_length_event_stream_never_completes_after_reframing() {
    let (advance, wait) = std::sync::mpsc::channel();
    let (port, worker) = praxis_test_utils::spawn_raw_http_backend(move |mut stream| {
        praxis_test_utils::read_http_request(&mut stream);
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 28\r\nConnection: close\r\n\r\ndata: 000000\n\n").unwrap();
        stream.flush().unwrap();
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
        // Close after half the declared body; the proxy must not emit EOS.
    });
    let other = start_counting_backend(PayloadSpec::binary(0, SEED), "other", 0);
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(free_port(), (port, other.port, health.port()), "", "");
    let proxy = start_transport(&config);
    let mut stream = connect(proxy.addr());
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut body = Vec::new();
    let mut acknowledged = false;
    let result = read_h1_response(&mut BufReader::new(stream), false, 28, |part| {
        body.extend_from_slice(part);
        if body.len() == 14 && !acknowledged {
            advance.send(()).unwrap();
            acknowledged = true;
        }
        Ok(())
    });
    assert_eq!(result.status, Some(200), "{result:?}");
    assert!(acknowledged, "the first event must arrive before upstream EOF");
    assert_eq!(body, b"data: 000000\n\n");
    assert_eq!(
        result.completion, None,
        "the incomplete upstream length must not become a complete chunked response: {result:?}"
    );
    assert!(result.abort.is_some(), "{result:?}");
    worker.join().unwrap();
    probe(proxy.addr());
    other.join();
}

/// Read one HTTP/1 header block without consuming following body bytes.
fn read_test_header(reader: &mut BufReader<TcpStream>) -> String {
    use std::io::BufRead as _;
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        let count = reader.read_line(&mut line).unwrap();
        assert_ne!(count, 0, "upstream closed before request headers");
        assert!(headers.len() + count <= 65_536, "request headers exceed test bound");
        if line == "\r\n" {
            break;
        }
        headers.push_str(&line);
    }
    headers
}

#[test]
fn h2_early_reply_keeps_control_healthy_after_unread_upload_cancel() {
    use std::io::{BufRead as _, Read as _};
    let (receipt_tx, receipt_rx) = std::sync::mpsc::channel();
    let (port, worker) = praxis_test_utils::spawn_raw_http_backend(move |stream| {
        stream.set_read_timeout(Some(DEADLINE)).unwrap();
        let mut reader = BufReader::new(stream);
        let headers = read_test_header(&mut reader);
        assert!(
            headers
                .lines()
                .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked")),
            "{headers}"
        );
        let mut size = String::new();
        reader.read_line(&mut size).unwrap();
        assert_eq!(usize::from_str_radix(size.trim(), 16).unwrap(), 4);
        let mut prefix = [0_u8; 4];
        reader.read_exact(&mut prefix).unwrap();
        let mut ending = [0_u8; 2];
        reader.read_exact(&mut ending).unwrap();
        assert_eq!(&ending, b"\r\n");
        receipt_tx.send(prefix).unwrap();
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nearly")
            .unwrap();
    });
    let other = start_counting_backend(PayloadSpec::binary(0, SEED), "other", 0);
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(
        free_port(),
        (port, other.port, health.port()),
        "body_limits:\n  max_request_bytes: 16",
        "",
    );
    let proxy = start_transport(&config);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(DEADLINE, async {
            let socket = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
            let (mut client, connection) = h2::client::handshake(socket).await.unwrap();
            let driver = tokio::spawn(async move {
                let _result = connection.await;
            });
            let request = http::Request::post("/").header("host", "localhost").body(()).unwrap();
            let (response, mut sender) = client.send_request(request, false).unwrap();
            sender.send_data(bytes::Bytes::from_static(b"tiny"), false).unwrap();
            let mut body = Vec::new();
            let result = praxis_test_utils::read_h2_response(response.await, 100, |part| {
                body.extend_from_slice(part);
                Ok(())
            })
            .await;
            assert_eq!(result.status, Some(200), "{result:?}");
            assert!(result.end_stream, "{result:?}");
            assert_eq!(body, b"early");
            assert_eq!(receipt_rx.recv_timeout(Duration::from_secs(2)).unwrap(), *b"tiny");
            // Only four content bytes were sent. Cancel the unfinished send half
            // instead of inventing a later 413 for an unread body.
            sender.send_reset(h2::Reason::CANCEL);
            let control = http::Request::get("/probe")
                .header("host", "localhost")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(control, true).unwrap();
            let mut bytes = Vec::new();
            let control = praxis_test_utils::read_h2_response(response.await, 100, |part| {
                bytes.extend_from_slice(part);
                Ok(())
            })
            .await;
            assert_eq!(control.status, Some(200), "{control:?}");
            assert!(control.end_stream);
            assert_eq!(bytes, b"probe");
            driver.abort();
        })
        .await
        .expect("early response, cancellation, and control deadline");
    });
    worker.join().unwrap();
    assert!(matches!(
        other.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    other.join();
}

/// Observe a bodyless response and then an ordinary response on the same client connection.
fn no_content_followed_by_probe(headers: &'static str) {
    let (port, worker) = praxis_test_utils::spawn_raw_http_backend(move |mut stream| {
        praxis_test_utils::read_http_request(&mut stream);
        write!(stream, "HTTP/1.1 204 No Content\r\n{headers}Connection: close\r\n\r\n").unwrap();
    });
    let other = start_counting_backend(PayloadSpec::binary(0, SEED), "other", 0);
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(free_port(), (port, other.port, health.port()), "", "");
    let proxy = start_transport(&config);
    let mut connection = BufReader::new(connect(proxy.addr()));
    connection
        .get_mut()
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut body = Vec::new();
    let response = read_h1_response(&mut connection, false, 4096, |part| {
        body.extend_from_slice(part);
        Ok(())
    });
    match response.status {
        Some(204) => {
            assert_eq!(
                response.completion,
                Some(H1Completion::Headers),
                "204 must end with its headers"
            );
            assert!(body.is_empty(), "204 must not deliver a body");
            assert!(
                !response
                    .headers
                    .iter()
                    .any(|(name, _)| name == "content-length" || name == "transfer-encoding"),
                "204 cannot carry framing headers: {response:?}"
            );
            connection
                .get_mut()
                .write_all(b"GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut next_body = Vec::new();
            let next = read_h1_response(&mut connection, false, 100, |part| {
                next_body.extend_from_slice(part);
                Ok(())
            });
            assert_eq!(next.status, Some(200), "{next:?}");
            assert_eq!(
                next.completion,
                Some(H1Completion::ContentLength),
                "following probe must complete"
            );
            assert_eq!(next_body, b"probe", "following probe body must be intact");
        },
        Some(502) if !headers.is_empty() => {
            assert!(
                response.completion.is_some(),
                "invalid upstream rejection must complete: {response:?}"
            );
            probe(proxy.addr());
        },
        _ => panic!("unexpected handling of 204 upstream: {response:?}"),
    }
    worker.join().unwrap();
    assert!(
        matches!(other.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
        "bodyless response must not reach the other backend"
    );
    other.join();
}

#[test]
fn no_content_response_has_no_body_and_preserves_next_response() {
    no_content_followed_by_probe("");
}

#[test]
fn invalid_204_huge_length_is_sanitized_or_rejected_without_desync() {
    // RFC 9110 forbids Content-Length on 204, including a hypothetical length.
    no_content_followed_by_probe("Content-Length: 1073741824\r\n");
}

#[cfg(feature = "pingora")]
#[test]
fn oversized_trailer_block_is_rejected_before_preread_dispatch() {
    let spec = PayloadSpec::padded(1, b"a", b"", b'x').unwrap();
    let selected = start_counting_backend(spec.clone(), "selected", 1);
    let other = start_counting_backend(spec.clone(), "sentinel", 1);
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(
        free_port(),
        (selected.port, other.port, health.port()),
        "body_limits:\n  max_request_bytes: 16",
        "      - filter: payload_preread_probe",
    );
    let observations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let registry = preread_registry(&spec, &observations);
    let proxy = start_transport_with_registry(&config, &registry);
    let mut stream = connect(proxy.addr());
    stream.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\na\r\n0\r\nX-Large: ").unwrap();
    let trailer = vec![b'x'; 65_537];
    let _sent = stream.write_all(&trailer);
    let _sent = stream.write_all(b"\r\n\r\nGET /other HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let result = response(stream);
    assert_eq!(
        result.status,
        Some(500),
        "Pingora currently maps overlong trailer parse errors to 500: {result:?}"
    );
    assert!(result.completion.is_some(), "{result:?}");
    assert!(observations.lock().unwrap().is_empty(), "no complete body callback");
    assert!(
        matches!(selected.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
        "oversized metadata dispatched a request"
    );
    assert!(
        matches!(other.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
        "oversized metadata dispatched the sentinel"
    );
    probe(proxy.addr());
    selected.join();
    other.join();
}
