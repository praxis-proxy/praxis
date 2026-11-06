// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Configured buffering boundaries with cumulative transfer limits disabled.

use std::{
    io::{BufReader, Write as _},
    sync::Arc,
};

use praxis_core::config::DEFAULT_MAX_BUFFER_BYTES;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
};

use super::{
    DEADLINE, PayloadSpec, SEED, assert_receipt, assert_rejected_receipt, connect, free_port, probe, response,
    start_backend_with_shutdown, start_counting_backend, start_transport_with_registry, transport_config,
};

/// Whether the test filter declares buffering statically or selects it later.
#[derive(Clone, Copy, Debug)]
enum BufferAt {
    /// Request pre-read before routing.
    PreRead,
    /// Request hook after the initial body plan is selected.
    Request,
    /// Response hook after an upstream is selected.
    Response,
    /// Response buffering declared before any hooks run.
    ResponsePreRead,
}

/// A filter that deliberately asks for the largest representable buffer.
struct OversizedBuffer(BufferAt);

#[async_trait::async_trait]
impl HttpFilter for OversizedBuffer {
    fn name(&self) -> &'static str {
        "oversized_buffer"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        match self.0 {
            BufferAt::PreRead => oversized_mode(),
            BufferAt::Request | BufferAt::Response | BufferAt::ResponsePreRead => BodyMode::Stream,
        }
    }

    fn response_body_mode(&self) -> BodyMode {
        if matches!(self.0, BufferAt::ResponsePreRead) {
            oversized_mode()
        } else {
            BodyMode::Stream
        }
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if matches!(self.0, BufferAt::Request) && ctx.request.uri.path() != "/probe" {
            ctx.set_request_body_mode(oversized_mode());
        }
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if matches!(self.0, BufferAt::Response) && ctx.request.uri.path() != "/probe" {
            ctx.set_response_body_mode(oversized_mode());
        }
        Ok(FilterAction::Continue)
    }
}

/// Request a finite limit beyond the hard cap instead of relying on `None`.
fn oversized_mode() -> BodyMode {
    BodyMode::StreamBuffer {
        max_bytes: Some(usize::MAX),
    }
}

/// Each process owns its own test filter and buffering selection.
fn registry(at: BufferAt) -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "oversized_buffer",
            FilterFactory::Http(Arc::new(move |_| Ok(Box::new(OversizedBuffer(at))))),
        )
        .unwrap();
    registry
}

/// Keep chunk-extension metadata out of a test of accumulated content bytes.
fn write_plain_chunks(stream: &mut std::net::TcpStream, spec: &PayloadSpec) -> u64 {
    let mut written = 0;
    while written < spec.len() {
        let chunk = spec.chunk(written, 16_384);
        if write!(stream, "{:x}\r\n", chunk.len()).is_err() || stream.write_all(&chunk).is_err() {
            return written;
        }
        written += chunk.len() as u64;
        if stream.write_all(b"\r\n").is_err() {
            return written;
        }
    }
    let _ended = stream.write_all(b"0\r\n\r\n");
    written
}

/// Disable only the cumulative transfer limits, leaving buffer enforcement active.
const LIMITS: &str = "body_limits:\n  max_request_bytes: null\n  max_response_bytes: null";

/// Install the deliberate oversized declaration ahead of ordinary routing.
const FILTER: &str = "      - filter: oversized_buffer";

#[test]
fn finite_preread_limit_cannot_bypass_the_hard_ceiling() {
    let spec = PayloadSpec::binary(0, SEED);
    let selected = start_counting_backend(spec.clone(), "selected", 0);
    let other = start_counting_backend(spec, "other", 0);
    let health = start_backend_with_shutdown("probe");
    let config = transport_config(free_port(), (selected.port, other.port, health.port()), LIMITS, FILTER);
    let proxy = start_transport_with_registry(&config, &registry(BufferAt::PreRead));
    let mut stream = connect(proxy.addr());
    write!(
        stream,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        DEFAULT_MAX_BUFFER_BYTES + 1
    )
    .unwrap();
    let observed = response(stream);
    assert_eq!(observed.status, Some(413), "{observed:?}");
    assert!(observed.completion.is_some(), "rejection must finish: {observed:?}");
    assert!(matches!(
        selected.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    probe(proxy.addr());
    selected.join();
    other.join();
}

/// Exercise one request without collecting the generated payload in the test client.
fn request_boundary(at: BufferAt, cap: usize, length: usize, chunked: bool, explicit: bool) {
    let spec = PayloadSpec::binary(length as u64, SEED);
    let selected = start_counting_backend(spec.clone(), "selected", spec.len());
    let other = start_counting_backend(spec.clone(), "other", spec.len());
    let health = start_backend_with_shutdown("probe");
    let limits = if explicit {
        format!("{LIMITS}\n  max_buffer_bytes: {cap}")
    } else {
        LIMITS.to_owned()
    };
    let config = transport_config(free_port(), (selected.port, other.port, health.port()), &limits, FILTER);
    let proxy = start_transport_with_registry(&config, &registry(at));
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
    if chunked {
        write_plain_chunks(&mut stream, &spec);
    } else {
        let mut offset = 0;
        while offset < spec.len() {
            let chunk = spec.chunk(offset, 16_384);
            if stream.write_all(&chunk).is_err() {
                break;
            }
            offset += chunk.len() as u64;
        }
    }
    let observed = response(stream);
    let succeeds = length <= cap;
    assert_eq!(
        observed.status,
        Some(if succeeds { 200 } else { 413 }),
        "{at:?}, cap={cap}, length={length}, chunked={chunked}: {observed:?}"
    );
    assert!(observed.completion.is_some(), "response must finish: {observed:?}");
    if succeeds {
        assert_receipt(&selected, &spec);
    } else {
        assert_rejected_receipt(&selected, 0);
    }
    probe(proxy.addr());
    selected.join();
    other.join();
}

/// Verify every delivered response byte and distinguish clean EOS from truncation.
fn response_boundary(
    at: BufferAt,
    cap: usize,
    length: usize,
    framing: praxis_test_utils::PayloadResponseFraming,
    explicit: bool,
) {
    let spec = PayloadSpec::binary(length as u64, SEED);
    let source = praxis_test_utils::start_payload_response_backend(spec.clone(), framing, None);
    let other = start_counting_backend(PayloadSpec::binary(0, SEED), "other", 0);
    let health = start_backend_with_shutdown("probe");
    let limits = if explicit {
        format!("{LIMITS}\n  max_buffer_bytes: {cap}")
    } else {
        LIMITS.to_owned()
    };
    let config = transport_config(free_port(), (source.port, other.port, health.port()), &limits, FILTER);
    let proxy = start_transport_with_registry(&config, &registry(at));
    let mut stream = connect(proxy.addr());
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let succeeds = length <= cap;
    let mut verified = 0;
    let mut rejected_body = Vec::new();
    let observation_limit = if succeeds { spec.len() + 1 } else { 1024 };
    let observed =
        praxis_test_utils::read_h1_response(&mut BufReader::new(stream), false, observation_limit, |chunk| {
            if succeeds {
                assert_eq!(
                    chunk,
                    spec.chunk(verified, chunk.len()),
                    "{at:?}, cap={cap}, length={length}, framing={framing:?}: response mismatch at {verified}"
                );
                verified += chunk.len() as u64;
            } else {
                rejected_body.extend_from_slice(chunk);
            }
            Ok(())
        });
    if succeeds {
        assert_eq!(observed.status, Some(200), "{observed:?}");
        assert_eq!(verified, spec.len(), "every accepted response byte must be verified");
        assert_eq!(
            observed.body_bytes,
            spec.len(),
            "accepted response length must remain intact"
        );
        assert!(
            observed.completion.is_some() && observed.abort.is_none(),
            "{observed:?}"
        );
    } else {
        praxis_test_utils::assert_buffered_response_rejected(&observed, &rejected_body);
    }
    let receipt = source.receipt.recv_timeout(DEADLINE).unwrap();
    assert_eq!(receipt.written_bytes, length as u64, "{receipt:?}");
    if succeeds {
        assert!(receipt.complete, "{receipt:?}");
    }
    probe(proxy.addr());
    source.join();
    other.join();
}

#[test]
fn runtime_request_buffer_accepts_the_cap_and_rejects_the_next_byte() {
    for length in [DEFAULT_MAX_BUFFER_BYTES, DEFAULT_MAX_BUFFER_BYTES + 1] {
        request_boundary(BufferAt::Request, DEFAULT_MAX_BUFFER_BYTES, length, true, false);
    }
}

#[test]
fn runtime_response_buffer_cannot_bypass_the_hard_ceiling() {
    response_boundary(
        BufferAt::Response,
        DEFAULT_MAX_BUFFER_BYTES,
        DEFAULT_MAX_BUFFER_BYTES + 1,
        praxis_test_utils::PayloadResponseFraming::Chunked,
        false,
    );
}

#[test]
fn configured_request_cap_covers_static_runtime_and_framing_boundaries() {
    let cap = 65_537;
    for at in [BufferAt::PreRead, BufferAt::Request] {
        for chunked in [false, true] {
            for length in [0, cap - 1, cap, cap + 1] {
                request_boundary(at, cap, length, chunked, true);
            }
        }
    }
}

#[test]
fn configured_response_cap_covers_static_runtime_and_framing_boundaries() {
    use praxis_test_utils::PayloadResponseFraming::{Chunked, Fixed};
    let cap = 65_537;
    for at in [BufferAt::ResponsePreRead, BufferAt::Response] {
        for framing in [Fixed, Chunked] {
            for length in [0, cap - 1, cap, cap + 1] {
                response_boundary(at, cap, length, framing, true);
            }
        }
    }
}

#[test]
fn explicit_override_buffers_real_bodies_above_the_default_in_both_directions() {
    let cap = DEFAULT_MAX_BUFFER_BYTES + 1;
    for at in [BufferAt::PreRead, BufferAt::Request] {
        request_boundary(at, cap, cap, true, true);
    }
    for at in [BufferAt::ResponsePreRead, BufferAt::Response] {
        response_boundary(at, cap, cap, praxis_test_utils::PayloadResponseFraming::Chunked, true);
    }
}

#[test]
fn configured_buffer_cap_preserves_other_h2_streams() {
    for at in [BufferAt::PreRead, BufferAt::Request] {
        for length in [65_537, 65_538] {
            let spec = PayloadSpec::binary(length, SEED);
            let selected = start_counting_backend(spec.clone(), "selected", length);
            let other = start_counting_backend(spec.clone(), "other", length);
            let health = start_backend_with_shutdown("probe");
            let config = transport_config(
                free_port(),
                (selected.port, other.port, health.port()),
                &format!("{LIMITS}\n  max_buffer_bytes: 65537"),
                FILTER,
            );
            let proxy = start_transport_with_registry(&config, &registry(at));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                tokio::time::timeout(
                    DEADLINE,
                    Box::pin(async {
                        let stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
                        let (mut client, connection) = h2::client::handshake(stream).await.unwrap();
                        let driver = tokio::spawn(Box::pin(async move {
                            let _result = connection.await;
                        }));
                        let (_, observed, control, control_body) = Box::pin(super::observe_h2_upload(
                            &mut client,
                            &spec,
                            false,
                            super::H2End::FinalData,
                        ))
                        .await;
                        assert_eq!(
                            observed.status,
                            Some(if length == 65_537 { 200 } else { 413 }),
                            "{observed:?}"
                        );
                        assert!(observed.end_stream, "{observed:?}");
                        assert_eq!(control.status, Some(200), "{control:?}");
                        assert!(control.end_stream, "{control:?}");
                        assert_eq!(control_body, b"probe");
                        driver.abort();
                    }),
                )
                .await
                .unwrap();
            });
            if length == 65_537 {
                assert_receipt(&selected, &spec);
            } else {
                assert_rejected_receipt(&selected, 0);
            }
            probe(proxy.addr());
            selected.join();
            other.join();
        }
    }
}

#[test]
fn json_routing_can_inspect_a_body_above_the_default_with_an_explicit_override() {
    let cap = DEFAULT_MAX_BUFFER_BYTES + 1;
    let spec = PayloadSpec::padded(cap as u64, br#"{"padding":""#, br#"","model":"trusted"}"#, b'x').unwrap();
    let selected = start_counting_backend(spec.clone(), "wrong", spec.len());
    let other = start_counting_backend(spec.clone(), "selected", spec.len());
    let health = start_backend_with_shutdown("probe");
    let limits = format!("{LIMITS}\n  max_buffer_bytes: {cap}");
    let guard = format!(
        "      - filter: json_body_field\n        field: model\n        header: x-praxis-model\n        max_body_bytes: {cap}"
    );
    let config = transport_config(free_port(), (selected.port, other.port, health.port()), &limits, &guard);
    let proxy = start_transport_with_registry(&config, &FilterRegistry::with_builtins());
    let mut stream = connect(proxy.addr());
    stream.write_all(b"POST /trailer HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").unwrap();
    assert_eq!(write_plain_chunks(&mut stream, &spec), spec.len());
    let observed = response(stream);
    assert_eq!(observed.status, Some(200), "{observed:?}");
    assert!(
        observed.completion.is_some() && observed.abort.is_none(),
        "{observed:?}"
    );
    assert_receipt(&other, &spec);
    assert!(matches!(
        selected.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    probe(proxy.addr());
    selected.join();
    other.join();
}
