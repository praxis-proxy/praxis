// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for the `guardrails` filter.

use std::{
    io::{BufReader, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{
    H1Completion, PayloadSpec, free_port, http_get, http_send, parse_body, parse_status, read_h1_response,
    start_backend_with_shutdown, start_counting_backend, start_full_proxy, start_proxy, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// Wait for the listener without sending a readiness request to a one-shot backend.
pub(super) fn inspection_proxy(config: &Config) -> praxis_test_utils::ProxyGuard {
    let proxy = start_full_proxy(config);
    wait_for_tcp(proxy.addr());
    proxy
}

/// Send deterministic chunks, withholding the final byte when requested.
pub(super) fn post_spec<F: FnOnce()>(addr: &str, spec: &PayloadSpec, chunk_size: usize, before_eos: F) -> Option<u16> {
    post_spec_with_headers(addr, spec, chunk_size, "", before_eos)
}

/// As [`post_spec`], with caller-provided HTTP request headers.
pub(super) fn post_spec_with_headers<F: FnOnce()>(
    addr: &str,
    spec: &PayloadSpec,
    chunk_size: usize,
    headers: &str,
    before_eos: F,
) -> Option<u16> {
    post_to_spec_with_headers(addr, "/", spec, chunk_size, headers, before_eos)
}

/// Send a payload to a specific path, optionally withholding the last byte.
#[expect(
    clippy::too_many_arguments,
    reason = "the wire fixture keeps request choices explicit"
)]
pub(super) fn post_to_spec_with_headers<F: FnOnce()>(
    addr: &str,
    path: &str,
    spec: &PayloadSpec,
    chunk_size: usize,
    headers: &str,
    before_eos: F,
) -> Option<u16> {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        spec.len()
    )
    .unwrap();
    let mut offset = 0;
    while offset < spec.len().saturating_sub(1) {
        let remaining = usize::try_from(spec.len() - 1 - offset).unwrap();
        let bytes = spec.chunk(offset, chunk_size.min(remaining));
        if stream.write_all(&bytes).is_err() {
            break;
        }
        offset += u64::try_from(bytes.len()).unwrap();
    }
    before_eos();
    if offset == spec.len().saturating_sub(1) {
        let _sent = stream.write_all(&spec.chunk(offset, 1));
    }
    let response = read_h1_response(&mut BufReader::new(stream), false, 4096, |_| Ok(()));
    response.status
}

/// Configure either standalone guardrails or a larger merged JSON buffer.
#[expect(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    reason = "the fixture tests independent pipeline settings"
)]
fn inspection_yaml(port: u16, backend: u16, merge: bool, flag: bool, oversized: bool, branch: bool) -> String {
    let promoter = if merge {
        "      - filter: json_body_field\n        field: model\n        header: x-praxis-test-model\n        max_body_bytes: 10485760\n"
    } else {
        ""
    };
    let action = if flag { "flag" } else { "reject" };
    let branch_config = if branch {
        r#"
        branch_chains:
          - name: reject_flagged
            on_result:
              filter: guardrails
              result: blocked
            rejoin: terminal
            chains:
              - name: denial
                filters:
                  - filter: static_response
                    status: 403"#
    } else {
        ""
    };
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
{promoter}      - filter: guardrails
        action: {action}
        reject_oversized: {oversized}
        rules:
          - target: body
            contains: [ssn, credit_card, phone, email]{branch_config}
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
"#
    )
}

/// Verify rejection has no upstream dispatch; a clean request then arrives intact.
#[expect(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    reason = "the fixture tests independent pipeline settings and wire schedules"
)]
fn inspection_pair(
    bad: &PayloadSpec,
    clean: &PayloadSpec,
    merge: bool,
    flag: bool,
    oversized: bool,
    branch: bool,
    expected: u16,
    chunk: usize,
) {
    let backend = start_counting_backend(PayloadSpec::clone(clean), "inspection", clean.len());
    let proxy_port = free_port();
    let mut yaml = inspection_yaml(proxy_port, backend.port, merge, flag, oversized, branch);
    if bad.len().max(clean.len()) > 10_485_760 {
        yaml = yaml.replace("max_body_bytes: 10485760", "max_body_bytes: 67108864");
        yaml.push_str("\nbody_limits:\n  max_request_bytes: 67108864\n");
    }
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = inspection_proxy(&config);
    let status = post_spec(proxy.addr(), bad, chunk, || {
        assert!(
            matches!(
                backend.accepted.recv_timeout(Duration::from_millis(100)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "upstream was selected before EOS"
        );
    });
    assert_eq!(
        status,
        Some(expected),
        "inspected request must return its expected status"
    );
    assert!(
        matches!(backend.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
        "rejected request reached upstream"
    );
    assert_eq!(
        post_spec(proxy.addr(), clean, chunk, || {}),
        Some(200),
        "clean control must reach the backend"
    );
    let receipt = backend.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(
        receipt.bytes,
        clean.len(),
        "backend must receive the complete clean body"
    );
    assert_eq!(
        receipt.verified_bytes,
        clean.len(),
        "every received byte must be verified"
    );
    assert_eq!(receipt.mismatch, None, "clean body content must remain unchanged");
    assert_eq!(
        receipt.completion,
        Some(H1Completion::ContentLength),
        "clean body framing must complete"
    );
    assert_eq!(receipt.abort, None, "clean body transfer must not abort");
    backend.join();
}

/// Fixed-size JSON with a literal suffix after a large neutral string.
fn padded_json(size: u64, suffix: &str) -> PayloadSpec {
    PayloadSpec::padded(size, br#"{"padding":""#, suffix.as_bytes(), b'x').unwrap()
}

#[test]
fn merged_buffer_inspects_pii_after_one_mib_and_at_ten_mib_tail() {
    for size in [1_048_700, 10_485_760] {
        let bad = padded_json(size, r#"","secret":"123-45-6789"}"#);
        let clean = padded_json(size, r#"","secret":"123-45-678x"}"#);
        assert_eq!(bad.len(), clean.len());
        inspection_pair(&bad, &clean, true, false, false, false, 403, 16_384);
    }
}

#[test]
#[ignore = "scheduled: inspects two 64 MiB request bodies"]
fn scheduled_64_mib_tail_pii_is_inspected_before_dispatch() {
    let bad = padded_json(67_108_864, r#"","secret":"123-45-6789"}"#);
    let clean = padded_json(67_108_864, r#"","secret":"123-45-678x"}"#);
    inspection_pair(&bad, &clean, true, false, false, false, 403, 16_384);
}

#[test]
fn standalone_and_merged_oversize_boundaries_are_distinct() {
    for size in [1_048_575, 1_048_576, 1_048_577] {
        let body = padded_json(size, r#""}"#);
        if size <= 1_048_576 {
            let backend = start_counting_backend(body.clone(), "standalone", size);
            let proxy_port = free_port();
            let config =
                Config::from_yaml(&inspection_yaml(proxy_port, backend.port, false, false, false, false)).unwrap();
            let proxy = inspection_proxy(&config);
            assert_eq!(post_spec(proxy.addr(), &body, 16_384, || {}), Some(200));
            let receipt = backend.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
            assert_eq!(
                (receipt.bytes, receipt.verified_bytes, receipt.completion),
                (size, size, Some(H1Completion::ContentLength))
            );
            backend.join();
        } else {
            inspection_pair(
                &body,
                &padded_json(32, r#""}"#),
                false,
                false,
                false,
                false,
                413,
                16_384,
            );
        }
        for flag in [false, true] {
            if size >= 1_048_576 {
                inspection_pair(&body, &padded_json(32, r#""}"#), true, flag, true, false, 413, 16_384);
            } else {
                let bad = padded_json(size, r#"","secret":"123-45-6789"}"#);
                let clean = padded_json(size, r#"","secret":"123-45-678x"}"#);
                inspection_pair(&bad, &clean, true, flag, true, flag, 403, 16_384);
            }
        }
    }
}

#[test]
fn pii_and_escaped_json_remain_visible_across_transport_splits() {
    let cases = [
        (r#"","v":"user@example.com"}"#, r#"","v":"user.example.com"}"#),
        (r#"","v":"123-45-6789"}"#, r#"","v":"123-45-678x"}"#),
        (r#"","v":"555-867-5309"}"#, r#"","v":"555-867-530x"}"#),
        (r#"","v":"4111-1111-1111-1111"}"#, r#"","v":"4111-1111-1111-111x"}"#),
        (
            r#"","v":[{"123\u002d45\u002d6789":0}]}"#,
            r#"","v":[{"123\u002d45\u002d678x":0}]}"#,
        ),
        (
            r#"","v":["123\u002d45\u002d6789"]}"#,
            r#"","v":["123\u002d45\u002d678x"]}"#,
        ),
    ];
    for (bad_tail, clean_tail) in cases {
        for chunk in [7, 4096] {
            let bad = padded_json(1_048_700, bad_tail);
            let clean = padded_json(1_048_700, clean_tail);
            assert_eq!(bad.len(), clean.len());
            inspection_pair(&bad, &clean, true, false, false, false, 403, chunk);
        }
    }
}

#[test]
fn generated_offsets_preserve_raw_and_escaped_pii_decisions() {
    let size = 1_048_700;
    for (offset, sample, near_miss) in [
        (15, "123-45-6789", "123-45-678x"),
        (4_093, r"123\u002d45\u002d6789", r"123\u002d45\u002d678x"),
        (16_381, "123-45-6789", "123-45-678x"),
        (1_048_650, r"123\u002d45\u002d6789", r"123\u002d45\u002d678x"),
    ] {
        let prefix = |value: &str| format!(r#"{{"v":"{}{value}"#, " ".repeat(offset - 6));
        let positive_prefix = prefix(sample);
        let negative_prefix = prefix(near_miss);
        assert_eq!(positive_prefix.find(sample), Some(offset));
        assert_eq!(positive_prefix.len(), negative_prefix.len());
        let bad = PayloadSpec::padded(size, positive_prefix.as_bytes(), br#""}"#, b' ').unwrap();
        let clean = PayloadSpec::padded(size, negative_prefix.as_bytes(), br#""}"#, b' ').unwrap();
        inspection_pair(&bad, &clean, true, false, false, false, 403, 4_096);
    }
}

/// Advance a reproducible, non-cryptographic generator for corpus layout and writes.
fn inspection_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Build one exact-length document with independently positioned model and PII fields.
fn seeded_inspection_body(size: usize, seed: u64, model: &str, pii: &str) -> String {
    let mut state = seed;
    let leading = usize::try_from(inspection_random(&mut state) % 8_192).unwrap();
    let middle = usize::try_from(inspection_random(&mut state) % 8_192).unwrap();
    let model_key = if seed & 1 == 0 { "model" } else { r"mo\u0064el" };
    let prefix = format!(
        r#"{{"first":"{}","{model_key}":"{model}","middle":"{}","v":"{pii}","tail":""#,
        " ".repeat(leading),
        " ".repeat(middle),
    );
    let suffix = "\"}";
    assert!(
        prefix.len() + suffix.len() <= size,
        "generated fields must fit in the requested body"
    );
    let body = format!("{prefix}{}{suffix}", " ".repeat(size - prefix.len() - suffix.len()));
    assert_eq!(
        body.len(),
        size,
        "generated inspection body must have its requested size"
    );
    body
}

/// Configure trusted model promotion, guarded inspection, and distinct routes.
fn seeded_inspection_config(port: u16, guarded: u16, other: u16) -> Config {
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_body_field
        field: model
        header: x-praxis-guard-model
        max_body_bytes: 32768
      - filter: guardrails
        conditions:
          - when:
              headers:
                x-praxis-guard-model: guarded-model
        rules:
          - target: body
            contains: [ssn]
      - filter: router
        routes:
          - path_prefix: "/"
            headers: {{x-praxis-guard-model: guarded-model}}
            cluster: guarded
          - path_prefix: "/"
            cluster: other
      - filter: load_balancer
        clusters:
          - name: guarded
            endpoints: ["127.0.0.1:{guarded}"]
          - name: other
            endpoints: ["127.0.0.1:{other}"]
insecure_options:
  allow_private_endpoints: true
  skip_pipeline_checks:
    conditional_security: true
"#
    );
    Config::from_yaml(&yaml).unwrap()
}

/// Send reproducibly varied chunks, holding the last byte until the oracle runs.
fn post_seeded<F: FnOnce()>(addr: &str, body: &str, seed: u64, before_eos: F) -> u16 {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    let mut offset = 0;
    let mut state = seed;
    while offset < body.len() - 1 {
        let width = 1 + usize::try_from(inspection_random(&mut state) % 4096).unwrap();
        let end = (offset + width).min(body.len() - 1);
        stream.write_all(&body.as_bytes()[offset..end]).unwrap();
        offset = end;
    }
    before_eos();
    stream.write_all(&body.as_bytes()[offset..]).unwrap();
    let response = read_h1_response(&mut BufReader::new(stream), false, 4096, |_| Ok(()));
    assert!(response.completion.is_some(), "{response:?}");
    response.status.unwrap()
}

#[test]
fn seeded_model_and_pii_invariance_preserves_decisions_and_routing() {
    const BASE_SEED: u64 = 0x6A09_E667_F3BC_C909;
    const SIZE: usize = 32_768;
    for index in 0..8_u64 {
        let seed = BASE_SEED.wrapping_add(index);
        let (positive, negative) = if index & 1 == 0 {
            ("123-45-6789", "123-45-678x")
        } else {
            (r"123\u002d45\u002d6789", r"123\u002d45\u002d678x")
        };
        let guarded_model = if index & 2 == 0 {
            "guarded-model"
        } else {
            r"guarded\u002dmodel"
        };
        let denied = seeded_inspection_body(SIZE, seed, guarded_model, positive);
        let clean = seeded_inspection_body(SIZE, seed, guarded_model, negative);
        let unguarded = seeded_inspection_body(SIZE, seed, "other-model", positive);
        assert_eq!(denied.len(), clean.len());
        let decoded_denied: serde_json::Value = serde_json::from_str(&denied).unwrap();
        let decoded_clean: serde_json::Value = serde_json::from_str(&clean).unwrap();
        let decoded_unguarded: serde_json::Value = serde_json::from_str(&unguarded).unwrap();
        assert_eq!(decoded_denied["model"], "guarded-model");
        assert_eq!(decoded_denied["v"], "123-45-6789");
        assert_eq!(decoded_clean["model"], "guarded-model");
        assert_eq!(decoded_clean["v"], "123-45-678x");
        assert_eq!(decoded_unguarded["model"], "other-model");
        assert_eq!(decoded_unguarded["v"], "123-45-6789");
        let clean_spec = PayloadSpec::padded(u64::try_from(SIZE).unwrap(), clean.as_bytes(), b"", b' ').unwrap();
        let other_spec = PayloadSpec::padded(u64::try_from(SIZE).unwrap(), unguarded.as_bytes(), b"", b' ').unwrap();
        let guarded = start_counting_backend(clean_spec.clone(), "guarded", clean_spec.len());
        let other = start_counting_backend(other_spec.clone(), "other", other_spec.len());
        let proxy = inspection_proxy(&seeded_inspection_config(free_port(), guarded.port, other.port));
        let no_dispatch = || {
            assert!(
                matches!(
                    guarded.accepted.recv_timeout(Duration::from_millis(100)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ),
                "seed {seed}"
            );
            assert!(
                matches!(
                    other.accepted.recv_timeout(Duration::from_millis(100)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ),
                "seed {seed}"
            );
        };
        assert_eq!(
            post_seeded(proxy.addr(), &denied, seed, no_dispatch),
            403,
            "seed {seed}"
        );
        assert_eq!(
            post_seeded(proxy.addr(), &denied, seed ^ 0xA5A5_5A5A_D3C1_B287, || {}),
            403,
            "the same bytes under a second partition schedule: seed {seed}"
        );
        assert!(matches!(
            guarded.accepted.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert!(matches!(
            other.accepted.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert_eq!(
            post_seeded(proxy.addr(), &clean, seed.wrapping_add(1), || {}),
            200,
            "seed {seed}"
        );
        let guarded_receipt = guarded.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
        assert_eq!(
            (
                guarded_receipt.backend_id.as_str(),
                guarded_receipt.bytes,
                guarded_receipt.verified_bytes,
                guarded_receipt.completion
            ),
            (
                "guarded",
                clean_spec.len(),
                clean_spec.len(),
                Some(H1Completion::ContentLength)
            )
        );
        assert_eq!(guarded_receipt.mismatch, None);
        assert!(
            !guarded_receipt
                .headers
                .iter()
                .any(|(name, _)| name == "x-praxis-guard-model")
        );
        assert!(matches!(
            other.accepted.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert_eq!(
            post_seeded(proxy.addr(), &unguarded, seed.wrapping_add(2), || {}),
            200,
            "seed {seed}"
        );
        let other_receipt = other.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
        assert_eq!(
            (
                other_receipt.backend_id.as_str(),
                other_receipt.bytes,
                other_receipt.verified_bytes,
                other_receipt.completion
            ),
            (
                "other",
                other_spec.len(),
                other_spec.len(),
                Some(H1Completion::ContentLength)
            )
        );
        assert_eq!(other_receipt.mismatch, None);
        assert!(
            !other_receipt
                .headers
                .iter()
                .any(|(name, _)| name == "x-praxis-guard-model")
        );
        guarded.join();
        other.join();
    }
}

#[test]
fn long_digit_near_matches_do_not_hide_a_terminal_ssn() {
    let size = 1_048_700;
    let bad = PayloadSpec::padded(size, b"", b" 123-45-6789", b'9').unwrap();
    let clean = PayloadSpec::padded(size, b"", b" 123-45-678x", b'9').unwrap();
    inspection_pair(&bad, &clean, true, false, false, false, 403, 16_384);
}

/// Send and observe one complete HTTP/2 body stream on a fresh connection.
async fn post_h2_spec(addr: &str, body: &PayloadSpec) -> praxis_test_utils::H2Response {
    let stream = Box::pin(tokio::net::TcpStream::connect(addr)).await.unwrap();
    let (mut client, connection) = Box::pin(h2::client::handshake(stream)).await.unwrap();
    let driver = tokio::spawn(Box::pin(async move {
        let _result = connection.await;
    }));
    let request = http::Request::post("/")
        .header("host", "localhost")
        .header("content-length", body.len().to_string())
        .body(())
        .unwrap();
    let (response, mut sender) = client.send_request(request, false).unwrap();
    let upload = Box::pin(praxis_test_utils::send_h2_payload(&mut sender, body, 4096)).await;
    assert_eq!(upload.queued_bytes, body.len(), "{upload:?}");
    assert!(upload.end_stream, "{upload:?}");
    let observed = Box::pin(praxis_test_utils::read_h2_response(response.await, 4096, |_| Ok(()))).await;
    driver.abort();
    observed
}

#[test]
fn h2_late_escaped_pii_is_blocked_and_clean_body_completes() {
    let bad = padded_json(1_048_700, r#"","v":["123\u002d45\u002d6789"]}"#);
    let clean = padded_json(1_048_700, r#"","v":["123\u002d45\u002d678x"]}"#);
    let backend = start_counting_backend(clean.clone(), "h2-inspection", clean.len());
    let config = Config::from_yaml(&inspection_yaml(free_port(), backend.port, true, false, false, false)).unwrap();
    let proxy = inspection_proxy(&config);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            let denied = post_h2_spec(proxy.addr(), &bad).await;
            assert_eq!(denied.status, Some(403), "{denied:?}");
            assert!(denied.end_stream, "{denied:?}");
            assert!(matches!(
                backend.accepted.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
            let allowed = post_h2_spec(proxy.addr(), &clean).await;
            assert_eq!(allowed.status, Some(200), "{allowed:?}");
            assert!(allowed.end_stream, "{allowed:?}");
        })
        .await
        .unwrap();
    });
    let receipt = backend.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!((receipt.bytes, receipt.verified_bytes), (clean.len(), clean.len()));
    assert!(matches!(
        receipt.completion,
        Some(H1Completion::ContentLength | H1Completion::Chunked)
    ));
    assert_eq!(receipt.mismatch, None);
    backend.join();
}

#[test]
fn wide_escaped_json_fails_closed_without_a_raw_pii_match() {
    // Both object keys and the padding value count as leaves, in addition to the array strings.
    let values = std::iter::repeat_n(r#""a""#, 9_997).collect::<Vec<_>>().join(",");
    let bad_prefix = format!(r#"{{"v":["\u0061",{values}],"padding":""#);
    let clean_prefix = format!(r#"{{"v":[123,{values}],"padding":""#);
    // Keep an escape in the clean case too, while replacing one string leaf with a number.
    let clean_prefix = clean_prefix.replacen(r#""a""#, r#""\u0061""#, 1);
    assert_eq!(bad_prefix.len(), clean_prefix.len());
    let bad = PayloadSpec::padded(1_048_700, bad_prefix.as_bytes(), b"\"}", b'x').unwrap();
    let clean = PayloadSpec::padded(1_048_700, clean_prefix.as_bytes(), b"\"}", b'x').unwrap();
    inspection_pair(&bad, &clean, true, false, false, false, 403, 16_384);
}

#[test]
fn reserved_headers_are_rejected_before_a_stalled_large_body() {
    let clean = padded_json(32, r#""}"#);
    let backend = start_counting_backend(clean.clone(), "protected", clean.len());
    let proxy_port = free_port();
    let config = Config::from_yaml(&inspection_yaml(proxy_port, backend.port, true, false, false, false)).unwrap();
    let proxy = inspection_proxy(&config);
    for header in ["X-Praxis-Test", "x-ext-protocol-test", "X-EXT-AGENT-TEST"] {
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(stream, "POST / HTTP/1.1\r\nHost: localhost\r\n{header}: one\r\n{header}: two\r\nContent-Length: 10485760\r\nConnection: close\r\n\r\n").unwrap();
        let response = read_h1_response(&mut BufReader::new(stream), false, 4096, |_| Ok(()));
        assert_eq!(response.status, Some(400), "{header}");
        assert!(matches!(
            backend.accepted.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
    }
    let body = String::from_utf8(clean.chunk(0, 32)).unwrap();
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nX-Ext-Other: allowed\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );
    assert_eq!(parse_status(&raw), 200);
    let receipt = backend.receipt.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(receipt.verified_bytes, clean.len());
    assert_eq!(receipt.completion, Some(H1Completion::ContentLength));
    assert!(
        receipt
            .headers
            .iter()
            .any(|(name, value)| name == "x-ext-other" && value == "allowed")
    );
    backend.join();
}

#[test]
fn header_contains_blocks_matching_request() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = guardrails_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: bad-bot/1.0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 403, "bad-bot User-Agent should be blocked");
    assert_eq!(parse_body(&raw), "Forbidden", "rejection body should be 'Forbidden'");
}

#[test]
fn clean_request_passes_through() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = guardrails_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "clean request should pass through");
    assert_eq!(body, "ok", "clean request should return backend response");
}

#[test]
fn body_contains_blocks_matching_content() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = guardrails_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "SELECT 1; DROP TABLE users;";
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(parse_status(&raw), 403, "body containing DROP TABLE should be blocked");
}

#[test]
fn body_without_match_passes_through() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = guardrails_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "SELECT 1 FROM users";
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(parse_status(&raw), 200, "clean body should pass through");
}

#[test]
fn header_pattern_blocks_regex_match() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = header_pattern_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Script: <script>alert(1)</script>\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 403, "script tag pattern should be blocked");
}

#[test]
fn header_only_rules_skip_body_inspection() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: guardrails
        rules:
          - target: header
            name: "X-Bad"
            contains: "evil"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "this body contains evil content but header-only rules won't catch it";
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(parse_status(&raw), 200, "header-only rules should not inspect body");
}

#[test]
fn multiple_rules_any_match_rejects() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = guardrails_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Evil: evilmonkey-value\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "X-Evil header with 'evilmonkey' should be blocked"
    );
}

#[test]
fn negated_header_rejects_missing_header() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = negate_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 403,
        "missing X-Authorized header should be rejected by negated rule"
    );
}

#[test]
fn negated_header_rejects_non_matching_value() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = negate_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Authorized: stranger\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "X-Authorized without 'trusted' should be rejected by negated rule"
    );
}

#[test]
fn negated_header_allows_matching_value() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = negate_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Authorized: trusted-client\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "X-Authorized with 'trusted' should pass negated rule"
    );
    assert_eq!(
        parse_body(&raw),
        "ok",
        "matching negated rule should forward to backend"
    );
}

#[test]
fn negated_body_rejects_non_matching_content() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = negate_body_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "not json at all";
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "body not matching JSON pattern should be rejected by negated rule"
    );
}

#[test]
fn negated_body_allows_matching_content() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = negate_body_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = r#"{"key":"value"}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "JSON-shaped body should pass negated pattern rule"
    );
}

#[test]
fn mixed_positive_and_negated_rules() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = mixed_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = r#"{"query":"SELECT 1"}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nX-Authorized: trusted-app\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "clean request with trusted header and JSON body should pass"
    );

    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nX-Authorized: trusted-app\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            "evilmonkey payload".len(),
            "evilmonkey payload"
        ),
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "positive body rule should still reject even with valid header"
    );

    let payload = r#"{"safe":"data"}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "missing X-Authorized header should be rejected even with clean body"
    );
}

// -----------------------------------------------------------------------------
// PII — body
// -----------------------------------------------------------------------------

#[test]
fn pii_ssn_in_body_is_blocked() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = pii_body_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "my ssn is 123-45-6789";
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(parse_status(&raw), 403, "SSN in body should be blocked");
}

#[test]
fn pii_credit_card_in_body_is_blocked() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = pii_body_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "card: 4111-1111-1111-1111";
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(parse_status(&raw), 403, "credit card number in body should be blocked");
}

#[test]
fn pii_phone_in_body_is_blocked() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = pii_body_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "call me at (555) 867-5309";
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(parse_status(&raw), 403, "phone number in body should be blocked");
}

#[test]
fn pii_email_in_body_is_blocked() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = pii_body_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "contact user@example.com for support";
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(parse_status(&raw), 403, "email address in body should be blocked");
}

#[test]
fn pii_body_clean_content_passes() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = pii_body_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = r#"{"query":"SELECT count FROM orders WHERE id = 42"}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(parse_status(&raw), 200, "body without PII should pass through");
}

// -----------------------------------------------------------------------------
// PII — header
// -----------------------------------------------------------------------------

#[test]
fn pii_ssn_in_header_is_blocked() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = pii_header_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Secret: 123-45-6789\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 403, "SSN in X-Secret header should be blocked");
}

#[test]
fn pii_credit_card_in_header_is_blocked() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = pii_header_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Secret: 4111-1111-1111-1111\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "credit card number in X-Secret header should be blocked"
    );
}

#[test]
fn pii_header_clean_content_passes() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = pii_header_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Secret: safe-token-value\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "header without PII should pass through");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// YAML config with header contains, body contains, and header pattern rules.
fn guardrails_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: guardrails
        rules:
          - target: header
            name: "User-Agent"
            pattern: "bad-bot.*"
          - target: body
            contains: "DROP TABLE"
          - target: header
            name: "X-Evil"
            contains: "evilmonkey"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// YAML config with a regex pattern rule for header inspection.
fn header_pattern_yaml(proxy_port: u16, backend_port: u16) -> String {
    guardrails_pipeline(
        proxy_port,
        backend_port,
        r#"
          - target: header
            name: "X-Script"
            pattern: "<script>.*</script>""#,
    )
}

/// YAML config with a negated header rule.
fn negate_yaml(proxy_port: u16, backend_port: u16) -> String {
    guardrails_pipeline(
        proxy_port,
        backend_port,
        r#"
          - target: header
            name: "X-Authorized"
            contains: "trusted"
            negate: true"#,
    )
}

/// YAML config with a negated body pattern rule.
fn negate_body_yaml(proxy_port: u16, backend_port: u16) -> String {
    guardrails_pipeline(
        proxy_port,
        backend_port,
        r#"
          - target: body
            pattern: ^\{.*\}$
            negate: true"#,
    )
}

/// YAML config mixing positive and negated rules.
fn mixed_yaml(proxy_port: u16, backend_port: u16) -> String {
    guardrails_pipeline(
        proxy_port,
        backend_port,
        r#"
          - target: header
            name: "X-Authorized"
            contains: "trusted"
            negate: true
          - target: body
            contains: "evilmonkey""#,
    )
}

/// YAML config with PII detection rules targeting the request body.
fn pii_body_yaml(proxy_port: u16, backend_port: u16) -> String {
    guardrails_pipeline(
        proxy_port,
        backend_port,
        r#"
          - target: body
            contains: [ssn, credit_card, phone, email]"#,
    )
}

/// YAML config with PII detection rules targeting the `X-Secret` header.
fn pii_header_yaml(proxy_port: u16, backend_port: u16) -> String {
    guardrails_pipeline(
        proxy_port,
        backend_port,
        r#"
          - target: header
            name: "X-Secret"
            contains: [ssn, credit_card, phone, email]"#,
    )
}

/// Build a guardrails pipeline YAML from inline rules.
fn guardrails_pipeline(proxy_port: u16, backend_port: u16, rules: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: guardrails
        rules:{rules}
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}
