// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bounded, reproducible transport campaigns against contained proxy processes.
//!
//! A failure prints its seed and variant. Minimize that single case before
//! changing expectations, then retain the minimized input as a normal regression.

use std::sync::mpsc::TryRecvError;

use praxis_test_utils::{PraxisProcess, ProcessLogCursor};

use super::*;

/// Stable generation independent of library RNG changes.
fn next(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    *seed >> 32
}

/// Serialize a real configuration, limiting the child independently of test timeouts.
fn process(config: &Config, port: u16) -> PraxisProcess {
    PraxisProcess::spawn_with_ulimit(
        &serde_yaml::to_string(config).unwrap(),
        &format!("127.0.0.1:{port}"),
        Some("-v 8388608 && ulimit -f 40960"),
    )
}

/// Confirm process survival, bounded diagnostics and graceful fixture shutdown.
fn finish(mut proxy: PraxisProcess, seed: u64) {
    let mut cursor = ProcessLogCursor::default();
    let _logs = proxy.logs_since(&mut cursor, 1_048_576).unwrap();
    let excess = proxy.logs_since(&mut cursor, 2).unwrap();
    assert!(
        excess.stdout.is_empty() && excess.stderr.is_empty(),
        "diagnostic budget exceeded: seed={seed}"
    );
    proxy.signal("TERM");
    let (status, killed) = proxy.wait_or_kill(Duration::from_secs(10));
    assert!(
        !killed && status.success(),
        "process cleanup: seed={seed}, status={status}"
    );
}

/// Exercise one exact framing mutation, optionally using a minimized body.
fn h1_framing_case(seed: u64, length_override: Option<u64>) {
    let mut random = seed;
    let generated_length = 1_048_576 + next(&mut random) % 4096;
    let length = length_override.unwrap_or(generated_length);
    let spec = PayloadSpec::padded(
        length,
        b"GET /other HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"\r\n0\r\n\r\n",
        b'x',
    )
    .unwrap();
    let selected = start_counting_backend(spec.clone(), "selected", spec.len());
    let other = start_counting_backend(PayloadSpec::binary(0, seed), "sentinel", 0);
    let health = start_backend_with_shutdown("probe");
    let port = free_port();
    let config = transport_config(port, (selected.port, other.port, health.port()), "", "");
    let proxy = process(&config, port);
    let address = format!("127.0.0.1:{port}");
    let mut stream = connect(&address);
    let duplicate = seed.is_multiple_of(2);
    let conflict = if duplicate {
        format!("Content-Length: {length}\r\ncOnTeNt-LeNgTh: {}\r\n", length + 1)
    } else {
        let hint = [0, 64, 1_073_741_824][usize::try_from(next(&mut random) % 3).unwrap()];
        format!("Content-Length: {hint}\r\nTransfer-Encoding: Chunked\r\n")
    };
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: localhost\r\n{conflict}Connection: keep-alive\r\n\r\n"
    )
    .unwrap();
    let width = usize::try_from(512 + next(&mut random) % 16_384).unwrap();
    let written = write_payload(&mut stream, &spec, width, !duplicate);
    let mut reader = BufReader::new(stream);
    let result = read_h1_response(&mut reader, false, 65_536, |_| Ok(()));
    assert!(
        result.completion.is_some(),
        "seed={seed}, duplicate={duplicate}: {result:?}"
    );
    let ending = std::io::Read::read(&mut reader, &mut [0_u8; 1]);
    assert!(
        matches!(ending, Ok(0))
            || matches!(&ending, Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted)),
        "conflicting framing must close despite keep-alive: seed={seed}, ending={ending:?}"
    );
    if duplicate || result.status == Some(400) {
        assert_eq!(result.status, Some(400), "seed={seed}: {result:?}");
        assert!(
            matches!(selected.accepted.try_recv(), Err(TryRecvError::Empty)),
            "rejected header reached upstream: seed={seed}"
        );
    } else {
        // RFC-compliant TE precedence is allowed only with complete,
        // byte-identical upstream delivery and unambiguous rewritten framing.
        assert_eq!(result.status, Some(200), "seed={seed}: {result:?}");
        assert_eq!(written, length, "seed={seed}");
        let receipt = selected.receipt.recv_timeout(DEADLINE).unwrap();
        assert_eq!(receipt.bytes, length, "seed={seed}: {receipt:?}");
        assert_eq!(receipt.verified_bytes, length, "seed={seed}: {receipt:?}");
        assert!(
            receipt.mismatch.is_none() && receipt.abort.is_none() && receipt.completion.is_some(),
            "seed={seed}: {receipt:?}"
        );
        let length_header = receipt.headers.iter().any(|(name, _)| name == "content-length");
        let transfer_header = receipt.headers.iter().any(|(name, _)| name == "transfer-encoding");
        assert!(
            !(length_header && transfer_header),
            "ambiguous upstream framing: seed={seed}"
        );
    }
    assert!(
        matches!(other.accepted.try_recv(), Err(TryRecvError::Empty)),
        "body bytes became a routed request: seed={seed}"
    );
    probe(&address);
    selected.join();
    other.join();
    finish(proxy, seed);
}

#[test]
fn h1_te_cl_regression_keeps_framing_and_connection_unambiguous() {
    h1_framing_case(0x2901, Some(128));
}

#[test]
#[ignore = "scheduled seeded subprocess transport campaign"]
fn scheduled_h1_framing_campaign_has_independent_backend_ledgers() {
    for seed in [0x1020_u64, 0x2901, 0xABC2, 0x1233, 0x9214, 0x5115, 0xFA16, 0xAA17] {
        h1_framing_case(seed, None);
    }
}

/// Send generated fragments, with occasional legal empty DATA frames.
async fn fragments(sender: &mut h2::SendStream<bytes::Bytes>, spec: &PayloadSpec, count: u64, random: &mut u64) {
    let mut offset = 0;
    while offset < count {
        let width = usize::try_from((count - offset).min(1024 + next(random) % 8192)).unwrap();
        sender.reserve_capacity(width);
        let capacity = std::future::poll_fn(|cx| sender.poll_capacity(cx))
            .await
            .unwrap()
            .unwrap();
        if capacity == 0 {
            continue;
        }
        let chunk = spec.chunk(offset, width.min(capacity));
        offset += u64::try_from(chunk.len()).unwrap();
        sender.send_data(bytes::Bytes::from(chunk), false).unwrap();
        if next(random).is_multiple_of(11) {
            sender.send_data(bytes::Bytes::new(), false).unwrap();
        }
    }
}

/// Read a same-connection control stream with an independent status/body oracle.
async fn h2_probe(client: &mut h2::client::SendRequest<bytes::Bytes>, seed: u64) {
    let request = http::Request::get("/probe")
        .header("host", "localhost")
        .body(())
        .unwrap();
    let (response, _) = client.send_request(request, true).unwrap();
    let mut body = Vec::new();
    let result = praxis_test_utils::read_h2_response(response.await, 100, |bytes| {
        body.extend_from_slice(bytes);
        Ok(())
    })
    .await;
    assert_eq!(result.status, Some(200), "seed={seed}: {result:?}");
    assert!(result.end_stream, "seed={seed}: {result:?}");
    assert_eq!(body, b"probe", "seed={seed}");
}

#[test]
#[ignore = "scheduled seeded subprocess transport campaign"]
fn scheduled_h2_stream_campaign_preserves_preread_and_sibling_progress() {
    for seed in 0..8_u64 {
        let mut random = seed.wrapping_add(0x9128);
        let length = 1_048_576 + next(&mut random) % 4096;
        let spec = PayloadSpec::padded(length, br#"{"padding":""#, br#"","model":"blue"}"#, b'x').unwrap();
        let selected = start_counting_backend(spec.clone(), "selected", spec.len());
        let other = start_counting_backend(spec.clone(), "other", spec.len());
        let health = start_backend_with_shutdown("probe");
        let port = free_port();
        let config = transport_config(
            port,
            (selected.port, other.port, health.port()),
            "",
            "      - filter: json_body_field\n        field: model\n        header: x-praxis-model\n        max_body_bytes: 2097152\n        conditions:\n          - when:\n              path_prefix: /upload",
        );
        let proxy = process(&config, port);
        let address = format!("127.0.0.1:{port}");
        let variant = seed % 4;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            tokio::time::timeout(DEADLINE, async {
                let socket = tokio::net::TcpStream::connect(&address).await.unwrap();
                let (mut client, connection) = h2::client::handshake(socket).await.unwrap();
                let driver = tokio::spawn(async move {
                    let _result = connection.await;
                });
                let mut request = http::Request::post("/upload").header("host", "localhost");
                if variant == 2 {
                    request = request.header("content-length", length + 1);
                }
                let (response, mut sender) = client.send_request(request.body(()).unwrap(), false).unwrap();
                let prefix = length / 2;
                fragments(&mut sender, &spec, prefix, &mut random).await;
                h2_probe(&mut client, seed).await;
                assert!(
                    matches!(selected.accepted.try_recv(), Err(TryRecvError::Empty)),
                    "pre-read dispatched before EOS: seed={seed}"
                );
                if variant == 1 {
                    sender.send_reset(h2::Reason::CANCEL);
                    let result = praxis_test_utils::read_h2_response(response.await, 100, |_| Ok(())).await;
                    assert_eq!(result.reset, Some(h2::Reason::CANCEL), "seed={seed}: {result:?}");
                    assert!(!result.end_stream && result.status.is_none(), "seed={seed}: {result:?}");
                } else {
                    // The remaining spec is generated at absolute offsets.
                    let mut offset = prefix;
                    while offset < length {
                        let width = usize::try_from((length - offset).min(8192)).unwrap();
                        sender.reserve_capacity(width);
                        let capacity = std::future::poll_fn(|cx| sender.poll_capacity(cx))
                            .await
                            .unwrap()
                            .unwrap();
                        if capacity == 0 {
                            continue;
                        }
                        let chunk = spec.chunk(offset, width.min(capacity));
                        offset += u64::try_from(chunk.len()).unwrap();
                        sender.send_data(bytes::Bytes::from(chunk), false).unwrap();
                    }
                    if variant == 3 {
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("x-test-end", "complete".parse().unwrap());
                        sender.send_trailers(trailers).unwrap();
                    } else {
                        sender.send_data(bytes::Bytes::new(), true).unwrap();
                    }
                    let result = praxis_test_utils::read_h2_response(response.await, 100, |_| Ok(())).await;
                    if variant == 2 {
                        assert_eq!(
                            result.reset,
                            Some(h2::Reason::PROTOCOL_ERROR),
                            "seed={seed}: {result:?}"
                        );
                        assert!(!result.end_stream && result.status.is_none(), "seed={seed}: {result:?}");
                    } else if variant == 3 && cfg!(feature = "hyper") {
                        assert_eq!(
                            result.status,
                            Some(400),
                            "Hyper refuses request trailers toward H1: seed={seed}: {result:?}"
                        );
                        assert!(result.end_stream, "seed={seed}: {result:?}");
                    } else {
                        assert_eq!(result.status, Some(200), "seed={seed}: {result:?}");
                        assert!(result.end_stream, "seed={seed}: {result:?}");
                    }
                }
                h2_probe(&mut client, seed).await;
                driver.abort();
                let _closed = driver.await;
            })
            .await
            .expect("seeded H2 stream deadline");
        });
        if variant == 1 || variant == 2 {
            assert!(
                matches!(selected.accepted.try_recv(), Err(TryRecvError::Empty)),
                "incomplete body dispatched: seed={seed}"
            );
        } else if variant == 3 && cfg!(feature = "hyper") {
            match selected.receipt.recv_timeout(Duration::from_millis(200)) {
                Ok(receipt) => {
                    assert_eq!(receipt.bytes, 0, "unsupported trailers delivered content: seed={seed}");
                    assert!(
                        receipt.completion.is_none(),
                        "unsupported trailers completed: seed={seed}"
                    );
                },
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    assert!(
                        matches!(selected.accepted.try_recv(), Err(TryRecvError::Empty)),
                        "unfinished upstream connection: seed={seed}"
                    );
                },
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("backend observer disconnected: seed={seed}")
                },
            }
        } else {
            assert_receipt(&selected, &spec);
        }
        assert!(
            matches!(other.accepted.try_recv(), Err(TryRecvError::Empty)),
            "wrong backend: seed={seed}"
        );
        probe(&address);
        selected.join();
        other.join();
        finish(proxy, seed);
    }
}
