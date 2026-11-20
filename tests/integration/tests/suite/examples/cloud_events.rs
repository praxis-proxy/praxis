// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the CloudEvents publisher example.

#[cfg(target_os = "linux")]
mod slow_process;

use std::{
    collections::HashMap,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::TcpStream,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use praxis_test_utils::{
    H1Completion, free_port, http_send, parse_status, read_h1_response, start_backend, start_full_proxy, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn cloud_events_example_publishes_after_response_completion() {
    let (receiver, receiver_port) = praxis_test_utils::bind_unique_port();
    let (sender, received) = mpsc::channel();
    let receiver_thread = thread::spawn(move || {
        let (mut stream, _) = receiver.accept().unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 4096];
        let body_length = loop {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0, "event receiver connection must contain a request");
            request.extend_from_slice(&chunk[..read]);
            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            break headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
        };
        let header_end = request.windows(4).position(|window| window == b"\r\n\r\n").unwrap() + 4;
        while request.len() < header_end + body_length {
            let read = stream.read(&mut chunk).unwrap();
            assert!(
                read > 0,
                "event receiver connection must contain the complete request body"
            );
            request.extend_from_slice(&chunk[..read]);
        }
        sender.send(request).unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });

    let backend_port = start_backend("cloud-events-backend");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/cloud-events.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", receiver_port)]),
    );
    let proxy = start_full_proxy(&config);

    let response = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: example-client\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&response),
        200,
        "event publication must not change the client response"
    );

    let event = received
        .recv_timeout(Duration::from_secs(2))
        .expect("receiver must receive a CloudEvent");
    let event = String::from_utf8(event).expect("CloudEvent request must be UTF-8");
    assert!(
        event.starts_with("POST /events HTTP/1.1\r\n"),
        "receiver must get the configured path: {event}"
    );
    assert!(
        event
            .to_ascii_lowercase()
            .contains("content-type: application/cloudevents+json"),
        "receiver must get structured CloudEvents content type: {event}"
    );
    assert!(
        event.contains("\"specversion\":\"1.0\""),
        "event must use CloudEvents 1.0: {event}"
    );
    assert!(
        event.contains("\"status\":200"),
        "event must include mapped response status: {event}"
    );
    assert!(
        event.contains("\"user_agent\":\"unverified\""),
        "event must include configured provenance: {event}"
    );
    receiver_thread.join().unwrap();
}

#[test]
fn cloud_events_receiver_failure_does_not_change_client_response() {
    let backend_port = start_backend("cloud-events-backend");
    let proxy_port = free_port();
    let unavailable_receiver_port = free_port();
    let config = super::load_example_config(
        "observability/cloud-events.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3000", backend_port),
            ("127.0.0.1:3001", unavailable_receiver_port),
        ]),
    );
    let proxy = start_full_proxy(&config);

    let response = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(
        parse_status(&response),
        200,
        "receiver failure must not change the client response"
    );
}

#[test]
fn cloud_event_waits_for_stream_completion_and_excludes_payload() {
    let (event_port, events) = bounded_event_receiver();
    let (backend_port, resume) = paused_sse_backend();
    let proxy_port = free_port();
    let mut config = super::load_example_config(
        "observability/cloud-events.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", event_port)]),
    );
    config.filter_chains[0]
        .filters
        .insert(0, serde_yaml::from_str("filter: access_log").unwrap());
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let mut socket = TcpStream::connect(proxy.addr()).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: safe-agent\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut received = Vec::new();
    let mut resumed = false;
    let result = read_h1_response(&mut BufReader::new(socket), false, 262_144, |chunk| {
        received.extend_from_slice(chunk);
        if !resumed {
            assert!(b"data: first\n\n".starts_with(&received));
            if received.len() == b"data: first\n\n".len() {
                assert!(events.try_recv().is_err(), "response-complete event must wait for EOS");
                resume.send(()).unwrap();
                resumed = true;
            }
        }
        Ok(())
    });
    assert!(resumed);
    assert_eq!(result.status, Some(200));
    assert_eq!(result.completion, Some(H1Completion::Chunked));
    let mut expected = b"data: first\n\n".to_vec();
    expected.extend_from_slice(b"data: CANARY_EVENT_BODY_SECRET\n\n");
    expected.extend(std::iter::repeat_n(b'x', 131_072));
    assert_eq!(received, expected);
    let event = events.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(event.len() <= 65_536, "event is bounded");
    assert!(event.contains("\"status\":200"));
    assert!(!event.contains("CANARY_EVENT_BODY_SECRET"));
    assert!(
        events.recv_timeout(Duration::from_millis(500)).is_err(),
        "one completed response emits one event"
    );
}

#[test]
fn cloud_event_does_not_hide_a_stream_response_limit() {
    let (event_port, events) = bounded_event_receiver();
    let (backend_port, resume) = paused_sse_backend();
    let proxy_port = free_port();
    let mut config = super::load_example_config(
        "observability/cloud-events.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", event_port)]),
    );
    config.body_limits.max_response_bytes = Some(16_384);
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let mut socket = TcpStream::connect(proxy.addr()).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut received = Vec::new();
    let mut resumed = false;
    let result = read_h1_response(&mut BufReader::new(socket), false, 16_384, |chunk| {
        received.extend_from_slice(chunk);
        if !resumed && received.len() >= b"data: first\n\n".len() {
            resume.send(()).unwrap();
            resumed = true;
        }
        Ok(())
    });
    assert!(resumed, "prefix must arrive before the tail");
    assert_eq!(result.status, Some(200));
    assert!(
        result.completion.is_none(),
        "an over-limit response cannot complete: {result:?}"
    );
    assert!(received.starts_with(b"data: first\n\n"));
    assert_eq!(
        received
            .windows(b"data: first\n\n".len())
            .filter(|window| *window == b"data: first\n\n")
            .count(),
        1
    );
    assert!(
        events.recv_timeout(Duration::from_millis(500)).is_err(),
        "the response-complete example must not emit for an aborted stream"
    );
    let probe = http_send(
        proxy.addr(),
        "GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&probe), 200);
    assert_eq!(praxis_test_utils::parse_body(&probe), "ok");
    let event = events.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(event.len() <= 65_536);
    assert!(!event.contains("CANARY_EVENT_BODY_SECRET"));
    events.recv_timeout(Duration::from_millis(500)).unwrap_err();
}

#[test]
fn cloud_events_request_complete_example_publishes_for_abort_and_success() {
    let (event_port, events) = bounded_event_receiver();
    let (backend_port, resume) = paused_sse_backend();
    let mut config = super::load_example_config(
        "observability/cloud-events-request-complete.yaml",
        free_port(),
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", event_port)]),
    );
    config.body_limits.max_response_bytes = Some(16_384);
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());

    let mut socket = TcpStream::connect(proxy.addr()).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    socket
        .write_all(b"GET /aborted HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut received = Vec::new();
    let mut saw_prefix = false;
    let result = read_h1_response(&mut BufReader::new(socket), false, 262_144, |chunk| {
        received.extend_from_slice(chunk);
        if !saw_prefix && received.starts_with(b"data: first\n\n") {
            resume.send(()).unwrap();
            saw_prefix = true;
        }
        Ok(())
    });
    assert!(saw_prefix, "the response must stream before the abort");
    assert_eq!(result.status, Some(200));
    assert!(result.completion.is_none(), "the over-limit response must abort");
    assert!(
        result.abort.as_ref().is_some_and(|(kind, _)| matches!(
            kind,
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
        )),
        "the proxy must abort the peer, not the bounded reader: {result:?}"
    );
    let aborted = events
        .recv_timeout(Duration::from_secs(5))
        .expect("aborted request emits one event");
    assert!(
        aborted.contains("\"status\":200"),
        "aborted event carries written status: {aborted}"
    );

    let response = http_send(
        proxy.addr(),
        "GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&response), 200);
    assert_eq!(praxis_test_utils::parse_body(&response), "ok");
    let completed = events
        .recv_timeout(Duration::from_secs(5))
        .expect("completed request emits one event");
    assert!(completed.contains("\"status\":200"));
    assert!(
        events.recv_timeout(Duration::from_millis(300)).is_err(),
        "no duplicate event"
    );
}

#[test]
fn cloud_events_request_complete_publishes_early_upstream_failure() {
    let (event_port, events) = bounded_event_receiver();
    let unavailable_port = free_port();
    let config = super::load_example_config(
        "observability/cloud-events-request-complete.yaml",
        free_port(),
        HashMap::from([("127.0.0.1:3000", unavailable_port), ("127.0.0.1:3001", event_port)]),
    );
    let proxy = start_full_proxy(&config);
    let response = http_send(
        proxy.addr(),
        "GET /unavailable HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&response);
    assert!((500..600).contains(&status), "failed dial returns a 5xx: {status}");
    let event = events
        .recv_timeout(Duration::from_secs(5))
        .expect("early failure emits one event");
    let event: serde_json::Value = serde_json::from_str(&event).unwrap();
    assert_eq!(event["data"]["status"].as_u64(), Some(u64::from(status)));
    assert!(
        events.recv_timeout(Duration::from_millis(300)).is_err(),
        "no duplicate event"
    );
}

#[test]
fn cloud_events_request_complete_respects_scope_and_instance_state() {
    let (event_port, events) = bounded_event_receiver();
    let backend_port = start_backend("completion-scope");
    let mut config = super::load_example_config(
        "observability/cloud-events-request-complete.yaml",
        free_port(),
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", event_port)]),
    );
    let first = config.filter_chains[0].filters.get_mut(0).unwrap();
    first.config["type"] = "first.request.completed".into();
    first.config["request_headers"] = serde_yaml::from_str("[user-agent]").unwrap();
    first.config["data"]["user_agent"] =
        serde_yaml::from_str("{value: request_header.user-agent, type: string, required: true}").unwrap();
    let mut second = first.clone();
    second.config["type"] = "second.request.completed".into();
    second.config["data"].as_mapping_mut().unwrap().remove("user_agent");
    let mut response_excluded = second.clone();
    response_excluded.config["type"] = "excluded.request.completed".into();
    for entry in [&mut *first, &mut second, &mut response_excluded] {
        entry.conditions = serde_yaml::from_str("- when: {path_prefix: /export}").unwrap();
        entry.response_conditions = serde_yaml::from_str("- when: {status: [200]}").unwrap();
    }
    response_excluded.response_conditions = serde_yaml::from_str("- when: {status: [201]}").unwrap();
    config.filter_chains[0].filters.insert(1, second);
    config.filter_chains[0].filters.insert(2, response_excluded);
    let proxy = start_full_proxy(&config);

    let private = http_send(
        proxy.addr(),
        "GET /private HTTP/1.1\r\nHost: localhost\r\nUser-Agent: known\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&private), 200);
    assert!(
        events.recv_timeout(Duration::from_millis(300)).is_err(),
        "request scope excludes /private"
    );

    let missing = http_send(
        proxy.addr(),
        "GET /export HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&missing), 200);
    let event: serde_json::Value = serde_json::from_str(&events.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
    assert_eq!(event["type"], "second.request.completed");
    assert!(
        events.recv_timeout(Duration::from_millis(300)).is_err(),
        "required mapping and 201 scope skip"
    );

    let included = http_send(
        proxy.addr(),
        "GET /export HTTP/1.1\r\nHost: localhost\r\nUser-Agent: known\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&included), 200);
    let events_for_request = (0..2)
        .map(|_| {
            serde_json::from_str::<serde_json::Value>(&events.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap()
        })
        .collect::<Vec<_>>();
    let types = events_for_request
        .iter()
        .map(|event| event["type"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        types,
        ["first.request.completed", "second.request.completed"]
            .into_iter()
            .collect()
    );
    assert_ne!(events_for_request[0]["id"], events_for_request[1]["id"]);
    assert!(
        events.recv_timeout(Duration::from_millis(300)).is_err(),
        "each invocation emits once"
    );
}

#[test]
fn cloud_events_request_complete_and_access_log_are_independent_in_both_orders() {
    for cloud_first in [true, false] {
        let (event_port, events) = bounded_event_receiver();
        let (backend_port, resume) = paused_sse_backend();
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.ndjson");
        let mut config = super::load_example_config(
            "observability/cloud-events-request-complete.yaml",
            free_port(),
            HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", event_port)]),
        );
        config.body_limits.max_response_bytes = Some(16_384);
        let access: praxis_core::config::FilterEntry = serde_yaml::from_str(&format!(
            "filter: access_log\nfields: [path, status]\nsink:\n  type: file\n  path: {}",
            log_path.display(),
        ))
        .unwrap();
        config.filter_chains[0].filters.insert(usize::from(cloud_first), access);
        let proxy = start_full_proxy(&config);
        wait_for_tcp(proxy.addr());

        let mut socket = TcpStream::connect(proxy.addr()).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        socket
            .write_all(b"GET /aborted HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut prefix = Vec::new();
        let mut resumed = false;
        let result = read_h1_response(&mut BufReader::new(socket), false, 262_144, |chunk| {
            prefix.extend_from_slice(chunk);
            if !resumed && prefix.starts_with(b"data: first\n\n") {
                resume.send(()).unwrap();
                resumed = true;
            }
            Ok(())
        });
        assert!(resumed);
        assert_eq!(result.status, Some(200));
        assert!(result.completion.is_none());
        assert!(
            result.abort.as_ref().is_some_and(|(kind, _)| matches!(
                kind,
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            )),
            "the proxy must abort the peer, not the bounded reader: {result:?}"
        );
        let aborted = events.recv_timeout(Duration::from_secs(5)).expect("abort event");
        assert!(aborted.contains("\"status\":200"));

        let response = http_send(
            proxy.addr(),
            "GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(parse_status(&response), 200);
        let completed = events.recv_timeout(Duration::from_secs(5)).expect("completed event");
        assert!(completed.contains("\"status\":200"));
        assert!(
            events.recv_timeout(Duration::from_millis(300)).is_err(),
            "no extra event"
        );

        let records = (0..100)
            .find_map(|_| {
                let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
                if contents.lines().count() == 2 {
                    Some(contents)
                } else {
                    thread::sleep(Duration::from_millis(20));
                    None
                }
            })
            .expect("abort and success each emit one access record");
        let paths = records
            .lines()
            .map(|line| {
                let record: serde_json::Value = serde_json::from_str(line).unwrap();
                assert_eq!(record["status"], "200");
                record["path"].as_str().unwrap().to_owned()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            paths,
            ["/aborted".to_owned(), "/probe".to_owned()].into_iter().collect()
        );
    }
}

#[test]
fn cloud_events_aborted_stream_preserves_access_log_and_scope() {
    for cloud_first in [true, false] {
        for (aborted_path, require_user_agent) in [("/private", false), ("/export", false), ("/export", true)] {
            let (event_port, events) = bounded_event_receiver();
            let (backend_port, resume) = paused_sse_backend();
            let dir = tempfile::tempdir().unwrap();
            let log_path = dir.path().join("access.ndjson");
            let mut config = super::load_example_config(
                "observability/cloud-events.yaml",
                free_port(),
                HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", event_port)]),
            );
            config.body_limits.max_response_bytes = Some(16_384);
            let access: praxis_core::config::FilterEntry = serde_yaml::from_str(&format!(
                "filter: access_log\nfields: [path, status]\nsink:\n  type: file\n  path: {}",
                log_path.display(),
            ))
            .unwrap();
            config.filter_chains[0].filters.insert(usize::from(cloud_first), access);
            for entry in &mut config.filter_chains[0].filters {
                if entry.filter_type == "cloud_events" {
                    entry.conditions = serde_yaml::from_str("- when:\n    path_prefix: /export").unwrap();
                    if require_user_agent {
                        entry.config["data"]["user_agent"]["required"] = true.into();
                    }
                }
            }
            let proxy = start_full_proxy(&config);
            wait_for_tcp(proxy.addr());
            let mut socket = TcpStream::connect(proxy.addr()).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            write!(
                socket,
                "GET {aborted_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let mut received = Vec::new();
            let mut resumed = false;
            let result = read_h1_response(&mut BufReader::new(socket), false, 16_384, |chunk| {
                received.extend_from_slice(chunk);
                if !resumed && received.len() >= b"data: first\n\n".len() {
                    resume.send(()).unwrap();
                    resumed = true;
                }
                Ok(())
            });
            assert!(resumed, "stream prefix must arrive");
            assert_eq!(result.status, Some(200));
            assert!(result.completion.is_none(), "aborted stream must not complete");
            assert!(
                events.recv_timeout(Duration::from_millis(500)).is_err(),
                "abort must not publish"
            );

            let probe = http_send(
                proxy.addr(),
                "GET /export/probe HTTP/1.1\r\nHost: localhost\r\nUser-Agent: completed-control\r\nConnection: close\r\n\r\n",
            );
            assert_eq!(parse_status(&probe), 200);
            let event = events
                .recv_timeout(Duration::from_secs(5))
                .expect("completed scoped response publishes");
            assert!(event.contains("\"status\":200"));
            if require_user_agent {
                assert!(event.contains("completed-control"), "required mapping positive control");
            }
            assert!(
                events.recv_timeout(Duration::from_millis(300)).is_err(),
                "exactly one event"
            );

            let records = (0..100)
                .find_map(|_| {
                    let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
                    if contents.lines().count() == 2 {
                        Some(contents)
                    } else {
                        thread::sleep(Duration::from_millis(20));
                        None
                    }
                })
                .expect("aborted and completed requests each log once");
            let paths: Vec<_> = records
                .lines()
                .map(|line| {
                    let record: serde_json::Value = serde_json::from_str(line).unwrap();
                    assert_eq!(record["status"], "200");
                    record["path"].as_str().unwrap().to_owned()
                })
                .collect();
            assert_eq!(paths.len(), 2);
            assert!(
                paths.iter().any(|path| path == aborted_path),
                "aborted request missing: {paths:?}"
            );
            assert!(
                paths.iter().any(|path| path == "/export/probe"),
                "completed request missing: {paths:?}"
            );
        }
    }
}

/// Accept events under a strict body bound, and acknowledge each one.
fn bounded_event_receiver() -> (u16, mpsc::Receiver<String>) {
    let (listener, port) = praxis_test_utils::bind_unique_port();
    listener.set_nonblocking(true).unwrap();
    let (sender, events) = mpsc::channel();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((socket, _)) => {
                    if sender.send(read_event(socket)).is_err() {
                        break;
                    }
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                },
                Err(error) => panic!("event receiver: {error}"),
            }
        }
    });
    (port, events)
}

/// Read and acknowledge one event without retaining unbounded data.
fn read_event(mut socket: TcpStream) -> String {
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reader = BufReader::new(&mut socket);
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "event headers ended prematurely"
        );
        headers.push_str(&line);
        assert!(headers.len() <= 16_384, "event headers exceeded the observation bound");
        if line == "\r\n" {
            break;
        }
    }
    let length: usize = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap();
    assert!(length <= 65_536, "event body exceeded the observation bound");
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    socket
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .unwrap();
    String::from_utf8(body).unwrap()
}

/// Hold the second event until the client has observed the first one.
fn paused_sse_backend() -> (u16, mpsc::Sender<()>) {
    let (listener, port) = praxis_test_utils::bind_unique_port();
    let (resume, wait) = mpsc::channel();
    thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut reader = BufReader::new(&mut socket);
        loop {
            let mut line = String::new();
            assert_ne!(
                reader.read_line(&mut line).unwrap(),
                0,
                "SSE request headers ended prematurely"
            );
            if line == "\r\n" {
                break;
            }
        }
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nd\r\ndata: first\n\n\r\n").unwrap();
        socket.flush().unwrap();
        wait.recv_timeout(Duration::from_secs(8)).unwrap();
        let tail = format!("data: CANARY_EVENT_BODY_SECRET\n\n{}", "x".repeat(131_072));
        let _sent = write!(socket, "{:x}\r\n{}\r\n0\r\n\r\n", tail.len(), tail);
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut probe, _)) => {
                    let mut reader = BufReader::new(&mut probe);
                    loop {
                        let mut line = String::new();
                        assert_ne!(
                            reader.read_line(&mut line).unwrap(),
                            0,
                            "probe request headers ended prematurely"
                        );
                        if line == "\r\n" {
                            break;
                        }
                    }
                    let _sent = probe.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                    break;
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                },
                Err(error) => panic!("probe backend: {error}"),
            }
        }
    });
    (port, resume)
}
