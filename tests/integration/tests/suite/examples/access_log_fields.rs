// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the access log field selection example configuration.

use std::{collections::HashMap, fs, thread::sleep, time::Duration};

use praxis_test_utils::{
    Backend, free_port, http_send, parse_status, start_backend_with_shutdown, start_full_proxy, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn access_log_fields() {
    let ok_backend = start_backend_with_shutdown("ok");
    let error_port = Backend::status(500, "error").start();
    let proxy_port = free_port();
    let mut config = super::load_example_config(
        "observability/access-log-fields.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", ok_backend.port()), ("127.0.0.1:3001", error_port)]),
    );
    let dir = tempfile::tempdir().expect("unique log directory");
    let path = dir.path().join("fields.ndjson");
    let mut patched = false;
    for chain in &mut config.filter_chains {
        for entry in &mut chain.filters {
            if entry.filter_type == "access_log" {
                entry.config.as_mapping_mut().expect("access log config").insert(
                    "sink".into(),
                    serde_yaml::from_str(&format!("type: file\npath: {}", path.display())).expect("file sink"),
                );
                patched = true;
            }
        }
    }
    assert!(patched, "example must contain access_log");
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());

    let raw = http_send(
        proxy.addr(),
        "GET /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "successful route should return 200");

    let raw = http_send(
        proxy.addr(),
        "GET /error HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 500, "error route should return 500");

    let contents = (0..50)
        .find_map(|_| {
            let contents = fs::read_to_string(&path).unwrap_or_default();
            if contents.lines().count() == 1 {
                Some(contents)
            } else {
                sleep(Duration::from_millis(20));
                None
            }
        })
        .expect("one filtered access record within one second");
    let records: Vec<HashMap<String, String>> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid NDJSON record"))
        .collect();
    assert_eq!(records.len(), 1, "only 5xx should be logged");
    let record = &records[0];
    let expected = ["method", "path", "status", "duration_ms", "request_id", "timestamp"];
    assert_eq!(
        record
            .keys()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>(),
        expected.into_iter().collect()
    );
    assert_utc_millisecond_timestamp(record.get("timestamp").expect("direct sink timestamp"));
    assert_eq!(record.get("method").map(String::as_str), Some("GET"));
    assert_eq!(record.get("path").map(String::as_str), Some("/error"));
    assert_eq!(record.get("status").map(String::as_str), Some("500"));
    assert!(record.get("request_id").is_some_and(|id| !id.is_empty()));
    assert!(
        record
            .get("duration_ms")
            .is_some_and(|value| value.parse::<u64>().is_ok())
    );
}

/// Require the direct sink's UTC timestamp shape with millisecond precision.
fn assert_utc_millisecond_timestamp(timestamp: &str) {
    assert_eq!(timestamp.len(), 24, "UTC timestamp with millisecond precision");
    for (index, byte) in timestamp.bytes().enumerate() {
        match index {
            4 | 7 => assert_eq!(
                byte, b'-',
                "timestamp {timestamp:?} has the wrong separator at byte {index}"
            ),
            10 => assert_eq!(
                byte, b'T',
                "timestamp {timestamp:?} has the wrong separator at byte {index}"
            ),
            13 | 16 => assert_eq!(
                byte, b':',
                "timestamp {timestamp:?} has the wrong separator at byte {index}"
            ),
            19 => assert_eq!(
                byte, b'.',
                "timestamp {timestamp:?} has the wrong separator at byte {index}"
            ),
            23 => assert_eq!(
                byte, b'Z',
                "timestamp {timestamp:?} has the wrong separator at byte {index}"
            ),
            _ => assert!(
                byte.is_ascii_digit(),
                "timestamp {timestamp:?} requires a digit at byte {index}"
            ),
        }
    }
}
