// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the access log file sink example configuration.

use std::{collections::HashMap, thread::sleep, time::Duration};

use praxis_test_utils::{
    free_port, http_send, load_example_config, parse_status, start_backend_with_shutdown, start_proxy,
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Read a file, retrying briefly so the asynchronous response-phase emit has
/// time to flush its line before the assertion runs.
fn read_with_retry(path: &std::path::Path) -> String {
    for _ in 0..50 {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.is_empty()
        {
            return contents;
        }
        sleep(Duration::from_millis(20));
    }
    std::fs::read_to_string(path).unwrap_or_default()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn access_log_file_sink() {
    let backend_port_guard = start_backend_with_shutdown("logged");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    // Load the real example through the shared harness, then point the file
    // sink at a unique temp path so the test is isolated and self-cleaning; the
    // example ships a fixed `/tmp` path for operators.
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("access.log");
    let mut config = load_example_config(
        "observability/access-log-file-sink.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let sink_path = log_path.to_str().expect("utf8 path");
    let mut patched = false;
    for chain in &mut config.filter_chains {
        for entry in &mut chain.filters {
            if entry.filter_type == "access_log"
                && let Some(sink) = entry.config.get_mut("sink").and_then(serde_yaml::Value::as_mapping_mut)
            {
                sink.insert("path".into(), sink_path.into());
                patched = true;
            }
        }
    }
    assert!(patched, "example should configure an access_log file sink to override");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "file sink should not disrupt proxying");

    // The file sink writes one NDJSON record per request. Prove the feature
    // end-to-end by parsing the written line back into a JSON object carrying
    // the configured fields with real per-request values.
    let contents = read_with_retry(&log_path);
    let line = contents.lines().next().expect("file sink should write one NDJSON line");
    let record: HashMap<String, String> = serde_json::from_str(line).expect("line should be valid NDJSON");
    assert_eq!(
        record.get("method").map(String::as_str),
        Some("GET"),
        "record: {record:?}"
    );
    assert_eq!(
        record.get("status").map(String::as_str),
        Some("200"),
        "record: {record:?}"
    );
    assert!(
        record.contains_key("path"),
        "record should carry the configured path field: {record:?}"
    );
    assert!(
        record.get("request_id").is_some_and(|id| !id.is_empty()),
        "record should carry the id promoted by the request_id filter: {record:?}"
    );
}
