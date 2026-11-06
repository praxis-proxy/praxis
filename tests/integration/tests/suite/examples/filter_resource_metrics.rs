// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional coverage for resource attribution without overload protection.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_test_utils::{PraxisProcess, example_config_path, free_port, http_get, patch_yaml, start_echo_backend};

#[test]
fn filter_resource_metrics_example_tracks_buffering_and_releases_payload() {
    let backend = start_echo_backend();
    let (port, metrics) = (free_port(), free_port());
    let source = std::fs::read_to_string(example_config_path("observability/filter-resource-metrics.yaml")).unwrap();
    let yaml = patch_yaml(
        &source,
        port,
        &HashMap::from([
            ("127.0.0.1:8080", port),
            ("127.0.0.1:9902", metrics),
            ("127.0.0.1:3000", backend.port()),
        ]),
    );
    let _proxy = PraxisProcess::spawn(&yaml, &format!("127.0.0.1:{port}"));
    let payload = br#"{"message":"hello","secret":"remove"}"#;
    let (prefix, suffix) = payload.split_at(12);
    let mut socket = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        socket,
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )
    .unwrap();
    socket.write_all(prefix).unwrap();
    wait_for_metric(metrics, "praxis_body_buffer_bytes", |value| value > 0.0);
    socket.write_all(suffix).unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "rewrite must succeed: {response}");
    assert!(
        response.contains("hello"),
        "the backend must receive the payload: {response}"
    );
    assert!(!response.contains("remove"), "the secret must be removed: {response}");
    wait_for_metric(metrics, "praxis_body_buffer_bytes", |value| value.abs() < f64::EPSILON);
    wait_for_metric(metrics, "praxis_filter_active{filter=\"json_body\"}", |value| {
        value.abs() < f64::EPSILON
    });
}

/// Wait for a numeric sample in the isolated subprocess's metrics endpoint.
fn wait_for_metric(port: u16, name: &str, predicate: impl Fn(f64) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let prefix = format!("{name} ");
    loop {
        let (status, body) = http_get(&format!("127.0.0.1:{port}"), "/metrics", None);
        assert_eq!(status, 200, "metrics endpoint must remain available");
        let value = body
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .and_then(|value| value.parse::<f64>().ok());
        if value.is_some_and(&predicate) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "metric {name} must reach its expected state: {body}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
