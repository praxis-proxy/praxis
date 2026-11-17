// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for header manipulation behavior.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
};

use praxis_test_utils::{
    Backend, free_port, http_send, parse_body, parse_header, spawn_raw_http_backend, start_backend_with_shutdown,
    start_full_proxy, start_proxy, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn header_manipulation() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "transformation/header-manipulation.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_header(&raw, "x-powered-by"),
        Some("praxis".to_owned()),
        "X-Powered-By header should be set to 'praxis'"
    );
    assert_eq!(
        parse_header(&raw, "x-frame-options"),
        Some("DENY".to_owned()),
        "X-Frame-Options header should be set to 'DENY'"
    );
}

#[test]
fn header_response_remove_strips_upstream_header() {
    let backend_port = Backend::fixed("ok").header("Server", "upstream-server").start();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "transformation/header-manipulation.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert!(
        parse_header(&raw, "server").is_none(),
        "Server header should be removed by response_remove; got response:\n{raw}"
    );
}

#[test]
fn header_request_mutations_replay_across_filter_instances_on_wire() {
    let (backend_port, backend_thread) = spawn_raw_http_backend(|mut stream| {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).expect("read request headers");
            assert_ne!(count, 0);
            request.extend_from_slice(&buffer[..count]);
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            request.len(),
            String::from_utf8_lossy(&request)
        );
        stream.write_all(response.as_bytes()).expect("write response");
    });
    let proxy_port = free_port();
    let yaml = format!(
        "listeners:\n  - name: default\n    address: 127.0.0.1:{proxy_port}\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: router\n        routes:\n          - path_prefix: /\n            cluster: backend\n      - filter: headers\n        name: first_fields\n        request_add:\n          - {{name: X-Set, value: first}}\n          - {{name: X-Order, value: first}}\n          - {{name: X-Multi, value: alpha}}\n      - filter: headers\n        name: second_fields\n        request_set:\n          - {{name: X-Set, value: second}}\n          - {{name: X-Order, value: second}}\n        request_add:\n          - {{name: X-Set, value: third}}\n          - {{name: X-Order, value: third}}\n          - {{name: X-Multi, value: beta}}\n      - filter: headers\n        name: final_fields\n        request_remove: [X-Order]\n        request_add:\n          - {{name: X-Order, value: fourth}}\n      - filter: load_balancer\n        clusters:\n          - name: backend\n            endpoints: ['127.0.0.1:{backend_port}']\ninsecure_options:\n  allow_private_endpoints: true\n"
    );
    let config = praxis_core::config::Config::from_yaml(&yaml).expect("header replay config");
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Order: client\r\nX-Set: client\r\nX-Multi: client\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(praxis_test_utils::parse_status(&raw), 200, "{raw}");
    let request = parse_body(&raw);
    let values = |name: &str| -> Vec<String> {
        request
            .split("\r\n")
            .filter_map(|line| {
                let (field, value) = line.split_once(':')?;
                field.eq_ignore_ascii_case(name).then(|| value.trim().to_owned())
            })
            .collect()
    };
    assert_eq!(
        values("x-set"),
        ["second", "third"],
        "set replaces earlier values before add: {request}"
    );
    assert_eq!(values("x-order"), ["fourth"], "remove then add wins: {request}");
    assert_eq!(
        values("x-multi"),
        ["client", "alpha", "beta"],
        "adds retain separate field values and filter order: {request}"
    );
    backend_thread.join().expect("backend completed");
}
