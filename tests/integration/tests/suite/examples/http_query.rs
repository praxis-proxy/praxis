// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional coverage for the HTTP QUERY example.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, parse_header, parse_status, start_full_proxy, start_recording_backend, wait_for_tcp,
};

use crate::query::{QUERY_BODY, assert_query, observed, request, response};

#[test]
fn http_query_example_preflights_retries_and_applies_method_conditions() {
    let (failing, failed_log) = start_recording_backend(|_| response(503, "unavailable"));
    let (healthy, healthy_log) = start_recording_backend(|_| response(200, "results"));
    let config = super::load_example_config(
        "traffic-management/http-query.yaml",
        free_port(),
        HashMap::from([("127.0.0.1:3001", failing.port()), ("127.0.0.1:3002", healthy.port())]),
    );
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());

    let preflight = http_send(
        proxy.addr(),
        "OPTIONS /products HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nAccess-Control-Request-Method: QUERY\r\nAccess-Control-Request-Headers: Content-Type\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&preflight), 204);
    assert_eq!(
        parse_header(&preflight, "access-control-allow-methods"),
        Some("QUERY".to_owned())
    );
    assert!(
        observed(&failed_log).is_empty(),
        "preflight must end before reaching a backend"
    );
    assert!(observed(&healthy_log).is_empty());

    let raw = http_send(
        proxy.addr(),
        &request("QUERY", QUERY_BODY).replace(
            "Host: localhost\r\n",
            "Host: localhost\r\nOrigin: https://app.example.com\r\n",
        ),
    );
    assert_eq!(parse_status(&raw), 200, "QUERY should retry the first origin: {raw}");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("https://app.example.com".to_owned())
    );
    for log in [&failed_log, &healthy_log] {
        let attempts = observed(log);
        assert_query(&attempts, QUERY_BODY);
        assert!(
            attempts[0]
                .headers
                .iter()
                .any(|(name, value)| name == "x-query-processed" && value == "true")
        );
    }

    let raw = http_send(proxy.addr(), &request("GET", ""));
    assert_eq!(parse_status(&raw), 200, "ordinary GET should remain supported: {raw}");
    let get = observed(&healthy_log)
        .into_iter()
        .find(|attempt| attempt.request_line.starts_with("GET "))
        .unwrap();
    assert!(
        !get.headers.iter().any(|(name, _)| name == "x-query-processed"),
        "QUERY conditions must not match GET"
    );
}
