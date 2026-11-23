// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the access log text template example configuration.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use praxis_test_utils::{
    PraxisProcess, example_config_path, free_port, http_send, parse_body, parse_header, parse_status, patch_yaml,
    start_backend_with_shutdown, start_header_echo_backend, start_proxy,
};

#[test]
fn access_log_template() {
    let backend = start_backend_with_shutdown("logged");
    let proxy_port = free_port();
    let yaml = std::fs::read_to_string(example_config_path("observability/access-log-template.yaml"))
        .expect("read access-log-template example");
    let yaml = patch_yaml(&yaml, proxy_port, &HashMap::from([("127.0.0.1:3000", backend.port())]));
    let addr = format!("127.0.0.1:{proxy_port}");
    let proxy = PraxisProcess::spawn_with_env(&yaml, &addr, &[("PRAXIS_LOG_FORMAT", "json"), ("RUST_LOG", "info")]);
    let path = "/template/captured-line";
    let request_id = format!("template-{proxy_port}");
    let raw = http_send(
        &addr,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: {request_id}\r\nConnection: close\r\n\r\n"),
    );
    assert_eq!(parse_status(&raw), 200, "example must proxy the logged request");
    assert_eq!(parse_header(&raw, "x-request-id").as_deref(), Some(request_id.as_str()));

    let deadline = Instant::now() + Duration::from_secs(5);
    let event = loop {
        let logs = proxy.logs();
        if let Some(event) = logs
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|event| {
                event["fields"]["message"] == "access"
                    && event["fields"]["line"]
                        .as_str()
                        .is_some_and(|line| line.contains(&format!("id={request_id}")))
            })
        {
            break event;
        }
        assert!(Instant::now() < deadline, "no access event for {request_id}: {logs}");
        std::thread::sleep(Duration::from_millis(20));
    };
    let line = event["fields"]["line"].as_str().expect("access event line");
    let fields: Vec<_> = line.split_whitespace().collect();
    assert_eq!(fields.len(), 5, "configured template field count/order: {line}");
    assert_eq!(fields[0], "GET", "configured method token");
    assert_eq!(fields[1], path, "configured path token");
    assert_eq!(fields[2], "200", "configured status token");
    let duration = fields[3].strip_suffix("ms").expect("duration token suffix");
    assert!(
        duration.parse::<u64>().is_ok(),
        "duration token must be numeric: {line}"
    );
    assert_eq!(fields[4], format!("id={request_id}"), "configured request-id token");
}

#[test]
fn access_log_template_proxies_generated_and_supplied_ids() {
    let backend = start_header_echo_backend();
    let config = super::load_example_config(
        "observability/access-log-template.yaml",
        free_port(),
        HashMap::from([("127.0.0.1:3000", backend.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /generated HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "generated-ID request must reach the backend");
    let generated_ids = forwarded_request_ids(&raw);
    assert_eq!(generated_ids.len(), 1, "one generated ID must reach the backend: {raw}");
    assert_eq!(generated_ids[0].len(), 32, "generated ID must have 32 hex digits");
    assert!(
        generated_ids[0].bytes().all(|byte| byte.is_ascii_hexdigit()),
        "generated ID must be hexadecimal: {}",
        generated_ids[0]
    );
    assert!(
        parse_header(&raw, "x-request-id").is_none(),
        "proxy-generated ID must not be echoed to the client"
    );

    let raw = http_send(
        proxy.addr(),
        "GET /supplied HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: tmpl-abc\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "supplied-ID request must reach the backend");
    assert_eq!(
        forwarded_request_ids(&raw),
        vec!["tmpl-abc".to_owned()],
        "supplied ID must reach the backend"
    );
    assert_eq!(
        parse_header(&raw, "x-request-id").as_deref(),
        Some("tmpl-abc"),
        "client-supplied ID must be echoed to the client"
    );
}

fn forwarded_request_ids(raw_response: &str) -> Vec<String> {
    parse_body(raw_response)
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-request-id")
                .then(|| value.trim().to_owned())
        })
        .collect()
}
