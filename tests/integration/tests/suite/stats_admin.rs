// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for `GET /api/stats` (#125 Phase 1).

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_backend, start_full_proxy, wait_for_tcp};
use serde_json::Value;

fn stats_config_yaml(proxy_port: u16, admin_port: u16, backend_port: u16) -> String {
    format!(
        r#"
insecure_options:
  allow_private_endpoints: true

admin:
  address: "127.0.0.1:{admin_port}"

listeners:
  - name: web
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]

clusters:
  - name: backend
    endpoints:
      - address: "127.0.0.1:{backend_port}"

filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - address: "127.0.0.1:{backend_port}"
"#,
    )
}

fn get_stats_json(admin_addr: &str) -> (u16, Value) {
    let (status, body) = http_get(admin_addr, "/api/stats", None);
    let json: Value = serde_json::from_str(&body)
        .unwrap_or_else(|_| panic!("admin /api/stats should return JSON, got status={status} body={body}"));
    (status, json)
}

#[test]
fn stats_json_shape_after_live_traffic() {
    let backend_port = start_backend("stats-api");
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = stats_config_yaml(proxy_port, admin_port, backend_port);
    let config = Config::from_yaml(&yaml).expect("config should parse");
    let _proxy = start_full_proxy(&config);
    let admin_addr = format!("127.0.0.1:{admin_port}");
    let proxy_addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&admin_addr);

    let (status, _) = http_get(&proxy_addr, "/hello", None);
    assert_eq!(status, 200, "proxy request should succeed before stats read");

    let (status, json) = get_stats_json(&admin_addr);
    assert_eq!(status, 200, "GET /api/stats should succeed: {json}");

    assert!(json["uptime_secs"].as_u64().is_some(), "uptime_secs required: {json}");
    assert!(json["version"]["semver"].is_string(), "version.semver required: {json}");
    assert!(
        json["version"]["display"].is_string(),
        "version.display required: {json}"
    );

    let listeners = json["listeners"].as_array().expect("listeners array");
    let web = listeners.iter().find(|l| l["name"] == "web").expect("web listener");
    assert_eq!(web["protocol"], "http", "web protocol: {json}");
    assert!(
        json["gaps"]["per_listener_http_requests"].is_string(),
        "per-listener HTTP request gap documented: {json}"
    );

    let clusters = json["clusters"].as_array().expect("clusters array");
    let backend = clusters
        .iter()
        .find(|c| c["name"] == "backend")
        .expect("backend cluster");
    assert_eq!(backend["total_endpoints"], 1, "endpoint count: {json}");
    assert_eq!(
        backend["healthy_endpoints"], 1,
        "healthy count without health_check: {json}"
    );
    assert!(
        backend["upstream_requests_total"].as_u64().unwrap_or(0) >= 1,
        "upstream request counter should reflect live traffic: {json}"
    );
    let endpoints = backend["endpoints"].as_array().expect("endpoints array");
    assert_eq!(
        endpoints[0]["address"],
        format!("127.0.0.1:{backend_port}"),
        "endpoint address: {json}"
    );
    assert_eq!(
        endpoints[0]["healthy"], true,
        "endpoint healthy without health_check: {json}"
    );
}
