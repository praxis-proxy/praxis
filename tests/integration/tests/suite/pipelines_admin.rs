// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for `GET /api/pipelines` (#796).

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_backend, start_full_proxy, start_reloadable_proxy, wait_for_tcp};
use serde_json::Value;

fn pipelines_config_yaml(proxy_port: u16, admin_port: u16, backend_port: u16) -> String {
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
  - name: empty
    address: "127.0.0.1:{empty_port}"
    filter_chains: [empty_chain]

clusters:
  - name: backend
    endpoints:
      - address: "127.0.0.1:{backend_port}"

filter_chains:
  - name: empty_chain
    filters: []
  - name: main
    filters:
      - filter: router
        name: routing
        routes:
          - path_prefix: "/"
            cluster: backend
        branch_chains:
          - name: utility_branch
            rejoin: next
            chains:
              - name: utility
                filters:
                  - filter: headers
                    request_add:
                      - name: X-Utility
                        value: "applied"
      - filter: load_balancer
"#,
        admin_port = admin_port,
        proxy_port = proxy_port,
        backend_port = backend_port,
        empty_port = free_port(),
    )
}

fn get_pipelines_json(admin_addr: &str, path: &str) -> (u16, Value) {
    let (status, body) = http_get(admin_addr, path, None);
    let json: Value = serde_json::from_str(&body)
        .unwrap_or_else(|_| panic!("admin {path} should return JSON, got status={status} body={body}"));
    (status, json)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn pipelines_aggregate_shape_and_branches() {
    let backend_port = start_backend("pipelines-api");
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = pipelines_config_yaml(proxy_port, admin_port, backend_port);
    let config = Config::from_yaml(&yaml).expect("config should parse");
    let _proxy = start_full_proxy(&config);
    let admin_addr = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin_addr);

    let (status, json) = get_pipelines_json(&admin_addr, "/api/pipelines");
    assert_eq!(status, 200, "aggregate should be 200: {json}");
    let listeners = json["listeners"].as_array().expect("listeners array");
    assert!(listeners.len() >= 2, "expected web + empty listeners: {json}");

    let web = listeners
        .iter()
        .find(|l| l["name"] == "web")
        .expect("web listener present");
    assert_eq!(web["chain_names"], serde_json::json!(["main"]));
    assert_eq!(web["protocol"], "http");
    assert_eq!(web["tls"], false);
    assert_eq!(web["filter_count"], 2);
    assert_eq!(web["filters"].as_array().unwrap().len(), 2);

    let router = &web["filters"][0];
    assert_eq!(router["filter"], "router");
    assert_eq!(router["name"], "routing");
    assert_eq!(router["failure_mode"], "closed");
    assert!(router["phases"].as_array().unwrap().contains(&Value::from("request")));
    assert!(router["request_body"].is_object(), "HTTP filter emits body info");
    let branches = router["branches"].as_array().expect("branches");
    assert!(!branches.is_empty(), "expected at least one branch");
    assert_eq!(branches[0]["rejoin"], "next");

    let empty = listeners
        .iter()
        .find(|l| l["name"] == "empty")
        .expect("empty listener present");
    assert_eq!(empty["filter_count"], 0);
    assert_eq!(empty["filters"], serde_json::json!([]));
    assert_eq!(empty["chain_names"], serde_json::json!(["empty_chain"]));
}

#[test]
fn pipelines_per_listener_envelope_and_404() {
    let backend_port = start_backend("pipelines-api-single");
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = pipelines_config_yaml(proxy_port, admin_port, backend_port);
    let config = Config::from_yaml(&yaml).expect("config should parse");
    let _proxy = start_full_proxy(&config);
    let admin_addr = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin_addr);

    let (status, json) = get_pipelines_json(&admin_addr, "/api/pipelines?listener=web");
    assert_eq!(status, 200, "per-listener should be 200: {json}");
    assert!(json.get("listener").is_some(), "single envelope uses listener: {json}");
    assert!(json.get("listeners").is_none(), "must not reuse listeners array");
    assert_eq!(json["listener"]["name"], "web");

    let (missing_status, missing_json) = get_pipelines_json(&admin_addr, "/api/pipelines?listener=nope");
    assert_eq!(missing_status, 404, "missing listener => 404: {missing_json}");
}

#[test]
fn pipelines_view_updates_after_reload() {
    let backend_port = start_backend("pipelines-reload");
    let proxy_port = free_port();
    let admin_port = free_port();
    let empty_port = free_port();

    let initial = format!(
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
"#
    );
    let updated = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: web
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
  - name: unused_until_restart
    address: "127.0.0.1:{empty_port}"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints:
      - address: "127.0.0.1:{backend_port}"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 204
"#
    );

    let guard = start_reloadable_proxy(&initial);
    let admin_addr = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin_addr);

    let (_, before) = get_pipelines_json(&admin_addr, "/api/pipelines?listener=web");
    assert_eq!(before["listener"]["filters"][0]["filter"], "router");
    assert_eq!(before["listener"]["filter_count"], 2);

    guard.reload(&updated);

    let (_, after) = get_pipelines_json(&admin_addr, "/api/pipelines?listener=web");
    assert_eq!(after["listener"]["filters"][0]["filter"], "static_response");
    assert_eq!(after["listener"]["filter_count"], 1);

    let (status, aggregate) = get_pipelines_json(&admin_addr, "/api/pipelines");
    assert_eq!(status, 200);
    let names: Vec<&str> = aggregate["listeners"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|l| l["name"].as_str())
        .collect();
    assert!(names.contains(&"web"));
    assert!(
        !names.contains(&"unused_until_restart"),
        "new hot-reload listeners stay absent: {names:?}"
    );
}

#[test]
fn pipelines_named_and_terminal_rejoins() {
    let backend_port = start_backend("named-rejoin-pipelines");
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true

admin:
  address: "127.0.0.1:{admin_port}"

listeners:
  - name: web
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [preprocessing, main]

clusters:
  - name: backend
    endpoints:
      - address: "127.0.0.1:{backend_port}"

filter_chains:
  - name: preprocessing
    filters:
      - filter: headers
        request_add:
          - name: X-Pre
            value: "true"
        branch_chains:
          - name: shortcut_to_routing
            rejoin: routing
            chains:
              - name: fast
                filters:
                  - filter: headers
                    request_add:
                      - name: X-Fast
                        value: "1"
  - name: main
    filters:
      - filter: headers
        name: tagger
        request_add:
          - name: X-Tag
            value: "checked"
        branch_chains:
          - name: tagged_terminal
            rejoin: terminal
            chains:
              - name: done
                filters:
                  - filter: static_response
                    status: 200
      - filter: router
        name: routing
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
"#
    );
    let config = Config::from_yaml(&yaml).expect("config should parse");
    let _proxy = start_full_proxy(&config);
    let admin_addr = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin_addr);

    let (status, json) = get_pipelines_json(&admin_addr, "/api/pipelines?listener=web");
    assert_eq!(status, 200, "{json}");
    assert_eq!(
        json["listener"]["chain_names"],
        serde_json::json!(["preprocessing", "main"])
    );
    let filters = json["listener"]["filters"].as_array().unwrap();
    assert!(!filters.is_empty());
    let has_named = filters.iter().any(|f| {
        f["branches"]
            .as_array()
            .is_some_and(|branches| branches.iter().any(|b| b["rejoin"] == "routing"))
    });
    let has_terminal = filters.iter().any(|f| {
        f["branches"]
            .as_array()
            .is_some_and(|branches| branches.iter().any(|b| b["rejoin"] == "terminal"))
    });
    assert!(has_named, "expected named SkipTo rejoin label: {json}");
    assert!(has_terminal, "expected terminal rejoin label: {json}");
}
