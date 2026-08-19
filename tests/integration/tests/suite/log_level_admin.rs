// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for `/api/log-level` admin API (#798).

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_delete, http_get, http_put_json, wait_for_tcp};
use serde_json::Value;

fn log_level_config_yaml(proxy_port: u16, admin_port: u16) -> String {
    format!(
        r#"
insecure_options:
  allow_private_endpoints: true

admin:
  address: "127.0.0.1:{admin_port}"

runtime:
  log_overrides:
    praxis_filter: warn

listeners:
  - name: web
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]

filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        body: ok
"#
    )
}

fn start_proxy_with_log_level(yaml: &str) -> String {
    let config = Config::from_yaml(yaml).expect("config should parse");
    let admin_addr = config.admin.address.clone().expect("admin address");

    std::thread::spawn(move || {
        let guard = praxis::init_tracing(&config).expect("tracing init");
        let log_level = Some(guard.log_level_state());
        let _guard = guard;
        praxis::run_server(config, None, log_level);
    });

    wait_for_tcp(&admin_addr);
    admin_addr
}

fn json_value(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|error| panic!("expected JSON body, got error={error} body={body}"))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn log_level_admin_put_get_delete_and_validation() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = log_level_config_yaml(proxy_port, admin_port);
    let admin_addr = start_proxy_with_log_level(&yaml);

    let (status, body) = http_get(&admin_addr, "/api/log-level", None);
    assert_eq!(status, 200, "GET should succeed: {body}");
    let baseline = json_value(&body);
    assert!(
        baseline["baseline_directive"]
            .as_str()
            .is_some_and(|d| d.contains("praxis_filter=warn")),
        "baseline should include YAML override: {baseline}"
    );
    assert!(baseline["overlays"].as_array().is_some_and(|o| o.is_empty()));

    let put_body = r#"{"module":"praxis_filter","level":"trace","duration_secs":300}"#;
    let (status, body) = http_put_json(&admin_addr, "/api/log-level", put_body);
    assert_eq!(status, 200, "PUT should succeed: {body}");
    let after_put = json_value(&body);
    assert!(
        after_put["effective_directive"]
            .as_str()
            .is_some_and(|d| d.contains("praxis_filter=trace")),
        "effective directive should include trace overlay: {after_put}"
    );
    let overlays = after_put["overlays"].as_array().expect("overlays array");
    assert_eq!(overlays.len(), 1, "one overlay expected: {after_put}");
    assert_eq!(overlays[0]["level"], "trace");

    let (status, body) = http_delete(&admin_addr, "/api/log-level?module=praxis_filter");
    assert_eq!(status, 200, "DELETE should succeed: {body}");
    let after_delete = json_value(&body);
    assert!(
        after_delete["overlays"].as_array().is_some_and(|o| o.is_empty()),
        "overlay should be cleared: {after_delete}"
    );

    let (status, body) = http_put_json(
        &admin_addr,
        "/api/log-level",
        r#"{"module":"","level":"debug","duration_secs":60}"#,
    );
    assert_eq!(status, 400, "empty module should be rejected: {body}");
    assert!(
        body.contains("must not be empty"),
        "error should mention empty module: {body}"
    );

    let (status, _body) = http_put_json(&admin_addr, "/api/log-level", r#"{"level":"bogus","duration_secs":60}"#);
    assert_eq!(status, 400, "unknown level should be rejected");

    let (status, _body) = http_get(&admin_addr, "/api/log-level", None);
    assert_eq!(status, 200, "HEAD/GET still healthy after validation errors");
}
