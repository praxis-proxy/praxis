// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for redirect filter behavior.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, parse_header, parse_status, start_proxy, wait_for_tcp};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn redirect_returns_301_with_location() {
    let proxy_port = free_port();
    let migration_port = free_port();
    let config = super::load_example_config(
        "traffic-management/redirect.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:8081", migration_port)]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET /some/path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 301, "redirect should return 301");
    assert_eq!(
        parse_header(&raw, "Location").as_deref(),
        Some("https://example.com/some/path"),
        "Location header should contain expanded template"
    );
}

#[test]
fn domain_migration_preserves_path_and_query() {
    let primary_port = free_port();
    let migration_port = free_port();
    let config = super::load_example_config(
        "traffic-management/redirect.yaml",
        primary_port,
        HashMap::from([("127.0.0.1:8081", migration_port)]),
    );
    let _proxy = start_proxy(&config);
    let migration_addr = format!("127.0.0.1:{migration_port}");
    wait_for_tcp(&migration_addr);

    let raw = http_send(
        &migration_addr,
        "GET /docs/guide?lang=en HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 308, "domain migration should return 308");
    assert_eq!(
        parse_header(&raw, "Location").as_deref(),
        Some("https://new.example.com/docs/guide?lang=en"),
        "Location should preserve both path and query"
    );
}

#[test]
fn domain_migration_with_path_but_no_query() {
    let primary_port = free_port();
    let migration_port = free_port();
    let config = super::load_example_config(
        "traffic-management/redirect.yaml",
        primary_port,
        HashMap::from([("127.0.0.1:8081", migration_port)]),
    );
    let _proxy = start_proxy(&config);
    let migration_addr = format!("127.0.0.1:{migration_port}");
    wait_for_tcp(&migration_addr);

    let raw = http_send(
        &migration_addr,
        "GET /docs/guide HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 308, "should return 308 even without query");
    assert_eq!(
        parse_header(&raw, "Location").as_deref(),
        Some("https://new.example.com/docs/guide"),
        "Location should have no trailing ? when query is absent"
    );
}

#[test]
fn redirect_returns_302_for_temporary_redirect() {
    let proxy_port = free_port();
    let config_yaml = r#"
listeners:
  - name: temp_redirect
    address: "127.0.0.1:PORT"
    filter_chains:
      - temp_chain

filter_chains:
  - name: temp_chain
    filters:
      - filter: redirect
        status: 302
        location: "https://temp.example.com${path}${query}"
"#
    .replace("PORT", &proxy_port.to_string());
    let config = praxis_core::config::Config::from_yaml(&config_yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET /landing?ref=home HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 302, "should return 302 Found");
    assert_eq!(
        parse_header(&raw, "Location").as_deref(),
        Some("https://temp.example.com/landing?ref=home"),
        "302 Location should preserve path and query"
    );
}

#[test]
fn redirect_works_for_post_method() {
    let proxy_port = free_port();
    let migration_port = free_port();
    let config = super::load_example_config(
        "traffic-management/redirect.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:8081", migration_port)]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "POST /form HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 301, "POST should also get redirected");
    assert_eq!(
        parse_header(&raw, "Location").as_deref(),
        Some("https://example.com/form"),
        "POST redirect should have correct Location"
    );
}
