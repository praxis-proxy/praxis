// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for route label path templating.

use std::time::Duration;

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_proxy, wait_for_tcp};

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

fn wait_for(admin: &str, needle: &str) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        last = http_get(admin, "/metrics", None).1;
        if last.contains(needle) {
            return last;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    last
}

fn proxy_yaml(cluster: &str, proxy_port: u16, admin_port: u16, backend_port: u16, templates: &str) -> String {
    format!(
        r#"
admin:
  metrics_address: "127.0.0.1:{admin_port}"
metrics:
{templates}
listeners:
  - name: templated
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: {cluster}
      - filter: load_balancer
        clusters:
          - name: {cluster}
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn route_templates_collapse_dynamic_paths_into_one_series() {
    let backend = start_backend_with_shutdown("templated");
    let proxy_port = free_port();
    let admin_port = free_port();
    let cluster = "tmpl-collapse";
    let templates = "  route_templates:\n    - \"/users/{id}/orders\"\n";
    let config = Config::from_yaml(&proxy_yaml(cluster, proxy_port, admin_port, backend.port(), templates)).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    for id in ["1", "2", "3"] {
        let (status, _) = http_get(proxy.addr(), &format!("/users/{id}/orders"), None);
        assert_eq!(status, 200, "proxy request should succeed");
    }

    let needle = format!("route=\"/users/{{id}}/orders\",cluster=\"{cluster}\"");
    let body = wait_for(&admin, &needle);
    assert!(
        body.contains(&needle),
        "three distinct paths should share one templated series:\n{body}"
    );
    for id in ["1", "2", "3"] {
        assert!(
            !body.contains(&format!("route=\"/users/{id}/orders\"")),
            "raw path /users/{id}/orders must not appear as a label value:\n{body}"
        );
    }
}

#[test]
fn unmatched_paths_keep_the_router_pattern() {
    let backend = start_backend_with_shutdown("unmatched");
    let proxy_port = free_port();
    let admin_port = free_port();
    let cluster = "tmpl-unmatched";
    let templates = "  route_templates:\n    - \"/users/{id}/orders\"\n";
    let config = Config::from_yaml(&proxy_yaml(cluster, proxy_port, admin_port, backend.port(), templates)).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let (status, _) = http_get(proxy.addr(), "/something/else/entirely", None);
    assert_eq!(status, 200, "proxy request should succeed");

    let needle = format!("route=\"/*\",cluster=\"{cluster}\"");
    let body = wait_for(&admin, &needle);
    assert!(
        body.contains(&needle),
        "an unmatched path should fall back to the router pattern, never the raw path:\n{body}"
    );
    assert!(
        !body.contains("/something/else/entirely"),
        "the raw path must never become a label value:\n{body}"
    );
}

#[test]
fn no_templates_leaves_the_route_label_unchanged() {
    let backend = start_backend_with_shutdown("no-templates");
    let proxy_port = free_port();
    let admin_port = free_port();
    let cluster = "tmpl-disabled";
    let config = Config::from_yaml(&proxy_yaml(
        cluster,
        proxy_port,
        admin_port,
        backend.port(),
        "  filter_duration: false\n",
    ))
    .unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let (status, _) = http_get(proxy.addr(), "/users/7/orders", None);
    assert_eq!(status, 200, "proxy request should succeed");

    let templated = format!("route=\"/users/{{id}}/orders\",cluster=\"{cluster}\"");
    let needle = format!("route=\"/*\",cluster=\"{cluster}\"");
    let body = wait_for(&admin, &needle);
    assert!(
        body.contains(&needle),
        "without templates the router pattern is used as before:\n{body}"
    );
    assert!(
        !body.contains(&templated),
        "no templating should occur when none is configured:\n{body}"
    );
}
