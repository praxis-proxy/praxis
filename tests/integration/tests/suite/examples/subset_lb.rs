// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the subset load-balancing example config.

use std::collections::{HashMap, HashSet};

use praxis_test_utils::{free_port, http_send, parse_body, parse_status, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn subset_lb() {
    let port_a_guard = start_backend_with_shutdown("sub-stable");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("sub-canary-1");
    let port_b = port_b_guard.port();
    let port_c_guard = start_backend_with_shutdown("sub-canary-2");
    let port_c = port_c_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/subset-lb.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
        ]),
    );
    let proxy = start_proxy(&config);

    // Subset routing: only canary endpoints should receive traffic.
    let mut backends_seen = HashSet::new();
    for _ in 0..20 {
        let raw = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: close\r\n\r\n",
        );
        backends_seen.insert(parse_body(&raw));
    }

    assert!(
        !backends_seen.contains("sub-stable"),
        "stable endpoint should not receive traffic when subset selector matches canary"
    );
    assert!(
        backends_seen.contains("sub-canary-1") || backends_seen.contains("sub-canary-2"),
        "at least one canary endpoint should receive traffic"
    );
}

#[test]
fn subset_lb_falls_back_when_no_subset_matches() {
    let stable = start_backend_with_shutdown("sub-stable");
    let canary_one = start_backend_with_shutdown("sub-canary-1");
    let canary_two = start_backend_with_shutdown("sub-canary-2");
    let proxy_port = free_port();
    let mut config = super::load_example_config(
        "traffic-management/subset-lb.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", stable.port()),
            ("127.0.0.1:3002", canary_one.port()),
            ("127.0.0.1:3003", canary_two.port()),
        ]),
    );
    let load_balancer = config.filter_chains[0]
        .filters
        .iter_mut()
        .find(|entry| entry.filter_type == "load_balancer")
        .expect("subset example load balancer");
    load_balancer.config["clusters"][0]["load_balancer_strategy"]["subset"]["selector"]["version"] =
        serde_yaml::Value::String("no-such-version".to_owned());

    let proxy = start_proxy(&config);
    let mut seen = HashSet::new();
    for _ in 0..6 {
        let raw = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: close\r\n\r\n",
        );
        assert_eq!(parse_status(&raw), 200, "any_endpoint fallback must succeed: {raw}");
        seen.insert(parse_body(&raw));
    }
    assert_eq!(
        seen,
        HashSet::from([
            "sub-stable".to_owned(),
            "sub-canary-1".to_owned(),
            "sub-canary-2".to_owned(),
        ]),
        "no-match any_endpoint fallback must cycle over every configured endpoint"
    );
}
