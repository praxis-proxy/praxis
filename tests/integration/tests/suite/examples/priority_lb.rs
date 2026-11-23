// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the priority-level load-balancing example config.

use std::collections::{HashMap, HashSet};

use praxis_test_utils::{
    free_port, http_send, parse_body, start_backend_with_shutdown, start_full_proxy, start_proxy, wait_for_http,
};

use super::routing_health::{TestHealthBackend, wait_for_routing_phase};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn priority_lb() {
    let port_a_guard = start_backend_with_shutdown("pri-primary-1");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("pri-primary-2");
    let port_b = port_b_guard.port();
    let port_c_guard = start_backend_with_shutdown("pri-failover-1");
    let port_c = port_c_guard.port();
    let port_d_guard = start_backend_with_shutdown("pri-failover-2");
    let port_d = port_d_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/priority-lb.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
            ("127.0.0.1:3004", port_d),
        ]),
    );
    let proxy = start_proxy(&config);

    // Without health issues, only primary-tier endpoints should be used.
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
        backends_seen.contains("pri-primary-1") || backends_seen.contains("pri-primary-2"),
        "primary-tier endpoints should receive traffic"
    );
    assert!(
        !backends_seen.contains("pri-failover-1") && !backends_seen.contains("pri-failover-2"),
        "failover-tier endpoints should not receive traffic when primary is healthy"
    );
}

#[test]
fn priority_lb_spills_when_primary_unhealthy() {
    let primary_one = TestHealthBackend::start("pri-primary-1");
    let primary_two = TestHealthBackend::start("pri-primary-2");
    let failover_one = TestHealthBackend::start("pri-failover-1");
    let failover_two = TestHealthBackend::start("pri-failover-2");
    let proxy_port = free_port();
    let mut config = super::load_example_config(
        "traffic-management/priority-lb.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", primary_one.port()),
            ("127.0.0.1:3002", primary_two.port()),
            ("127.0.0.1:3003", failover_one.port()),
            ("127.0.0.1:3004", failover_two.port()),
        ]),
    );
    let check = config.clusters[0]
        .health_check
        .as_mut()
        .expect("priority example health check");
    check.interval_ms = 200;
    check.timeout_ms = 100;

    let proxy = start_full_proxy(&config);
    wait_for_http(proxy.addr());
    for backend in [&primary_one, &primary_two, &failover_one, &failover_two] {
        backend.wait_for_probe_after(0);
    }

    let initial = wait_for_routing_phase(proxy.addr(), |seen| {
        seen.len() == 2 && seen.contains("pri-primary-1") && seen.contains("pri-primary-2")
    });
    assert_eq!(initial.len(), 2, "healthy priority tier must use both primaries");

    let prior_probe = primary_one.probe_count();
    primary_one.set_healthy(false);
    primary_one.wait_for_probe_after(prior_probe);
    let degraded = wait_for_routing_phase(proxy.addr(), |seen| {
        seen.len() == 2 && seen.contains("pri-failover-1") && seen.contains("pri-failover-2")
    });
    assert_eq!(
        degraded.len(),
        2,
        "half-healthy primary tier must spill to failover only"
    );

    let prior_probe = primary_one.probe_count();
    primary_one.set_healthy(true);
    primary_one.wait_for_probe_after(prior_probe);
    let recovered = wait_for_routing_phase(proxy.addr(), |seen| {
        seen.len() == 2 && seen.contains("pri-primary-1") && seen.contains("pri-primary-2")
    });
    assert_eq!(recovered.len(), 2, "recovered priority tier must use both primaries");
}
