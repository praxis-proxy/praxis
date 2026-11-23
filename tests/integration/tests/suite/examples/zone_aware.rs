// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the zone-aware load-balancing example config.

use std::collections::{HashMap, HashSet};

use praxis_test_utils::{
    free_port, http_send, parse_body, start_backend_with_shutdown, start_full_proxy, start_proxy, wait_for_http,
};

use super::routing_health::{TestHealthBackend, wait_for_routing_phase};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn zone_aware() {
    let port_a_guard = start_backend_with_shutdown("za-local-1");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("za-local-2");
    let port_b = port_b_guard.port();
    let port_c_guard = start_backend_with_shutdown("za-remote-1");
    let port_c = port_c_guard.port();
    let port_d_guard = start_backend_with_shutdown("za-remote-2");
    let port_d = port_d_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/zone-aware.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
            ("127.0.0.1:3004", port_d),
        ]),
    );
    let proxy = start_proxy(&config);

    // Without health issues, only local-zone endpoints should be used.
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
        backends_seen.contains("za-local-1") || backends_seen.contains("za-local-2"),
        "local-zone endpoints should receive traffic"
    );
    assert!(
        !backends_seen.contains("za-remote-1") && !backends_seen.contains("za-remote-2"),
        "remote-zone endpoints should not receive traffic when local is healthy"
    );
}

#[test]
fn zone_aware_spills_when_local_unhealthy() {
    let local_one = TestHealthBackend::start("za-local-1");
    let local_two = TestHealthBackend::start("za-local-2");
    let remote_one = TestHealthBackend::start("za-remote-1");
    let remote_two = TestHealthBackend::start("za-remote-2");
    let proxy_port = free_port();
    let mut config = super::load_example_config(
        "traffic-management/zone-aware.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", local_one.port()),
            ("127.0.0.1:3002", local_two.port()),
            ("127.0.0.1:3003", remote_one.port()),
            ("127.0.0.1:3004", remote_two.port()),
        ]),
    );
    let check = config.clusters[0]
        .health_check
        .as_mut()
        .expect("zone example health check");
    check.interval_ms = 200;
    check.timeout_ms = 100;

    let proxy = start_full_proxy(&config);
    wait_for_http(proxy.addr());
    for backend in [&local_one, &local_two, &remote_one, &remote_two] {
        backend.wait_for_probe_after(0);
    }

    let initial = wait_for_routing_phase(proxy.addr(), |seen| {
        seen.len() == 2 && seen.contains("za-local-1") && seen.contains("za-local-2")
    });
    assert_eq!(initial.len(), 2, "healthy zone must use both local endpoints");

    let prior_probe = local_one.probe_count();
    local_one.set_healthy(false);
    local_one.wait_for_probe_after(prior_probe);
    let degraded = wait_for_routing_phase(proxy.addr(), |seen| {
        !seen.contains("za-local-1")
            && seen.contains("za-local-2")
            && (seen.contains("za-remote-1") || seen.contains("za-remote-2"))
            && seen
                .iter()
                .all(|body| matches!(body.as_str(), "za-local-2" | "za-remote-1" | "za-remote-2"))
    });
    assert!(
        degraded.contains("za-remote-1") || degraded.contains("za-remote-2"),
        "one failed local probe must spill to another zone: {degraded:?}"
    );

    let prior_probe = local_one.probe_count();
    local_one.set_healthy(true);
    local_one.wait_for_probe_after(prior_probe);
    let recovered = wait_for_routing_phase(proxy.addr(), |seen| {
        seen.len() == 2 && seen.contains("za-local-1") && seen.contains("za-local-2")
    });
    assert_eq!(recovered.len(), 2, "recovered zone must use both local endpoints");
}
