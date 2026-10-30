// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the cluster references example configuration.

use std::time::Duration;

use praxis_core::config::{Cluster, Config};
use praxis_test_utils::{
    example_config_path, free_port, http_get, start_backend_with_shutdown, start_full_proxy, wait_for_http,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn cluster_references_example_routes_and_health_gates_filled_endpoints() {
    let stable = start_backend_with_shutdown("stable");
    let flaky = start_backend_with_shutdown("flaky");
    let stable_port = stable.port();
    let flaky_port = flaky.port();
    let proxy_port = free_port();

    let yaml = std::fs::read_to_string(example_config_path("traffic-management/cluster-references.yaml"))
        .expect("read example")
        .replace("127.0.0.1:8080", &format!("127.0.0.1:{proxy_port}"))
        .replace("127.0.0.1:9902", &format!("127.0.0.1:{}", free_port()))
        .replace("127.0.0.1:3001", &format!("127.0.0.1:{stable_port}"))
        .replace("127.0.0.1:3002", &format!("127.0.0.1:{flaky_port}"))
        .replace("interval_ms: 2000", "interval_ms: 200")
        .replace("timeout_ms: 1000", "timeout_ms: 100");
    let config = Config::from_yaml(&yaml).expect("cluster references example should validate");

    let load_balancer = config.filter_chains[0]
        .filters
        .iter()
        .find(|entry| entry.filter_type == "load_balancer")
        .expect("load_balancer filter");
    let clusters: Vec<Cluster> =
        serde_yaml::from_value(load_balancer.config.get("clusters").cloned().expect("clusters key"))
            .expect("inline clusters");
    assert_eq!(clusters.len(), 1, "one inline cluster");
    let filled: Vec<&str> = clusters[0].endpoints.iter().map(|ep| ep.address()).collect();
    assert_eq!(
        filled,
        vec![format!("127.0.0.1:{stable_port}"), format!("127.0.0.1:{flaky_port}")],
        "endpoints filled from the top-level declaration"
    );

    let _proxy = start_full_proxy(&config);
    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_http(&addr);

    let mut saw_stable = false;
    let mut saw_flaky = false;
    for _ in 0..20 {
        let (status, body) = http_get(&addr, "/", None);
        assert_eq!(status, 200, "request should succeed while both backends healthy");
        saw_stable |= body == "stable";
        saw_flaky |= body == "flaky";
        if saw_stable && saw_flaky {
            break;
        }
    }
    assert!(saw_stable, "traffic should reach the stable backend");
    assert!(
        saw_flaky,
        "traffic should reach the flaky backend through the filled endpoints"
    );

    drop(flaky);

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut consecutive_stable = 0;
    while std::time::Instant::now() < deadline {
        let (status, body) = http_get(&addr, "/", None);
        if status == 200 && body == "stable" {
            consecutive_stable += 1;
            if consecutive_stable >= 5 {
                break;
            }
        } else {
            consecutive_stable = 0;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        consecutive_stable >= 5,
        "health checks track the declaration, so traffic should converge on the stable backend \
         (got {consecutive_stable} consecutive)"
    );
}
