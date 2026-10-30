// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the weighted route-target example config.

use std::{collections::HashMap, thread::sleep, time::Duration};

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_full_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn weighted_route_targets_split_and_fail_over() {
    let stable_guard = start_backend_with_shutdown("stable");
    let stable_port = stable_guard.port();
    let canary_guard = start_backend_with_shutdown("canary");
    let canary_port = canary_guard.port();
    let dr_a_guard = start_backend_with_shutdown("dr-a");
    let dr_a_port = dr_a_guard.port();
    let dr_b_guard = start_backend_with_shutdown("dr-b");
    let dr_b_port = dr_b_guard.port();

    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/weighted-clusters.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", stable_port),
            ("127.0.0.1:3002", canary_port),
            ("127.0.0.1:3003", dr_a_port),
            ("127.0.0.1:3004", dr_b_port),
        ]),
    );
    // `start_full_proxy` also spawns the active health-check tasks the
    // priority-tier fallback depends on.
    let proxy = start_full_proxy(&config);

    let total = 100_u32;
    let mut stable_count = 0_u32;
    let mut canary_count = 0_u32;
    for _ in 0..total {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "weighted request should return 200");
        match body.as_str() {
            "stable" => stable_count += 1,
            "canary" => canary_count += 1,
            "dr-a" | "dr-b" => panic!("the priority-1 fallback must not serve while priority 0 is healthy"),
            other => panic!("unexpected body: {other}"),
        }
    }

    assert_eq!(
        stable_count + canary_count,
        total,
        "every request should reach a priority-0 backend"
    );
    let ratio = f64::from(stable_count) / f64::from(canary_count.max(1));
    assert!(
        (8.0..=10.0).contains(&ratio),
        "expected a ~9:1 split over {total} requests, got {stable_count}:{canary_count} ({ratio})"
    );

    // Both priority-0 clusters lose every healthy endpoint, so the router must
    // spill to the priority-1 `dr-a`/`dr-b` tier.
    drop(stable_guard);
    drop(canary_guard);

    let mut fell_back = false;
    let mut last = String::new();
    for _ in 0..100 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        last = format!("{status} {body:?}");
        if status == 200 && (body == "dr-a" || body == "dr-b") {
            fell_back = true;
            break;
        }
        sleep(Duration::from_millis(100));
    }
    assert!(
        fell_back,
        "traffic should spill to the dr tier once both priority-0 clusters have no healthy endpoint (last: {last})"
    );

    let mut dr_a_count = 0_u32;
    let mut dr_b_count = 0_u32;
    for _ in 0..10 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "fallback request should return 200");
        match body.as_str() {
            "dr-a" => dr_a_count += 1,
            "dr-b" => dr_b_count += 1,
            other => panic!("all traffic should stay on the fallback tier, got {other}"),
        }
    }
    assert_eq!(
        (dr_a_count, dr_b_count),
        (5, 5),
        "the 1:1 fallback tier must rotate between its targets, not pin the first one"
    );
}
