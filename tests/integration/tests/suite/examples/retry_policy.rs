// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for retry-policy example configuration.

use std::{collections::HashMap, sync::atomic::Ordering};

use praxis_test_utils::{free_port, http_get, start_full_proxy, start_request_counting_backend, wait_for_tcp};

#[test]
fn retry_policy() {
    let (healthy_guard, deliveries) = start_request_counting_backend("healthy");
    let healthy_port = healthy_guard.port();
    let proxy_port = free_port();
    let dead_port = free_port();

    let config = example_config(proxy_port, dead_port, healthy_port);
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "retry should recover from dead backend");
    assert_eq!(body, "healthy", "response should come from healthy backend");
    assert_eq!(
        deliveries.load(Ordering::SeqCst),
        1,
        "one retry should reach the live backend"
    );

    drop(proxy);
    let control_port = free_port();
    let mut no_retry = example_config(control_port, dead_port, healthy_port);
    let load_balancer = no_retry.filter_chains[0]
        .filters
        .iter_mut()
        .find(|entry| entry.filter_type == "load_balancer")
        .expect("example load balancer");
    load_balancer.config["clusters"][0]["retry_policy"]["max_retries"] = serde_yaml::Value::from(0);
    let control = start_full_proxy(&no_retry);
    wait_for_tcp(control.addr());
    let (status, body) = http_get(control.addr(), "/", None);
    assert_eq!(
        status, 502,
        "dead first endpoint must return an upstream failure: {body}"
    );
    assert_eq!(
        deliveries.load(Ordering::SeqCst),
        1,
        "zero-retry control must not reach the live backend"
    );
}

fn example_config(proxy_port: u16, dead_port: u16, healthy_port: u16) -> praxis_core::config::Config {
    super::load_example_config(
        "traffic-management/retry-policy.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", dead_port), ("127.0.0.1:3002", healthy_port)]),
    )
}
