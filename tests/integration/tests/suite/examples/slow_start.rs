// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Slow start example: installing the pipeline seeds the baseline.

#[cfg(feature = "slow-start")]
use std::{collections::HashMap, sync::Arc};

#[cfg(feature = "slow-start")]
use praxis_test_utils::{
    free_port, http_get, http_send, parse_body, parse_header, parse_status, start_backend_with_shutdown, start_proxy,
    start_reloadable_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(feature = "slow-start")]
#[test]
fn slow_start_config_serves_the_baseline_endpoints() {
    let port_a_guard = start_backend_with_shutdown("a");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("b");
    let port_b = port_b_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/slow-start.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", port_a), ("127.0.0.1:3002", port_b)]),
    );
    let load_balancer = config
        .filter_chains
        .iter()
        .flat_map(|chain| chain.filters.iter())
        .find(|entry| entry.filter_type == "load_balancer")
        .expect("the example configures a load balancer");
    let slow_start = load_balancer
        .config
        .get("clusters")
        .and_then(|clusters| clusters.as_sequence())
        .and_then(|clusters| clusters.first())
        .and_then(|cluster| cluster.get("slow_start"))
        .expect("the example must set slow_start; deleting it must fail this test");
    assert_eq!(
        slow_start.get("window_ms").and_then(serde_yaml::Value::as_u64),
        Some(30_000),
        "the example window is 30 seconds"
    );

    let registry = Arc::new(praxis_filter::SlowStartRegistry::new());
    let filter = praxis_filter::LoadBalancerFilter::from_config(&load_balancer.config)
        .expect("the example load balancer parses");
    filter.bind_slow_start(&registry);
    assert!(
        registry.baseline_seeded("backend"),
        "installing the load balancer seeds the listed endpoints at full weight"
    );

    let proxy = start_proxy(&config);

    let mut seen: HashMap<String, u32> = HashMap::new();
    for _ in 0..4 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "slow start config should proxy the request");
        *seen.entry(body).or_default() += 1;
    }
    assert_eq!(seen.len(), 2, "baseline endpoints stay in rotation");
}

#[cfg(feature = "slow-start")]
#[test]
fn a_reloaded_endpoint_gets_no_requests_at_the_start_of_its_window() {
    let backend_a = start_backend_with_shutdown("a");
    let backend_b = start_backend_with_shutdown("b");
    let backend_c = start_backend_with_shutdown("c");
    let proxy_port = free_port();
    let yaml = slow_start_proxy_yaml(proxy_port, &[backend_a.port(), backend_b.port()], "one");
    let proxy = start_reloadable_proxy(&yaml);
    let reloaded = slow_start_proxy_yaml(
        proxy_port,
        &[backend_a.port(), backend_b.port(), backend_c.port()],
        "two",
    );
    let applied = proxy.reload_until(
        &reloaded,
        || {
            http_send(
                proxy.addr(),
                "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
        },
        |raw| parse_header(raw, "x-generation").as_deref() == Some("two"),
    );
    assert_eq!(
        parse_header(&applied, "x-generation").as_deref(),
        Some("two"),
        "the reload that adds the third endpoint is being served"
    );

    for _ in 0..12 {
        let raw = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(parse_status(&raw), 200, "the baseline endpoints still answer");
        assert_ne!(parse_body(&raw), "c", "a just-added endpoint stays out of rotation");
    }
}

/// Proxy config whose round robin ramps over an hour at low aggression.
#[cfg(feature = "slow-start")]
fn slow_start_proxy_yaml(proxy_port: u16, backend_ports: &[u16], generation: &str) -> String {
    let endpoints = backend_ports
        .iter()
        .map(|port| format!("              - \"127.0.0.1:{port}\""))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "\
listeners:
  - name: default
    address: \"127.0.0.1:{proxy_port}\"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: \"/\"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            load_balancer_strategy: round_robin
            slow_start:
              window_ms: 3600000
              aggression: 0.1
            endpoints:
{endpoints}
      - filter: headers
        response_set:
          - name: x-generation
            value: {generation}
insecure_options:
  allow_private_endpoints: true
"
    )
}
