// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Overload gauge example: the sampler publishes pressure, and admitted
//! connections move the connections series.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use praxis_test_utils::{
    PraxisProcess, allow_loopback_endpoints, example_config_path, free_port, http_get, open_requests, patch_yaml,
    start_slow_backend,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The example under test.
const EXAMPLE: &str = "observability/overload-gauges.yaml";

/// Cap patched into the example so a handful of in-flight requests can cross
/// the connections scaling band (70%).
const TIGHT_CAP: &str = "max_connections: 4";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn overload_gauges_example_connection_pressure_rises() {
    let backend = start_slow_backend("ok", Duration::from_secs(8));
    let (port, admin) = (free_port(), free_port());
    let yaml = example_yaml(port, admin, backend);
    let proxy = PraxisProcess::spawn(&yaml, &addr(port));
    let admin_addr = addr(admin);

    let initial = wait_for_pressure(&admin_addr, "connections", Duration::from_secs(5));
    assert!(
        initial < 0.01,
        "an idle proxy should publish connection pressure near 0, saw {initial}; scrape:\n{}",
        scrape(&admin_addr)
    );

    let _in_flight = open_requests(&addr(port), "/", 4);
    let risen = wait_until(Duration::from_secs(8), || {
        pressure(&scrape(&admin_addr), "connections").is_some_and(|value| value > initial)
    });
    let after = scrape(&admin_addr);
    assert!(
        risen,
        "admitted connections should raise connection pressure above {initial}:\n{after}\n{}",
        proxy.logs()
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The example on test ports, with a connection cap small enough to saturate.
fn example_yaml(port: u16, admin: u16, backend: u16) -> String {
    let yaml = std::fs::read_to_string(example_config_path(EXAMPLE)).expect("read example");
    assert!(
        yaml.contains("overload_gauges: true"),
        "the example must enable overload gauges"
    );
    assert!(
        yaml.contains("max_connections: 1000"),
        "the example must set the connection cap the test tightens"
    );
    let ports = HashMap::from([("127.0.0.1:9902", admin), ("127.0.0.1:3000", backend)]);
    let patched = allow_loopback_endpoints(&patch_yaml(&yaml, port, &ports));
    format!(
        "shutdown_timeout_secs: 1\n{}",
        patched.replacen("max_connections: 1000", TIGHT_CAP, 1)
    )
}

/// Loopback address for `port`.
fn addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// Latest `/metrics` body.
fn scrape(admin: &str) -> String {
    http_get(admin, "/metrics", None).1
}

/// `praxis_overload_pressure` for `resource`, when that series is present.
fn pressure(body: &str, resource: &str) -> Option<f64> {
    let label = format!("resource=\"{resource}\"");
    body.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') || !line.starts_with("praxis_overload_pressure") || !line.contains(&label) {
            return None;
        }
        line.split_whitespace().next_back()?.parse().ok()
    })
}

/// Poll until the connections gauge exists and return its value.
fn wait_for_pressure(admin: &str, resource: &str, timeout: Duration) -> f64 {
    let deadline = Instant::now() + timeout;
    let mut last = String::new();
    while Instant::now() < deadline {
        last = scrape(admin);
        if let Some(value) = pressure(&last, resource) {
            return value;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("`{resource}` pressure was not published within {timeout:?}:\n{last}");
}

/// Poll `done` every 50 ms until it holds or `timeout` passes.
fn wait_until<F: Fn() -> bool>(timeout: Duration, done: F) -> bool {
    let deadline = Instant::now() + timeout;
    while !done() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}
