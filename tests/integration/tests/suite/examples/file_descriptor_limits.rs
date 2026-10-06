// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! File descriptor limits example tests.
//!
//! The open file limit belongs to the whole process, so these run the real
//! binary against the example config. Timeouts and the limit are shortened
//! where waiting out the example's production values would take minutes.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use praxis_test_utils::{
    PraxisProcess, allow_loopback_endpoints, concurrent_gets, example_config_path, free_port, http_get,
    idle_keepalive_connections, is_closed_by_peer, open_requests, own_open_file_limits, patch_yaml, read_raw_responses,
    start_keepalive_backend,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The example under test.
const EXAMPLE: &str = "operations/file-descriptor-limits.yaml";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn file_descriptor_limits_example_pins_the_limit_and_exports_usage() {
    let backend = start_keepalive_backend("ok", Duration::ZERO);
    let (port, admin) = (free_port(), free_port());
    let mut proxy = PraxisProcess::spawn(&example_yaml(port, admin, backend.port(), &[]), &addr(port));
    let (_, hard) = own_open_file_limits();
    let pinned = hard.min(65_536);

    assert_eq!(
        proxy.open_file_limits(),
        (pinned, hard),
        "max_open_files: 65536 pins the soft limit, clamped to the hard limit"
    );
    assert!(
        concurrent_gets(&addr(port), "/", 1, 1, false).only(&[200]),
        "the example proxies to its backend"
    );
    assert!(
        wait_for_scrape(admin, &format!("praxis_process_max_fds {pinned}")),
        "the limit is exported as a gauge"
    );
    let logs = shut_down(&mut proxy);
    assert!(
        hard < 65_536 || !logs.contains("open file limit is low"),
        "30000 connections fit a 65536 descriptor limit without a warning:\n{logs}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn file_descriptor_limits_example_closes_idle_connections() {
    let backend = start_keepalive_backend("ok", Duration::ZERO);
    let (port, admin) = (free_port(), free_port());
    let yaml = example_yaml(
        port,
        admin,
        backend.port(),
        &[
            (
                "downstream_keepalive_timeout_ms: 60000",
                "downstream_keepalive_timeout_ms: 1000",
            ),
            ("idle_timeout_ms: 30000", "idle_timeout_ms: 500"),
        ],
    );
    let proxy = PraxisProcess::spawn(&yaml, &addr(port));
    let before = proxy.open_fds();

    let idle = idle_keepalive_connections(&addr(port), "/", 20);
    let held = proxy.open_fds();
    let all_closed = wait_until(Duration::from_secs(5), || idle.iter().all(is_closed_by_peer));
    let settled = proxy.wait_open_fds_at_most(before + 4, Duration::from_secs(5));

    assert!(
        held >= before + 20,
        "20 idle clients hold descriptors: {held}, before {before}"
    );
    assert!(all_closed, "the keep-alive timeout closes every idle client");
    assert!(
        settled <= before + 4,
        "idle clients and pooled upstreams are released: {settled}, before {before}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn file_descriptor_limits_example_sheds_near_the_limit() {
    let backend = start_keepalive_backend("ok", Duration::from_millis(500));
    let (port, admin) = (free_port(), free_port());
    let yaml = example_yaml(
        port,
        admin,
        backend.port(),
        &[("max_open_files: 65536", "max_open_files: 192")],
    );
    let _proxy = PraxisProcess::spawn(&yaml, &addr(port));

    let responses = read_raw_responses(open_requests(&addr(port), "/", 70));
    let status_of = |raw: &str| raw.split_whitespace().nth(1).map(str::to_owned);
    let ok = responses
        .iter()
        .filter(|(raw, _)| status_of(raw).as_deref() == Some("200"))
        .count();
    let shed: Vec<&String> = responses
        .iter()
        .map(|(raw, _)| raw)
        .filter(|raw| status_of(raw).as_deref() == Some("503"))
        .collect();

    assert_eq!(ok + shed.len(), 70, "every request gets a 200 or a 503: {responses:?}");
    assert!(ok > 0, "requests within the limit are served");
    assert!(!shed.is_empty(), "70 in-flight requests exceed a 192 descriptor limit");
    assert!(
        shed.iter()
            .all(|raw| raw.to_ascii_lowercase().contains("retry-after: 1")),
        "shed responses tell clients when to retry"
    );
    let (_, metrics) = http_get(&addr(admin), "/metrics", None);
    assert!(
        metrics.contains("praxis_overload_rejects_total{reason=\"file_descriptors\"}"),
        "sheds are counted:\n{metrics}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The example config on test ports with `replacements` applied and a short
/// shutdown grace period, so stopping it does not wait out the default.
fn example_yaml(port: u16, admin: u16, backend: u16, replacements: &[(&str, &str)]) -> String {
    let yaml = std::fs::read_to_string(example_config_path(EXAMPLE)).expect("read example");
    let ports = HashMap::from([("127.0.0.1:9902", admin), ("127.0.0.1:3000", backend)]);
    let mut patched = allow_loopback_endpoints(&patch_yaml(&yaml, port, &ports));
    for (from, to) in replacements {
        assert!(patched.contains(from), "the example must contain {from:?}");
        patched = patched.replacen(from, to, 1);
    }
    format!("shutdown_timeout_secs: 1\n{patched}")
}

/// Loopback address for `port`.
fn addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
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

/// Scrape `/metrics` on `admin` until it contains `needle`.
fn wait_for_scrape(admin: u16, needle: &str) -> bool {
    wait_until(Duration::from_secs(5), || {
        http_get(&addr(admin), "/metrics", None).1.contains(needle)
    })
}

/// Gracefully stop `proxy`, assert a clean exit, and return its logs.
fn shut_down(proxy: &mut PraxisProcess) -> String {
    let status = proxy.terminate();
    let logs = proxy.logs();
    assert!(
        status.success(),
        "graceful shutdown should exit zero ({status}):\n{logs}"
    );
    logs
}
