// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the open file limit the proxy sets for itself at startup.
//!
//! Each test runs the real binary so the limit it reads and changes is the
//! child's, never the shared test process's.

use praxis_test_utils::{PraxisProcess, free_port, own_open_file_limits};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn max_open_files_sets_the_soft_limit() {
    let (_, hard) = own_open_file_limits();
    if !hard_limit_at_least(256) {
        return;
    }
    let port = free_port();
    let mut proxy = PraxisProcess::spawn(&config(port, "max_open_files: 256"), &addr(port));

    assert_eq!(
        proxy.open_file_limits(),
        (256, hard),
        "max_open_files must set the soft limit and leave the hard limit alone"
    );
    let logs = shut_down(&mut proxy);
    assert!(
        logs.contains("open file limit set") && logs.contains("current=256"),
        "startup must log the limit in effect:\n{logs}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn default_raises_soft_limit_to_hard() {
    let (_, hard) = own_open_file_limits();
    if !hard_limit_at_least(1_024) {
        return;
    }
    let port = free_port();
    let mut proxy = PraxisProcess::spawn_with_ulimit(&config(port, ""), &addr(port), Some("-S -n 512"));

    assert_eq!(
        proxy.open_file_limits(),
        (hard, hard),
        "an unset max_open_files must raise the soft limit to the hard limit"
    );
    let logs = shut_down(&mut proxy);
    assert!(
        logs.contains("previous=512") && logs.contains(&format!("current={hard}")),
        "startup must log the raise:\n{logs}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn max_open_files_above_hard_is_clamped() {
    if !hard_limit_at_least(1_024) {
        return;
    }
    let port = free_port();
    let mut proxy = PraxisProcess::spawn_with_ulimit(
        &config(port, "max_open_files: 4096"),
        &addr(port),
        Some("-S -n 256 && ulimit -H -n 1024"),
    );

    assert_eq!(
        proxy.open_file_limits(),
        (1_024, 1_024),
        "a request above the hard limit must be clamped to it"
    );
    let logs = shut_down(&mut proxy);
    assert!(
        logs.contains("runtime.max_open_files exceeds the hard limit; clamped"),
        "the clamp must be reported:\n{logs}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn container_default_limit_is_warned() {
    if !hard_limit_at_least(1_024) {
        return;
    }
    let port = free_port();
    let mut proxy =
        PraxisProcess::spawn_with_ulimit(&config(port, ""), &addr(port), Some("-S -n 1024 && ulimit -H -n 1024"));

    assert_eq!(
        proxy.open_file_limits(),
        (1_024, 1_024),
        "nothing to raise at 1024:1024"
    );
    let logs = shut_down(&mut proxy);
    assert!(
        logs.contains("open file limit is low for this configuration")
            && logs.contains("limit=1024")
            && logs.contains("recommended=4096"),
        "a 1024 descriptor limit must be called out at startup:\n{logs}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn connection_limit_raises_the_recommendation() {
    if !hard_limit_at_least(8_192) {
        return;
    }
    let port = free_port();
    let mut proxy = PraxisProcess::spawn_with_ulimit(
        &config(port, "max_connections: 5000"),
        &addr(port),
        Some("-S -n 1024 && ulimit -H -n 8192"),
    );

    assert_eq!(proxy.open_file_limits(), (8_192, 8_192), "raised to the hard limit");
    let logs = shut_down(&mut proxy);
    assert!(
        logs.contains("open file limit is low for this configuration") && logs.contains("recommended=10320"),
        "5000 connections need 2 descriptors each plus pools and baseline:\n{logs}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn ample_limit_is_not_warned() {
    if !hard_limit_at_least(8_192) {
        return;
    }
    let port = free_port();
    let mut proxy =
        PraxisProcess::spawn_with_ulimit(&config(port, ""), &addr(port), Some("-S -n 1024 && ulimit -H -n 8192"));

    let logs = shut_down(&mut proxy);
    assert!(
        logs.contains("current=8192") && !logs.contains("open file limit is low"),
        "8192 descriptors covers an unbounded default config without a warning:\n{logs}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Proxy config on `port` with `runtime_line` under `runtime:`.
fn config(port: u16, runtime_line: &str) -> String {
    format!(
        r#"
shutdown_timeout_secs: 1
runtime:
  threads: 1
  {runtime_line}
listeners:
  - name: web
    address: "127.0.0.1:{port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        body: "ok"
"#
    )
}

/// Loopback address for `port`.
fn addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// Whether this environment's hard limit allows the test to lower limits to
/// `needed`; prints why the test is skipped when it does not.
#[expect(clippy::print_stderr, reason = "explains a skipped test")]
fn hard_limit_at_least(needed: u64) -> bool {
    let (_, hard) = own_open_file_limits();
    if hard < needed {
        eprintln!("skipping: hard open file limit {hard} is below the {needed} this test needs");
    }
    hard >= needed
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
