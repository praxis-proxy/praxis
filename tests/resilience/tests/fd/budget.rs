// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Descriptor budget tests: the proxy's real open descriptor count under
//! load.
//!
//! Each test runs the real binary and samples `/proc/<pid>/fd`, so the counts
//! are the child's alone. Budgets allow [`MARGIN`] for descriptors the runtime
//! opens and closes on its own (timers, DNS, logging, admin scrapes).

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_test_utils::{
    Backend, PraxisProcess, collect_responses, concurrent_gets, free_port, http_get, idle_keepalive_connections,
    is_closed_by_peer, open_requests, own_open_file_limits, start_keepalive_backend,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Slack for descriptors the runtime opens and closes on its own.
const MARGIN: usize = 32;

/// Interval between descriptor samples while load runs.
const SAMPLE_EVERY: Duration = Duration::from_millis(20);

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn baseline_descriptors_are_small() {
    let _serial = crate::serial();
    let backend = start_keepalive_backend("ok", Duration::ZERO);
    let proxy = Proxy::start(&Setup::new(format!("127.0.0.1:{}", backend.port())));

    assert!(
        proxy.baseline <= 64,
        "an idle proxy with one listener and the metrics endpoint holds {} descriptors",
        proxy.baseline
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn keepalive_load_stays_within_two_descriptors_per_client() {
    let _serial = crate::serial();
    let backend = start_keepalive_backend("ok", Duration::from_millis(50));
    let proxy = Proxy::start(&Setup::new(format!("127.0.0.1:{}", backend.port())));

    let (peak, report) = proxy
        .process
        .peak_open_fds_during(SAMPLE_EVERY, || concurrent_gets(&proxy.addr, "/", 128, 10, true));

    assert!(
        report.only(&[200]) && report.total() == 1_280,
        "every request must succeed: {report:?}"
    );
    assert!(
        peak <= proxy.baseline + 2 * 128 + MARGIN,
        "128 keep-alive clients need a client and an upstream descriptor each: peak {peak}, baseline {}",
        proxy.baseline
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn idle_timeouts_release_idle_client_and_pooled_descriptors() {
    let _serial = crate::serial();
    let backend = start_keepalive_backend("ok", Duration::ZERO);
    let setup = Setup {
        listener_lines: "downstream_keepalive_timeout_ms: 1000",
        cluster_lines: "idle_timeout_ms: 500",
        ..Setup::new(format!("127.0.0.1:{}", backend.port()))
    };
    let proxy = Proxy::start(&setup);

    let idle = idle_keepalive_connections(&proxy.addr, "/", 100);
    let held = proxy.process.open_fds();
    let all_closed = wait_until(Duration::from_secs(8), || idle.iter().all(is_closed_by_peer));
    let settled = proxy
        .process
        .wait_open_fds_at_most(proxy.baseline + 8, Duration::from_secs(5));

    assert!(
        held >= proxy.baseline + 95,
        "100 idle keep-alive clients hold their descriptors at first: {held}, baseline {}",
        proxy.baseline
    );
    assert!(all_closed, "the proxy must close each idle client connection");
    assert!(
        settled <= proxy.baseline + 8,
        "idle timeouts must hand every descriptor back: {settled}, baseline {}",
        proxy.baseline
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn without_timeouts_idle_clients_keep_their_descriptors() {
    let _serial = crate::serial();
    let backend = start_keepalive_backend("ok", Duration::ZERO);
    let proxy = Proxy::start(&Setup::new(format!("127.0.0.1:{}", backend.port())));

    let idle = idle_keepalive_connections(&proxy.addr, "/", 100);
    std::thread::sleep(Duration::from_secs(3));
    let open = proxy.process.open_fds();

    assert!(
        open >= proxy.baseline + 95 && open <= proxy.baseline + 100 + MARGIN,
        "by default each idle keep-alive client pins one descriptor: {open}, baseline {}",
        proxy.baseline
    );
    assert!(
        !idle.iter().any(is_closed_by_peer),
        "no idle client may be closed without a keep-alive timeout"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn the_upstream_pool_keeps_at_most_its_size_per_thread() {
    let _serial = crate::serial();
    let backend = start_keepalive_backend("ok", Duration::from_millis(300));
    let proxy = Proxy::start(&Setup::new(format!("127.0.0.1:{}", backend.port())));

    let report = collect_responses(open_requests(&proxy.addr, "/", 128));
    std::thread::sleep(Duration::from_secs(1));
    let pooled = proxy.process.open_fds().saturating_sub(proxy.baseline);

    assert!(report.only(&[200]), "every request must succeed: {report:?}");
    assert!(
        (32..=64 + 8).contains(&pooled),
        "128 concurrent upstreams must leave at most the 64-per-thread pool open: {pooled} above baseline"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn streaming_responses_hold_two_descriptors_each() {
    let _serial = crate::serial();
    let backend = Backend::chunked(vec!["data: tick\n\n".to_owned(); 40])
        .chunk_delay(Duration::from_millis(50))
        .start_with_shutdown();
    let proxy = Proxy::start(&Setup::new(format!("127.0.0.1:{}", backend.port())));

    let (peak, report) = proxy
        .process
        .peak_open_fds_during(SAMPLE_EVERY, || collect_responses(open_requests(&proxy.addr, "/", 128)));
    let settled = proxy
        .process
        .wait_open_fds_at_most(proxy.baseline + 8, Duration::from_secs(5));

    assert!(
        report.only(&[200]) && report.total() == 128,
        "every stream must complete: {report:?}"
    );
    assert!(
        peak <= proxy.baseline + 2 * 128 + MARGIN,
        "128 two-second streams need a client and an upstream descriptor each: peak {peak}, baseline {}",
        proxy.baseline
    );
    assert!(
        settled <= proxy.baseline + 8,
        "finished streams must release their descriptors: {settled}, baseline {}",
        proxy.baseline
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn the_global_connection_limit_bounds_descriptors() {
    let _serial = crate::serial();
    let backend = start_keepalive_backend("ok", Duration::from_millis(500));
    let setup = Setup {
        runtime_lines: "max_connections: 64",
        ..Setup::new(format!("127.0.0.1:{}", backend.port()))
    };
    let proxy = Proxy::start(&setup);

    let (peak, report) = proxy
        .process
        .peak_open_fds_during(SAMPLE_EVERY, || collect_responses(open_requests(&proxy.addr, "/", 128)));

    assert!(report.only(&[200, 503]), "requests past the limit get 503: {report:?}");
    assert!(
        report.count(200) >= 32 && report.count(503) >= 32,
        "about half of 128 requests fit a limit of 64: {report:?}"
    );
    assert!(
        peak <= proxy.baseline + 128 + 64 + MARGIN,
        "only admitted requests open upstreams: peak {peak}, baseline {}",
        proxy.baseline
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn issue_1288_the_container_default_limit_no_longer_caps_concurrency() {
    let _serial = crate::serial();
    let (_, hard) = own_open_file_limits();
    if hard < 4_096 {
        eprintln!("skipping: hard open file limit {hard} is below the 4096 this test needs");
        return;
    }
    let backend = start_keepalive_backend("ok", Duration::from_secs(1));
    let setup = Setup {
        ulimit: Some("-S -n 1024"),
        ..Setup::new(format!("127.0.0.1:{}", backend.port()))
    };
    let mut proxy = Proxy::start(&setup);

    let report = collect_responses(open_requests(&proxy.addr, "/", 512));

    assert_eq!(
        proxy.process.open_file_limits(),
        (hard, hard),
        "the 1024 soft limit containers start with must be raised"
    );
    assert!(
        report.only(&[200]) && report.total() == 512,
        "512 in-flight requests need about 1060 descriptors and must all succeed: {report:?}"
    );
    crate::assert_no_emfile(&proxy.shut_down());
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn issue_1288_at_the_limit_requests_are_shed_not_failed() {
    let _serial = crate::serial();
    let backend = Backend::chunked(vec!["data: tick\n\n".to_owned(); 10])
        .chunk_delay(Duration::from_millis(50))
        .start_with_shutdown();
    let setup = Setup {
        runtime_lines: "max_open_files: 512",
        ..Setup::new(format!("localhost:{}", backend.port()))
    };
    let mut proxy = Proxy::start(&setup);

    let report = proxy
        .process
        .peak_open_fds_during(SAMPLE_EVERY, || concurrent_gets(&proxy.addr, "/", 300, 3, true))
        .1;

    assert!(
        report.only(&[200, 503]),
        "past the limit requests must be shed with a retryable 503, never fail: {report:?}"
    );
    assert!(
        report.count(503) > 0,
        "300 streaming clients must exceed 512 descriptors: {report:?}"
    );
    assert!(
        report.count(200) > 0,
        "requests within the limit must succeed: {report:?}"
    );
    assert!(proxy.overload_rejects() > 0, "sheds must be counted");
    assert!(
        proxy.eventually_serves(Duration::from_secs(5)),
        "the proxy must serve again once the load drains"
    );
    crate::assert_no_emfile(&proxy.shut_down());
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn issue_1288_reported_shape_runs_within_budget() {
    let _serial = crate::serial();
    let backend = Backend::chunked(vec!["data: token\n\n".to_owned(); 5])
        .chunk_delay(Duration::from_millis(20))
        .start_with_shutdown();
    let setup = Setup {
        runtime_lines: "max_open_files: 1024",
        listener_lines: "downstream_keepalive_timeout_ms: 5000",
        cluster_lines: "idle_timeout_ms: 5000",
        ..Setup::new(format!("localhost:{}", backend.port()))
    };
    let mut proxy = Proxy::start(&setup);

    let (peak, report) = proxy
        .process
        .peak_open_fds_during(SAMPLE_EVERY, || concurrent_gets(&proxy.addr, "/", 128, 25, true));
    let settled = proxy
        .process
        .wait_open_fds_at_most(proxy.baseline + 16, Duration::from_secs(10));

    assert!(
        report.only(&[200]) && report.total() == 3_200,
        "128 concurrent streaming clients fit a 1024 limit without a single failure or shed: {report:?}"
    );
    assert!(
        peak <= proxy.baseline + 2 * 128 + MARGIN,
        "each client costs a client and an upstream descriptor: peak {peak}, baseline {}",
        proxy.baseline
    );
    assert_eq!(proxy.overload_rejects(), 0, "nothing may be shed within the budget");
    assert!(
        settled <= proxy.baseline + 16,
        "descriptors must return to baseline once the clients leave: {settled}, baseline {}",
        proxy.baseline
    );
    crate::assert_no_emfile(&proxy.shut_down());
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Proxy configuration under test.
struct Setup<'cfg> {
    /// Upstream endpoint (`host:port`).
    endpoint: String,

    /// Extra lines under the cluster.
    cluster_lines: &'cfg str,

    /// Extra lines under the listener.
    listener_lines: &'cfg str,

    /// Extra lines under `runtime:`.
    runtime_lines: &'cfg str,

    /// Shell `ulimit` arguments applied before the proxy starts.
    ulimit: Option<&'cfg str>,
}

impl Setup<'_> {
    /// Defaults: one worker thread, nothing extra.
    fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            cluster_lines: "",
            listener_lines: "",
            runtime_lines: "",
            ulimit: None,
        }
    }
}

/// A running proxy and its descriptor baseline.
struct Proxy {
    /// Proxy listener address.
    addr: String,

    /// Admin address.
    admin: String,

    /// Open descriptors after startup and one proxied request.
    baseline: usize,

    /// The child process.
    process: PraxisProcess,
}

impl Proxy {
    /// Start the proxy for `setup`, send one request, and record the
    /// baseline.
    fn start(setup: &Setup<'_>) -> Self {
        let (port, admin_port) = (free_port(), free_port());
        let addr = format!("127.0.0.1:{port}");
        let process = PraxisProcess::spawn_with_ulimit(&config(port, admin_port, setup), &addr, setup.ulimit);
        let warm = concurrent_gets(&addr, "/", 1, 1, false);
        assert!(warm.only(&[200]), "warm-up request: {warm:?}\n{}", process.logs());
        std::thread::sleep(Duration::from_millis(300));
        let baseline = process.open_fds();
        Self {
            addr,
            admin: format!("127.0.0.1:{admin_port}"),
            baseline,
            process,
        }
    }

    /// Poll `GET /` until it returns 200.
    fn eventually_serves(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if raw_status(&self.addr) == Some(200) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// `praxis_overload_rejects_total{reason="file_descriptors"}`.
    fn overload_rejects(&self) -> u64 {
        let (_, body) = http_get(&self.admin, "/metrics", None);
        body.lines()
            .find_map(|line| line.strip_prefix("praxis_overload_rejects_total{reason=\"file_descriptors\"} "))
            .and_then(|value| value.trim().parse::<f64>().ok())
            .map_or(0, |value| value as u64)
    }

    /// Gracefully stop the proxy, assert a clean exit, and return its logs.
    fn shut_down(&mut self) -> String {
        let status = self.process.terminate();
        let logs = self.process.logs();
        assert!(
            status.success(),
            "graceful shutdown should exit zero ({status}):\n{logs}"
        );
        logs
    }
}

/// Proxy config for `setup` on `port`, admin on `admin`.
fn config(port: u16, admin: u16, setup: &Setup<'_>) -> String {
    format!(
        r#"
shutdown_timeout_secs: 1
admin:
  metrics_address: "127.0.0.1:{admin}"
runtime:
  threads: 1
  {runtime}
listeners:
  - name: web
    address: "127.0.0.1:{port}"
    filter_chains: [main]
    {listener}
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "{endpoint}"
            {cluster}
insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true
"#,
        runtime = setup.runtime_lines,
        listener = setup.listener_lines,
        endpoint = setup.endpoint,
        cluster = setup.cluster_lines,
    )
}

/// Status of one `GET /` on a fresh connection, or `None` on failure.
fn raw_status(addr: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut raw = String::new();
    let _read = stream.read_to_string(&mut raw);
    raw.split_whitespace().nth(1)?.parse().ok()
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
