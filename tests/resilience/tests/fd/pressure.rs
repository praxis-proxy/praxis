// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for shedding load before open file descriptors run out.
//!
//! Each test runs the real binary with a small `max_open_files` so the
//! descriptor table it fills is the child's, never the shared test
//! process's.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_test_utils::{
    PraxisProcess, collect_responses, concurrent_gets, free_port, http_get, open_requests, read_raw_responses,
    start_slow_backend, start_tcp_echo_backend,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn a_burst_near_the_limit_is_shed_with_503_not_failed() {
    let _serial = crate::serial();
    let backend = start_slow_backend("slow", Duration::from_millis(500));
    let (port, admin) = (free_port(), free_port());
    let mut proxy = PraxisProcess::spawn(&http_config(port, admin, backend, "max_open_files: 256"), &addr(port));

    let report = collect_responses(open_requests(&addr(port), "/", 150));

    assert!(
        report.only(&[200, 503]),
        "every request must get a 200 or a retryable 503, never a failure: {report:?}"
    );
    assert!(
        report.count(503) > 0,
        "150 in-flight requests must exceed 256 descriptors: {report:?}"
    );
    // How many are admitted depends on how many client sockets the accept loop
    // has taken, and how fresh the descriptor sample is, at each admission, so
    // it varies with scheduling. The admission arithmetic is pinned exactly by
    // `fd::tests::a_burst_is_shed_before_the_next_sample`; here it is enough
    // that shedding is partial and that the proxy recovers (checked below).
    assert!(
        report.count(200) > 0,
        "requests within the limit must still succeed: {report:?}"
    );
    assert!(
        overload_rejects(admin) > 0,
        "sheds must be counted as file_descriptors overload rejects"
    );
    assert_eq!(
        wait_for_status(&addr(port), 200, Duration::from_secs(5)),
        200,
        "the proxy must serve again once the burst drains"
    );
    let logs = shut_down(&mut proxy);
    crate::assert_no_emfile(&logs);
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn shed_responses_carry_retry_after_and_close() {
    let _serial = crate::serial();
    let backend = start_slow_backend("slow", Duration::from_millis(500));
    let (port, admin) = (free_port(), free_port());
    let proxy = PraxisProcess::spawn(&http_config(port, admin, backend, "max_open_files: 256"), &addr(port));

    let responses = read_raw_responses(open_requests(&addr(port), "/", 150));
    let shed: Vec<&(String, bool)> = responses
        .iter()
        .filter(|(raw, _)| raw.starts_with("HTTP/1.1 503"))
        .collect();

    assert!(
        !shed.is_empty(),
        "a burst past the limit must be shed:\n{}",
        proxy.logs()
    );
    for (raw, closed) in shed {
        assert!(
            raw.to_ascii_lowercase().contains("retry-after: 1"),
            "a shed response must tell the client when to retry: {raw:?}"
        );
        assert!(
            closed,
            "a shed request must close its connection to free the descriptor: {raw:?}"
        );
    }
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn disabling_shedding_lets_requests_fail_at_the_limit() {
    let _serial = crate::serial();
    let backend = start_slow_backend("slow", Duration::from_millis(500));
    let (port, admin) = (free_port(), free_port());
    let _proxy = PraxisProcess::spawn(
        &http_config(
            port,
            admin,
            backend,
            "max_open_files: 256\n  shed_on_fd_pressure: false",
        ),
        &addr(port),
    );

    let report = collect_responses(open_requests(&addr(port), "/", 150));

    assert_eq!(
        report.count(503),
        0,
        "nothing may be shed with shedding disabled: {report:?}"
    );
    assert!(
        report.count(502) + report.failures.len() > 0,
        "without shedding, 150 in-flight requests must run out of descriptors: {report:?}"
    );
    assert_eq!(overload_rejects(admin), 0, "no file_descriptors rejects when disabled");
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn tcp_listener_closes_new_connections_near_the_limit() {
    let _serial = crate::serial();
    let echo = start_tcp_echo_backend();
    let (port, admin) = (free_port(), free_port());
    let mut proxy = PraxisProcess::spawn(&tcp_config(port, admin, echo), &addr(port));

    let sessions: Vec<Option<TcpStream>> = std::iter::repeat_with(|| echo_session(&addr(port))).take(120).collect();
    let served = sessions.iter().flatten().count();

    assert!(
        served >= 40,
        "sessions within the limit must be proxied: {served} of 120\n{}",
        proxy.logs()
    );
    assert!(served < 120, "sessions past the limit must be closed: all 120 served");
    assert!(
        overload_rejects(admin) > 0,
        "TCP sheds must be counted ({served} of 120 served):\n{}",
        proxy.logs()
    );
    drop(sessions);
    assert!(
        wait_for_echo(&addr(port), Duration::from_secs(5)),
        "new sessions must be proxied once the held ones close"
    );
    let logs = shut_down(&mut proxy);
    crate::assert_no_emfile(&logs);
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn descriptor_usage_is_exported() {
    let _serial = crate::serial();
    let backend = start_slow_backend("ok", Duration::ZERO);
    let (port, admin) = (free_port(), free_port());
    let proxy = PraxisProcess::spawn(&http_config(port, admin, backend, "max_open_files: 512"), &addr(port));

    let actual = u64::try_from(proxy.open_fds()).expect("fd count fits u64");
    let metrics = wait_for_metric(admin, "praxis_process_open_fds", |open| open.abs_diff(actual) <= 16);
    assert!(
        metrics.contains("praxis_process_max_fds 512"),
        "the limit gauge must match max_open_files:\n{metrics}"
    );

    let (status, body) = http_get(&addr(admin), "/api/stats", None);
    assert_eq!(status, 200, "stats endpoint: {body}");
    let stats: serde_json::Value = serde_json::from_str(&body).expect("stats JSON");
    assert_eq!(stats["file_descriptors"]["limit"], 512, "stats limit: {body}");
    assert!(
        stats["file_descriptors"]["open"]
            .as_u64()
            .is_some_and(|count| count >= 10),
        "stats open count: {body}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// HTTP proxy on `port` routing to `backend`, admin on `admin`, with
/// `runtime_lines` under `runtime:`.
fn http_config(port: u16, admin: u16, backend: u16, runtime_lines: &str) -> String {
    format!(
        r#"
shutdown_timeout_secs: 1
admin:
  metrics_address: "127.0.0.1:{admin}"
runtime:
  threads: 1
  {runtime_lines}
listeners:
  - name: web
    address: "127.0.0.1:{port}"
    filter_chains: [main]
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
              - "127.0.0.1:{backend}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// TCP proxy on `port` forwarding to `upstream`, admin on `admin`, with
/// `max_open_files: 256`.
fn tcp_config(port: u16, admin: u16, upstream: u16) -> String {
    format!(
        r#"
shutdown_timeout_secs: 1
admin:
  metrics_address: "127.0.0.1:{admin}"
runtime:
  threads: 1
  max_open_files: 256
listeners:
  - name: tcp
    address: "127.0.0.1:{port}"
    protocol: tcp
    upstream: "127.0.0.1:{upstream}"
filter_chains: []
insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true
"#
    )
}

/// Loopback address for `port`.
fn addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// Open a TCP session and prove it is proxied with an echo round trip,
/// returning the open stream, or `None` when the proxy closed it.
fn echo_session(addr: &str) -> Option<TcpStream> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream.write_all(b"ping").ok()?;
    let mut buf = [0_u8; 4];
    stream.read_exact(&mut buf).ok()?;
    (&buf == b"ping").then_some(stream)
}

/// Poll until a new TCP session echoes, or `timeout` passes.
fn wait_for_echo(addr: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if echo_session(addr).is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Poll `GET /` until it returns `want`, returning the last status seen.
fn wait_for_status(addr: &str, want: u16, timeout: Duration) -> u16 {
    let deadline = Instant::now() + timeout;
    loop {
        let report = concurrent_gets(addr, "/", 1, 1, false);
        let status = report.statuses.keys().next().copied().unwrap_or(0);
        if status == want || Instant::now() >= deadline {
            return status;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Scrape `/metrics` until sample `name` satisfies `accept`, since the gauge
/// is published by a periodic sampler.
fn wait_for_metric<F: Fn(u64) -> bool>(admin: u16, name: &str, accept: F) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (_, body) = http_get(&addr(admin), "/metrics", None);
        if metric_value(&body, name).is_some_and(&accept) {
            return body;
        }
        assert!(
            Instant::now() < deadline,
            "{name} never reached the expected value in /metrics:\n{body}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Value of the unlabeled sample `name` in a Prometheus scrape.
fn metric_value(body: &str, name: &str) -> Option<u64> {
    body.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
        .and_then(|value| value.trim().parse::<f64>().ok())
        .and_then(|value| format!("{value:.0}").parse().ok())
}

/// `praxis_overload_rejects_total{reason="file_descriptors"}` on `admin`.
fn overload_rejects(admin: u16) -> u64 {
    let (_, body) = http_get(&addr(admin), "/metrics", None);
    metric_value(&body, "praxis_overload_rejects_total{reason=\"file_descriptors\"}").unwrap_or(0)
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
