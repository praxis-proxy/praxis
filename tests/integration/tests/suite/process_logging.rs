// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for `runtime.logging` file output.

use std::{
    fs, io,
    net::TcpStream,
    process::{Command, Stdio},
};

use praxis_test_utils::{free_port, praxis_bin, wait_for_tcp};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn terminate_gracefully(mut child: std::process::Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status()
            .expect("send SIGTERM");
        let status = child.wait().expect("wait child");
        assert!(status.success(), "graceful shutdown should exit zero");
    }
    #[cfg(not(unix))]
    {
        child.kill().expect("kill child");
        let _ = child.wait().expect("wait child");
    }
}

fn ping_proxy(port: u16) {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    io::Write::write_all(
        &mut stream,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .expect("write request");
    let mut buf = Vec::new();
    let _read = io::Read::read_to_end(&mut stream, &mut buf);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
// Spawns the `praxis` binary and waits for it to exit. Under cargo-llvm-cov the
// spawned binary is instrumented and can deadlock on exit (coverage flush) on
// constrained runners, hanging child.wait(). The logging paths are covered by
// unit and schema tests, so skip this end-to-end spawn test under coverage; it
// still runs in `make test`.
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn process_log_non_blocking_flushes_on_shutdown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("proxy.log");
    let port = free_port();
    let config = format!(
        r#"
runtime:
  logging:
    output: file
    file_path: {{log}}
    non_blocking: true
    buffer_size: 128

shutdown_timeout_secs: 1

listeners:
  - name: web
    address: "127.0.0.1:{{port}}"
    filter_chains: [main]

filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        body: "ok"
"#
    )
    .replace("{log}", &log_path.display().to_string());

    let config_path = dir.path().join("praxis.yaml");
    fs::write(&config_path, config.replace("{port}", &port.to_string())).expect("write config");
    let child = Command::new(praxis_bin())
        .arg("-c")
        .arg(&config_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn praxis");
    wait_for_tcp(&format!("127.0.0.1:{port}"));
    ping_proxy(port);
    terminate_gracefully(child);

    let active = fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        active.contains("INFO"),
        "non-blocking logs should flush to disk on graceful shutdown: {active:?}"
    );
}
