// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Process logging example tests.

use std::{
    fs, io,
    net::TcpStream,
    process::{Command, Stdio},
};

use praxis_test_utils::{example_config_path, free_port, patch_yaml, praxis_bin, wait_for_tcp};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn stop_child(mut child: std::process::Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status()
            .expect("send SIGTERM");
        let status = child.wait().expect("wait");
        assert!(status.success(), "graceful shutdown should exit zero");
    }
    #[cfg(not(unix))]
    {
        child.kill().expect("kill child");
        let _ = child.wait().expect("wait");
    }
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
fn process_logging_writes_to_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("praxis-process.log");
    let port = free_port();
    let yaml = fs::read_to_string(example_config_path("observability/process-logging.yaml")).expect("read example");
    let yaml = yaml.replace("/tmp/praxis-process.log", &log_path.display().to_string());
    let yaml = patch_yaml(&yaml, port, &std::collections::HashMap::new());
    // Keep the graceful-shutdown drain short so the SIGTERM in stop_child()
    // returns promptly instead of blocking on the default 30s timeout.
    let yaml = format!("{yaml}\nshutdown_timeout_secs: 1\n");

    let config_path = dir.path().join("praxis.yaml");
    fs::write(&config_path, &yaml).expect("write config");

    let child = Command::new(praxis_bin())
        .arg("-c")
        .arg(&config_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn praxis");

    wait_for_tcp(&format!("127.0.0.1:{port}"));

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    io::Write::write_all(
        &mut stream,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .expect("write request");
    let mut buf = Vec::new();
    let _read = io::Read::read_to_end(&mut stream, &mut buf);
    assert!(String::from_utf8_lossy(&buf).contains("200"));

    stop_child(child);

    let active = fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        active.contains("INFO"),
        "example config should write process logs to disk"
    );
}
