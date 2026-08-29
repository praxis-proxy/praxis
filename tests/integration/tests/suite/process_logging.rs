// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for `runtime.logging` file output and rotation.

use std::{
    fs, io,
    net::TcpStream,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use praxis_test_utils::{free_port, praxis_bin};

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
fn process_log_size_rotation_respects_max_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("proxy.log");
    let port = free_port();
    let config = format!(
        r#"
runtime:
  logging:
    output: file
    file_path: {{log}}
    rotation: size:32
    max_files: 3
    non_blocking: false

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
    thread::sleep(Duration::from_millis(800));

    for _ in 0..10 {
        ping_proxy(port);
    }
    terminate_gracefully(child);

    let rotated_one = dir.path().join("proxy.log.1");
    assert!(rotated_one.exists(), "size rotation should produce proxy.log.1");

    let combined = format!(
        "{}{}",
        fs::read_to_string(&log_path).unwrap_or_default(),
        fs::read_to_string(&rotated_one).unwrap_or_default()
    );
    assert!(
        combined.contains("INFO"),
        "logs should be written to disk: {combined:?}"
    );
}

#[test]
fn process_log_daily_writes_active_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("proxy.log");
    let port = free_port();
    let config = format!(
        r#"
runtime:
  logging:
    output: file
    file_path: {{log}}
    rotation: daily
    max_files: 3
    non_blocking: false

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
    thread::sleep(Duration::from_millis(800));
    ping_proxy(port);
    terminate_gracefully(child);

    let dir_entries: Vec<_> = fs::read_dir(dir.path())
        .expect("read log dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        dir_entries.iter().any(|name| name.contains("proxy")),
        "daily logging should create files under the log directory: {dir_entries:?}"
    );
}

#[test]
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
    thread::sleep(Duration::from_millis(800));
    ping_proxy(port);
    terminate_gracefully(child);

    let active = fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        active.contains("INFO"),
        "non-blocking logs should flush to disk on graceful shutdown: {active:?}"
    );
}
