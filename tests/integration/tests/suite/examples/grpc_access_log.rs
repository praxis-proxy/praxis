// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the gRPC access logging example configuration.
//!
//! The example's whole point is what lands in the log, so these run the
//! real proxy binary with file logging bolted onto the example config
//! and read the emitted records back off disk.

use std::{
    collections::HashMap,
    fs, io,
    net::TcpStream,
    process::{Command, Stdio},
};

use praxis_test_utils::{
    GrpcBackend, GrpcBackendGuard, allow_loopback_endpoints, example_config_path, free_port, patch_yaml, praxis_bin,
    start_grpc_backend, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Run one gRPC call through the example config and return the log output.
fn example_access_log(backend: &GrpcBackendGuard) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("proxy.log");
    let port = free_port();

    let yaml = fs::read_to_string(example_config_path("observability/grpc-access-log.yaml")).expect("read example");
    let patched = allow_loopback_endpoints(&patch_yaml(
        &yaml,
        port,
        &HashMap::from([("127.0.0.1:50051", backend.port())]),
    ));
    let config = format!(
        "{patched}\nruntime:\n  logging:\n    output: file\n    file_path: {log}\n    non_blocking: false\nshutdown_timeout_secs: 1\n",
        log = log_path.display(),
    );

    let config_path = dir.path().join("praxis.yaml");
    fs::write(&config_path, config).expect("write config");
    let child = Command::new(praxis_bin())
        .arg("-c")
        .arg(&config_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn praxis");
    wait_for_tcp(&format!("127.0.0.1:{port}"));

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect to proxy");
    io::Write::write_all(
        &mut stream,
        b"POST /pkg.Svc/Method HTTP/1.1\r\n\
          Host: localhost\r\n\
          Content-Type: application/grpc\r\n\
          Content-Length: 0\r\n\
          Connection: close\r\n\r\n",
    )
    .expect("write gRPC request");
    let mut response = Vec::new();
    let _read = io::Read::read_to_end(&mut stream, &mut response);

    let _status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("send SIGTERM");
    let _exit = child.wait_with_output().expect("wait for proxy");

    fs::read_to_string(&log_path).unwrap_or_default()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn example_logs_the_grpc_status_of_a_failed_call() {
    let backend = start_grpc_backend(GrpcBackend::status(5).message("no%20such%20user"));

    let log = example_access_log(&backend);

    assert!(
        log.contains(r#""grpc_status":"5""#),
        "the example should log the numeric gRPC status: {log}"
    );
    assert!(
        log.contains(r#""grpc_status_name":"NOT_FOUND""#),
        "the example should log the canonical status name: {log}"
    );
    assert!(
        log.contains(r#""grpc_message":"no%20such%20user""#),
        "the example should log the gRPC message: {log}"
    );
    // The reason the example exists: HTTP says the call succeeded.
    assert!(
        log.contains(r#""status":"200""#),
        "a failed gRPC call is still HTTP 200: {log}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn example_logs_a_successful_call_as_ok() {
    let backend = start_grpc_backend(GrpcBackend::ok().body(b"\x00\x00\x00\x00\x02hi".as_slice()));

    let log = example_access_log(&backend);

    assert!(
        log.contains(r#""grpc_status_name":"OK""#),
        "a successful call should log OK: {log}"
    );
}
