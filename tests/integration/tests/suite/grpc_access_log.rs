// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! gRPC trailer extraction into the access log, end to end.
//!
//! A gRPC call's outcome lives in the response trailers, which arrive
//! after the response body. These tests spawn the real proxy binary
//! against an HTTP/2 gRPC backend and read the emitted access records
//! back off disk, so a regression in trailer capture — or in the order
//! the access log runs relative to the trailers — fails here rather
//! than silently logging `-`.

use std::{
    fs, io,
    net::TcpStream,
    process::{Command, Stdio},
};

use praxis_test_utils::{GrpcBackend, GrpcBackendGuard, free_port, praxis_bin, start_grpc_backend, wait_for_tcp};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Send one gRPC request through the proxy and read the whole response.
fn call_grpc(port: u16) {
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
    let mut buf = Vec::new();
    let _read = io::Read::read_to_end(&mut stream, &mut buf);
}

/// Stop the proxy so its non-blocking log writer flushes to disk.
fn terminate_gracefully(child: std::process::Child) {
    let _status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("send SIGTERM");
    let _exit = child.wait_with_output().expect("wait for proxy");
}

/// Run one gRPC call against `backend` through a proxy logging to a file,
/// and return the access log contents.
fn access_log_for(backend: &GrpcBackendGuard) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("proxy.log");
    let port = free_port();
    let config = format!(
        r#"
runtime:
  logging:
    output: file
    file_path: {log}
    non_blocking: false

shutdown_timeout_secs: 1

listeners:
  - name: grpc
    address: "127.0.0.1:{port}"
    filter_chains: [main]

filter_chains:
  - name: main
    filters:
      - filter: access_log
        fields:
          - status
          - grpc_status
          - grpc_status_name
          - grpc_message
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: grpc-backend
      - filter: load_balancer
        clusters:
          - name: grpc-backend
            endpoints:
              - "127.0.0.1:{backend_port}"
            http:
              version: h2

insecure_options:
  allow_private_endpoints: true
"#,
        log = log_path.display(),
        port = port,
        backend_port = backend.port(),
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
    call_grpc(port);
    terminate_gracefully(child);

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
fn access_log_records_a_failed_grpc_call() {
    let backend = start_grpc_backend(
        GrpcBackend::status(5)
            .message("no%20such%20user")
            .body(b"\x00\x00\x00\x00\x00".as_slice()),
    );

    let log = access_log_for(&backend);

    assert!(
        log.contains(r#""grpc_status":"5""#),
        "the grpc-status trailer should reach the access log: {log}"
    );
    assert!(
        log.contains(r#""grpc_status_name":"NOT_FOUND""#),
        "the canonical status name should be rendered: {log}"
    );
    assert!(
        log.contains(r#""grpc_message":"no%20such%20user""#),
        "the grpc-message trailer should reach the access log: {log}"
    );
    assert!(
        log.contains(r#""status":"200""#),
        "the HTTP status stays 200 for a failed gRPC call: {log}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn access_log_records_a_successful_grpc_call() {
    let backend = start_grpc_backend(GrpcBackend::ok().body(b"\x00\x00\x00\x00\x02hi".as_slice()));

    let log = access_log_for(&backend);

    assert!(
        log.contains(r#""grpc_status":"0""#),
        "a successful call should log grpc-status 0: {log}"
    );
    assert!(
        log.contains(r#""grpc_status_name":"OK""#),
        "a successful call should log the OK name: {log}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn access_log_records_a_trailers_only_grpc_error() {
    // A gRPC error is often a single HEADERS frame with END_STREAM: the
    // status is in the header block and no trailer frame ever arrives.
    let backend = start_grpc_backend(GrpcBackend::status(7).message("denied").trailers_only());

    let log = access_log_for(&backend);

    assert!(
        log.contains(r#""grpc_status":"7""#),
        "a Trailers-Only response carries its status in the header block: {log}"
    );
    assert!(
        log.contains(r#""grpc_status_name":"PERMISSION_DENIED""#),
        "the canonical status name should be rendered: {log}"
    );
}
