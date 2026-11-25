// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Proves the `access_log` stdout sink writes NDJSON to the process's real
//! stdout.
//!
//! This needs the actual binary: the sink writes to the process stdout file
//! descriptor, which the in-process test harness cannot observe. A request is
//! driven through a `static_response` chain so no backend is required.

use std::{
    io::{BufReader, Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_test_utils::{PraxisProcess, free_port};

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn stdout_sink_writes_ndjson_to_process_stdout() {
    let port = free_port();
    let mut proxy = PraxisProcess::spawn(&config(port), &addr(port));

    send_request(&addr(port));

    // The sink writes on a background thread, so poll the captured stdout for
    // the compact NDJSON object the sink emits (serde_json has no spaces).
    let mut logs = String::new();
    for _ in 0..100 {
        logs = proxy.logs();
        if logs.contains(r#""method":"GET""#) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    proxy.terminate();
    assert!(
        logs.contains(r#""method":"GET""#) && logs.contains(r#""status":"200""#),
        "stdout sink must emit an NDJSON record with the request method and status:\n{logs}"
    );
    assert!(
        logs.contains(r#""path":"/health""#) && logs.contains(r#""timestamp":"#),
        "the NDJSON record must carry the request path and a timestamp:\n{logs}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn stdout_sink_records_client_ip_for_early_upgrade_refusal() {
    let port = free_port();
    let config = config(port).replace(
        "    filter_chains: [main]\n",
        "    upgrade_policy:\n      default: deny\n    filter_chains: [main]\n",
    );
    let mut proxy = PraxisProcess::spawn(&config, &addr(port));

    let mut stream = TcpStream::connect(addr(port)).expect("connect to proxy");
    stream
        .write_all(
            b"GET /refused-upgrade HTTP/1.1\r\n\
              Host: test\r\n\
              Connection: Upgrade\r\n\
              Upgrade: websocket\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .expect("write WebSocket handshake");
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let head = praxis_test_utils::read_h1_response(&mut BufReader::new(stream), true, 0, |_| Ok(()));
    assert_eq!(head.status, Some(403), "{head:?}");
    assert!(head.abort.is_none(), "{head:?}");

    let mut logs = String::new();
    for _ in 0..100 {
        logs = proxy.logs();
        if refused_record(&logs).is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    proxy.terminate();
    let record = refused_record(&logs).unwrap_or_else(|| panic!("missing refused handshake access record: {logs}"));
    assert_eq!(record["client_ip"], "127.0.0.1", "{record}");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Find the NDJSON record for this request among the proxy's other output.
fn refused_record(logs: &str) -> Option<serde_json::Value> {
    logs.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|record| record["status"] == "403" && record["path"] == "/refused-upgrade")
}

/// Proxy config on `port`: a stdout access-log sink in front of a static 200.
fn config(port: u16) -> String {
    format!(
        r#"
shutdown_timeout_secs: 1
runtime:
  threads: 1
listeners:
  - name: web
    address: "127.0.0.1:{port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: access_log
        sink:
          type: stdout
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

/// Send one `GET /health` request and drain the response so the proxy completes
/// the exchange (and the access log fires).
fn send_request(addr: &str) {
    let mut stream = TcpStream::connect(addr).expect("connect to proxy");
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut response = Vec::new();
    let _read = stream.read_to_end(&mut response);
}
