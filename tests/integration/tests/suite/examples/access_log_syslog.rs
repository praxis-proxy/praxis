// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration test for the access log syslog sink example.

use std::{collections::HashMap, net::UdpSocket, time::Duration};

use praxis_test_utils::{free_port, http_send, parse_status, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn access_log_syslog_sink() {
    let backend_port_guard = start_backend_with_shutdown("logged");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let collector = UdpSocket::bind("127.0.0.1:0").expect("bind udp collector");
    collector
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let collector_addr = collector.local_addr().expect("collector addr").to_string();

    let mut config = super::load_example_config(
        "observability/access-log-syslog.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let mut patched = false;
    for chain in &mut config.filter_chains {
        for entry in &mut chain.filters {
            if entry.filter_type == "access_log"
                && let Some(sink) = entry.config.get_mut("sink").and_then(serde_yaml::Value::as_mapping_mut)
            {
                sink.insert("address".into(), collector_addr.as_str().into());
                patched = true;
            }
        }
    }
    assert!(
        patched,
        "example should configure an access_log syslog sink to override"
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "syslog sink should not disrupt proxying");

    let mut buf = [0_u8; 2048];
    let mut seen = Vec::new();
    let delivered = loop {
        let Ok(len) = collector.recv(&mut buf) else {
            break false;
        };
        let message = String::from_utf8_lossy(buf.get(..len).unwrap_or_default()).into_owned();
        if message.contains("GET /health 200") {
            assert!(
                message.contains("praxis"),
                "datagram should carry the RFC 3164 process tag: {message}"
            );
            break true;
        }
        seen.push(message);
    };
    assert!(
        delivered,
        "syslog sink should deliver the rendered template line for the request; saw: {seen:?}"
    );
}
