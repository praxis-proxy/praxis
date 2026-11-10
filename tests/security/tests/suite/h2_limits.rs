// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! HTTP/2 resource-limit tests for HTTP listeners.
//!
//! Each test drives a raw HTTP/2 (h2c, prior-knowledge) connection just past
//! one server limit, using the frame writer in
//! [`praxis_test_utils::h2_frames`], and asserts the RFC 9113 §10.5 outcome:
//! the offending stream or connection is terminated with the right error code,
//! while a separate well-behaved client is still served. Limits the proxy does
//! not yet enforce are ignored with a pointer into `FAILING_TESTS.md`.

use praxis_core::config::Config;
use praxis_test_utils::{
    ACK, END_HEADERS, END_STREAM, ENHANCE_YOUR_CALM, FLOW_CONTROL_ERROR, H2TestConnection, REFUSED_STREAM, frame_bytes,
    frame_type, h2c_get, start_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// SETTINGS identifier for `INITIAL_WINDOW_SIZE` (RFC 9113 §6.5.2).
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;

/// RST_STREAM error code `CANCEL` (RFC 9113 §7).
const CANCEL: u32 = 0x8;

/// A WINDOW_UPDATE increment that drives any window past the `2^31 - 1`
/// ceiling (RFC 9113 §6.9.1), since the stream window starts at 65 535.
const WINDOW_OVERFLOW_INCREMENT: u32 = 0x7FFF_FFFF;

// -----------------------------------------------------------------------------
// Reset-stream churn (CVE-2023-44487)
// -----------------------------------------------------------------------------

#[test]
fn reset_stream_churn_is_capped_with_goaway() {
    let backend = start_backend("ok");
    let proxy = start_proxy(&proxy_config(backend));
    let mut conn = H2TestConnection::connect(proxy.addr());
    conn.send_settings_ack();
    // Open and immediately reset far more streams than the pending-accept
    // reset budget allows, in one burst so they are reset before acceptance.
    let mut burst = Vec::new();
    for stream_id in (1..=127).step_by(2) {
        burst.extend(frame_bytes(
            frame_type::HEADERS,
            END_HEADERS | END_STREAM,
            stream_id,
            &request_block(),
        ));
        burst.extend(frame_bytes(frame_type::RST_STREAM, 0, stream_id, &CANCEL.to_be_bytes()));
    }
    conn.send_raw(&burst);
    assert_eq!(
        conn.wait_for_goaway(),
        Some(ENHANCE_YOUR_CALM),
        "a burst of reset streams must be answered with GOAWAY ENHANCE_YOUR_CALM"
    );
    assert_control_served(proxy.addr());
}

// -----------------------------------------------------------------------------
// Header blocks
// -----------------------------------------------------------------------------

#[test]
fn continuation_flood_is_rejected() {
    let backend = start_backend("ok");
    let proxy = start_proxy(&proxy_config(backend));
    let mut conn = H2TestConnection::connect(proxy.addr());
    conn.send_settings_ack();
    // HEADERS without END_HEADERS, then far more CONTINUATION frames than a
    // 64 KiB header list can justify, none of them ending the block.
    conn.send_headers_unterminated(1, &request_block());
    for _ in 0..32 {
        conn.send_continuation(1, &[0x00, 0x01, b'a', 0x00], false);
    }
    assert_eq!(
        conn.wait_for_goaway(),
        Some(ENHANCE_YOUR_CALM),
        "an unbounded CONTINUATION sequence must be cut off with GOAWAY, bounding memory"
    );
    assert_control_served(proxy.addr());
}

#[test]
fn oversized_header_list_is_rejected_at_stream_scope() {
    let backend = start_backend("ok");
    let proxy = start_proxy(&proxy_config(backend));
    // ~2000 small fields, each costing name + value + 32 bytes toward the
    // header-list size, push the decoded list past the 64 KiB limit while the
    // encoded block still fits one frame. The h2 client decodes the response
    // status; the server answers 431 (RFC 9113 §10.5.1) and keeps the
    // connection open.
    let status = oversized_request_status(proxy.addr(), 2000);
    assert_eq!(
        status,
        Some(431),
        "an oversized header list must draw a 431, not a connection error"
    );
    assert_control_served(proxy.addr());
}

// -----------------------------------------------------------------------------
// Concurrent streams
// -----------------------------------------------------------------------------

#[test]
fn excess_concurrent_streams_are_refused() {
    let backend = start_backend("ok");
    let proxy = start_proxy(&proxy_config(backend));
    let mut conn = H2TestConnection::connect(proxy.addr());
    conn.send_settings_ack();
    // Open many more half-open streams (no END_STREAM, so each stays active)
    // than the 128 concurrent-stream limit, in one burst.
    let mut burst = Vec::new();
    for stream_id in (1..=321).step_by(2) {
        burst.extend(frame_bytes(
            frame_type::HEADERS,
            END_HEADERS,
            stream_id,
            &request_block(),
        ));
    }
    conn.send_raw(&burst);
    let refused = conn
        .read_until(|frame| frame.ftype == frame_type::RST_STREAM && frame.error_code() == Some(REFUSED_STREAM))
        .is_some();
    assert!(
        refused,
        "streams beyond max_concurrent_streams must be answered with REFUSED_STREAM"
    );
    assert_control_served(proxy.addr());
}

// -----------------------------------------------------------------------------
// Frame floods
// -----------------------------------------------------------------------------

#[test]
fn ping_and_settings_burst_stays_responsive() {
    let backend = start_backend("ok");
    let proxy = start_proxy(&proxy_config(backend));
    let mut conn = H2TestConnection::connect(proxy.addr());
    conn.send_settings_ack();
    let mut burst = Vec::new();
    for index in 0..256_u16 {
        burst.extend(frame_bytes(frame_type::PING, 0, 0, &u64::from(index).to_be_bytes()));
        burst.extend(frame_bytes(frame_type::SETTINGS, 0, 0, &[]));
    }
    conn.send_raw(&burst);
    let acked = conn
        .read_until(|frame| frame.ftype == frame_type::PING && frame.flags & ACK != 0)
        .is_some();
    assert!(
        acked,
        "the server must acknowledge PINGs under a burst rather than stall or crash"
    );
    assert_control_served(proxy.addr());
}

#[test]
fn empty_data_frame_flood_is_capped_with_goaway() {
    let backend = start_backend("ok");
    let proxy = start_proxy(&proxy_config(backend));
    let mut conn = H2TestConnection::connect(proxy.addr());
    conn.send_settings_ack();
    conn.send_request(1, &[], false);
    let mut burst = Vec::new();
    for _ in 0..200 {
        burst.extend(frame_bytes(frame_type::DATA, 0, 1, &[]));
    }
    conn.send_raw(&burst);
    assert_eq!(
        conn.wait_for_goaway(),
        Some(ENHANCE_YOUR_CALM),
        "a flood of zero-length DATA frames must be cut off with GOAWAY ENHANCE_YOUR_CALM"
    );
    assert_control_served(proxy.addr());
}

// -----------------------------------------------------------------------------
// Flow control
// -----------------------------------------------------------------------------

#[test]
fn window_update_overflow_is_flow_control_error() {
    let backend = start_backend("ok");
    let proxy = start_proxy(&proxy_config(backend));
    let mut conn = H2TestConnection::connect(proxy.addr());
    conn.send_settings_ack();
    conn.send_request(1, &[], false);
    conn.send_window_update(1, WINDOW_OVERFLOW_INCREMENT);
    let frame = conn
        .read_until(|frame| matches!(frame.ftype, frame_type::RST_STREAM | frame_type::GOAWAY))
        .expect("a window overflow must draw a reset or GOAWAY");
    assert_eq!(
        frame.error_code(),
        Some(FLOW_CONTROL_ERROR),
        "a window overflow must give FLOW_CONTROL_ERROR"
    );
    assert_control_served(proxy.addr());
}

#[test]
fn zero_window_client_does_not_starve_others() {
    let backend = start_backend("ok");
    let proxy = start_proxy(&proxy_config(backend));
    // A connection that advertises a zero initial window and completes a
    // request: the server cannot send the response body and holds it, bounded
    // by its send buffer.
    let mut stalled = H2TestConnection::connect_with_settings(proxy.addr(), &[(SETTINGS_INITIAL_WINDOW_SIZE, 0)]);
    stalled.send_settings_ack();
    stalled.send_request(1, &[], true);
    // A separate well-behaved client must still be served meanwhile.
    assert_control_served(proxy.addr());
    drop(stalled);
}

// -----------------------------------------------------------------------------
// Test utilities
// -----------------------------------------------------------------------------

/// A minimal request HEADERS block (GET `/` on `localhost`).
fn request_block() -> Vec<u8> {
    praxis_test_utils::request_block("/", "localhost", &[])
}

/// Send an h2c GET carrying `field_count` padding header fields and return the
/// response status, or `None` if the stream failed instead of answering.
fn oversized_request_status(addr: &str, field_count: usize) -> Option<u16> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut client, connection) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(connection);
        let mut builder = http::Request::get("/").header("host", "localhost");
        for _ in 0..field_count {
            builder = builder.header("x-pad", "x".repeat(24).as_str());
        }
        let (response, _body) = client.send_request(builder.body(()).unwrap(), true).unwrap();
        response.await.ok().map(|resp| resp.status().as_u16())
    })
}

/// Assert a well-behaved h2c client still gets a 200 from `addr`.
fn assert_control_served(addr: &str) {
    let (status, _) = h2c_get(addr, "/", None);
    assert_eq!(status, 200, "a well-behaved client must still be served");
}

/// Proxy config: one h2c listener routing everything to `backend`.
fn proxy_config(backend: u16) -> Config {
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{}"
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
"#,
        praxis_test_utils::free_port(),
    );
    Config::from_yaml(&yaml).unwrap()
}
