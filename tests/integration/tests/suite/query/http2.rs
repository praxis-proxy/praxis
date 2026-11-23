// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! QUERY over HTTP/2 on either or both proxy legs.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use praxis_test_utils::{
    RecordedRequest, RequestLog, bind_unique_port, http_send, parse_body, parse_header, parse_status, read_h2_response,
    start_recording_backend,
};

use super::{QUERY_BODY, TARGET, observed, response, start, yaml};

#[tokio::test]
async fn query_http2_preserves_method_target_headers_and_body() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        for (downstream_h2, upstream_h2) in [(true, false), (false, true), (true, true)] {
            let (h1, h1_log) = start_recording_backend(|_| response(202, "results"));
            let (h2_port, h2_log, server) = start_h2_backend();
            let port = if upstream_h2 { h2_port } else { h1.port() };
            let mut config = yaml(&[port], "max_retries: 0");
            if upstream_h2 {
                config = config.replace(
                    "            retry_policy:",
                    "            http:\n              version: h2\n            retry_policy:",
                );
            }
            let proxy = start(&config);

            if downstream_h2 {
                send_h2(proxy.addr()).await;
            } else {
                let address = proxy.addr().to_owned();
                let raw =
                    tokio::task::spawn_blocking(move || http_send(&address, &super::request("QUERY", QUERY_BODY)))
                        .await
                        .unwrap();
                assert_eq!(parse_status(&raw), 202, "H1 to H2 QUERY: {raw}");
                assert_eq!(parse_body(&raw), "results");
                assert_eq!(parse_header(&raw, "accept-query"), Some("application/json".to_owned()));
            }

            let attempts = observed(if upstream_h2 { &h2_log } else { &h1_log });
            assert_eq!(attempts.len(), 1, "one complete request should reach the origin");
            let version = if upstream_h2 { "HTTP/2" } else { "HTTP/1.1" };
            assert_eq!(attempts[0].request_line, format!("QUERY {TARGET} {version}"));
            assert_eq!(attempts[0].body, QUERY_BODY.as_bytes());
            assert!(
                attempts[0]
                    .headers
                    .iter()
                    .any(|(name, value)| name == "content-type" && value == "application/json")
            );
            server.abort();
            let _joined = server.await;
        }
    })
    .await
    .expect("QUERY HTTP/2 exchanges must finish within the deadline");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Send a body-bearing QUERY on a driven HTTP/2 client connection.
async fn send_h2(address: &str) {
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut client, connection) = Box::pin(h2::client::handshake(tcp)).await.unwrap();
    let driver = tokio::spawn(Box::pin(connection));
    let request = http::Request::builder()
        .method("QUERY")
        .uri(format!("http://localhost{TARGET}"))
        .header("content-type", "application/json")
        .body(())
        .unwrap();
    let (result, mut body) = client.send_request(request, false).unwrap();
    body.send_data(Bytes::from_static(QUERY_BODY.as_bytes()), true).unwrap();
    let mut received = Vec::new();
    let reply = Box::pin(read_h2_response(result.await, 1024, |chunk| {
        received.extend_from_slice(chunk);
        Ok(())
    }))
    .await;
    assert_eq!(reply.status, Some(202), "{reply:?}");
    assert!(reply.end_stream, "the complete response must arrive: {reply:?}");
    assert_eq!(
        received, b"results",
        "the HTTP/2 response must preserve the result bytes"
    );
    assert_eq!(
        reply.headers.unwrap().get("accept-query").unwrap(),
        "application/json",
        "HTTP/2 must preserve resource discovery metadata"
    );
    driver.abort();
    let _joined = driver.await;
}

/// Start a request-recording h2c server on this test's runtime.
fn start_h2_backend() -> (u16, RequestLog, tokio::task::JoinHandle<()>) {
    let (listener, port) = bind_unique_port();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&log);
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let seen = Arc::clone(&seen);
            connections.spawn(async move {
                let mut connection = h2::server::handshake(tcp).await.unwrap();
                let mut streams = tokio::task::JoinSet::new();
                while let Some(Ok((request, respond))) = connection.accept().await {
                    let seen = Arc::clone(&seen);
                    streams.spawn(record_h2_request(request, respond, seen));
                }
            });
        }
    });
    (port, log, server)
}

/// Consume and record one complete HTTP/2 request before returning results.
async fn record_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    log: RequestLog,
) {
    let (parts, mut stream) = request.into_parts();
    let mut body = Vec::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.unwrap();
        assert!(
            body.len() + chunk.len() <= 65_536,
            "the recording backend has a bounded body"
        );
        body.extend_from_slice(&chunk);
        stream.flow_control().release_capacity(chunk.len()).unwrap();
    }
    let request_line = format!("{} {} HTTP/2", parts.method, parts.uri.path_and_query().unwrap());
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap().to_owned()))
        .collect();
    log.lock().unwrap().push(RecordedRequest {
        body,
        headers,
        request_line,
    });
    let response = http::Response::builder()
        .status(202)
        .header("accept-query", "application/json")
        .body(())
        .unwrap();
    respond
        .send_response(response, false)
        .unwrap()
        .send_data(Bytes::from_static(b"results"), true)
        .unwrap();
}
