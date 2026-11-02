// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End-to-end tests of the hyper HTTP adapter over real sockets.
//!
//! Each test starts a [`HyperRuntime`] on its own thread with the adapter
//! registered from a YAML configuration, the way the server and the test
//! harness build it, and talks to it with raw HTTP/1 and `h2` clients and
//! raw HTTP/1 and `h2` backends.
//!
//! [`HyperRuntime`]: praxis_core::server::HyperRuntime

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::Method;
use praxis_core::{
    config::{Config, DEFAULT_RETRY_BODY_LIMIT_BYTES, ExpandedFilterChains},
    server::{HyperRuntime, ServerRuntime as _},
};
use praxis_filter::{
    BodyAccess, FilterAction, FilterError, FilterFactory, FilterPipeline, FilterRegistry, HttpFilter, HttpFilterContext,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::Notify,
};

use super::HyperHttp;
use crate::ListenerPipelines;

#[tokio::test]
async fn get_round_trips_over_http11() {
    let backend = Backend::start(Reply::Fixed(ok("hello"))).await;
    let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;

    let response = proxy
        .send("GET /hello?x=1 HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .await;

    assert_eq!(response.status, 200, "the upstream status reaches the client");
    assert_eq!(response.body, "hello", "the upstream body reaches the client");
    let seen = backend.only_request();
    assert!(
        seen.head.starts_with("GET /hello?x=1 HTTP/1.1"),
        "the target is forwarded: {}",
        seen.head
    );
    assert_eq!(seen.header("host"), Some("example.test"), "Host is forwarded");
}

#[test]
fn listener_startup_failure_stops_the_runtime() {
    let yaml = routed_yaml("127.0.0.1:1".parse().unwrap(), "");
    let mut config = Config::from_yaml(&yaml).unwrap();
    let mut second = config.listeners[0].clone();
    second.name = "second".to_owned();
    second.address = closed_port().to_string();
    let blocked_address = second.address.clone();
    config.listeners.push(second);
    let address = config.listeners[0].address.clone();
    let mut runtime = HyperRuntime::new(&config);
    HyperHttp::register_on(
        &mut runtime,
        &config,
        &pipelines(&config, &FilterRegistry::with_builtins()),
    )
    .unwrap();
    let occupied = std::net::TcpListener::bind(blocked_address).unwrap();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.run_with_shutdown(Box::pin(async { tokio::time::sleep(Duration::from_secs(2)).await }));
    }));
    drop(occupied);
    assert!(
        failed.is_err(),
        "a configured HTTP listener that cannot listen must fail startup"
    );
    assert!(
        std::net::TcpListener::bind(address).is_ok(),
        "other listeners must close too"
    );
}

#[tokio::test]
async fn request_trailers_survive_streaming_and_pre_read_to_http2() {
    for filter in [
        "",
        "\n      - filter: json_body_field\n        field: model\n        header: X-Model\n",
    ] {
        let (backend, mut captured) = trailer_backend(false, &[200]).await;
        let yaml = with_cluster(
            &routed_yaml(backend, filter),
            "            http:\n              version: h2\n",
        );
        let proxy = Proxy::start(&yaml).await;
        let response = proxy.send(&request_with_trailers()).await;
        assert_eq!(response.status, 200, "HTTP/2 upstreams support request trailers");
        let (body, trailers) = captured.recv().await.unwrap();
        assert_eq!(body, br#"{"model":"m1"}"#, "the body arrives before its trailers");
        assert_eq!(
            trailers.get("x-checksum").unwrap(),
            "abc",
            "pre-read must retain trailers"
        );
        assert_eq!(
            trailers.get("x-ext-tenant").unwrap(),
            "public",
            "other x-ext names are ordinary trailers"
        );
    }
}

#[tokio::test]
async fn reserved_request_trailers_are_rejected_streaming_and_pre_read_to_http2() {
    for filter in [
        "",
        "\n      - filter: json_body_field\n        field: model\n        header: X-Model\n",
    ] {
        for name in ["X-Praxis-Spoof", "X-Ext-Protocol-Spoof", "X-Ext-Agent-Spoof"] {
            let (backend, mut captured) = trailer_backend(false, &[200]).await;
            let yaml = with_cluster(
                &routed_yaml(backend, filter),
                "            http:\n              version: h2\n",
            );
            let proxy = Proxy::start(&yaml).await;

            let response = proxy.send(&request_with_trailers().replace("x-checksum", name)).await;

            assert_eq!(
                response.status,
                400,
                "{name} must be rejected with pre-read={}",
                !filter.is_empty()
            );
            if filter.is_empty() {
                assert_upload_aborted(captured).await;
            } else {
                assert!(
                    captured.try_recv().is_err(),
                    "pre-read rejects before forwarding an upload"
                );
            }
        }
    }
}

#[tokio::test]
async fn ordinary_request_trailers_survive_http2_retry_after_streaming_and_pre_read() {
    for filter in [
        "",
        "\n      - filter: json_body_field\n        field: model\n        header: X-Model\n",
    ] {
        let (backend, mut captured) = trailer_backend(false, &[503, 200]).await;
        let policy = RESET_RETRIES.replace("connect_failure, reset", "status_5xx");
        let settings = format!("            http:\n              version: h2\n{policy}");
        let proxy = Proxy::start(&with_cluster(&routed_yaml(backend, filter), &settings)).await;

        let response = proxy.send(&request_with_trailers()).await;

        assert_eq!(response.status, 200, "the retried response succeeds");
        for _attempt in 0..2 {
            let (body, trailers) = tokio::time::timeout(Duration::from_secs(2), captured.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(body, br#"{"model":"m1"}"#, "each attempt sends the whole body");
            assert_eq!(
                trailers.get("x-checksum").unwrap(),
                "abc",
                "each attempt retains the checksum"
            );
            assert_eq!(
                trailers.get("x-ext-tenant").unwrap(),
                "public",
                "other x-ext names remain supported"
            );
        }
    }
}

#[tokio::test]
async fn reserved_request_trailers_abort_an_early_http2_response() {
    let (backend, captured) = trailer_backend(true, &[200]).await;
    let proxy = Proxy::start(&with_cluster(
        &routed_yaml(backend, ""),
        "            http:\n              version: h2\n",
    ))
    .await;
    let (mut client, mut response) = begin_trailer_upload(&proxy).await;

    client.write_all(b"0\r\nx-praxis-spoof: yes\r\n\r\n").await.unwrap();

    let (mut reader, _writer) = client.into_split();
    response.extend_from_slice(
        &tokio::time::timeout(Duration::from_secs(2), read_to_close(&mut reader))
            .await
            .unwrap(),
    );
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "the response was already committed"
    );
    assert!(
        !response.ends_with(b"0\r\n\r\n"),
        "reserved trailers must abort the response"
    );
    assert_upload_aborted(captured).await;
}

#[tokio::test]
async fn request_trailers_are_rejected_for_http1_in_streaming_and_pre_read() {
    for filter in [
        "",
        "\n      - filter: json_body_field\n        field: model\n        header: X-Model\n",
    ] {
        let backend = Backend::start(Reply::Deaf).await;
        let proxy = Proxy::start(&routed_yaml(backend.addr, filter)).await;
        let response = proxy.send(&request_with_trailers()).await;
        assert_eq!(
            response.status, 400,
            "unsupported trailers must never become a successful truncated upload"
        );
    }
}

#[tokio::test]
async fn unsupported_request_trailers_abort_an_early_response() {
    let backend = Backend::start(Reply::Early(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n".to_vec(),
    ))
    .await;
    let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), read_head(&mut client, &mut response))
        .await
        .unwrap()
        .unwrap();
    client.write_all(b"0\r\nx-checksum: abc\r\n\r\n").await.unwrap();
    let (mut reader, _writer) = client.into_split();
    let remaining = tokio::time::timeout(Duration::from_secs(2), read_to_close(&mut reader))
        .await
        .unwrap();
    response.extend_from_slice(&remaining);
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "the response had already started"
    );
    assert!(
        !response.ends_with(b"0\r\n\r\n"),
        "unsupported trailers must abort the response, not end it cleanly"
    );
}

/// A chunked HTTP/1 request with a trailer per [RFC 9112 Section 7.1.2].
///
/// [RFC 9112 Section 7.1.2]: https://datatracker.ietf.org/doc/html/rfc9112#section-7.1.2
fn request_with_trailers() -> String {
    let body = r#"{"model":"m1"}"#;
    format!(
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nTrailer: x-checksum, x-ext-tenant\r\n\r\n{:x}\r\n{body}\r\n0\r\nx-checksum: abc\r\nx-ext-tenant: public\r\n\r\n",
        body.len()
    )
}

/// Capture HTTP/2 uploads and answer with `statuses`, optionally starting
/// the response before the upload ends.
async fn trailer_backend(
    early: bool,
    statuses: &'static [u16],
) -> (SocketAddr, tokio::sync::mpsc::Receiver<(Vec<u8>, http::HeaderMap)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, received) = tokio::sync::mpsc::channel(statuses.len());
    drop(tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(socket).await.unwrap();
        for status in statuses {
            let (request, respond) = connection.accept().await.unwrap().unwrap();
            drop(tokio::spawn(answer_trailer_upload(
                request,
                respond,
                sent.clone(),
                *status,
                early,
            )));
        }
        drop(sent);
        while connection.accept().await.is_some() {}
    }));
    (address, received)
}

/// Start a chunked upload and wait for an early upstream response.
async fn begin_trailer_upload(proxy: &Proxy) -> (TcpStream, Vec<u8>) {
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(b"POST / HTTP/1.1\r\nHost: a\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), read_head(&mut client, &mut response))
        .await
        .unwrap()
        .unwrap();
    (client, response)
}

/// Verify that the backend did not receive a complete upload with trailers.
async fn assert_upload_aborted(mut captured: tokio::sync::mpsc::Receiver<(Vec<u8>, http::HeaderMap)>) {
    let upload = tokio::time::timeout(Duration::from_secs(2), captured.recv())
        .await
        .unwrap();
    assert!(upload.is_none(), "reserved trailers never reach the HTTP/2 backend");
}

/// Capture and answer one upload, or abandon it when the proxy resets it.
async fn answer_trailer_upload(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    sent: tokio::sync::mpsc::Sender<(Vec<u8>, http::HeaderMap)>,
    status: u16,
    early: bool,
) {
    let mut outgoing = early.then(|| respond.send_response(http::Response::new(()), false).unwrap());
    if let Some(stream) = outgoing.as_mut() {
        stream.send_data(Bytes::from_static(b"hi"), false).unwrap();
    }
    let Some(captured) = capture_h2_upload(request.into_body()).await else {
        return;
    };
    sent.send(captured).await.unwrap();
    if let Some(mut stream) = outgoing {
        stream.send_data(Bytes::new(), true).unwrap();
    } else {
        let response = http::Response::builder().status(status).body(()).unwrap();
        respond.send_response(response, true).unwrap();
    }
}

/// Read a complete HTTP/2 upload, or stop if the proxy resets it.
async fn capture_h2_upload(mut incoming: h2::RecvStream) -> Option<(Vec<u8>, http::HeaderMap)> {
    let mut body = Vec::new();
    while let Some(chunk) = incoming.data().await {
        let chunk = chunk.ok()?;
        incoming.flow_control().release_capacity(chunk.len()).unwrap();
        body.extend_from_slice(&chunk);
    }
    let trailers = incoming.trailers().await.ok()?.unwrap_or_default();
    Some((body, trailers))
}

#[tokio::test]
async fn post_body_is_forwarded() {
    let backend = Backend::start(Reply::Fixed(ok("done"))).await;
    let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;

    let response = proxy
        .send("POST /submit HTTP/1.1\r\nHost: a\r\nContent-Length: 7\r\n\r\npayload")
        .await;

    assert_eq!(response.status, 200, "the POST is answered");
    let seen = backend.only_request();
    assert_eq!(seen.body, "payload", "the request body reaches the upstream");
    assert_eq!(seen.header("content-length"), Some("7"), "the body length is kept");
}

#[tokio::test]
async fn http2_prior_knowledge_round_trips() {
    let backend = Backend::start(Reply::Fixed(ok("over h2"))).await;
    let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;

    let (status, headers, body) = proxy.send_h2("/h2").await;

    assert_eq!(status, 200, "an HTTP/2 client is answered");
    assert_eq!(body, "over h2", "the body crosses the protocols");
    assert_eq!(
        headers.get("via").unwrap(),
        "1.1 praxis",
        "the response Via names the upstream leg"
    );
    let seen = backend.only_request();
    assert_eq!(
        seen.header("via"),
        Some("2 praxis"),
        "the request Via names the client leg"
    );
    assert!(
        seen.header("host").is_some(),
        "the HTTP/2 authority becomes Host upstream"
    );
}

#[tokio::test]
async fn via_is_added_on_both_legs() {
    let backend = Backend::start(Reply::Fixed(ok("x"))).await;
    let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;

    let response = proxy.send("GET / HTTP/1.1\r\nHost: a\r\nVia: 1.0 edge\r\n\r\n").await;

    assert_eq!(response.header("via"), Some("1.1 praxis"), "the response Via is added");
    assert_eq!(
        backend.only_request().header("via"),
        Some("1.0 edge, 1.1 praxis"),
        "the request Via keeps the chain and appends this proxy"
    );
}

#[tokio::test]
async fn hop_by_hop_headers_are_stripped_on_both_legs() {
    let upstream_reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: x-up\r\nX-Up: 1\r\nKeep-Alive: timeout=5\r\nX-Kept: yes\r\n\r\nok";
    let backend = Backend::start(Reply::Fixed(upstream_reply.as_bytes().to_vec())).await;
    let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;

    let response = proxy
        .send("GET / HTTP/1.1\r\nHost: a\r\nConnection: x-down\r\nX-Down: 1\r\nTE: gzip\r\n\r\n")
        .await;

    let seen = backend.only_request();
    for gone in ["x-down", "te"] {
        assert!(seen.header(gone).is_none(), "{gone} must not reach the upstream");
    }
    for gone in ["x-up", "keep-alive"] {
        assert!(response.header(gone).is_none(), "{gone} must not reach the client");
    }
    assert_eq!(
        response.header("x-kept"),
        Some("yes"),
        "end-to-end headers reach the client"
    );
}

#[tokio::test]
async fn unmatched_route_is_rejected_with_404() {
    let backend = Backend::start(Reply::Fixed(ok("x"))).await;
    let yaml = routed_yaml(backend.addr, "").replace(r#"path_prefix: "/""#, r#"path_prefix: "/api""#);
    let proxy = Proxy::start(&yaml).await;

    let response = proxy.send("GET /elsewhere HTTP/1.1\r\nHost: a\r\n\r\n").await;

    assert_eq!(response.status, 404, "no route is a 404");
    assert!(backend.requests().is_empty(), "nothing reaches the upstream");
}

#[tokio::test]
async fn static_response_is_answered_locally() {
    let backend = Backend::start(Reply::Fixed(ok("x"))).await;
    let filter = r#"
      - filter: static_response
        status: 418
        body: "short and stout"
        headers:
          - name: x-tea
            value: earl-grey
"#;
    let proxy = Proxy::start(&routed_yaml(backend.addr, filter)).await;

    let response = proxy.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n").await;

    assert_eq!(response.status, 418, "the filter's status is sent");
    assert_eq!(response.body, "short and stout", "the filter's body is sent");
    assert_eq!(
        response.header("x-tea"),
        Some("earl-grey"),
        "the filter's headers are sent"
    );
    assert_eq!(
        response.header("content-length"),
        Some("15"),
        "the length comes from the body"
    );
    assert!(backend.requests().is_empty(), "nothing reaches the upstream");
}

#[tokio::test]
async fn connect_refused_is_a_502_problem_document() {
    let proxy = Proxy::start(&routed_yaml(closed_port(), "")).await;

    let response = proxy.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n").await;

    assert_eq!(response.status, 502, "an unreachable upstream is a 502");
    assert_eq!(
        response.header("content-type"),
        Some("application/problem+json"),
        "the error is an RFC 9457 problem document"
    );
    assert!(
        response.body.contains("Upstream connection refused"),
        "the problem says why: {}",
        response.body
    );
    assert_eq!(
        response.header("cache-control"),
        Some("no-transform"),
        "the error is not transformed"
    );
}

#[tokio::test]
async fn upstream_read_timeout_is_a_504() {
    let backend = Backend::start(Reply::Silent).await;
    let yaml = routed_yaml(backend.addr, "").replace(
        "            endpoints:",
        "            read_timeout_ms: 200\n            endpoints:",
    );
    let proxy = Proxy::start(&yaml).await;

    let response = proxy.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n").await;

    assert_eq!(response.status, 504, "an upstream that never answers is a 504");
    assert!(
        response.body.contains("Upstream read timed out"),
        "body: {}",
        response.body
    );
}

#[tokio::test]
async fn forwarded_headers_adds_the_client_address() {
    let backend = Backend::start(Reply::Fixed(ok("x"))).await;
    let filter = "\n      - filter: forwarded_headers\n";
    let proxy = Proxy::start(&routed_yaml(backend.addr, filter)).await;

    let response = proxy.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n").await;

    assert_eq!(response.status, 200, "the request is proxied");
    assert_eq!(
        backend.only_request().header("x-forwarded-for"),
        Some("127.0.0.1"),
        "the client address is forwarded"
    );
}

#[tokio::test]
async fn zero_max_forwards_is_answered_by_the_proxy() {
    let backend = Backend::start(Reply::Fixed(ok("x"))).await;
    let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;

    let trace = proxy
        .send("TRACE /t HTTP/1.1\r\nHost: a\r\nMax-Forwards: 0\r\n\r\n")
        .await;
    let options = proxy
        .send("OPTIONS / HTTP/1.1\r\nHost: a\r\nMax-Forwards: 0\r\n\r\n")
        .await;

    assert_eq!(trace.status, 200, "TRACE is echoed");
    assert_eq!(trace.header("content-type"), Some("message/http"), "as message/http");
    assert!(
        trace.body.starts_with("TRACE /t HTTP/1.1"),
        "the request line is echoed: {}",
        trace.body
    );
    assert_eq!(options.status, 200, "OPTIONS is answered");
    assert!(backend.requests().is_empty(), "nothing reaches the upstream");
}

#[tokio::test]
async fn connect_and_proxy_form_requests_are_refused() {
    let backend = Backend::start(Reply::Fixed(ok("x"))).await;
    let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;

    let connect = proxy
        .send("CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\n")
        .await;
    let mismatched = proxy
        .send("GET http://a.example/x HTTP/1.1\r\nHost: other.example\r\n\r\n")
        .await;
    let matching = proxy
        .send("GET http://a.example/x HTTP/1.1\r\nHost: a.example\r\n\r\n")
        .await;

    assert_eq!(connect.status, 400, "CONNECT is refused");
    assert_eq!(
        connect.header("connection"),
        Some("close"),
        "and the connection closes after it"
    );
    assert_eq!(
        mismatched.status, 400,
        "an absolute-form target whose authority differs from Host is refused"
    );
    assert_eq!(
        matching.status, 200,
        "an absolute-form target whose authority is the Host is proxied"
    );
    assert!(
        backend.only_request().head.starts_with("GET /x HTTP/1.1"),
        "the absolute-form target reaches the upstream in origin form"
    );
}

#[tokio::test]
async fn two_hundred_request_headers_are_accepted() {
    let backend = Backend::start(Reply::Fixed(ok("x"))).await;
    let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;
    let many_headers: String = (0..200).map(|idx| format!("x-h{idx}: {idx}\r\n")).collect();

    let crowded = proxy
        .send(&format!("GET / HTTP/1.1\r\nHost: a\r\n{many_headers}\r\n"))
        .await;

    assert_eq!(crowded.status, 200, "200 header lines are within the limit");
    assert_eq!(
        backend.only_request().header("x-h199"),
        Some("199"),
        "every header reaches the upstream"
    );
}

#[tokio::test]
async fn stream_buffer_filter_reads_the_whole_body() {
    let backend = Backend::start(Reply::Fixed(ok("x"))).await;
    let filter = "\n      - filter: json_body_field\n        field: model\n        header: X-Model\n";
    let proxy = Proxy::start(&routed_yaml(backend.addr, filter)).await;
    let body = r#"{"model":"m1","prompt":"hi"}"#;

    let response = proxy
        .send(&format!(
            "POST / HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ))
        .await;

    assert_eq!(response.status, 200, "the request is proxied");
    let seen = backend.only_request();
    assert_eq!(
        seen.header("x-model"),
        Some("m1"),
        "the filter saw the whole body before routing"
    );
    assert_eq!(seen.body, body, "the pre-read body is forwarded");
}

#[tokio::test]
async fn head_response_carries_no_body() {
    let upstream_reply = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".to_vec();
    let backend = Backend::start(Reply::Fixed(upstream_reply)).await;
    let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;

    let response = proxy.send("HEAD / HTTP/1.1\r\nHost: a\r\n\r\n").await;

    assert_eq!(response.status, 200, "HEAD is answered");
    assert_eq!(
        response.header("content-length"),
        Some("5"),
        "the length of the entity is kept"
    );
    assert!(response.body.is_empty(), "no body follows a HEAD response");
}

#[tokio::test]
async fn oversized_body_is_rejected_with_413() {
    let backend = Backend::start(Reply::Fixed(ok("x"))).await;
    let yaml = format!(
        "{}\nbody_limits:\n  max_request_bytes: 16\n",
        routed_yaml(backend.addr, "")
    );
    let proxy = Proxy::start(&yaml).await;
    let body = "x".repeat(64);

    let response = proxy
        .send(&format!(
            "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 64\r\n\r\n{body}"
        ))
        .await;

    assert_eq!(response.status, 413, "a body over the limit is refused");
}

#[tokio::test]
async fn early_answer_reaches_the_client_while_the_upstream_ignores_the_body() {
    let early = b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 8\r\n\r\ntoo much".to_vec();
    let backend = Backend::start(Reply::Early(early)).await;
    let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;
    let (mut reader, writer) = TcpStream::connect(proxy.addr).await.unwrap().into_split();
    let upload = tokio::spawn(write_large_body(writer, LARGE_BODY_BYTES));

    let raw = tokio::time::timeout(Duration::from_secs(10), read_until(&mut reader, b"too much"))
        .await
        .expect("the early answer must arrive while the body is still being sent");
    upload.abort();

    let response = RawResponse::parse(&raw);
    assert_eq!(response.status, 413, "the upstream's early answer reaches the client");
    assert_eq!(response.body, "too much", "with its body");
    assert!(
        backend.only_request().head.starts_with("POST /upload HTTP/1.1"),
        "the upstream saw the request head"
    );
}

#[tokio::test]
async fn upstream_that_stops_reading_the_body_is_a_write_timeout() {
    let backend = Backend::start(Reply::Deaf).await;
    let yaml = routed_yaml(backend.addr, "").replace(
        "            endpoints:",
        "            write_timeout_ms: 200\n            endpoints:",
    );
    let proxy = Proxy::start(&yaml).await;
    let (mut reader, writer) = TcpStream::connect(proxy.addr).await.unwrap().into_split();
    let upload = tokio::spawn(write_large_body(writer, LARGE_BODY_BYTES));

    let raw = tokio::time::timeout(
        Duration::from_secs(10),
        read_until(&mut reader, b"Upstream write timed out"),
    )
    .await
    .expect("the write timeout must fire while the body is still being sent");
    upload.abort();

    let response = RawResponse::parse(&raw);
    assert_eq!(response.status, 504, "a body the upstream stops taking is a 504");
    assert!(
        response.body.contains("Upstream write timed out"),
        "body: {}",
        response.body
    );
}

#[tokio::test]
async fn completion_runs_when_the_client_leaves_mid_body() {
    crate::http::metrics::install_prometheus_recorder();
    let backend = Backend::start(Reply::Dribble).await;
    let yaml = routed_yaml(backend.addr, "").replace("name: default", "name: departing");
    let proxy = Proxy::start(&yaml).await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
    let mut first = [0_u8; 64];
    let read = client.read(&mut first).await.unwrap();
    assert!(read > 0, "the response head arrives before the body ends");
    assert_eq!(
        active_requests("departing"),
        Some(1),
        "the request is in flight while its body streams"
    );
    client.set_zero_linger().unwrap();
    drop(client);

    eventually(
        || active_requests("departing") == Some(0),
        "the request completes once the client leaves",
    )
    .await;
}

#[tokio::test]
async fn client_leaving_mid_upload_cuts_the_upstream_body_and_completes_once() {
    crate::http::metrics::install_prometheus_recorder();
    let backend = Backend::start(Reply::Absorb).await;
    let proxy = Proxy::start(&labelled(&routed_yaml(backend.addr, ""), "leaving-upload")).await;
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client.write_all(&post_of(100_000).as_bytes()[..1_000]).await.unwrap();
    eventually(|| !backend.requests().is_empty(), "the upstream gets the request head").await;
    assert_eq!(active_requests("leaving-upload"), Some(1), "the upload is in flight");
    client.set_zero_linger().unwrap();
    drop(client);

    eventually(
        || backend.requests().iter().any(|seen| seen.body_complete.is_some()),
        "the upstream body ends once the client leaves",
    )
    .await;

    assert_eq!(
        backend.only_request().body_complete,
        Some(false),
        "the upstream must see the body cut short, not a clean end"
    );
    eventually(
        || active_requests("leaving-upload") == Some(0),
        "no request is left in flight",
    )
    .await;
    assert_eq!(
        completed_requests("leaving-upload").await,
        1,
        "completion runs exactly once"
    );
}

#[tokio::test]
async fn upstream_abort_mid_body_cuts_the_http1_response_without_a_retry() {
    crate::http::metrics::install_prometheus_recorder();
    let backend = Backend::start(Reply::AbortMidBody).await;
    let yaml = with_cluster(&labelled(&routed_yaml(backend.addr, ""), "aborting-h1"), RESET_RETRIES);
    let proxy = Proxy::start(&yaml).await;

    let raw = proxy.send_lossy("GET / HTTP/1.1\r\nHost: a\r\n\r\n").await;

    let text = String::from_utf8_lossy(&raw);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "the committed head reaches the client: {text}"
    );
    assert!(
        text.contains("5\r\nhello\r\n"),
        "so do the bytes the upstream sent: {text}"
    );
    assert!(
        !text.ends_with("0\r\n\r\n"),
        "the body must not be ended as if it were whole: {text}"
    );
    assert_eq!(
        backend.requests().len(),
        1,
        "an attempt whose bytes reached the client is not retried"
    );
    assert_eq!(
        completed_requests("aborting-h1").await,
        1,
        "completion runs exactly once"
    );
}

#[tokio::test]
async fn upstream_abort_mid_body_resets_the_http2_stream() {
    crate::http::metrics::install_prometheus_recorder();
    let backend = Backend::start(Reply::AbortMidBody).await;
    let yaml = with_cluster(&labelled(&routed_yaml(backend.addr, ""), "aborting-h2"), RESET_RETRIES);
    let proxy = Proxy::start(&yaml).await;

    let reply = proxy.h2_request(Method::GET, "/").await;

    let body = String::from_utf8_lossy(&reply.body);
    assert_eq!(reply.head.status, 200, "the committed head reaches the client");
    assert!(
        reply.error.is_some(),
        "the stream must end in a reset, not a clean end of stream"
    );
    assert!(
        "hello".starts_with(&*body),
        "only bytes the upstream sent arrive: {body}"
    );
    assert_eq!(
        backend.requests().len(),
        1,
        "an attempt whose head reached the client is not retried"
    );
    assert_eq!(
        completed_requests("aborting-h2").await,
        1,
        "completion runs exactly once"
    );
}

#[tokio::test]
async fn pooled_post_partial_response_is_not_replayed_without_opt_in() {
    for policy in [
        String::new(),
        RESET_RETRIES.replace("allow_non_idempotent: true", "allow_non_idempotent: false"),
    ] {
        let backend = Backend::start(Reply::PartialHeadAfterWarm).await;
        let proxy = Proxy::start(&with_cluster(&routed_yaml(backend.addr, ""), &policy)).await;
        let warm = proxy.send("GET /warm HTTP/1.1\r\nHost: a\r\n\r\n").await;
        assert_eq!(warm.status, 200, "warm the upstream connection");
        tokio::time::sleep(POOL_SETTLE).await;

        let response = proxy.send(&post_of(1_024)).await;

        let requests = backend.requests();
        let connections: Vec<_> = requests.iter().map(|seen| seen.connection).collect();
        assert_eq!(connections, [0, 0], "a fully processed POST must not be repeated");
        assert_eq!(requests[1].body.len(), 1_024, "the backend received the full POST");
        assert_eq!(response.status, 502, "the partial response head fails the exchange");
    }
}

#[tokio::test]
async fn pooled_post_partial_response_opt_in_obeys_retry_limit() {
    let backend = Backend::start(Reply::PartialHeadAfterWarm).await;
    let policy = RESET_RETRIES.replace("max_retries: 2", "max_retries: 1");
    let proxy = Proxy::start(&with_cluster(&routed_yaml(backend.addr, ""), &policy)).await;
    let warm = proxy.send("GET /warm HTTP/1.1\r\nHost: a\r\n\r\n").await;
    assert_eq!(warm.status, 200, "warm the upstream connection");
    tokio::time::sleep(POOL_SETTLE).await;

    let response = proxy.send(&post_of(1_024)).await;

    let requests = backend.requests();
    let connections: Vec<_> = requests.iter().map(|seen| seen.connection).collect();
    assert_eq!(connections, [0, 0, 1], "the pooled failure consumes the sole retry");
    assert!(
        requests.iter().skip(1).all(|seen| seen.body.len() == 1_024),
        "every attempt carries the full body"
    );
    assert_eq!(response.status, 502, "the retry limit ends the failed exchange");
}

#[tokio::test]
async fn reset_post_within_the_replay_buffer_is_retried() {
    let backend = Backend::start(Reply::ResetFirst(ok("again"))).await;
    let proxy = Proxy::start(&with_cluster(&routed_yaml(backend.addr, ""), RESET_RETRIES)).await;

    let response = proxy.send(&post_of(1_024)).await;

    assert_eq!(
        response.status, 200,
        "a reset with the whole body in the replay buffer is retried"
    );
    assert_eq!(response.body, "again", "the retry's answer reaches the client");
    let requests = backend.requests();
    assert_eq!(requests.len(), 2, "the request is sent twice");
    assert_eq!(
        requests.get(1).map(|seen| seen.body.len()),
        Some(1_024),
        "the replay carries the whole body"
    );
}

#[tokio::test]
async fn reset_post_past_the_replay_buffer_is_not_retried() {
    let backend = Backend::start(Reply::ResetFirst(ok("again"))).await;
    let proxy = Proxy::start(&with_cluster(&routed_yaml(backend.addr, ""), RESET_RETRIES)).await;

    let response = proxy.send(&post_of(past_replay_limit())).await;

    assert_eq!(
        response.status, 502,
        "a body past the replay buffer cannot be sent again, so the reset stands"
    );
    assert_eq!(backend.requests().len(), 1, "the request is not retried");
}

#[tokio::test]
async fn pooled_connection_failure_is_not_replayed_for_a_post_past_the_replay_buffer() {
    let backend = Backend::start(Reply::KillOnReuse(ok("warm"))).await;
    let proxy = Proxy::start(&with_cluster(&routed_yaml(backend.addr, ""), RESET_RETRIES)).await;
    let warm = proxy.send("GET /warm HTTP/1.1\r\nHost: a\r\n\r\n").await;
    assert_eq!(warm.status, 200, "the first exchange pools its upstream connection");
    tokio::time::sleep(POOL_SETTLE).await;

    let response = proxy.send(&post_of(past_replay_limit())).await;

    let connections: Vec<usize> = backend.requests().iter().map(|seen| seen.connection).collect();
    assert_eq!(
        connections,
        [0, 0],
        "the POST goes out on the pooled connection and is not replayed on a fresh one"
    );
    assert_eq!(
        response.status, 502,
        "a failed exchange is not replayed once the body outgrew the replay buffer"
    );
}

#[tokio::test]
async fn body_filter_failing_on_the_first_chunk_is_a_500() {
    let backend = Backend::start(Reply::Fixed(ok("confidential"))).await;
    let yaml = routed_yaml(backend.addr, &format!("\n      - filter: {FAILING_BODY_FILTER}\n"));
    let proxy = Proxy::start_with(&yaml, &failing_registry()).await;

    let response = proxy.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n").await;

    assert_eq!(
        response.status, 500,
        "a body filter that fails before the commit is answered with a 500"
    );
    assert!(
        !response.body.contains("confidential"),
        "the upstream body must not leak: {}",
        response.body
    );
}

#[tokio::test]
async fn late_first_chunk_streams_behind_an_early_head() {
    let backend = Backend::start(Reply::Late("late body")).await;
    let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;
    let (mut reader, mut writer) = TcpStream::connect(proxy.addr).await.unwrap().into_split();
    let started = Instant::now();
    writer
        .write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let head = read_until(&mut reader, b"\r\n\r\n").await;
    let head_after = started.elapsed();
    let rest = read_until(&mut reader, b"late body").await;

    assert!(
        head_after < LATE_BODY_DELAY,
        "the head must not wait for a body slower than the commit window: {head_after:?}"
    );
    let response = RawResponse::parse(&[head, rest].concat());
    assert_eq!(response.status, 200, "the response is the upstream's");
    assert_eq!(response.body, "late body", "the late body follows the head");
}

#[tokio::test]
async fn body_filter_failing_after_the_commit_cuts_the_response() {
    let backend = Backend::start(Reply::Late("late body")).await;
    let yaml = routed_yaml(backend.addr, &format!("\n      - filter: {FAILING_BODY_FILTER}\n"));
    let proxy = Proxy::start_with(&yaml, &failing_registry()).await;

    let response = RawResponse::parse(&proxy.send_lossy("GET / HTTP/1.1\r\nHost: a\r\n\r\n").await);

    assert_eq!(response.status, 200, "a head already sent cannot turn into a 500");
    assert_eq!(
        response.header("content-length"),
        Some("9"),
        "the head promised the whole body"
    );
    assert!(
        response.body.is_empty(),
        "the failed body is cut off rather than delivered: {}",
        response.body
    );
}

#[tokio::test]
async fn head_over_http2_ends_the_stream_with_its_headers() {
    let backend = Backend::start(Reply::Fixed(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".to_vec())).await;
    let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;

    let reply = proxy.h2_request(Method::HEAD, "/").await;

    assert_eq!(reply.head.status, 200, "HEAD is answered");
    assert!(reply.ended_with_head, "the header block ends a HEAD response's stream");
    assert!(reply.body.is_empty(), "no body follows a HEAD response");
    assert!(reply.error.is_none(), "the stream ends cleanly: {:?}", reply.error);
}

#[tokio::test]
async fn no_content_and_not_modified_carry_no_body_on_either_protocol() {
    for (status, head) in [
        (204, "HTTP/1.1 204 No Content\r\n\r\n"),
        (304, "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n\r\n"),
    ] {
        let backend = Backend::start(Reply::Fixed(head.as_bytes().to_vec())).await;
        let proxy = Proxy::start(&routed_yaml(backend.addr, "")).await;

        let over_h1 = proxy.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n").await;
        let over_h2 = proxy.h2_request(Method::GET, "/").await;

        assert_eq!(
            over_h1.status, status,
            "the upstream's {status} reaches an HTTP/1.1 client"
        );
        assert!(
            over_h1.body.is_empty() && over_h1.header("transfer-encoding").is_none(),
            "a {status} carries no body and no body framing: {:?}",
            over_h1.headers
        );
        assert_eq!(
            over_h2.head.status, status,
            "the upstream's {status} reaches an HTTP/2 client"
        );
        assert!(
            over_h2.ended_with_head,
            "a {status} ends its HTTP/2 stream with the headers"
        );
    }
}

#[tokio::test]
async fn upstream_trailers_reach_an_http2_client() {
    let upstream = start_h2_backend().await;
    let yaml = with_cluster(
        &routed_yaml(upstream, ""),
        "            http:\n              version: h2\n",
    );
    let proxy = Proxy::start(&yaml).await;

    let reply = proxy.h2_request(Method::GET, "/").await;

    assert_eq!(reply.body, b"hi", "the upstream body reaches the client");
    assert_eq!(
        reply
            .trailers
            .as_ref()
            .and_then(|trailers| trailers.get("x-checksum"))
            .and_then(|value| value.to_str().ok()),
        Some("abc"),
        "the upstream's trailers end the client's stream: {:?}",
        reply.error
    );
}

#[tokio::test]
async fn refused_upstream_is_counted_as_upstream_unavailable() {
    crate::http::metrics::install_prometheus_recorder();
    let before = errors_total("upstream_unavailable");
    let proxy = Proxy::start(&labelled(&routed_yaml(closed_port(), ""), "counted-502")).await;

    let response = proxy.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n").await;

    assert_eq!(response.status, 502, "a refused connection is a 502");
    assert!(
        errors_total("upstream_unavailable") > before,
        "and is counted as praxis_errors_total{{type=\"upstream_unavailable\"}}"
    );
    assert_eq!(requests_total("counted-502"), 1, "the request is counted once");
}

#[tokio::test]
async fn upstream_read_timeout_is_counted_as_timeout() {
    crate::http::metrics::install_prometheus_recorder();
    let before = errors_total("timeout");
    let backend = Backend::start(Reply::Silent).await;
    let yaml = labelled(&routed_yaml(backend.addr, ""), "counted-504");
    let proxy = Proxy::start(&with_cluster(&yaml, "            read_timeout_ms: 200\n")).await;

    let response = proxy.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n").await;

    assert_eq!(response.status, 504, "an upstream that never answers is a 504");
    assert!(
        errors_total("timeout") > before,
        "and is counted as praxis_errors_total{{type=\"timeout\"}}"
    );
    assert_eq!(requests_total("counted-504"), 1, "the request is counted once");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A proxy config routing everything to `backend`, with `filters` first.
fn routed_yaml(backend: SocketAddr, filters: &str) -> String {
    let port = free_port();
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:{filters}
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "{backend}"
runtime:
  threads: 2
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// `yaml` with its listener and cluster renamed to `name`, so the metric
/// series a test reads are its own.
fn labelled(yaml: &str, name: &str) -> String {
    yaml.replace("name: default", &format!("name: {name}"))
        .replace("\"backend\"", &format!("\"{name}\""))
}

/// `yaml` with `settings`, YAML at the cluster's indentation, added to its
/// cluster.
fn with_cluster(yaml: &str, settings: &str) -> String {
    yaml.replace("            endpoints:", &format!("{settings}            endpoints:"))
}

/// A cluster retry policy that retries resets, POSTs included, with a token
/// backoff.
const RESET_RETRIES: &str = "
            retry_policy:
              max_retries: 2
              allow_non_idempotent: true
              retriable_conditions: [connect_failure, reset]
              backoff:
                base_interval_ms: 1
                max_interval_ms: 5
";

/// How long [`Reply::Late`] holds its body back: far past the first-chunk
/// wait of the response commit.
const LATE_BODY_DELAY: Duration = Duration::from_millis(800); // 800 ms

/// How long a released upstream connection may take to be back in the pool.
const POOL_SETTLE: Duration = Duration::from_millis(100); // 100 ms

/// How long a second completion of one request would take to show.
const COMPLETION_SETTLE: Duration = Duration::from_millis(100); // 100 ms

/// A `POST /upload` with a `length`-byte body.
fn post_of(length: usize) -> String {
    let body = "x".repeat(length);
    format!("POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: {length}\r\n\r\n{body}")
}

/// A body size past the retry replay buffer, so a retry could not send it
/// again.
fn past_replay_limit() -> usize {
    usize::try_from(DEFAULT_RETRY_BODY_LIMIT_BYTES)
        .unwrap()
        .saturating_mul(2)
}

/// Bytes of request body sent at an upstream that never reads it: well past
/// what the sockets in between can buffer.
const LARGE_BODY_BYTES: usize = 16_777_216; // 16 MiB

/// How much of a large body [`write_large_body`] sends per write.
const LARGE_BODY_CHUNK_BYTES: usize = 65_536; // 64 KiB

/// Send a `POST /upload` with a `length`-byte body; stops when the proxy
/// stops reading.
async fn write_large_body(mut writer: tokio::net::tcp::OwnedWriteHalf, length: usize) -> std::io::Result<()> {
    let head = format!("POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: {length}\r\n\r\n");
    writer.write_all(head.as_bytes()).await?;
    let chunk = vec![b'x'; LARGE_BODY_CHUNK_BYTES];
    for _chunk in 0..length.div_ceil(chunk.len()) {
        writer.write_all(&chunk).await?;
    }
    Ok(())
}

/// Read until `needle` arrives, the connection ends, or reading fails.
async fn read_until(reader: &mut tokio::net::tcp::OwnedReadHalf, needle: &[u8]) -> Vec<u8> {
    let mut raw = Vec::new();
    while !raw.windows(needle.len()).any(|window| window == needle) {
        match reader.read_buf(&mut raw).await {
            Ok(0) | Err(_) => break,
            Ok(_read) => {},
        }
    }
    raw
}

/// Read until the connection ends or fails.
async fn read_to_close(reader: &mut tokio::net::tcp::OwnedReadHalf) -> Vec<u8> {
    let mut raw = Vec::new();
    loop {
        match reader.read_buf(&mut raw).await {
            Ok(0) | Err(_) => return raw,
            Ok(_read) => {},
        }
    }
}

/// A `200 OK` with `body` and its length.
fn ok(body: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
}

/// A port nothing listens on.
fn closed_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

/// A port free to bind right now.
fn free_port() -> u16 {
    closed_port().port()
}

/// The `praxis_http_active_requests` gauge for `listener`, if exported.
fn active_requests(listener: &str) -> Option<u64> {
    let scrape = crate::http::metrics::render_prometheus()?;
    let prefix = format!("praxis_http_active_requests{{listener=\"{listener}\"}} ");
    scrape
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(|value| value.trim().parse::<f64>().ok())
        .and_then(|value| format!("{value:.0}").parse().ok())
}

/// The sum of the exported `metric` series that carry `label`
/// (`name="value"`); 0 when there are none.
fn metric_sum(metric: &str, label: &str) -> u64 {
    let Some(scrape) = crate::http::metrics::render_prometheus() else {
        return 0;
    };
    let series = format!("{metric}{{");
    let total: f64 = scrape
        .lines()
        .filter(|line| line.starts_with(&series) && line.contains(label))
        .filter_map(|line| line.rsplit_once(' '))
        .filter_map(|(_series, value)| value.trim().parse::<f64>().ok())
        .sum();
    format!("{total:.0}").parse().unwrap_or(0)
}

/// `praxis_errors_total` for `error_type`.
fn errors_total(error_type: &str) -> u64 {
    metric_sum("praxis_errors_total", &format!("type=\"{error_type}\""))
}

/// `praxis_http_requests_total` over every series for `cluster`.
fn requests_total(cluster: &str) -> u64 {
    metric_sum("praxis_http_requests_total", &format!("cluster=\"{cluster}\""))
}

/// The requests counted for `cluster` once the first one completed and a
/// second completion of it would have shown.
async fn completed_requests(cluster: &str) -> u64 {
    eventually(|| requests_total(cluster) > 0, "the request completes").await;
    tokio::time::sleep(COMPLETION_SETTLE).await;
    requests_total(cluster)
}

/// Wait up to two seconds for `check` to hold.
async fn eventually(check: impl Fn() -> bool, what: &str) {
    for _attempt in 0..200 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{what}");
}

/// A proxy runtime serving one configuration on its own thread.
struct Proxy {
    /// Where the proxy listens.
    addr: SocketAddr,

    /// Stops the runtime.
    stop: Arc<Notify>,

    /// The runtime's thread.
    thread: Option<JoinHandle<()>>,
}

impl Proxy {
    /// Send a request over HTTP/2 with prior knowledge and read the response
    /// however its stream ends.
    async fn h2_request(&self, method: Method, path: &str) -> H2Reply {
        let exchange = Box::pin(h2_exchange(self.addr, method, path));
        tokio::time::timeout(Duration::from_secs(10), exchange)
            .await
            .expect("the proxy ends the HTTP/2 response in time")
    }

    /// Send a raw HTTP/1.1 request on a new connection and read the response
    /// until the proxy closes it.
    async fn send(&self, request: &str) -> RawResponse {
        let request = request.replacen("\r\n", "\r\nConnection: close\r\n", 1);
        let mut client = TcpStream::connect(self.addr).await.unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut raw))
            .await
            .expect("the proxy answers in time")
            .unwrap();
        RawResponse::parse(&raw)
    }

    /// Send a GET for `path` over HTTP/2 with prior knowledge.
    async fn send_h2(&self, path: &str) -> (u16, http::HeaderMap, String) {
        let reply = self.h2_request(Method::GET, path).await;
        assert!(reply.error.is_none(), "the stream ends cleanly: {:?}", reply.error);
        (
            reply.head.status.as_u16(),
            reply.head.headers,
            String::from_utf8(reply.body).unwrap(),
        )
    }

    /// Send a raw HTTP/1.1 request on a new connection and read whatever
    /// arrives until the proxy closes or resets it.
    async fn send_lossy(&self, request: &str) -> Vec<u8> {
        let request = request.replacen("\r\n", "\r\nConnection: close\r\n", 1);
        let (mut reader, mut writer) = TcpStream::connect(self.addr).await.unwrap().into_split();
        writer.write_all(request.as_bytes()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), read_to_close(&mut reader))
            .await
            .expect("the proxy ends the response in time")
    }

    /// Build the pipelines for `yaml` from the builtin filters, register the
    /// adapter, and serve.
    async fn start(yaml: &str) -> Self {
        Self::start_with(yaml, &FilterRegistry::with_builtins()).await
    }

    /// Build the pipelines for `yaml` from `registry`, register the adapter,
    /// and serve.
    async fn start_with(yaml: &str, registry: &FilterRegistry) -> Self {
        let config = Config::from_yaml(yaml).unwrap();
        let addr: SocketAddr = config.listeners[0].address.parse().unwrap();
        let mut runtime = HyperRuntime::new(&config);
        let _watchers = HyperHttp::register_on(&mut runtime, &config, &pipelines(&config, registry)).unwrap();
        let stop = Arc::new(Notify::new());
        let notified = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            runtime.run_with_shutdown(Box::pin(async move { notified.notified().await }));
        });
        for _attempt in 0..200 {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Self {
            addr,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.notify_one();
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
    }
}

/// The listener pipelines for `config`, built from `registry` as the server
/// builds them.
fn pipelines(config: &Config, registry: &FilterRegistry) -> ListenerPipelines {
    let expanded = ExpandedFilterChains::new(&config.filter_chains);
    let chains = expanded.as_slices();
    let mut built = HashMap::new();
    for listener in &config.listeners {
        let mut entries = expanded.for_listener(listener).unwrap();
        let mut pipeline = FilterPipeline::build_with_chains(
            &mut entries,
            registry,
            &chains,
            &config.insecure_options,
            &config.clusters,
        )
        .unwrap();
        pipeline
            .apply_body_limits(
                config.body_limits.max_request_bytes,
                config.body_limits.max_response_bytes,
                config.insecure_options.allow_unbounded_body,
            )
            .unwrap();
        pipeline.set_allow_private_upstreams(config.insecure_options.allow_private_upstreams);
        built.insert(listener.name.clone(), Arc::new(pipeline));
    }
    ListenerPipelines::new(built)
}

/// A response read off the wire.
struct RawResponse {
    /// The body, as text.
    body: String,

    /// The headers, lowercased names.
    headers: Vec<(String, String)>,

    /// The status code.
    status: u16,
}

impl RawResponse {
    /// The first value of `name`.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _value)| header == name)
            .map(|(_header, value)| value.as_str())
    }

    /// Parse a whole HTTP/1.1 response with a length-delimited body.
    fn parse(raw: &[u8]) -> Self {
        let text = String::from_utf8_lossy(raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
        let mut lines = head.lines();
        let status = lines
            .next()
            .unwrap_or_default()
            .split(' ')
            .nth(1)
            .unwrap_or("0")
            .parse()
            .unwrap();
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        Self {
            body: body.to_owned(),
            headers,
            status,
        }
    }
}

/// A response read off an HTTP/2 stream.
struct H2Reply {
    /// The body bytes received before the stream ended or failed.
    body: Vec<u8>,

    /// Whether the header block ended the stream.
    ended_with_head: bool,

    /// What the stream ended in, if it did not end cleanly.
    error: Option<h2::Error>,

    /// The status and headers.
    head: http::response::Parts,

    /// The trailers the stream ended with, if any.
    trailers: Option<http::HeaderMap>,
}

/// One HTTP/2 request with prior knowledge to `addr`, read to the end of
/// its response stream.
async fn h2_exchange(addr: SocketAddr, method: Method, path: &str) -> H2Reply {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (mut client, connection) = h2::client::handshake(tcp).await.unwrap();
    drop(tokio::spawn(connection));
    let request = http::Request::builder()
        .method(method)
        .uri(format!("http://example.test{path}"))
        .body(())
        .unwrap();
    let (response, _stream) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    let ended_with_head = response.body().is_end_stream();
    let (head, body) = response.into_parts();
    let mut reply = H2Reply {
        body: Vec::new(),
        ended_with_head,
        error: None,
        head,
        trailers: None,
    };
    read_h2_body(body, &mut reply).await;
    reply
}

/// Read `body` into `reply` to the end of its stream: the data, then the
/// trailers or the error the stream ended in.
async fn read_h2_body(mut body: h2::RecvStream, reply: &mut H2Reply) {
    while let Some(chunk) = body.data().await {
        match chunk {
            Ok(chunk) => {
                let _released = body.flow_control().release_capacity(chunk.len());
                reply.body.extend_from_slice(&chunk);
            },
            Err(err) => {
                reply.error = Some(err);
                return;
            },
        }
    }
    match body.trailers().await {
        Ok(trailers) => reply.trailers = trailers,
        Err(err) => reply.error = Some(err),
    }
}

/// How the test backend answers.
#[derive(Clone)]
enum Reply {
    /// Write a chunked head and one chunk, then close the connection without
    /// the chunk that ends the body.
    AbortMidBody,

    /// Record the request head at once, then read the body until it ends or
    /// the connection does, recording which; never answer.
    Absorb,

    /// Read the request head, then neither read the body nor answer.
    Deaf,

    /// Write a head and the start of a body, then the rest a byte at a time.
    Dribble,

    /// Write these bytes as soon as the request head is in, then never read.
    Early(Vec<u8>),

    /// Write these bytes.
    Fixed(Vec<u8>),

    /// Answer the first request on each connection with these bytes; read a
    /// later one whole, then close the connection without answering it.
    KillOnReuse(Vec<u8>),

    /// Write a `200` head with this body's length at once, and the body
    /// after [`LATE_BODY_DELAY`].
    Late(&'static str),

    /// Answer the warmup, then record each whole POST and close after a
    /// partial response head, including on fresh connections.
    PartialHeadAfterWarm,

    /// Read the first connection's request whole, then close it without
    /// answering; answer every later request with these bytes.
    ResetFirst(Vec<u8>),

    /// Read the request and never answer.
    Silent,
}

/// A request the backend received.
#[derive(Clone, Debug)]
struct Captured {
    /// The body.
    body: String,

    /// Whether the body arrived whole: `None` while it is still being read,
    /// or when it is never read.
    body_complete: Option<bool>,

    /// Which backend connection it came on, in accept order from 0.
    connection: usize,

    /// The request line and headers.
    head: String,
}

impl Captured {
    /// The first value of header `name`, case-insensitively.
    fn header(&self, name: &str) -> Option<&str> {
        header_in(&self.head, name)
    }
}

/// A raw HTTP/1 backend that records what it receives.
struct Backend {
    /// Where it listens.
    addr: SocketAddr,

    /// What it received, in order.
    received: Arc<Mutex<Vec<Captured>>>,
}

impl Backend {
    /// The single request received.
    fn only_request(&self) -> Captured {
        let requests = self.requests();
        assert_eq!(
            requests.len(),
            1,
            "exactly one request reaches the upstream: {requests:?}"
        );
        requests.into_iter().next().unwrap()
    }

    /// Every request received so far.
    fn requests(&self) -> Vec<Captured> {
        self.received.lock().unwrap().clone()
    }

    /// Start a backend answering every request with `reply`.
    async fn start(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&received);
        drop(tokio::spawn(async move {
            let mut connection = 0_usize;
            while let Ok((socket, _peer)) = listener.accept().await {
                let served = serve(socket, connection, reply.clone(), Arc::clone(&log));
                drop(tokio::spawn(Box::pin(served)));
                connection = connection.saturating_add(1);
            }
        }));
        Self { addr, received }
    }
}

/// Serve requests on backend connection number `connection`.
async fn serve(mut socket: TcpStream, connection: usize, reply: Reply, log: Arc<Mutex<Vec<Captured>>>) {
    match &reply {
        Reply::Absorb => return absorb(socket, connection, &log).await,
        Reply::Deaf => return answer_early(socket, connection, b"", &log).await,
        Reply::Early(bytes) => return answer_early(socket, connection, bytes, &log).await,
        Reply::AbortMidBody
        | Reply::Dribble
        | Reply::Fixed(_)
        | Reply::KillOnReuse(_)
        | Reply::Late(_)
        | Reply::PartialHeadAfterWarm
        | Reply::ResetFirst(_)
        | Reply::Silent => {},
    }
    let mut answered = 0_usize;
    while let Some(captured) = read_request(&mut socket, connection).await {
        log.lock().unwrap().push(captured);
        let turn = Turn { answered, connection };
        if !Box::pin(respond(&mut socket, &reply, turn)).await {
            return;
        }
        answered = answered.saturating_add(1);
    }
}

/// Where a backend connection is when it answers a request.
#[derive(Clone, Copy)]
struct Turn {
    /// Requests the connection answered before this one.
    answered: usize,

    /// The connection's number, in accept order from 0.
    connection: usize,
}

/// Answer one request as `reply` says; `false` once the connection is to
/// close.
async fn respond(socket: &mut TcpStream, reply: &Reply, turn: Turn) -> bool {
    match reply {
        Reply::Fixed(bytes) => socket.write_all(bytes).await.is_ok(),
        Reply::KillOnReuse(bytes) => turn.answered == 0 && socket.write_all(bytes).await.is_ok(),
        Reply::ResetFirst(bytes) => turn.connection > 0 && socket.write_all(bytes).await.is_ok(),
        Reply::PartialHeadAfterWarm => partial_head_after_warm(socket, turn).await,
        Reply::AbortMidBody => {
            let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
            let _sent = socket.write_all(head).await;
            false
        },
        Reply::Late(body) => {
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            if socket.write_all(head.as_bytes()).await.is_err() {
                return false;
            }
            tokio::time::sleep(LATE_BODY_DELAY).await;
            socket.write_all(body.as_bytes()).await.is_ok()
        },
        Reply::Dribble => dribble(socket).await,
        Reply::Absorb | Reply::Deaf | Reply::Early(_) | Reply::Silent => {
            tokio::time::sleep(Duration::from_secs(30)).await;
            true
        },
    }
}

/// Keep the warmup connection alive, then fail every later response after
/// sending an incomplete head.
async fn partial_head_after_warm(socket: &mut TcpStream, turn: Turn) -> bool {
    if turn.connection == 0 && turn.answered == 0 {
        return socket.write_all(&ok("warm")).await.is_ok();
    }
    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: ").await.unwrap();
    false
}

/// Write a `200` head and the start of its body, then the rest a byte at a
/// time; `false` once the client is gone.
async fn dribble(socket: &mut TcpStream) -> bool {
    let _sent = socket
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nfirst")
        .await;
    for _byte in 0..900 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if socket.write_all(b".").await.is_err() {
            return false;
        }
    }
    true
}

/// Record the request head as soon as it is in, then read the body until it
/// ends or the connection does, recording whether it arrived whole.
async fn absorb(mut socket: TcpStream, connection: usize, log: &Mutex<Vec<Captured>>) {
    let mut buffer = Vec::new();
    let Some(head_end) = read_head(&mut socket, &mut buffer).await else {
        return;
    };
    let mut body = buffer.split_off(head_end.saturating_add(4));
    buffer.truncate(head_end);
    let head = String::from_utf8_lossy(&buffer).into_owned();
    let length = content_length(&head);
    let index = {
        let mut log = log.lock().unwrap();
        log.push(Captured {
            body: String::new(),
            body_complete: None,
            connection,
            head,
        });
        log.len().saturating_sub(1)
    };
    while body.len() < length {
        match socket.read_buf(&mut body).await {
            Ok(0) | Err(_) => break,
            Ok(_read) => {},
        }
    }
    if let Some(seen) = log.lock().unwrap().get_mut(index) {
        seen.body_complete = Some(body.len() >= length);
        seen.body = String::from_utf8_lossy(&body).into_owned();
    }
}

/// Answer with `bytes` (perhaps none) as soon as the request head is in,
/// then hold the connection open without reading the body.
async fn answer_early(mut socket: TcpStream, connection: usize, bytes: &[u8], log: &Mutex<Vec<Captured>>) {
    let mut buffer = Vec::new();
    let Some(head_end) = read_head(&mut socket, &mut buffer).await else {
        return;
    };
    log.lock().unwrap().push(Captured {
        body: String::new(),
        body_complete: None,
        connection,
        head: String::from_utf8_lossy(&buffer[..head_end]).into_owned(),
    });
    if socket.write_all(bytes).await.is_ok() {
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

/// Read one request with a length-delimited (or no) body from connection
/// number `connection`.
async fn read_request(socket: &mut TcpStream, connection: usize) -> Option<Captured> {
    let mut buffer = Vec::new();
    let head_end = read_head(socket, &mut buffer).await?;
    let mut body = buffer.split_off(head_end.saturating_add(4));
    buffer.truncate(head_end);
    let head = String::from_utf8_lossy(&buffer).into_owned();
    let length = content_length(&head);
    while body.len() < length {
        if socket.read_buf(&mut body).await.ok()? == 0 {
            return None;
        }
    }
    Some(Captured {
        body: String::from_utf8_lossy(&body).into_owned(),
        body_complete: Some(true),
        connection,
        head,
    })
}

/// Read into `buffer` until it holds a whole request head; where it ends.
async fn read_head(socket: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<usize> {
    loop {
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            return Some(end);
        }
        if socket.read_buf(buffer).await.ok()? == 0 {
            return None;
        }
    }
}

/// The first value of header `name` in a request or response head,
/// case-insensitively.
fn header_in<'head>(head: &'head str, name: &str) -> Option<&'head str> {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(header, _value)| header.trim().eq_ignore_ascii_case(name))
        .map(|(_header, value)| value.trim())
}

/// The `Content-Length` a head declares; 0 when it declares none.
fn content_length(head: &str) -> usize {
    header_in(head, "content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// Start an HTTP/2 backend, prior knowledge only, answering every stream
/// with a `200`, the body `hi` and an `x-checksum: abc` trailer.
async fn start_h2_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(tokio::spawn(async move {
        while let Ok((socket, _peer)) = listener.accept().await {
            drop(tokio::spawn(Box::pin(serve_h2(socket))));
        }
    }));
    addr
}

/// Answer every stream of one HTTP/2 connection with a body and trailers.
async fn serve_h2(socket: TcpStream) {
    let Ok(mut connection) = h2::server::handshake(socket).await else {
        return;
    };
    while let Some(Ok((_request, mut respond))) = connection.accept().await {
        let Ok(mut stream) = respond.send_response(http::Response::new(()), false) else {
            return;
        };
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-checksum", http::HeaderValue::from_static("abc"));
        if stream.send_data(Bytes::from_static(b"hi"), false).is_err() || stream.send_trailers(trailers).is_err() {
            return;
        }
    }
}

/// Registry name of [`FailingResponseBody`].
const FAILING_BODY_FILTER: &str = "failing_response_body";

/// A response body filter that fails on every chunk.
struct FailingResponseBody;

#[async_trait::async_trait]
impl HttpFilter for FailingResponseBody {
    fn name(&self) -> &'static str {
        FAILING_BODY_FILTER
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Err("response body inspection failed".to_owned().into())
    }
}

/// The builtin filters plus [`FailingResponseBody`].
fn failing_registry() -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    let factory = FilterFactory::Http(Arc::new(|_config| Ok(Box::new(FailingResponseBody))));
    registry.register(FAILING_BODY_FILTER, factory).unwrap();
    registry
}
