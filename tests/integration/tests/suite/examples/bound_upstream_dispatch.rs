// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the bound-upstream dispatch example.
//!
//! One pipeline drives two ownership modes from the same frozen logical
//! binding: a provider-owned request is dispatched directly by a branch whose
//! `cluster_source: bound_upstream` load balancer reads the binding, while every
//! other request runs gateway-owned processing and an `iterative_request_router`
//! whose step dispatches from the same binding. Neither path uses a second
//! router or a top-level load balancer.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use praxis_test_utils::{
    allow_loopback_endpoints, example_config_path, free_port, http_send, parse_body, parse_header, parse_status,
    patch_yaml, start_backend_with_shutdown, start_echo_backend, start_reloadable_proxy,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn dual_path_dispatches_both_modes_from_one_binding() {
    let openai = start_backend_with_shutdown("openai");
    let chat = start_backend_with_shutdown("chat");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/bound-upstream-dispatch.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", openai.port()), ("127.0.0.1:3002", chat.port())]),
    );
    let proxy = praxis_test_utils::start_full_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /openai/v1/responses HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "direct provider path should return 200");
    assert_eq!(
        parse_body(&raw),
        "openai",
        "the /openai/ route binds openai, so the direct branch should reach the openai backend"
    );
    assert_eq!(
        parse_header(&raw, "X-Gateway-Processed"),
        None,
        "direct path must skip gateway-owned processing and the IRR (branch rejoins terminal)"
    );

    let raw = http_send(
        proxy.addr(),
        "GET /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "gateway + IRR path should return 200");
    assert_eq!(
        parse_body(&raw),
        "chat",
        "the catch-all route binds chat, so the IRR step's bound load balancer should reach the chat backend"
    );
    assert_eq!(
        parse_header(&raw, "X-Gateway-Processed").as_deref(),
        Some("true"),
        "non-provider path should run gateway-owned processing before the IRR"
    );

    let query = http_send(
        proxy.addr(),
        "GET /openai/v1/responses?stream=false HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_body(&query),
        "openai",
        "the query string must not change prefix routing"
    );

    let boundary = http_send(
        proxy.addr(),
        "GET /openai HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_body(&boundary),
        "openai",
        "the configured trailing slash is normalized at the /openai segment boundary"
    );
}

#[test]
fn direct_path_preserves_body_and_applies_pipeline_wide_limit() {
    let openai = start_echo_backend();
    let chat = start_backend_with_shutdown("chat");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/bound-upstream-dispatch.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", openai.port()), ("127.0.0.1:3002", chat.port())]),
    );
    let proxy = praxis_test_utils::start_full_proxy(&config);

    let body = "provider-body";
    let request = format!(
        "POST /openai/v1/responses HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let response = http_send(proxy.addr(), &request);
    assert_eq!(
        parse_status(&response),
        200,
        "a direct-path POST within the limit should return 200"
    );
    assert_eq!(parse_body(&response), body, "buffering must preserve direct-path bytes");

    let oversized = "x".repeat(65_537);
    let request = format!(
        "POST /openai/v1/responses HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{oversized}",
        oversized.len()
    );
    let response = http_send(proxy.addr(), &request);
    assert_eq!(
        parse_status(&response),
        413,
        "the IRR StreamBuffer ceiling applies before the direct branch"
    );
}

#[test]
fn each_request_reaches_exactly_one_backend_once() {
    let openai = start_counting_backend("openai");
    let chat = start_counting_backend("chat");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/bound-upstream-dispatch.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", openai.port), ("127.0.0.1:3002", chat.port)]),
    );
    let proxy = praxis_test_utils::start_full_proxy(&config);

    let direct = http_send(proxy.addr(), &get("/openai/v1/responses", true));
    let hits_after_direct = (openai.hits(), chat.hits());
    let gateway = http_send(proxy.addr(), &get("/v1/chat/completions", true));

    assert_eq!(
        parse_body(&direct),
        "openai",
        "the direct path reaches the openai backend"
    );
    assert_eq!(
        hits_after_direct,
        (1, 0),
        "the direct branch dispatches once and the IRR never runs"
    );
    assert_eq!(parse_body(&gateway), "chat", "the IRR path reaches the chat backend");
    assert_eq!(
        (openai.hits(), chat.hits()),
        (1, 1),
        "the IRR step dispatches once and the direct branch does not fire again"
    );
}

#[test]
fn bindings_stay_separate_on_one_keep_alive_connection_and_in_parallel() {
    let openai = start_backend_with_shutdown("openai");
    let chat = start_backend_with_shutdown("chat");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/bound-upstream-dispatch.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", openai.port()), ("127.0.0.1:3002", chat.port())]),
    );
    let proxy = praxis_test_utils::start_full_proxy(&config);
    praxis_test_utils::wait_for_tcp(proxy.addr());
    let mut stream = TcpStream::connect(proxy.addr()).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    for pass in 0..3 {
        let direct = send_keep_alive(&mut stream, &get("/openai/v1/responses", false));
        let gateway = send_keep_alive(&mut stream, &get("/v1/chat/completions", false));

        assert_eq!(parse_body(&direct), "openai", "keep-alive pass {pass}: direct path");
        assert_eq!(
            parse_header(&direct, "X-Gateway-Processed"),
            None,
            "keep-alive pass {pass}: no binding leaks from the previous IRR request"
        );
        assert_eq!(parse_body(&gateway), "chat", "keep-alive pass {pass}: IRR path");
        assert_eq!(
            parse_header(&gateway, "X-Gateway-Processed").as_deref(),
            Some("true"),
            "keep-alive pass {pass}: the gateway marker is set per request"
        );
    }

    let addr = proxy.addr().to_owned();
    let workers: Vec<_> = (0..8)
        .map(|worker| {
            let addr = addr.clone();
            std::thread::spawn(move || {
                let (path, body) = if worker % 2 == 0 {
                    ("/openai/v1/responses", "openai")
                } else {
                    ("/v1/chat/completions", "chat")
                };
                let raw = http_send(&addr, &get(path, true));
                assert_eq!(parse_body(&raw), body, "worker {worker} reaches its own backend");
                assert_eq!(
                    parse_header(&raw, "X-Gateway-Processed").is_some(),
                    body == "chat",
                    "worker {worker} sees the marker only on the IRR path"
                );
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("a parallel request kept its own binding");
    }
}

#[test]
fn head_and_case_sensitive_paths_and_a_dead_backend() {
    let chat = start_backend_with_shutdown("chat");
    let proxy_port = free_port();
    let dead_openai_port = free_port();
    let config = super::load_example_config(
        "traffic-management/bound-upstream-dispatch.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", dead_openai_port), ("127.0.0.1:3002", chat.port())]),
    );
    let proxy = praxis_test_utils::start_full_proxy(&config);

    let head = http_send(
        proxy.addr(),
        "HEAD /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let upper = http_send(proxy.addr(), &get("/OPENAI/v1/responses", true));
    let dead = http_send(proxy.addr(), &get("/openai/v1/responses", true));

    assert_eq!(parse_status(&head), 200, "HEAD dispatches through the IRR path");
    assert_eq!(parse_body(&head), "", "a HEAD response carries no body");
    assert_eq!(
        parse_header(&head, "X-Gateway-Processed").as_deref(),
        Some("true"),
        "HEAD runs the same gateway processing as GET"
    );
    assert_eq!(
        parse_body(&upper),
        "chat",
        "prefix matching is case-sensitive, so /OPENAI/ binds the catch-all chat cluster"
    );
    assert_eq!(parse_status(&dead), 502, "a dead openai backend fails the direct path");
    assert_ne!(
        parse_body(&dead),
        "chat",
        "the direct path never falls back to the chat cluster or the IRR"
    );
}

#[test]
fn chunked_uploads_on_the_direct_path_are_buffered_and_capped() {
    let openai = start_echo_backend();
    let chat = start_backend_with_shutdown("chat");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/bound-upstream-dispatch.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", openai.port()), ("127.0.0.1:3002", chat.port())]),
    );
    let proxy = praxis_test_utils::start_full_proxy(&config);

    let small = http_send(proxy.addr(), &chunked_post("/openai/v1/responses", &["hel", "lo"]));
    let oversized = http_send(
        proxy.addr(),
        &chunked_post("/openai/v1/responses", &["x".repeat(65_537)]),
    );

    assert_eq!(
        parse_status(&small),
        200,
        "a chunked upload within the limit is buffered and forwarded"
    );
    assert_eq!(
        parse_body(&small),
        "hello",
        "the chunks are reassembled before dispatch"
    );
    assert_eq!(
        parse_status(&oversized),
        413,
        "a chunked upload over the IRR's StreamBuffer ceiling is rejected even on the direct path"
    );
}

#[test]
fn hot_reload_rebinds_routes_and_catalog_without_restart() {
    let openai = start_backend_with_shutdown("openai");
    let chat = start_backend_with_shutdown("chat");
    let proxy_port = free_port();
    let source =
        std::fs::read_to_string(example_config_path("traffic-management/bound-upstream-dispatch.yaml")).unwrap();
    let ports = HashMap::from([("127.0.0.1:3001", openai.port()), ("127.0.0.1:3002", chat.port())]);
    let yaml = allow_loopback_endpoints(&patch_yaml(&source, proxy_port, &ports));
    let proxy = start_reloadable_proxy(&yaml);

    let before = http_send(proxy.addr(), &get("/openai/v1/responses", true));
    proxy.reload(&yaml.replace("path_prefix: \"/openai/\"", "path_prefix: \"/provider/\""));
    let moved = http_send(proxy.addr(), &get("/provider/v1/responses", true));
    let old = http_send(proxy.addr(), &get("/openai/v1/responses", true));

    assert_eq!(parse_body(&before), "openai", "the original route binds openai");
    assert_eq!(
        parse_body(&moved),
        "openai",
        "after the reload the new prefix binds openai and takes the direct branch"
    );
    assert_eq!(
        parse_body(&old),
        "chat",
        "after the reload the old prefix falls to the catch-all and the IRR"
    );
    assert_eq!(
        parse_header(&old, "X-Gateway-Processed").as_deref(),
        Some("true"),
        "the rebuilt pipeline runs gateway processing for the rerouted request"
    );
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// A backend answering `tag` that counts the requests it served.
struct CountingBackend {
    hits: Arc<AtomicUsize>,
    port: u16,
}

impl CountingBackend {
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// A chunked POST request with one chunk per entry of `chunks`.
fn chunked_post(path: &str, chunks: &[impl AsRef<str>]) -> String {
    let body: String = chunks
        .iter()
        .map(|chunk| format!("{:x}\r\n{}\r\n", chunk.as_ref().len(), chunk.as_ref()))
        .collect();
    format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{body}0\r\n\r\n"
    )
}

/// A GET request, closing the connection afterwards when `close` is set.
fn get(path: &str, close: bool) -> String {
    let close = if close { "Connection: close\r\n" } else { "" };
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{close}\r\n")
}

/// Send one request on an open keep-alive connection and read the whole
/// response, which the proxy frames with Content-Length.
fn send_keep_alive(stream: &mut TcpStream, request: &str) -> String {
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let mut byte = [0_u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        assert_eq!(
            stream.read(&mut byte).unwrap(),
            1,
            "the proxy closed the connection mid-header"
        );
        raw.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&raw).into_owned();
    let length: usize = parse_header(&head, "Content-Length")
        .expect("keep-alive responses are framed with Content-Length")
        .parse()
        .unwrap();
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).unwrap();
    raw.extend_from_slice(&body);
    String::from_utf8_lossy(&raw).into_owned()
}

/// Start a backend that serves `tag` to one request per connection and counts
/// the requests it saw.
fn start_counting_backend(tag: &'static str) -> CountingBackend {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let served = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            served.fetch_add(1, Ordering::SeqCst);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{tag}",
                tag.len()
            );
            drop(stream.write_all(response.as_bytes()));
        }
    });
    CountingBackend { hits, port }
}
