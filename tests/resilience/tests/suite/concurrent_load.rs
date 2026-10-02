// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for proxy behavior under concurrent load.

use std::{
    sync::{Arc, Barrier},
    thread,
};

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_send, parse_body, parse_status, simple_proxy_yaml, start_backend, start_echo_backend,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Request body sizes the mixed workload rotates through.
const BODY_SIZES: [usize; 4] = [0, 1_024, 16_384, 262_144]; // 0 B, 1 KiB, 16 KiB, 256 KiB

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn concurrent_requests_all_succeed() {
    let backend_port = start_backend("concurrent-ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let num_threads = 10;
    let barrier = Arc::new(Barrier::new(num_threads));
    let addr = Arc::new(proxy.addr().to_owned());

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let addr = Arc::clone(&addr);
            thread::spawn(move || {
                barrier.wait();
                let (status, body) = http_get(&addr, "/", None);
                (status, body)
            })
        })
        .collect();

    for (i, handle) in handles.into_iter().enumerate() {
        let (status, body) = handle.join().expect("thread should not panic");
        assert_eq!(status, 200, "concurrent request {i} should return 200");
        assert_eq!(body, "concurrent-ok", "concurrent request {i} should get correct body");
    }
}

#[test]
fn concurrent_requests_to_dead_backend_all_return_502() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let num_threads = 10;
    let barrier = Arc::new(Barrier::new(num_threads));
    let addr = Arc::new(proxy.addr().to_owned());

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let addr = Arc::clone(&addr);
            thread::spawn(move || {
                barrier.wait();
                let (status, _) = http_get(&addr, "/", None);
                status
            })
        })
        .collect();

    for (i, handle) in handles.into_iter().enumerate() {
        let status = handle.join().expect("thread should not panic");
        assert_eq!(status, 502, "concurrent request {i} to dead backend should return 502");
    }
}

#[test]
fn sequential_burst_all_succeed() {
    let backend_port = start_backend("burst-ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    for i in 0..50 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "burst request {i} should return 200");
        assert_eq!(body, "burst-ok", "burst request {i} body mismatch");
    }
}

#[test]
fn concurrent_requests_to_multiple_routes() {
    let api_port = start_backend("api-response");
    let web_port = start_backend("web-response");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: api
          - path_prefix: "/"
            cluster: web
      - filter: load_balancer
        clusters:
          - name: api
            endpoints:
              - "127.0.0.1:{api_port}"
          - name: web
            endpoints:
              - "127.0.0.1:{web_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let num_threads = 10;
    let barrier = Arc::new(Barrier::new(num_threads));
    let addr = Arc::new(proxy.addr().to_owned());

    let handles: Vec<_> = (0..num_threads)
        .map(|i| {
            let barrier = Arc::clone(&barrier);
            let addr = Arc::clone(&addr);
            thread::spawn(move || {
                barrier.wait();
                if i % 2 == 0 {
                    let (status, body) = http_get(&addr, "/api/data", None);
                    (status, body, "api-response")
                } else {
                    let (status, body) = http_get(&addr, "/page", None);
                    (status, body, "web-response")
                }
            })
        })
        .collect();

    for (i, handle) in handles.into_iter().enumerate() {
        let (status, body, expected) = handle.join().expect("thread should not panic");
        assert_eq!(status, 200, "concurrent routed request {i} should return 200");
        assert_eq!(
            body, expected,
            "concurrent routed request {i} should reach correct backend"
        );
    }
}

#[test]
fn concurrent_requests_with_mixed_live_dead_backends() {
    let live_port = start_backend("live");
    let dead_port = free_port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
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
            retry_policy:
              max_retries: 0
            endpoints:
              - "127.0.0.1:{live_port}"
              - "127.0.0.1:{dead_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let num_threads = 20;
    let barrier = Arc::new(Barrier::new(num_threads));
    let addr = Arc::new(proxy.addr().to_owned());

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let addr = Arc::clone(&addr);
            thread::spawn(move || {
                barrier.wait();
                let (status, body) = http_get(&addr, "/", None);
                (status, body)
            })
        })
        .collect();

    let mut ok_count = 0_u32;
    let mut err_count = 0_u32;
    for handle in handles {
        let (status, body) = handle.join().expect("thread should not panic");
        match status {
            200 => {
                assert_eq!(body, "live", "200 response should come from live backend");
                ok_count += 1;
            },
            502 => err_count += 1,
            other => panic!("unexpected status {other} under concurrent mixed load"),
        }
    }

    assert!(ok_count > 0, "some concurrent requests should succeed via live backend");
    assert!(err_count > 0, "some concurrent requests should hit dead backend");
}

#[test]
fn concurrent_mixed_methods_sizes_and_routes_all_succeed() {
    let echo = start_echo_backend();
    let static_port = start_backend("static");
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/echo"
            cluster: echo
          - path_prefix: "/"
            cluster: static
      - filter: load_balancer
        clusters:
          - name: echo
            endpoints:
              - "127.0.0.1:{}"
          - name: static
            endpoints:
              - "127.0.0.1:{static_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        echo.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let num_threads = 32;
    let rounds = 8;
    let barrier = Arc::new(Barrier::new(num_threads));
    let handles: Vec<_> = (0..num_threads)
        .map(|worker| {
            let barrier = Arc::clone(&barrier);
            let addr = proxy.addr().to_owned();
            thread::spawn(move || {
                barrier.wait();
                (0..rounds)
                    .map(|round| {
                        let (request, expected) = mixed_request(worker, round);
                        let raw = http_send(&addr, &request);
                        (round, parse_status(&raw), parse_body(&raw), expected)
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();

    for (worker, handle) in handles.into_iter().enumerate() {
        let results = handle.join().expect("worker thread should not panic");
        for (round, status, body, expected) in results {
            assert_eq!(status, 200, "worker {worker} round {round} should succeed");
            assert!(
                body == expected,
                "worker {worker} round {round} should get its own {}-byte body back, got {} bytes",
                expected.len(),
                body.len()
            );
        }
    }

    let (status, body) = http_get(proxy.addr(), "/after", None);
    assert_eq!(status, 200, "proxy should stay responsive after the mixed burst");
    assert_eq!(body, "static", "the static route should still answer");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build request `round` for `worker` in the mixed workload, returning
/// the raw request and the body the client should get back. Methods,
/// routes, and body sizes rotate so concurrent requests differ, and
/// echoed bodies carry the worker and round so a crossed response shows.
fn mixed_request(worker: usize, round: usize) -> (String, String) {
    let method = ["GET", "DELETE", "POST", "PUT"][(worker + round) % 4];
    if matches!(method, "GET" | "DELETE") {
        let request = format!("{method} /static/{worker} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        return (request, "static".to_owned());
    }

    let size = BODY_SIZES[round % BODY_SIZES.len()];
    let body: String = format!("{worker}-{round}-").chars().cycle().take(size).collect();
    let request = format!(
        "{method} /echo/{worker} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {size}\r\n\
         Connection: close\r\n\r\n{body}"
    );
    (request, body)
}
