// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Hot-reload resilience: concurrent traffic during pipeline swaps and
//! debounce behavior under rapid config rewrites.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_reloadable_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// N clients hammer the proxy while the config is rewritten repeatedly
/// between two upstream generations. Every response must be a 200 from
/// exactly one generation — no errors, no torn or mixed pipelines.
#[test]
fn reload_under_load_every_response_from_one_generation() {
    let backend_a = start_backend_with_shutdown("gen-a");
    let backend_b = start_backend_with_shutdown("gen-b");
    let proxy_port = free_port();

    let proxy = start_reloadable_proxy(&proxy_yaml(proxy_port, backend_a.port()));

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "initial request should succeed");
    assert_eq!(body, "gen-a", "should serve generation A initially");

    let stop = Arc::new(AtomicBool::new(false));
    let addr = Arc::new(proxy.addr().to_owned());
    let num_clients = 8;

    let clients: Vec<_> = (0..num_clients)
        .map(|_| {
            let stop = Arc::clone(&stop);
            let addr = Arc::clone(&addr);
            thread::spawn(move || {
                let mut requests = 0_u32;
                let mut saw_gen_b = false;
                let mut bad: Vec<(u16, String)> = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    let (status, body) = http_get(&addr, "/", None);
                    requests += 1;
                    saw_gen_b |= body == "gen-b";
                    if status != 200 || (body != "gen-a" && body != "gen-b") {
                        bad.push((status, body));
                    }
                }
                (requests, saw_gen_b, bad)
            })
        })
        .collect();

    // Flip the config between generations while clients are running.
    // Each write is spaced past the 500ms watcher debounce so every
    // rewrite becomes a real pipeline swap under live traffic.
    for i in 0..6 {
        let port = if i % 2 == 0 { backend_b.port() } else { backend_a.port() };
        proxy.write_config(&proxy_yaml(proxy_port, port));
        thread::sleep(Duration::from_millis(700));
    }

    stop.store(true, Ordering::Relaxed);

    let mut total_requests = 0;
    let mut any_saw_gen_b = false;
    for (i, client) in clients.into_iter().enumerate() {
        let (requests, saw_gen_b, bad) = client.join().expect("client thread should not panic");
        total_requests += requests;
        any_saw_gen_b |= saw_gen_b;
        assert!(
            bad.is_empty(),
            "client {i}: {} of {requests} responses were not a clean 200 from one generation: {:?}",
            bad.len(),
            bad.first()
        );
    }
    assert!(
        total_requests > 100,
        "clients should sustain load across the swaps (got {total_requests} requests)"
    );
    // Without this the test passes even if hot reload never fires: the
    // proxy starts on generation A and every response above is valid.
    assert!(
        any_saw_gen_b,
        "the config swaps must actually take effect: no client ever saw generation B"
    );
}

/// A burst of rewrites inside one debounce window collapses to a single
/// swap: intermediate configs are never served, the final one is, and
/// the proxy keeps answering throughout.
#[test]
fn rapid_rewrites_debounce_to_final_config() {
    let backend = start_backend_with_shutdown("origin");
    let proxy_port = free_port();

    let proxy = start_reloadable_proxy(&proxy_yaml(proxy_port, backend.port()));

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "initial request should succeed");
    assert_eq!(body, "origin", "should proxy to the backend initially");

    // 10 rewrites well inside the 500ms debounce window; only the last
    // must ever take effect.
    for i in 0..9 {
        proxy.write_config(&static_yaml(proxy_port, &format!("intermediate-{i}")));
        thread::sleep(Duration::from_millis(10));
    }
    proxy.write_config(&static_yaml(proxy_port, "final"));

    // Observe continuously until the final config serves. Every response
    // on the way must be the old generation or the final one — an
    // intermediate body means the debounce applied a stale config.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "proxy must keep serving during the debounce window");
        assert!(
            body == "origin" || body == "final",
            "only the pre-burst or final config may ever serve, got {body:?}"
        );
        if body == "final" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "final config should apply within the deadline"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

// -----------------------------------------------------------------------------
// Config YAML
// -----------------------------------------------------------------------------

/// Minimal proxy config routing everything to one backend.
fn proxy_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
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
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// Proxy config answering every request with a static body.
fn static_yaml(proxy_port: u16, body: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        body: "{body}"
"#
    )
}
