// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Credential-store parity acceptance tests (#1160, migrated from
//! praxis-proxy/ai#1040).
//!
//! The IPP data plane hit two high-severity credential-store bug classes:
//! secrets created before the gateway started were never seeded into the
//! credential cache (every request 500'd until each secret was touched), and
//! rotation went unnoticed because the reconciler read from a cache that was
//! not the same watch that received the change event (traffic kept using the
//! old key). The general rule both violate: **the event source and the read
//! source must be the same store** — a request must only ever observe a
//! credential set that some version of the watched source actually published.
//!
//! These tests pin that rule at the proxy boundary for the credential store
//! the proxy consumes natively: the `credential_injection` filter rebuilt by
//! config hot reload. The config file is the change-detection watch; the
//! swapped pipeline is the read source, so the guarantees under test are:
//!
//! 1. **Seeding** — credentials present when the gateway starts are usable from the very first request, with zero
//!    credential edits.
//! 2. **Rotation under traffic** — a rotated credential switches over monotonically: every request serves either the
//!    pre- or post-rotation value, and once the new value is observed the old one never reappears.
//! 3. **Deletion** — removing a credential takes effect without ever serving the removed value again afterwards,
//!    without affecting other routes, and without crashing the pipeline.
//!
//! The reload watcher debounces for 500 ms; the tests poll with a 15 s budget,
//! asserting rotation latency well under the 60 s end-to-end target.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use praxis_test_utils::{
    free_port, http_send, parse_body, parse_status, start_header_echo_backend, start_reloadable_proxy,
};

/// Poll a request until `pred(status, body)` holds or the budget is exhausted,
/// returning the last observed response so the caller's assertion produces a
/// clear diff. Reload is applied asynchronously (500 ms debounce then
/// pipeline rebuild), so post-reload assertions must poll rather than race a
/// single request. Same contract as `hot_reload::get_eventually`.
fn request_eventually(addr: &str, path: &str, pred: impl Fn(u16, &str) -> bool) -> (u16, String) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let (status, body) = request(addr, path);
        if pred(status, &body) || Instant::now() >= deadline {
            return (status, body);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn request(addr: &str, path: &str) -> (u16, String) {
    let raw = http_send(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    );
    (parse_status(&raw), parse_body(&raw))
}

/// The credential material the header-echo backend observed for one request.
///
/// The echo backend returns the forwarded request headers as the body, so the
/// `Authorization` line is exactly the credential the pipeline published —
/// present, absent, or one of the candidate values.
fn served_credential(body: &str) -> Option<String> {
    body.lines()
        .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
        .and_then(|line| line.split_once(':').map(|(_, value)| value.trim().to_owned()))
}

/// `Authorization` value expected for a seeded credential token.
fn expected_header(token: &str) -> String {
    format!("Bearer {token}")
}

// -----------------------------------------------------------------------------
// Config builders
// -----------------------------------------------------------------------------

/// Proxy config routing `/a`, `/b`, `/c` to the shared echo backend and
/// injecting a per-cluster Bearer credential for the entries in `tokens`
/// (cluster name → token; a missing entry means no credential is injected).
fn credential_yaml(proxy_port: u16, backend_port: u16, tokens: &BTreeMap<&'static str, &'static str>) -> String {
    let mut entries = String::new();
    for (cluster, token) in tokens {
        entries.push_str(&format!(
            "          - name: {cluster}\n            header: Authorization\n            value: \"{token}\"\n            header_prefix: \"Bearer \"\n"
        ));
    }
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
          - path_prefix: "/a"
            cluster: cluster-a
          - path_prefix: "/b"
            cluster: cluster-b
          - path_prefix: "/c"
            cluster: cluster-c
      - filter: credential_injection
        clusters:
{entries}      - filter: load_balancer
        clusters:
          - name: cluster-a
            endpoints:
              - "127.0.0.1:{backend_port}"
          - name: cluster-b
            endpoints:
              - "127.0.0.1:{backend_port}"
          - name: cluster-c
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

fn tokens(pairs: &[(&'static str, &'static str)]) -> BTreeMap<&'static str, &'static str> {
    pairs.iter().copied().collect()
}

/// Pre-existing credential set, as it would look when the gateway (re)starts:
/// three clusters, each with its own secret already published.
fn seeded_tokens() -> BTreeMap<&'static str, &'static str> {
    tokens(&[
        ("cluster-a", "seed-a"),
        ("cluster-b", "seed-b"),
        ("cluster-c", "seed-c"),
    ])
}

// -----------------------------------------------------------------------------
// 1. Seeding
// -----------------------------------------------------------------------------

#[test]
fn seeded_credentials_usable_from_first_request() {
    // Reproduces the IPP startup-seeding bug: secrets that existed *before*
    // the gateway started were not seeded into the cache, so a fresh start
    // 500'd until each secret was individually touched. Here the credential
    // set is present in the config at startup with zero subsequent edits, and
    // the first request to each route must already carry its credential.
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let proxy = start_reloadable_proxy(&credential_yaml(proxy_port, backend.port(), &seeded_tokens()));
    let addr = proxy.addr();

    for (path, token) in [("/a", "seed-a"), ("/b", "seed-b"), ("/c", "seed-c")] {
        let (status, body) = request(addr, path);
        assert_eq!(status, 200, "first request to {path} should succeed, body:\n{body}");
        assert_eq!(
            served_credential(&body).as_deref(),
            Some(expected_header(token).as_str()),
            "first request to {path} must carry its seeded credential, body:\n{body}"
        );
    }
}

// -----------------------------------------------------------------------------
// 2. Rotation under traffic
// -----------------------------------------------------------------------------

#[test]
fn rotation_under_traffic_switches_monotonically_without_gaps() {
    // Reproduces the IPP stale-credential-under-rotation bug: the reconciler
    // read from a different cache than the watch that received the change
    // event, so traffic kept using the old key after rotation. The acceptance
    // form of "event source == read source": while a rotation is in flight,
    // every served request must carry either the pre- or post-rotation value
    // (never missing, never mixed), and after the new value is first observed
    // the old value must never be served again.
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let mut before = seeded_tokens();
    let proxy = start_reloadable_proxy(&credential_yaml(proxy_port, backend.port(), &before));
    let addr = proxy.addr();

    let (status, body) = request(addr, "/b");
    assert_eq!(status, 200, "baseline request should succeed");
    assert_eq!(
        served_credential(&body).as_deref(),
        Some(expected_header("seed-b").as_str()),
        "baseline should serve the pre-rotation credential"
    );

    // Rotate only cluster-b's credential; a and c stay fixed so a torn or
    // over-broad reload would show up as collateral change.
    before.insert("cluster-b", "rotated-b");
    proxy.write_config(&credential_yaml(proxy_port, backend.port(), &before));

    // Steady traffic on the rotated route until the new value appears.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut saw_new = false;
    let mut served_before_new = 0;
    while Instant::now() < deadline {
        let (status, body) = request(addr, "/b");
        let served = served_credential(&body);
        assert_eq!(
            status, 200,
            "in-flight request lost status during rotation, body:\n{body}"
        );
        match served.as_deref() {
            Some(v) if v == expected_header("seed-b") => {
                assert!(!saw_new, "stale credential served after rotation took effect");
                served_before_new += 1;
            },
            Some(v) if v == expected_header("rotated-b") => saw_new = true,
            Some(other) => panic!("served an unexpected credential during rotation: {other:?}"),
            None => panic!("request served without any credential during rotation (gap)"),
        }
        if saw_new {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(saw_new, "rotation was never observed within the 15 s reload budget");
    assert!(
        served_before_new >= 1,
        "traffic never served the old value before rotation applied"
    );

    // Post-rotation traffic stays on the new value, and the untouched routes
    // keep their original credentials.
    for _ in 0..4 {
        let (_, body) = request(addr, "/b");
        assert_eq!(
            served_credential(&body).as_deref(),
            Some(expected_header("rotated-b").as_str()),
            "post-rotation traffic must keep serving the rotated credential"
        );
    }
    for (path, token) in [("/a", "seed-a"), ("/c", "seed-c")] {
        let (_, body) = request(addr, path);
        assert_eq!(
            served_credential(&body).as_deref(),
            Some(expected_header(token).as_str()),
            "rotating one credential must not disturb {path}"
        );
    }
}

// -----------------------------------------------------------------------------
// 3. Deletion
// -----------------------------------------------------------------------------

#[test]
fn deleted_credential_never_served_again_and_others_unaffected() {
    // Reproduces the IPP deletion gap: a removed secret must fail the route
    // closed deterministically — no stale fallback, no pipeline crash. At the
    // proxy boundary that means: after the removal is observed, the route
    // forwards no credential at all (the upstream provider's 401 then closes
    // the route deterministically), the removed value never appears again,
    // sibling routes keep serving, and the proxy stays healthy.
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let proxy = start_reloadable_proxy(&credential_yaml(proxy_port, backend.port(), &seeded_tokens()));
    let addr = proxy.addr();

    let (_, body) = request(addr, "/b");
    assert_eq!(
        served_credential(&body).as_deref(),
        Some(expected_header("seed-b").as_str()),
        "baseline should serve cluster-b's credential"
    );

    // Delete the credential: a valid config without the cluster-b entry.
    let after = tokens(&[("cluster-a", "seed-a"), ("cluster-c", "seed-c")]);
    proxy.write_config(&credential_yaml(proxy_port, backend.port(), &after));

    let (_, body) = request_eventually(addr, "/b", |status, body| {
        status == 200 && served_credential(body).is_none()
    });
    assert_eq!(
        served_credential(&body),
        None,
        "deletion not observed within the 15 s reload budget — the route kept a credential, body:\n{body}"
    );

    // Once removed, the stale value must never reappear, and the pipeline
    // must stay healthy: sibling routes still serve their credentials.
    for _ in 0..4 {
        let (status, body) = request(addr, "/b");
        assert_eq!(status, 200, "route b should stay up after deletion, body:\n{body}");
        assert_eq!(
            served_credential(&body),
            None,
            "deleted credential reappeared after removal, body:\n{body}"
        );
    }
    for (path, token) in [("/a", "seed-a"), ("/c", "seed-c")] {
        let (status, body) = request(addr, path);
        assert_eq!(
            status, 200,
            "proxy pipeline should stay healthy after deletion (via {path})"
        );
        assert_eq!(
            served_credential(&body).as_deref(),
            Some(expected_header(token).as_str()),
            "sibling route {path} must keep its credential after an unrelated deletion"
        );
    }
}
