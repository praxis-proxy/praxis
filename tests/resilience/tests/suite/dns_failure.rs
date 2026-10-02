// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for proxy behavior when a backend hostname does not resolve.

use std::time::{Duration, Instant};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn unresolvable_backend_fails_promptly_and_spares_other_clusters() {
    let live_port = start_backend("resolved");
    let proxy_port = free_port();
    let config = Config::from_yaml(&nxdomain_yaml(
        proxy_port,
        live_port,
        "praxis-resilience-nxdomain-a.invalid",
    ))
    .unwrap();
    let proxy = start_proxy(&config);

    for attempt in ["first lookup", "cached failure"] {
        let start = Instant::now();
        let (status, _) = http_get(proxy.addr(), "/nxdomain", None);
        let elapsed = start.elapsed();
        assert!(
            (500..600).contains(&status),
            "{attempt}: a backend hostname that does not resolve should fail with a server error, got {status}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "{attempt}: the resolution failure should surface promptly; took {elapsed:?}"
        );
    }

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "other clusters should keep working after a DNS failure");
    assert_eq!(body, "resolved", "the live cluster should serve its own response");
}

#[test]
#[ignore = "an unresolvable HTTP upstream hostname gets a 500 today: resolve_upstream in the protocol crate maps \
            resolver failures to InternalError, while the iterative request router maps the same failure to 502"]
fn unresolvable_backend_returns_502() {
    let live_port = start_backend("resolved");
    let proxy_port = free_port();
    let config = Config::from_yaml(&nxdomain_yaml(
        proxy_port,
        live_port,
        "praxis-resilience-nxdomain-b.invalid",
    ))
    .unwrap();
    let proxy = start_proxy(&config);

    for attempt in ["first lookup", "cached failure"] {
        let (status, body) = http_get(proxy.addr(), "/nxdomain", None);
        assert_eq!(
            status, 502,
            "{attempt}: an upstream hostname that does not resolve is a bad gateway, not a proxy fault: {body}"
        );
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Proxy config that routes `/nxdomain` to a cluster whose only endpoint
/// is `host` (meant to be a name that cannot resolve) and everything
/// else to the live backend, so the harness's readiness probe never
/// touches the resolver.
fn nxdomain_yaml(proxy_port: u16, live_port: u16, host: &str) -> String {
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
          - path_prefix: "/nxdomain"
            cluster: nxdomain
          - path_prefix: "/"
            cluster: live
      - filter: load_balancer
        clusters:
          - name: nxdomain
            endpoints:
              - "{host}:80"
          - name: live
            endpoints:
              - "127.0.0.1:{live_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}
