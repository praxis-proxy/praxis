//! Integration tests for retry behavior (or lack thereof).

use praxis_core::config::Config;

use crate::common::{free_port, http_get, http_send, parse_status, simple_proxy_yaml, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn no_retry_on_dead_backend_returns_502() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, _body) = http_get(&addr, "/", None);
    assert_eq!(status, 502, "dead backend should return 502 without retry");
}

#[test]
fn no_retry_on_dead_backend_post_returns_502() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 502, "POST to dead backend should return 502 without retry");
}

#[test]
fn no_retry_all_endpoints_down_returns_502() {
    let dead_a = free_port();
    let dead_b = free_port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
routes:
  - path_prefix: "/"
    cluster: "backend"
clusters:
  - name: "backend"
    endpoints:
      - "127.0.0.1:{dead_a}"
      - "127.0.0.1:{dead_b}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, _body) = http_get(&addr, "/", None);
    assert_eq!(
        status, 502,
        "all-dead cluster should return 502 without retrying other endpoints"
    );
}

#[test]
fn no_retry_mixed_endpoints_healthy_serves() {
    let dead_port = free_port();
    let live_port = start_backend("live-backend");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
routes:
  - path_prefix: "/"
    cluster: "backend"
clusters:
  - name: "backend"
    endpoints:
      - "127.0.0.1:{dead_port}"
      - "127.0.0.1:{live_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let mut saw_live = false;
    let mut saw_502 = false;
    for _ in 0..10 {
        let (status, body) = http_get(&addr, "/", None);
        match status {
            200 => {
                assert_eq!(body, "live-backend", "healthy endpoint should serve response");
                saw_live = true;
            },
            502 => saw_502 = true,
            other => panic!("unexpected status {other} from mixed cluster"),
        }
    }

    assert!(saw_live, "at least one request should reach the healthy endpoint");
    assert!(
        saw_502,
        "at least one request should hit the dead endpoint and return 502 (no retry)"
    );
}

#[test]
fn no_retry_pipeline_style_dead_backend_returns_502() {
    let dead_port = free_port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: "backend"
  - filter: load_balancer
    clusters:
      - name: "backend"
        endpoints:
          - "127.0.0.1:{dead_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, _body) = http_get(&addr, "/", None);
    assert_eq!(
        status, 502,
        "pipeline-style config with dead backend should return 502 without retry"
    );
}

#[test]
fn no_retry_sequential_requests_to_dead_backend_all_fail() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    for i in 0..3 {
        let (status, _body) = http_get(&addr, "/", None);
        assert_eq!(
            status, 502,
            "request {i} to dead backend should return 502 (no retry recovery)"
        );
    }
}
