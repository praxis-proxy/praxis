//! Host header adversarial tests.

use praxis_core::config::Config;

use crate::common::{free_port, http_send, parse_body, parse_status, simple_proxy_yaml, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn duplicate_host_headers_do_not_crash() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );

    let status = parse_status(&raw);
    assert!(
        status == 200 || status == 400,
        "duplicate Host must yield 200 or 400, got {status}"
    );
}

#[test]
fn conflicting_host_headers_rejected_or_safe() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: victim.com\r\n\
         Host: attacker.com\r\n\
         Connection: close\r\n\r\n",
    );

    let status = parse_status(&raw);
    assert_ne!(status, 500, "conflicting Host headers must not cause 500");
}

#[test]
fn host_port_mismatch_handled_gracefully() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost:9999\r\n\
         Connection: close\r\n\r\n",
    );

    let status = parse_status(&raw);
    assert_ne!(status, 500, "Host port mismatch must not cause 500");
    assert_ne!(status, 0, "Host port mismatch must not crash the proxy");
}

#[test]
fn empty_host_header_handled_gracefully() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: \r\n\
         Connection: close\r\n\r\n",
    );

    let status = parse_status(&raw);
    assert_ne!(status, 500, "empty Host header must not cause 500");
    assert_ne!(status, 0, "empty Host header must not crash the proxy");
}

#[test]
fn host_with_special_characters_handled() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost; DROP TABLE users\r\n\
         Connection: close\r\n\r\n",
    );

    let status = parse_status(&raw);
    assert_ne!(status, 500, "special chars in Host must not cause 500");
}

#[test]
fn conflicting_hosts_do_not_route_to_attacker_backend() {
    let victim_port = start_backend("victim-response");
    let attacker_port = start_backend("attacker-response");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            host: "victim.com"
            cluster: "victim"
          - path_prefix: "/"
            host: "attacker.com"
            cluster: "attacker"
      - filter: load_balancer
        clusters:
          - name: "victim"
            endpoints:
              - "127.0.0.1:{victim_port}"
          - name: "attacker"
            endpoints:
              - "127.0.0.1:{attacker_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: victim.com\r\n\
         Host: attacker.com\r\n\
         Connection: close\r\n\r\n",
    );

    let status = parse_status(&raw);
    let body = parse_body(&raw);

    if status == 400 {
        return;
    }

    assert!(
        !body.contains("attacker-response"),
        "conflicting Host routed to attacker backend; body: {body}"
    );
}
