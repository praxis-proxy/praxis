//! Integration tests verifying that each HTTP listener uses its own filter pipeline.

use praxis_core::config::Config;

use crate::common::{free_port, http_send, parse_header, start_backend, start_proxy, wait_for_http};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn listeners_with_different_filter_chains_use_own_pipeline() {
    let backend_port = start_backend("ok");
    let alpha_port = free_port();
    let beta_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: alpha
    address: "127.0.0.1:{alpha_port}"
    filter_chains:
      - alpha_chain

  - name: beta
    address: "127.0.0.1:{beta_port}"
    filter_chains:
      - beta_chain

filter_chains:
  - name: alpha_chain
    filters:
      - filter: headers
        response_set:
          - name: "X-Listener"
            value: "alpha"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"

  - name: beta_chain
    filters:
      - filter: headers
        response_set:
          - name: "X-Listener"
            value: "beta"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _ = start_proxy(&config);
    wait_for_http(&format!("127.0.0.1:{alpha_port}"));
    wait_for_http(&format!("127.0.0.1:{beta_port}"));

    let alpha_raw = http_send(
        &format!("127.0.0.1:{alpha_port}"),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let beta_raw = http_send(
        &format!("127.0.0.1:{beta_port}"),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    let alpha_header = parse_header(&alpha_raw, "X-Listener");
    let beta_header = parse_header(&beta_raw, "X-Listener");

    assert_eq!(
        alpha_header.as_deref(),
        Some("alpha"),
        "alpha listener should use alpha_chain pipeline"
    );
    assert_eq!(
        beta_header.as_deref(),
        Some("beta"),
        "beta listener should use beta_chain pipeline"
    );
}

#[test]
fn listeners_with_shared_chain_both_work() {
    let backend_port = start_backend("shared");
    let first_port = free_port();
    let second_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: first
    address: "127.0.0.1:{first_port}"
    filter_chains:
      - common

  - name: second
    address: "127.0.0.1:{second_port}"
    filter_chains:
      - common

filter_chains:
  - name: common
    filters:
      - filter: headers
        response_set:
          - name: "X-Via"
            value: "praxis"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _ = start_proxy(&config);
    wait_for_http(&format!("127.0.0.1:{first_port}"));
    wait_for_http(&format!("127.0.0.1:{second_port}"));

    let first_raw = http_send(
        &format!("127.0.0.1:{first_port}"),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let second_raw = http_send(
        &format!("127.0.0.1:{second_port}"),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(
        parse_header(&first_raw, "X-Via").as_deref(),
        Some("praxis"),
        "first listener should apply shared pipeline"
    );
    assert_eq!(
        parse_header(&second_raw, "X-Via").as_deref(),
        Some("praxis"),
        "second listener should apply shared pipeline"
    );
}

#[test]
fn three_listeners_each_with_distinct_pipeline() {
    let backend_port = start_backend("ok");
    let port_a = free_port();
    let port_b = free_port();
    let port_c = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: a
    address: "127.0.0.1:{port_a}"
    filter_chains: [chain_a]
  - name: b
    address: "127.0.0.1:{port_b}"
    filter_chains: [chain_b]
  - name: c
    address: "127.0.0.1:{port_c}"
    filter_chains: [chain_c]

filter_chains:
  - name: chain_a
    filters:
      - filter: headers
        response_set:
          - name: "X-Chain"
            value: "a"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"

  - name: chain_b
    filters:
      - filter: headers
        response_set:
          - name: "X-Chain"
            value: "b"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"

  - name: chain_c
    filters:
      - filter: headers
        response_set:
          - name: "X-Chain"
            value: "c"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _ = start_proxy(&config);
    wait_for_http(&format!("127.0.0.1:{port_a}"));
    wait_for_http(&format!("127.0.0.1:{port_b}"));
    wait_for_http(&format!("127.0.0.1:{port_c}"));

    let get = |port: u16| {
        http_send(
            &format!("127.0.0.1:{port}"),
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
    };

    assert_eq!(
        parse_header(&get(port_a), "X-Chain").as_deref(),
        Some("a"),
        "listener a should use chain_a"
    );
    assert_eq!(
        parse_header(&get(port_b), "X-Chain").as_deref(),
        Some("b"),
        "listener b should use chain_b"
    );
    assert_eq!(
        parse_header(&get(port_c), "X-Chain").as_deref(),
        Some("c"),
        "listener c should use chain_c"
    );
}
