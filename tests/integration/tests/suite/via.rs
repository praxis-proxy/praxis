// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Response `Via` header semantics (RFC 9110 §7.6.3).

use praxis_core::config::Config;
use praxis_test_utils::{free_port, start_backend_with_shutdown, start_proxy};

/// Minimal router + load-balancer proxy config.
fn proxy_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: web
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

#[test]
fn response_via_reports_upstream_protocol_not_client_protocol() {
    // RFC 9110 §7.6.3: the received-protocol in a response Via entry is the
    // protocol the proxy received the RESPONSE over — the upstream leg, which
    // is always HTTP/1.1 — not the downstream client's version. An HTTP/2
    // client must therefore see "1.1 praxis", not "2 praxis".
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, backend.port())).unwrap();
    let _proxy = start_proxy(&config);

    let addr = format!("127.0.0.1:{proxy_port}");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let (mut client, h2_conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            drop(h2_conn.await);
        });

        let request = http::Request::get("/").header("host", "localhost").body(()).unwrap();
        let (response_fut, _) = client.send_request(request, true).unwrap();
        let response = response_fut.await.expect("h2 request should succeed");

        assert_eq!(response.status(), 200, "proxied h2 request should return 200");
        let via = response
            .headers()
            .get("via")
            .expect("proxied response should carry a Via header")
            .to_str()
            .unwrap();
        assert_eq!(
            via, "1.1 praxis",
            "response Via must report the upstream (HTTP/1.1) leg, not the h2 client leg"
        );
    });
}
