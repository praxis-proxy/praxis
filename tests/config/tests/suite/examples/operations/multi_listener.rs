use praxis_core::config::Config;

use crate::common::{free_port, http_get, start_backend, start_proxy, wait_for_tcp};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn multi_listener() {
    let api_port = start_backend("api");
    let web_port = start_backend("web");
    let http_port = free_port();
    let admin_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: http
    address: "127.0.0.1:{http_port}"
  - name: admin
    address: "127.0.0.1:{admin_port}"

pipeline:
  - filter: request_id
  - filter: access_log
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
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let addr_http = format!("127.0.0.1:{http_port}");
    let addr_admin = format!("127.0.0.1:{admin_port}");

    let _ = start_proxy(&config);
    wait_for_tcp(&addr_admin);

    let (status, body) = http_get(&addr_http, "/api/test", None);
    assert_eq!(status, 200, "http listener /api/ should return 200");
    assert_eq!(body, "api", "http listener should route /api/ to api backend");

    let (status, body) = http_get(&addr_admin, "/", None);
    assert_eq!(status, 200, "admin listener root should return 200");
    assert_eq!(body, "web", "admin listener should route root to web backend");

    let (status, body) = http_get(&addr_admin, "/api/test", None);
    assert_eq!(status, 200, "admin listener /api/ should return 200");
    assert_eq!(body, "api", "admin listener should route /api/ to api backend");
}
