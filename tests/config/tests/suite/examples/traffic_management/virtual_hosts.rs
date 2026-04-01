use std::collections::HashMap;

use crate::common::{free_port, http_get, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn virtual_hosts() {
    let api_port = start_backend("api-host");
    let web_port = start_backend("web-host");
    let default_port = start_backend("default-host");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "traffic-management/hosts.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", api_port),
            ("127.0.0.1:3002", api_port),
            ("127.0.0.1:4000", web_port),
            ("127.0.0.1:5000", default_port),
        ]),
    );
    let addr = start_proxy(&config);
    let (status, body) = http_get(&addr, "/", Some("api.example.com"));
    assert_eq!(status, 200, "api.example.com should return 200");
    assert_eq!(body, "api-host", "api.example.com should route to api backend");
    let (status, body) = http_get(&addr, "/", Some("www.example.com"));
    assert_eq!(status, 200, "www.example.com should return 200");
    assert_eq!(body, "web-host", "www.example.com should route to web backend");
    let (status, body) = http_get(&addr, "/", Some("unknown.example.com"));
    assert_eq!(status, 200, "unknown host should return 200");
    assert_eq!(body, "default-host", "unknown host should route to default backend");
}
