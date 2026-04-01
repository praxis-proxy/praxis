use std::collections::HashMap;

use crate::common::{free_port, http_get, start_backend};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn basic_reverse_proxy() {
    let backend_port = start_backend("hello");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/basic-reverse-proxy.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let addr = crate::common::start_proxy(&config);
    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "basic reverse proxy should return 200");
    assert_eq!(body, "hello", "proxy should forward backend response");
}
