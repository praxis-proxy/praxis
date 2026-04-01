use std::collections::HashMap;

use crate::common::{Backend, free_port, http_send, parse_header, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn header_manipulation() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "transformation/header-manipulation.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let addr = start_proxy(&config);
    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_header(&raw, "x-powered-by"),
        Some("praxis".to_string()),
        "X-Powered-By header should be set to 'praxis'"
    );
    assert_eq!(
        parse_header(&raw, "x-frame-options"),
        Some("DENY".to_string()),
        "X-Frame-Options header should be set to 'DENY'"
    );
}

#[test]
fn header_response_remove_strips_upstream_header() {
    let backend_port = Backend::fixed("ok").header("Server", "upstream-server").start();
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "transformation/header-manipulation.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let addr = start_proxy(&config);
    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert!(
        parse_header(&raw, "server").is_none(),
        "Server header should be removed by response_remove; got response:\n{raw}"
    );
}
