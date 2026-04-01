use std::collections::HashMap;

use crate::common::{free_port, http_send, parse_header, parse_status, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn logging() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/logging.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(parse_status(&raw), 200, "request without X-Request-Id should succeed");

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Request-Id: my-trace-42\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "request with X-Request-Id should return 200");
    assert_eq!(
        parse_header(&raw, "x-request-id"),
        Some("my-trace-42".to_string()),
        "proxy should echo back X-Request-Id"
    );

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Request-Id: other-99\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_header(&raw, "x-request-id"),
        Some("other-99".to_string()),
        "proxy should echo back different X-Request-Id"
    );
}
