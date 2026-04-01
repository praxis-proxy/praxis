use std::collections::{HashMap, HashSet};

use crate::common::{free_port, http_send, parse_body, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn session_affinity() {
    let port_a = start_backend("sa-a");
    let port_b = start_backend("sa-b");
    let port_c = start_backend("sa-c");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/session-affinity.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
        ]),
    );
    let addr = start_proxy(&config);

    let mut first_body = None;
    for _ in 0..6 {
        let raw = http_send(
            &addr,
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             X-User-Id: user-42\r\n\
             Connection: close\r\n\r\n",
        );
        let body = parse_body(&raw);
        match &first_body {
            None => first_body = Some(body),
            Some(expected) => assert_eq!(
                &body, expected,
                "consistent hash should pin user-42 to the same backend"
            ),
        }
    }

    let mut backends_seen = HashSet::new();
    for i in 0..30 {
        let raw = http_send(
            &addr,
            &format!(
                "GET / HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 X-User-Id: user-{i}\r\n\
                 Connection: close\r\n\r\n"
            ),
        );
        backends_seen.insert(parse_body(&raw));
    }
    assert_eq!(
        backends_seen.len(),
        3,
        "30 distinct user IDs should hash to all 3 backends, \
         got {}: {:?}",
        backends_seen.len(),
        backends_seen
    );
}
