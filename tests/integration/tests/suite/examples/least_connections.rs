use std::{collections::HashMap, thread, time::Duration};

use crate::common::{free_port, http_get, start_backend, start_proxy, start_slow_backend};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// Least-connections with 3 backends and sequential (non-concurrent).
#[test]
fn least_connections() {
    let port_a = start_backend("lc-a");
    let port_b = start_backend("lc-b");
    let port_c = start_backend("lc-c");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/least-connections.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
        ]),
    );
    let addr = start_proxy(&config);

    let total = 30u32;
    let mut counts: HashMap<String, u32> = HashMap::new();
    for _ in 0..total {
        let (status, body) = http_get(&addr, "/", None);
        assert_eq!(status, 200, "least-conn request should return 200");
        *counts.entry(body).or_default() += 1;
    }

    assert_eq!(counts.len(), 3, "least-conn should use all 3 backends");

    for (backend, count) in &counts {
        assert!(
            (7..=13).contains(count),
            "expected ~10 for backend {backend}, got {count}"
        );
    }
}

/// Least-connections under concurrent load.
#[test]
fn least_connections_concurrent() {
    let delay = Duration::from_millis(200);
    let port_a = start_slow_backend("lc-a", delay);
    let port_b = start_slow_backend("lc-b", delay);
    let port_c = start_slow_backend("lc-c", delay);
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/least-connections.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
        ]),
    );
    let addr = start_proxy(&config);

    let total = 30;
    let handles: Vec<_> = (0..total)
        .map(|_| {
            let addr = addr.clone();
            thread::spawn(move || http_get(&addr, "/", None))
        })
        .collect();

    let mut counts: HashMap<String, u32> = HashMap::new();
    for handle in handles {
        let (status, body) = handle.join().expect("request thread panicked");
        assert_eq!(status, 200, "concurrent least-conn request should return 200");
        *counts.entry(body).or_default() += 1;
    }

    assert_eq!(counts.len(), 3, "concurrent least-conn should use all 3 backends");

    for (backend, count) in &counts {
        assert!(
            (7..=13).contains(count),
            "expected ~10 for backend {backend}, got {count}"
        );
    }
}
