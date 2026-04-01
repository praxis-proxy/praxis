use std::collections::HashMap;

use crate::common::{free_port, http_get, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn canary_routing() {
    let port_stable = start_backend("stable");
    let port_canary = start_backend("canary");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "traffic-management/canary-routing.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", port_stable), ("127.0.0.1:3002", port_canary)]),
    );
    let addr = start_proxy(&config);
    let total = 200u32;
    let mut stable_count = 0u32;
    let mut canary_count = 0u32;
    for _ in 0..total {
        let (status, body) = http_get(&addr, "/", None);
        assert_eq!(status, 200, "canary request should return 200");
        match body.as_str() {
            "stable" => stable_count += 1,
            "canary" => canary_count += 1,
            other => panic!("unexpected body: {other}"),
        }
    }
    assert_eq!(
        stable_count + canary_count,
        total,
        "all requests should reach a backend"
    );
    assert!(canary_count > 0, "canary backend received no requests");

    let ratio = stable_count as f64 / canary_count as f64;
    assert!(
        (8.0..=10.0).contains(&ratio),
        "expected ratio ~9.0 (90/10 split over {total} requests), got {ratio}"
    );
}
