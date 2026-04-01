use std::collections::HashMap;

use crate::common::{free_port, http_get, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn round_robin() {
    let port_a = start_backend("a");
    let port_b = start_backend("b");
    let port_c = start_backend("c");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "traffic-management/round-robin.yaml",
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
    let mut sequence: Vec<String> = Vec::with_capacity(total as usize);
    for _ in 0..total {
        let (status, body) = http_get(&addr, "/", None);
        assert_eq!(status, 200, "round-robin request should return 200");
        *counts.entry(body.clone()).or_default() += 1;
        sequence.push(body);
    }

    assert_eq!(counts.len(), 3, "round robin should hit all 3 backends");

    for (backend, count) in &counts {
        assert_eq!(*count, 10, "expected exactly 10 for backend {backend}, got {count}");
    }

    let cycle: Vec<&str> = sequence[..3].iter().map(|s| s.as_str()).collect();
    for chunk in sequence.chunks(3).skip(1) {
        let got: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
        assert_eq!(got, cycle, "round-robin should repeat the same cycle order");
    }
}
