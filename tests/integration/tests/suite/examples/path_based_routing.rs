use std::collections::HashMap;

use crate::common::{free_port, http_get, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn path_based_routing() {
    let api_port = start_backend("api");
    let static_port = start_backend("static");
    let default_port = start_backend("default");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/path-based-routing.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", api_port),
            ("127.0.0.1:3002", api_port),
            ("127.0.0.1:3003", api_port),
            ("127.0.0.1:4000", static_port),
            ("127.0.0.1:5000", default_port),
        ]),
    );
    let addr = start_proxy(&config);
    let (status, body) = http_get(&addr, "/api/users", None);
    assert_eq!(status, 200, "/api/ path should return 200");
    assert_eq!(body, "api", "/api/ should route to api backend");
    let (status, body) = http_get(&addr, "/static/index.html", None);
    assert_eq!(status, 200, "/static/ path should return 200");
    assert_eq!(body, "static", "/static/ should route to static backend");
    let (status, body) = http_get(&addr, "/other", None);
    assert_eq!(status, 200, "default path should return 200");
    assert_eq!(body, "default", "unmatched path should route to default backend");
}
