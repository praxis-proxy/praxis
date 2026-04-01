use praxis_core::config::Config;
use serde_json::Value;

use crate::common::{free_port, http_get, start_proxy};
// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default example config loaded at compile time.
const DEFAULT_CONFIG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/configs/pipeline/default.yaml"
));

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn default_config_root_returns_200() {
    let proxy_port = free_port();
    let yaml = DEFAULT_CONFIG.replace("0.0.0.0:8080", &format!("127.0.0.1:{proxy_port}"));
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "default config root should return 200");
    let json: Value = serde_json::from_str(&body).expect("response body should be valid JSON");
    assert_eq!(json["status"], "ok", "status field should be 'ok'");
    assert_eq!(json["server"], "praxis", "server field should be 'praxis'");
}

#[test]
fn default_config_other_path_returns_404() {
    let proxy_port = free_port();
    let yaml = DEFAULT_CONFIG.replace("0.0.0.0:8080", &format!("127.0.0.1:{proxy_port}"));
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let (status, body) = http_get(&addr, "/anything", None);
    assert_eq!(status, 404, "non-root path should return 404");
    assert!(body.contains("not found"), "404 body should contain 'not found'");
}
