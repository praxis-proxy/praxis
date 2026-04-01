use std::collections::HashMap;

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_yaml_replaces_listener_0000() {
        let yaml = "address: \"0.0.0.0:8080\"";
        let result = patch_yaml(yaml, 9999, &HashMap::new());
        assert_eq!(result, "address: \"127.0.0.1:9999\"");
    }

    #[test]
    fn patch_yaml_replaces_listener_localhost() {
        let yaml = "address: \"127.0.0.1:8080\"";
        let result = patch_yaml(yaml, 9999, &HashMap::new());
        assert_eq!(result, "address: \"127.0.0.1:9999\"");
    }

    #[test]
    fn patch_yaml_replaces_endpoints() {
        let yaml = "- \"127.0.0.1:3000\"\n- \"127.0.0.1:4000\"";
        let map = HashMap::from([("127.0.0.1:3000", 5555_u16), ("127.0.0.1:4000", 6666_u16)]);
        let result = patch_yaml(yaml, 8080, &map);
        assert!(result.contains("127.0.0.1:5555"));
        assert!(result.contains("127.0.0.1:6666"));
    }

    #[test]
    fn patch_yaml_leaves_unmatched_unchanged() {
        let yaml = "upstream: \"10.0.0.1:443\"";
        let result = patch_yaml(yaml, 8080, &HashMap::new());
        assert_eq!(result, yaml);
    }

    #[test]
    fn example_config_path_resolves() {
        let path = example_config_path("traffic-management/basic-reverse-proxy.yaml");
        assert!(std::path::Path::new(&path).exists(), "expected {path} to exist");
    }

    #[test]
    fn load_example_config_parses() {
        let config = load_example_config(
            "traffic-management/basic-reverse-proxy.yaml",
            19999,
            HashMap::from([("127.0.0.1:3000", 19998_u16)]),
        );
        assert_eq!(config.listeners[0].address, "127.0.0.1:19999");
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Load an example config YAML, patch the listener and endpoint
/// addresses with free ports, and return the parsed `Config`.
///
/// `port_map` maps original `"host:port"` strings to replacement
/// ports on `127.0.0.1`.
pub fn load_example_config(filename: &str, listener_port: u16, port_map: HashMap<&str, u16>) -> Config {
    let path = example_config_path(filename);
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let patched = patch_yaml(&yaml, listener_port, &port_map);
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse {filename}: {e}"))
}

/// Resolve the absolute path to an example config file.
fn example_config_path(filename: &str) -> String {
    format!("{}/../../examples/configs/{filename}", env!("CARGO_MANIFEST_DIR"),)
}

/// Replace the default listener address and all endpoint addresses in the YAML string.
fn patch_yaml(yaml: &str, listener_port: u16, port_map: &HashMap<&str, u16>) -> String {
    let mut result = yaml
        .replace("0.0.0.0:8080", &format!("127.0.0.1:{listener_port}"))
        .replace("127.0.0.1:8080", &format!("127.0.0.1:{listener_port}"));
    for (original, port) in port_map {
        result = result.replace(original, &format!("127.0.0.1:{port}"));
    }
    result
}
