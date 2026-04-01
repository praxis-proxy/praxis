use std::collections::HashMap;

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Load an example config YAML.
pub(crate) fn load_example_config(filename: &str, listener_port: u16, port_map: HashMap<&str, u16>) -> Config {
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
