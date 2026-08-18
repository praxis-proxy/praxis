// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Test utilities for loading and patching example configuration files.

use std::collections::HashMap;

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Load an example config YAML, patch the listener and endpoint
/// addresses with free ports, and return the parsed [`Config`].
///
/// `port_map` maps original `"host:port"` strings to replacement
/// ports on `127.0.0.1`.
///
/// # Panics
///
/// Panics if the config file cannot be read or parsed.
///
/// # Examples
///
/// ```no_run
/// use std::collections::HashMap;
///
/// let config = praxis_test_utils::load_example_config(
///     "traffic-management/basic-reverse-proxy.yaml",
///     9090,
///     HashMap::from([("127.0.0.1:3000", 19998_u16)]),
/// );
/// assert!(!config.listeners.is_empty());
/// ```
///
/// [`Config`]: praxis_core::config::Config
#[expect(clippy::needless_pass_by_value, reason = "callers construct inline")]
pub fn load_example_config(filename: &str, listener_port: u16, port_map: HashMap<&str, u16>) -> Config {
    let path = example_config_path(filename);
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let patched = patch_yaml(&yaml, listener_port, &port_map);
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse {filename}: {e}"))
}

/// Resolve the absolute path to an example config file.
///
/// # Examples
///
/// ```
/// let path =
///     praxis_test_utils::example_config_path("traffic-management/basic-reverse-proxy.yaml");
/// assert!(path.contains("examples/configs/"));
/// ```
pub fn example_config_path(filename: &str) -> String {
    format!("{}/../../examples/configs/{filename}", env!("CARGO_MANIFEST_DIR"),)
}

/// Replace the default listener address and all endpoint addresses
/// in a YAML string.
///
/// Rewrites both `0.0.0.0:8080` and `127.0.0.1:8080` to the given
/// `listener_port`, and applies every entry in `port_map`.
///
/// Substitution is a single left-to-right pass, and a match is rejected when a
/// digit follows it. Sequential `str::replace` calls were not safe here: ports
/// come from `free_port()`, so a listener patched to `127.0.0.1:30019` was then
/// matched by the `127.0.0.1:3001` mapping and left the stranded trailing digit
/// behind as `127.0.0.1:353059`. One pass also keeps a value this function just
/// wrote from being rewritten by a later mapping.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
///
/// let yaml = "address: \"0.0.0.0:8080\"";
/// let result = praxis_test_utils::patch_yaml(yaml, 9999, &HashMap::new());
/// assert_eq!(result, "address: \"127.0.0.1:9999\"");
/// ```
pub fn patch_yaml(yaml: &str, listener_port: u16, port_map: &HashMap<&str, u16>) -> String {
    let listener = format!("127.0.0.1:{listener_port}");
    let mut rules: Vec<(&str, String)> = vec![("0.0.0.0:8080", listener.clone()), ("127.0.0.1:8080", listener)];
    rules.extend(
        port_map
            .iter()
            .map(|(original, port)| (*original, format!("127.0.0.1:{port}"))),
    );
    // Longest first, so a key that prefixes another key cannot win the match.
    rules.sort_by_key(|(original, _)| std::cmp::Reverse(original.len()));
    substitute(yaml, &rules)
}

/// Apply `rules` in one left-to-right pass, so a replacement is never rescanned.
fn substitute(yaml: &str, rules: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(yaml.len());
    let mut rest = yaml;
    while !rest.is_empty() {
        let matched = rules.iter().find_map(|(original, replacement)| {
            rest.strip_prefix(original)
                // A digit here means the key only prefixed a longer port.
                .filter(|tail| !tail.starts_with(|c: char| c.is_ascii_digit()))
                .map(|tail| (replacement, tail))
        });

        if let Some((replacement, tail)) = matched {
            out.push_str(replacement);
            rest = tail;
        } else {
            let mut chars = rest.chars();
            if let Some(c) = chars.next() {
                out.push(c);
            }
            rest = chars.as_str();
        }
    }
    out
}

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
        assert_eq!(result, "address: \"127.0.0.1:9999\"", "0.0.0.0 should be replaced");
    }

    #[test]
    fn patch_yaml_replaces_listener_localhost() {
        let yaml = "address: \"127.0.0.1:8080\"";
        let result = patch_yaml(yaml, 9999, &HashMap::new());
        assert_eq!(result, "address: \"127.0.0.1:9999\"", "localhost should be replaced");
    }

    #[test]
    fn patch_yaml_replaces_endpoints() {
        let map = HashMap::from([("127.0.0.1:3000", 5555_u16), ("127.0.0.1:4000", 6666_u16)]);
        let yaml = "- \"127.0.0.1:3000\"\n- \"127.0.0.1:4000\"";
        let result = patch_yaml(yaml, 8080, &map);
        assert!(
            result.contains("127.0.0.1:5555"),
            "first endpoint should be patched to port 5555"
        );
        assert!(
            result.contains("127.0.0.1:6666"),
            "second endpoint should be patched to port 6666"
        );
    }

    /// The listener port comes from `free_port()`, so its digits can begin with
    /// a mapped port's digits. That must not turn the listener into a 6-digit
    /// port: `127.0.0.1:3001` prefixes `127.0.0.1:30019`, and a plain replace
    /// left the trailing `9` behind as `127.0.0.1:353059`.
    #[test]
    fn patch_yaml_does_not_match_a_mapped_port_inside_a_longer_one() {
        let map = HashMap::from([("127.0.0.1:3001", 35305_u16)]);
        let yaml = "listener: \"127.0.0.1:8080\"\nendpoint: \"127.0.0.1:3001\"";
        let result = patch_yaml(yaml, 30019, &map);
        assert!(
            result.contains("listener: \"127.0.0.1:30019\""),
            "the listener port must survive intact, got: {result}"
        );
        assert!(
            !result.contains("353059"),
            "a mapped port must not match inside a longer port, got: {result}"
        );
        assert!(
            result.contains("endpoint: \"127.0.0.1:35305\""),
            "the endpoint must still be patched, got: {result}"
        );
    }

    /// A port this function just wrote must not be rewritten by another mapping.
    #[test]
    fn patch_yaml_does_not_rewrite_its_own_substitutions() {
        let map = HashMap::from([("127.0.0.1:3000", 4000_u16), ("127.0.0.1:4000", 5000_u16)]);
        let yaml = "a: \"127.0.0.1:3000\"\nb: \"127.0.0.1:4000\"";
        let result = patch_yaml(yaml, 8080, &map);
        assert!(
            result.contains("a: \"127.0.0.1:4000\""),
            "the first mapping applies once, not twice, got: {result}"
        );
        assert!(
            result.contains("b: \"127.0.0.1:5000\""),
            "the second mapping still applies, got: {result}"
        );
    }

    /// When one key prefixes another, the longer key wins.
    #[test]
    fn patch_yaml_prefers_the_longest_matching_key() {
        let map = HashMap::from([("127.0.0.1:300", 1111_u16), ("127.0.0.1:3001", 2222_u16)]);
        let result = patch_yaml("e: \"127.0.0.1:3001\"", 8080, &map);
        assert!(
            result.contains("127.0.0.1:2222"),
            "the longer key must win, got: {result}"
        );
    }

    #[test]
    fn patch_yaml_leaves_unmatched_unchanged() {
        let yaml = "upstream: \"10.0.0.1:443\"";
        let result = patch_yaml(yaml, 8080, &HashMap::new());
        assert_eq!(result, yaml, "unmatched addresses should stay unchanged");
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
        assert_eq!(
            config.listeners[0].address, "127.0.0.1:19999",
            "listener address should be patched"
        );
    }
}
