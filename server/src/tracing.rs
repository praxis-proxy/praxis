//! Tracing subscriber setup shared by all Praxis binaries.

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Tracing
// -----------------------------------------------------------------------------

/// Build an `EnvFilter` from `RUST_LOG` (or the given default) merged with any `log_overrides` from the config.
pub(crate) fn build_env_filter(config: &Config) -> tracing_subscriber::EnvFilter {
    let base = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if config.runtime.log_overrides.is_empty() {
        return base;
    }

    // Serialize the base filter back to a directive string, then append the config-driven overrides so they take precedence.
    let mut directives = base.to_string();
    for (module, level) in &config.runtime.log_overrides {
        directives.push(',');
        directives.push_str(module);
        directives.push('=');
        directives.push_str(level);
    }

    tracing_subscriber::EnvFilter::new(directives)
}

/// Initialize the global tracing subscriber.
///
/// Set `PRAXIS_LOG_FORMAT=json` for structured JSON output.
/// Per-module overrides come from `runtime.log_overrides` in
/// the config YAML.
///
/// ```no_run
/// let config = praxis::load_config(None);
/// praxis::init_tracing(&config);
/// ```
pub fn init_tracing(config: &Config) {
    let env_filter = build_env_filter(config);
    let json = std::env::var("PRAXIS_LOG_FORMAT").as_deref() == Ok("json");

    if json {
        tracing_subscriber::fmt().json().with_env_filter(env_filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use praxis_core::config::Config;

    use super::*;

    /// Build a minimal [`Config`] with the given log overrides.
    fn config_with_overrides(overrides: HashMap<String, String>) -> Config {
        let yaml = r#"
listeners:
  - name: test
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
"#;
        let mut config = Config::from_yaml(yaml).expect("test config should parse");
        config.runtime.log_overrides = overrides;
        config
    }

    #[test]
    fn empty_log_overrides_produces_valid_filter() {
        let config = config_with_overrides(HashMap::new());
        let filter = build_env_filter(&config);
        let filter_str = filter.to_string();
        assert!(
            !filter_str.is_empty(),
            "filter with no overrides should still produce a non-empty directive string"
        );
    }

    #[test]
    fn log_overrides_appended_to_filter_string() {
        let mut overrides = HashMap::new();
        overrides.insert("praxis_filter".to_owned(), "trace".to_owned());
        overrides.insert("praxis_protocol".to_owned(), "debug".to_owned());

        let config = config_with_overrides(overrides);
        let filter = build_env_filter(&config);
        let filter_str = filter.to_string();

        assert!(
            filter_str.contains("praxis_filter=trace"),
            "filter should contain praxis_filter=trace, got: {filter_str}"
        );
        assert!(
            filter_str.contains("praxis_protocol=debug"),
            "filter should contain praxis_protocol=debug, got: {filter_str}"
        );
    }
}
