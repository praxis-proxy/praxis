// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Check-mode command helpers shared by `--validate` and `--dump`.

use praxis_core::config::Config;

use crate::dump;

// -----------------------------------------------------------------------------
// Shared Validation
// -----------------------------------------------------------------------------

/// Load and fully validate configuration without starting the server.
///
/// Shared by `--validate` and `--dump`. Runs the same validation
/// checks used during server startup: log override validation,
/// filter factory instantiation, chain expansion, ordering checks,
/// and body-limit application.
///
/// # Errors
///
/// Returns an error if loading or validation fails.
pub(crate) fn load_and_validate_for_cli(
    explicit: Option<&str>,
) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    let config = praxis::load_config(explicit)?;
    validate_config_for_startup(&config)?;
    Ok(config)
}

/// Validate a parsed configuration by building filter pipelines.
pub(crate) fn validate_config_for_startup(config: &Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    praxis_core::logging::validate_log_overrides(config)?;
    let registry = praxis_filter::FilterRegistry::with_builtins();
    let health_registry = praxis_core::health::build_health_registry(&config.clusters);
    let kv_stores = praxis_core::kv::KvStoreRegistry::new();
    #[cfg(feature = "ai-inference")]
    let response_stores = praxis_filter::ResponseStoreRegistry::new();
    praxis::resolve_pipelines(
        config,
        &registry,
        &health_registry,
        &kv_stores,
        #[cfg(feature = "ai-inference")]
        &response_stores,
    )?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Dump
// -----------------------------------------------------------------------------

/// Load, validate, and dump effective configuration to stdout.
///
/// # Errors
///
/// Returns an error if loading, validation, or serialization fails.
pub(crate) fn run_dump(explicit: Option<&str>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = load_and_validate_for_cli(explicit)?;
    let source = match explicit {
        Some(path) => path.to_owned(),
        None => default_config_source(),
    };
    let dump_model = dump::build_dump(&config, &source)?;
    dump::write_dump(&dump_model)
}

/// Determine the human-readable label for implicit config sources.
fn default_config_source() -> String {
    if std::path::Path::new("praxis.yaml").exists() {
        return "praxis.yaml".to_owned();
    }
    "<built-in default>".to_owned()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn validate_catches_invalid_log_overrides() {
        let config = Config::from_yaml(
            r#"
runtime:
  log_overrides:
    "invalid module": "info"
    "praxis_core": "invalid_level"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters: []
"#,
        )
        .unwrap();
        let result = validate_config_for_startup(&config);
        assert!(result.is_err(), "invalid log overrides should fail validation");
        let err = result.err().unwrap().to_string();
        assert!(
            err.contains("invalid module path 'invalid module'"),
            "error should mention invalid module path: {err}"
        );
        assert!(
            err.contains("invalid level 'invalid_level'"),
            "error should mention invalid level: {err}"
        );
    }

    #[test]
    fn validate_rejects_unknown_filter_type() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: nonexistent_filter_type
"#,
        )
        .unwrap();
        let result = validate_config_for_startup(&config);
        assert!(result.is_err(), "unknown filter type should fail validation");
    }

    #[test]
    fn invalid_yaml_syntax_returns_error() {
        let result = Config::from_yaml("{{{{ not: valid: yaml: [");
        assert!(result.is_err(), "malformed YAML syntax should fail parsing");
    }

    #[test]
    fn empty_config_string_returns_error() {
        let result = Config::from_yaml("");
        assert!(result.is_err(), "empty config string should fail parsing");
    }

    #[test]
    fn config_with_invalid_chain_reference_returns_error() {
        let result = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [nonexistent_chain]
filter_chains:
  - name: main
    filters: []
"#,
        );
        assert!(
            result.is_err(),
            "listener referencing undefined chain should fail validation"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nonexistent_chain"),
            "error should mention the missing chain name: {err}"
        );
    }
}
