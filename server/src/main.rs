// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

#![deny(unsafe_code)]

//! Praxis server entry point.
//!
//! Loads configuration, initializes tracing (with optional JSON output and
//! per-module log level overrides), and delegates to [`praxis::run_server`].
//!
//! [`praxis::run_server`]: praxis::run_server

/// Jemalloc global allocator is used by default on unix platforms.
///
/// Reduces allocator contention under concurrent load.
#[cfg(unix)]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::Parser;
use tracing::info;

// -----------------------------------------------------------------------------
// CLI
// -----------------------------------------------------------------------------

/// Cloud and AI-native proxy server.
#[derive(Parser)]
#[command(name = "praxis")]
struct Cli {
    /// Path to the YAML configuration file.
    #[arg(short = 'c', long = "config")]
    config: Option<String>,

    /// Validate configuration and exit.
    #[arg(short = 't', long = "validate")]
    validate: bool,
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

/// Entry point.
#[allow(clippy::print_stderr, reason = "fatal error output")]
fn main() {
    let cli = Cli::parse();
    let explicit = cli.config.or_else(|| std::env::var("PRAXIS_CONFIG").ok());

    if cli.validate {
        if let Err(e) = run_validate(explicit.as_deref()) {
            eprintln!("invalid configuration: {e}");
            std::process::exit(1);
        }
        return;
    }

    let config_path = praxis::resolve_config_path(explicit.as_deref());
    let config = praxis::load_config(explicit.as_deref()).unwrap_or_else(|e| praxis::fatal(&e));
    praxis::init_tracing(&config).unwrap_or_else(|e| praxis::fatal(&e));
    info!("starting server");
    praxis::run_server(config, config_path)
}

/// Load and fully validate configuration without starting the server.
#[allow(clippy::print_stderr, reason = "validation error output")]
fn run_validate(explicit: Option<&str>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = praxis::load_config(explicit)?;
    validate_config(&config)?;
    Ok(())
}

/// Validate a parsed configuration by building filter pipelines.
///
/// Runs the same validation checks used during server startup:
/// log override validation (validates `runtime.log_overrides`),
/// filter factory instantiation, chain expansion, ordering checks,
/// and body-limit application.
fn validate_config(config: &praxis_core::config::Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Validate log overrides (same validation as startup)
    praxis_core::logging::validate_log_overrides(config)?;
    let registry = praxis_filter::FilterRegistry::with_builtins();
    let health_registry = praxis_core::health::build_health_registry(&config.clusters);
    praxis::resolve_pipelines(config, &registry, &health_registry)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use clap::Parser;

    use super::{Cli, validate_config};

    #[test]
    fn cli_validate_short_flag() {
        let cli = Cli::parse_from(["praxis", "-t"]);
        assert!(cli.validate, "-t should set validate to true");
        assert!(cli.config.is_none(), "config should be None");
    }

    #[test]
    fn cli_validate_long_flag() {
        let cli = Cli::parse_from(["praxis", "--validate"]);
        assert!(cli.validate, "--validate should set validate to true");
    }

    #[test]
    fn cli_validate_with_config() {
        let cli = Cli::parse_from(["praxis", "-t", "-c", "custom.yaml"]);
        assert!(cli.validate, "-t should set validate to true");
        assert_eq!(cli.config.as_deref(), Some("custom.yaml"), "-c should set config path");
    }

    #[test]
    fn cli_default_no_validate() {
        let cli = Cli::parse_from(["praxis"]);
        assert!(!cli.validate, "validate should default to false");
    }

    #[test]
    fn validate_config_catches_invalid_log_overrides() {
        let config = praxis_core::config::Config::from_yaml(
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
        let result = validate_config(&config);
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
}
