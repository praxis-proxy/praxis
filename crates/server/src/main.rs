// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

#![forbid(unsafe_code)]

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

mod commands;
mod dump;

use std::process::ExitCode;

use clap::Parser;
use praxis_core::config::{Config, ConfigFile};
use tracing::info;

// -----------------------------------------------------------------------------
// CLI
// -----------------------------------------------------------------------------

/// Cloud and AI-native proxy server.
#[derive(Parser)]
#[command(name = "praxis", version = env!("PRAXIS_VERSION"))]
struct Cli {
    /// Path to the YAML configuration file.
    #[arg(short = 'c', long = "config")]
    config: Option<String>,

    /// Dump effective configuration as YAML and exit.
    #[arg(short = 'T', long = "dump", conflicts_with = "validate")]
    dump: bool,

    /// Validate configuration and exit.
    #[arg(short = 't', long = "validate")]
    validate: bool,
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

/// Entry point.
#[expect(clippy::print_stderr, reason = "fatal error output")]
fn main() -> ExitCode {
    // Before anything that might build a TLS config. `--validate` and `--dump`
    // return without reaching `try_run_server`, and both construct a sub-request
    // connector, so installing only on the serving path would leave those two
    // subcommands panicking inside rustls.
    praxis::install_crypto_provider();

    let cli = Cli::parse();
    let explicit = cli.config.or_else(|| std::env::var("PRAXIS_CONFIG").ok());

    if cli.validate {
        if let Err(error) = commands::load_and_validate_for_cli(explicit.as_deref()) {
            eprintln!("invalid configuration: {error}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    if cli.dump {
        if let Err(error) = commands::run_dump(explicit.as_deref()) {
            eprintln!("dump failed: {error}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    let (config, config_file) = load_serving_config(explicit.as_deref());
    let tracing_guard = praxis::init_tracing(&config).unwrap_or_else(|error| praxis::fatal(&error));
    let log_level = Some(tracing_guard.log_level_state());
    let log_output = config.runtime.logging.output;
    info!(version = env!("PRAXIS_VERSION"), "starting server");

    let _tracing_guard = tracing_guard;
    // Returning instead of exiting drops the guard, flushing queued logs and spans.
    praxis::try_run_server(config, config_file, log_level)
        .map_or_else(|error| praxis::report_fatal(&error, log_output), |()| ExitCode::SUCCESS)
}

/// Resolve the config path, read it once and parse that text, so the config
/// that runs, the file the reload watcher watches, and the baseline it
/// compares against are all the same bytes. Exits on failure: tracing is not
/// up yet, so there is nothing to flush.
fn load_serving_config(explicit: Option<&str>) -> (Config, Option<ConfigFile>) {
    let config_path = praxis::resolve_config_path(explicit);
    let config_file = config_path
        .as_deref()
        .map(ConfigFile::read)
        .transpose()
        .unwrap_or_else(|error| praxis::fatal(&error));
    // Validation warns before the configured subscriber can exist.
    let config = praxis::with_bootstrap_logging(|| {
        Config::from_config_file_or(config_file.as_ref(), praxis_core::config::DEFAULT_CONFIG)
    })
    .unwrap_or_else(|error| praxis::fatal(&error));
    (config, config_file)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use clap::Parser as _;

    use super::Cli;

    // -------------------------------------------------------------------------
    // --validate CLI parsing
    // -------------------------------------------------------------------------

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
        assert!(!cli.dump, "dump should default to false");
    }

    // -------------------------------------------------------------------------
    // --dump CLI parsing
    // -------------------------------------------------------------------------

    #[test]
    fn cli_dump_short_flag() {
        let cli = Cli::parse_from(["praxis", "-T"]);
        assert!(cli.dump, "-T should set dump to true");
        assert!(!cli.validate, "validate should remain false");
    }

    #[test]
    fn cli_dump_long_flag() {
        let cli = Cli::parse_from(["praxis", "--dump"]);
        assert!(cli.dump, "--dump should set dump to true");
    }

    #[test]
    fn cli_dump_with_config() {
        let cli = Cli::parse_from(["praxis", "-T", "-c", "custom.yaml"]);
        assert!(cli.dump, "-T should set dump to true");
        assert_eq!(cli.config.as_deref(), Some("custom.yaml"), "-c should set config path");
    }

    #[test]
    fn cli_dump_conflicts_with_validate() {
        let result = Cli::try_parse_from(["praxis", "--dump", "--validate"]);
        assert!(result.is_err(), "--dump and --validate should conflict");
    }

    #[test]
    fn cli_dump_short_conflicts_with_validate_short() {
        let result = Cli::try_parse_from(["praxis", "-T", "-t"]);
        assert!(result.is_err(), "-T and -t should conflict");
    }

    // -------------------------------------------------------------------------
    // --version CLI parsing
    // -------------------------------------------------------------------------

    #[test]
    fn cli_version_flag() {
        let result = Cli::try_parse_from(["praxis", "--version"]);
        assert!(
            matches!(&result, Err(error) if error.kind() == clap::error::ErrorKind::DisplayVersion),
            "--version should be recognized"
        );
    }

    #[test]
    fn cli_version_short_flag() {
        let result = Cli::try_parse_from(["praxis", "-V"]);
        assert!(
            matches!(&result, Err(error) if error.kind() == clap::error::ErrorKind::DisplayVersion),
            "-V should be recognized"
        );
    }
}
