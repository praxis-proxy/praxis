// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

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
#[allow(clippy::print_stderr, reason = "fatal error output")]
fn main() {
    let cli = Cli::parse();
    let explicit = cli.config.or_else(|| std::env::var("PRAXIS_CONFIG").ok());

    if cli.validate {
        if let Err(e) = commands::load_and_validate_for_cli(explicit.as_deref()) {
            eprintln!("invalid configuration: {e}");
            std::process::exit(1);
        }
        return;
    }

    if cli.dump {
        if let Err(e) = commands::run_dump(explicit.as_deref()) {
            eprintln!("dump failed: {e}");
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use clap::Parser;

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
}
