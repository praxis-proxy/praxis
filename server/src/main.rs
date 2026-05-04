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
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

/// Entry point.
#[allow(clippy::print_stderr, reason = "fatal error output")]
fn main() {
    let cli = Cli::parse();
    let explicit = cli.config.or_else(|| std::env::var("PRAXIS_CONFIG").ok());
    let config_path = praxis::resolve_config_path(explicit.as_deref());
    let config = praxis::load_config(explicit.as_deref()).unwrap_or_else(|e| praxis::fatal(&e));
    praxis::init_tracing(&config).unwrap_or_else(|e| praxis::fatal(&e));
    info!("starting server");
    praxis::run_server(config, config_path)
}
