//! Development tasks for the Praxis proxy.
//!
//! Usage: `cargo xtask <command>`

#![deny(unsafe_code)]

mod benchmark;
mod debug;
mod echo;
mod port;

use clap::{Parser, Subcommand};

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

// Dispatch the CLI subcommand to its handler.
fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Echo(args) => echo::run(args),
        Command::Debug(args) => debug::run(&args),
        Command::Benchmark(args) => benchmark::run(*args),
    }
}

// -----------------------------------------------------------------------------
// CLI Definition
// -----------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "xtask", about = "Praxis development tasks")]
/// Top-level CLI for xtask development commands.
struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    command: Command,
}

/// Available xtask subcommands.
#[derive(Subcommand)]
enum Command {
    /// Start a quick HTTP test server returning a static
    /// response to every request.
    Echo(echo::Args),

    /// Run praxis with development settings.
    /// Runs single-threaded by default.
    Debug(debug::Args),

    /// Run proxy benchmarks and generate reports.
    Benchmark(Box<benchmark::Args>),
}

// -----------------------------------------------------------------------------
// Tracing Setup
// -----------------------------------------------------------------------------

/// Initialize tracing with the given default level.
///
/// Respects `RUST_LOG` if set, otherwise falls back to
/// `default_level`. Set `PRAXIS_LOG_FORMAT=json` for
/// structured JSON output.
pub(crate) fn init_tracing(default_level: &str) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));

    let json = std::env::var("PRAXIS_LOG_FORMAT").map(|v| v == "json").unwrap_or(false);

    if json {
        tracing_subscriber::fmt().json().with_env_filter(env_filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }
}
