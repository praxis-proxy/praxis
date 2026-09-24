// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

#![forbid(unsafe_code)]

//! Development tasks for the Praxis proxy.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::exit,
    clippy::indexing_slicing,
    clippy::min_ident_chars,
    clippy::mod_module_files,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::shadow_unrelated,
    clippy::single_char_lifetime_names,
    clippy::struct_field_names,
    clippy::unused_result_ok,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::wildcard_enum_match_arm,
    reason = "development tooling"
)]
#![allow(let_underscore_drop, reason = "development tooling")]

#[cfg(feature = "dev")]
mod benchmark;
#[cfg(feature = "dev")]
mod debug;
#[cfg(feature = "dev")]
mod echo;
#[cfg(feature = "dev")]
mod filter_docs;
mod fips;
mod lint_deps;
mod lint_example_tests;
#[cfg(feature = "dev")]
mod port;
mod sync_example_readme;

use clap::{Parser, Subcommand};

// -----------------------------------------------------------------------------
// CLI Definition
// -----------------------------------------------------------------------------

/// Top-level CLI for xtask development commands.
#[derive(Parser)]
#[command(name = "xtask", about = "Praxis development tasks")]
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
    #[cfg(feature = "dev")]
    Echo(echo::Args),

    /// Run praxis with development settings.
    /// Runs single-threaded by default.
    #[cfg(feature = "dev")]
    Debug(debug::Args),

    /// Run proxy benchmarks and generate reports.
    #[cfg(feature = "dev")]
    Benchmark(Box<benchmark::Args>),

    /// FIPS build tooling: the compliance report and Red Hat
    /// base image verification.
    Fips(fips::Args),

    /// Check that workspace dependency versions use
    /// three-component semver.
    LintDeps(lint_deps::Args),

    /// Check that every example config has a corresponding
    /// integration test.
    LintExampleTests(lint_example_tests::Args),

    /// Verify or regenerate the `examples/README.md` table
    /// from YAML config header comments.
    SyncExampleReadme(sync_example_readme::Args),

    /// Generate per-filter documentation under `docs/filters/`.
    #[cfg(feature = "dev")]
    GenerateFilterDocs(filter_docs::GenerateArgs),

    /// Check that filter doc files are up to date.
    #[cfg(feature = "dev")]
    LintFilterDocs(filter_docs::LintArgs),
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

/// Dispatch the CLI subcommand to its handler.
fn main() {
    let cli = Cli::parse();
    match cli.command {
        #[cfg(feature = "dev")]
        Command::Echo(args) => echo::run(args),
        #[cfg(feature = "dev")]
        Command::Debug(args) => debug::run(&args),
        #[cfg(feature = "dev")]
        Command::Benchmark(args) => benchmark::run(*args),
        Command::Fips(args) => fips::run(args),
        Command::LintDeps(args) => lint_deps::run(args),
        Command::LintExampleTests(args) => lint_example_tests::run(args),
        Command::SyncExampleReadme(args) => sync_example_readme::run(&args),
        #[cfg(feature = "dev")]
        Command::GenerateFilterDocs(args) => filter_docs::generate(args),
        #[cfg(feature = "dev")]
        Command::LintFilterDocs(args) => filter_docs::lint(args),
    }
}

// -----------------------------------------------------------------------------
// Tracing Setup
// -----------------------------------------------------------------------------

/// Initialize tracing with the given default level.
///
/// Respects `RUST_LOG` if set, otherwise falls back to
/// `default_level`. Set `PRAXIS_LOG_FORMAT=json` for
/// structured JSON output.
#[cfg(feature = "dev")]
pub(crate) fn init_tracing(default_level: &str) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));

    let json = std::env::var("PRAXIS_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json"));

    if json {
        tracing_subscriber::fmt().json().with_env_filter(env_filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }
}
