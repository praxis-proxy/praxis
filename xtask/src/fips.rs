// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask fips`: the FIPS tooling that is specific to Praxis.
//!
//! - `runtime-probe`: run the shipped FIPS image on a FIPS host and prove from outside what it negotiates and refuses.
//!
//! Everything that is not specific to Praxis (the compliance report, the
//! Red Hat base image verification, the signature store setup and the FIPS
//! host attestation) is `cargo fips-check`, from
//! <https://github.com/praxis-proxy/cargo-fips-check>; the Makefile's FIPS
//! targets install it at a pinned revision and `fips-check.toml` configures it.

mod policy_probe;
mod runtime_probe;

use clap::{Parser, Subcommand};

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask fips`.
#[derive(Parser)]
pub(crate) struct Args {
    /// The FIPS task to run.
    #[command(subcommand)]
    command: Command,
}

/// FIPS tasks.
#[derive(Subcommand)]
enum Command {
    /// Run the shipped FIPS image on this FIPS host and drive the listener
    /// probes against it.
    RuntimeProbe(runtime_probe::Args),
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Dispatch a FIPS task.
pub(crate) fn run(args: Args) {
    match args.command {
        Command::RuntimeProbe(args) => runtime_probe::run(&args),
    }
}
