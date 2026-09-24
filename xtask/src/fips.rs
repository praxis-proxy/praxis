// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask fips`: tooling for the FIPS build.
//!
//! - `report`: assess a praxis build against the rules Red Hat's release scanner (openshift/check-payload) applies to
//!   Rust binaries, with a reason and a pointer for every finding.
//! - `verify-image`: prove that a Red Hat base image is signed by Red Hat before it becomes the base of a FIPS build.
//! - `signature-store`: point podman at Red Hat's signature store on hosts whose podman packaging never did, without
//!   which `verify-image` cannot see the signatures.
//!
//! Everything the tasks need (Red Hat's release key, the signature store
//! location, an OpenSSL configuration that activates the FIPS provider) is
//! compiled in from `xtask/assets/fips/`, so nothing depends on host files.

mod assets;
mod binary;
mod environment;
mod graph;
mod guards;
mod openpgp;
mod report;
mod signature_store;
mod verify_image;

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
    /// Compliance report for a praxis build: dependency graph, binary,
    /// source guards.
    Report(report::Args),

    /// Verify that a digest-pinned registry.access.redhat.com image is
    /// signed by Red Hat.
    VerifyImage(verify_image::Args),

    /// Whether podman knows where Red Hat's image signatures live;
    /// --install adds the entry on hosts whose podman packaging ships none.
    SignatureStore(signature_store::Args),
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Dispatch a FIPS task.
pub(crate) fn run(args: Args) {
    match args.command {
        Command::Report(args) => report::run(&args),
        Command::VerifyImage(args) => verify_image::run(&args),
        Command::SignatureStore(args) => signature_store::run(&args),
    }
}
