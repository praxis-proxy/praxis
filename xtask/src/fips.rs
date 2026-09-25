// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask fips`: tooling for the FIPS build.
//!
//! - `report`: assess a praxis build against the rules Red Hat's release scanner (openshift/check-payload) applies to
//!   Rust binaries, with a reason and a pointer for every finding.
//! - `verify-image`: prove that a Red Hat base image is signed by Red Hat before it becomes the base of a FIPS build.
//! - `signature-store`: point podman at Red Hat's signature store on hosts whose podman packaging never did, without
//!   which `verify-image` cannot see the signatures.
//! - `host-check`: attest that this host is in FIPS mode as the module's Security Policy requires, and that the FIPS
//!   image carries a validated build of the module.
//! - `runtime-probe`: run the shipped FIPS image on a FIPS host and prove from outside what it negotiates and refuses.
//!
//! Everything the tasks need (Red Hat's release key, the signature store
//! location, an OpenSSL configuration that activates the FIPS provider, the
//! list of validated module builds) is compiled in from `xtask/assets/fips/`,
//! so nothing depends on host files.

mod assets;
mod binary;
mod certified;
mod environment;
mod graph;
mod guards;
mod host_check;
mod openpgp;
mod report;
mod runtime_probe;
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

    /// Attest that this host is in FIPS mode as the module's Security
    /// Policy requires, and that a FIPS image carries a validated module.
    HostCheck(host_check::Args),

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
        Command::Report(args) => report::run(&args),
        Command::VerifyImage(args) => verify_image::run(&args),
        Command::SignatureStore(args) => signature_store::run(&args),
        Command::HostCheck(args) => host_check::run(&args),
        Command::RuntimeProbe(args) => runtime_probe::run(&args),
    }
}
