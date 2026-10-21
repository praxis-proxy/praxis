// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask features`: the workspace's features, qualified by package,
//! for cargo invocations that cannot use `--all-features`.
//!
//! The network backends are mutually exclusive, so `--all-features` does
//! not compile the workspace. The Makefile asks this command for every
//! feature of the selected packages except the ones it names, read from
//! `cargo metadata`, so a feature added to any manifest is picked up
//! without editing the Makefile.

use cargo_metadata::{MetadataCommand, Package};
use clap::Parser;

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask features`.
#[derive(Parser)]
pub(crate) struct Args {
    /// Features to leave out of every package; `default` is always left out.
    #[arg(long = "except", value_name = "FEATURE")]
    except: Vec<String>,

    /// Workspace members to leave out.
    #[arg(long = "exclude", value_name = "PACKAGE")]
    excludes: Vec<String>,

    /// Packages to list features for; every workspace member when empty.
    #[arg(long = "package", short = 'p', value_name = "PACKAGE")]
    packages: Vec<String>,
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Print the selected packages' features as one comma-separated
/// `package/feature` list, the form `cargo --features` takes for a
/// multi-package invocation.
pub(crate) fn run(args: &Args) {
    let metadata = MetadataCommand::new().no_deps().exec().unwrap_or_else(|err| {
        eprintln!("cargo metadata failed: {err}");
        std::process::exit(1);
    });
    let packages = metadata.workspace_packages();
    reject_unknown_names(args, &packages);

    let mut entries = Vec::new();
    for package in packages {
        let name = package.name.to_string();
        if !args.packages.is_empty() && !args.packages.contains(&name) {
            continue;
        }
        if args.excludes.contains(&name) {
            continue;
        }
        for feature in package.features.keys() {
            if feature == "default" || args.except.contains(feature) {
                continue;
            }
            entries.push(format!("{name}/{feature}"));
        }
    }

    println!("{}", entries.join(","));
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Exit with an error when a package named by `args` is not a workspace
/// member, so a typo cannot quietly shorten the list.
fn reject_unknown_names(args: &Args, packages: &[&Package]) {
    let members: Vec<String> = packages.iter().map(|package| package.name.to_string()).collect();
    if let Some(unknown) = args
        .packages
        .iter()
        .chain(&args.excludes)
        .find(|name| !members.contains(name))
    {
        eprintln!("`{unknown}` is not a workspace member");
        std::process::exit(1);
    }
}
