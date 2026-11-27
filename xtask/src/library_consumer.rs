// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Check the default library dependency graph outside the Praxis workspace.

use std::{error::Error, process::Command};

/// Report a failed check without leaving a temporary consumer behind.
pub(crate) fn run() {
    if let Err(error) = check() {
        eprintln!("standalone library consumer failed: {error}");
        std::process::exit(1);
    }
}

/// Compile a source consumer that cannot inherit root workspace patches.
fn check() -> Result<(), Box<dyn Error>> {
    let consumer = tempfile::tempdir()?;
    prepare(consumer.path())?;
    let status = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .arg("check")
        .arg("--manifest-path")
        .arg(consumer.path().join("Cargo.toml"))
        .current_dir(consumer.path())
        .status()?;
    drop(consumer);
    if !status.success() {
        return Err(format!("cargo check exited with {status}").into());
    }
    Ok(())
}

/// Write an isolated Cargo workspace with a source dependency on Praxis core.
fn prepare(consumer: &std::path::Path) -> Result<(), Box<dyn Error>> {
    let core = crate::paths::workspace_root().join("crates/core");
    let core = serde_json::to_string(&core.to_string_lossy().replace('\\', "/"))?;
    let manifest = format!(
        r#"[package]
name = "praxis-library-consumer-check"
version = "0.0.0"
edition = "2024"

[workspace]

[dependencies]
praxis-core = {{ package = "praxis-proxy-core", path = {core} }}
"#
    );
    std::fs::create_dir(consumer.join("src"))?;
    std::fs::write(consumer.join("Cargo.toml"), manifest)?;
    std::fs::write(consumer.join("src/main.rs"), "fn main() {}\n")?;
    Ok(())
}
