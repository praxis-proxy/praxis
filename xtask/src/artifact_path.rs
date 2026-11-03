// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Resolve the built binary without guessing Cargo target or profile directories.

/// Print the executable Cargo actually emitted, including cached artifacts.
#[expect(
    clippy::disallowed_methods,
    reason = "development tool consumes Cargo JSON, not proxy input"
)]
pub(crate) fn run() {
    let executable = cargo_metadata::Message::parse_stream(std::io::stdin().lock())
        .filter_map(Result::ok)
        .find_map(|message| match message {
            cargo_metadata::Message::CompilerArtifact(artifact) if artifact.target.name == "praxis" => {
                artifact.executable
            },
            _ => None,
        })
        .expect("Cargo must emit the praxis executable artifact");
    println!("{executable}");
}
