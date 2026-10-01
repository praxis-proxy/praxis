// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask publish`: publish the workspace's publishable crates to
//! crates.io, skipping any already on the index at their current version.
//!
//! A bare `cargo publish --workspace` refuses to run when any member's
//! version is already published, and a multi-crate publish is not
//! transactional: crates that landed before a failure stay live. Checking
//! the index first makes the publish re-runnable, so a release that failed
//! partway, or a release published a second time, can simply run it again.

use std::process::Command;

use clap::Parser;

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask publish`.
#[derive(Parser)]
pub(crate) struct Args {
    /// Print which crates would be skipped or published, and the `cargo
    /// publish` invocation, without publishing anything.
    #[arg(long)]
    dry_run: bool,
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Publish every publishable workspace crate whose version is not already on
/// crates.io, in one dependency-ordered `cargo publish` run.
pub(crate) fn run(args: &Args) {
    let metadata = cargo_metadata();
    let workspace_root = metadata["workspace_root"].as_str().unwrap_or(".").to_owned();

    let crates = publishable_crates(&metadata);
    if crates.is_empty() {
        eprintln!("no publishable crates in the workspace");
        std::process::exit(1);
    }

    let (published, pending) = partition_by_index(crates);
    if pending.is_empty() {
        println!("every publishable crate is already on crates.io at its current version");
        return;
    }
    publish_pending(&workspace_root, &published, args.dry_run);
}

/// Sort the crates into those crates.io already has at their current version
/// and those still awaiting publication, reporting each.
fn partition_by_index(crates: Vec<(String, String)>) -> (Vec<String>, Vec<String>) {
    let mut published = Vec::new();
    let mut pending = Vec::new();
    for (name, version) in crates {
        if index_has_version(&name, &version) {
            println!("{name} {version}: already on crates.io, skipping");
            published.push(name);
        } else {
            println!("{name} {version}: to publish");
            pending.push(name);
        }
    }
    (published, pending)
}

/// Run the dependency-ordered `cargo publish` for the workspace, excluding
/// the crates the index already has.
fn publish_pending(workspace_root: &str, published: &[String], dry_run: bool) {
    let mut cargo_args: Vec<String> = ["publish", "--workspace", "--locked"]
        .iter()
        .map(ToString::to_string)
        .collect();
    for name in published {
        cargo_args.push("--exclude".to_owned());
        cargo_args.push(name.clone());
    }

    if dry_run {
        println!("dry run; would run: cargo {}", cargo_args.join(" "));
        return;
    }

    let status = Command::new("cargo")
        .args(&cargo_args)
        .current_dir(workspace_root)
        .status()
        .unwrap_or_else(|err| {
            eprintln!("failed to run cargo publish: {err}");
            std::process::exit(1);
        });
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}

// -----------------------------------------------------------------------------
// Workspace Inspection
// -----------------------------------------------------------------------------

/// `cargo metadata` for the workspace, without dependencies.
fn cargo_metadata() -> serde_json::Value {
    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .unwrap_or_else(|err| {
            eprintln!("failed to run cargo metadata: {err}");
            std::process::exit(1);
        });
    if !output.status.success() {
        eprintln!("cargo metadata failed: {}", String::from_utf8_lossy(&output.stderr));
        std::process::exit(1);
    }
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        eprintln!("failed to parse cargo metadata: {err}");
        std::process::exit(1);
    })
}

/// The workspace members that may be published to crates.io, as
/// `(name, version)` pairs.
///
/// A `publish` of `null` is unrestricted. A list restricts the allowed
/// registries and counts only when it names crates.io (`publish = false`
/// surfaces here as an empty list).
fn publishable_crates(metadata: &serde_json::Value) -> Vec<(String, String)> {
    metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|package| match &package["publish"] {
            serde_json::Value::Null => true,
            serde_json::Value::Array(registries) => registries.iter().any(|r| r == "crates-io"),
            _ => false,
        })
        .filter_map(|package| {
            Some((
                package["name"].as_str()?.to_owned(),
                package["version"].as_str()?.to_owned(),
            ))
        })
        .collect()
}

// -----------------------------------------------------------------------------
// Index Lookup
// -----------------------------------------------------------------------------

/// Whether crates.io's index already has `version` of `name`.
///
/// Reads the sparse index over HTTP with curl (present on dev machines and
/// CI runners alike; the Makefile already leans on it). A 404 means the
/// crate has never been published; any other failure aborts, because
/// guessing here risks publishing a version the index would reject.
fn index_has_version(name: &str, version: &str) -> bool {
    let url = format!("https://index.crates.io/{}", index_path(name));
    let body = tempfile::NamedTempFile::new().unwrap_or_else(|err| {
        eprintln!("failed to create a temporary file: {err}");
        std::process::exit(1);
    });
    match fetch_status(&url, body.path()).as_str() {
        "200" => {},
        "404" => return false,
        other => {
            eprintln!("index lookup for {name} failed (HTTP {other})");
            std::process::exit(1);
        },
    }
    let listing = std::fs::read_to_string(body.path()).unwrap_or_else(|err| {
        eprintln!("failed to read the index response for {name}: {err}");
        std::process::exit(1);
    });
    listing_has_version(&listing, version)
}

/// GET `url` with curl, writing the body to `out` and returning the HTTP
/// status code (curl's transport errors go straight to stderr).
fn fetch_status(url: &str, out: &std::path::Path) -> String {
    let output = Command::new("curl")
        .args(["-sS", "-o"])
        .arg(out)
        .args(["-w", "%{http_code}", url])
        .output()
        .unwrap_or_else(|err| {
            eprintln!("failed to run curl (needed for the crates.io index check): {err}");
            std::process::exit(1);
        });
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Whether an index file (one JSON object per published version, one per
/// line) lists `version`. Yanked versions still count: crates.io keeps
/// their version numbers taken.
fn listing_has_version(listing: &str, version: &str) -> bool {
    listing
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .any(|entry| entry["vers"] == version)
}

/// The sparse-index path for a crate name, per the index's layout: one- to
/// three-character names get length-keyed folders, longer names are keyed
/// by their first four characters.
fn index_path(name: &str) -> String {
    let name = name.to_lowercase();
    let prefix: Vec<char> = name.chars().take(4).collect();
    match prefix.as_slice() {
        [] => name, // not a valid crate name; the lookup will 404
        [_] => format!("1/{name}"),
        [_, _] => format!("2/{name}"),
        [a, _, _] => format!("3/{a}/{name}"),
        [a, b, c, d, ..] => format!("{a}{b}/{c}{d}/{name}"),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_paths_follow_the_sparse_index_scheme() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("ab"), "2/ab");
        assert_eq!(index_path("abc"), "3/a/abc");
        assert_eq!(index_path("praxis-proxy-core"), "pr/ax/praxis-proxy-core");
        assert_eq!(index_path("Serde"), "se/rd/serde");
    }

    #[test]
    fn listings_match_exact_versions_including_yanked() {
        let listing = concat!(
            r#"{"name":"demo","vers":"0.7.0","yanked":false}"#,
            "\n",
            r#"{"name":"demo","vers":"0.7.1","yanked":true}"#,
            "\n",
        );
        assert!(listing_has_version(listing, "0.7.0"));
        assert!(listing_has_version(listing, "0.7.1"));
        assert!(!listing_has_version(listing, "0.7.2"));
    }

    #[test]
    fn publish_false_and_foreign_registry_crates_are_left_out() {
        let metadata = serde_json::json!({
            "packages": [
                {"name": "open", "version": "0.7.1", "publish": null},
                {"name": "closed", "version": "0.7.1", "publish": []},
                {"name": "internal", "version": "0.7.1", "publish": ["corp"]},
                {"name": "dual", "version": "0.7.1", "publish": ["corp", "crates-io"]},
            ]
        });
        let crates = publishable_crates(&metadata);
        assert_eq!(
            crates,
            vec![
                ("open".to_owned(), "0.7.1".to_owned()),
                ("dual".to_owned(), "0.7.1".to_owned()),
            ]
        );
    }
}
