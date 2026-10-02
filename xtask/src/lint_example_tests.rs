// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask lint-example-tests` enforce that every example config has a
//! corresponding integration test.

use clap::Parser;

use crate::paths::workspace_root;

// -----------------------------------------------------------------------------
// Allowlist
// -----------------------------------------------------------------------------

/// Example configs that are intentionally exempt from the integration test
/// requirement. Each entry must have a justification. Shrink this list over
/// time by adding tests.
const SKIP: &[&str] = &[
    // Protocols: TLS/mTLS variants requiring cert infrastructure
    "protocols/tls-cipher-suites.yaml",
    "protocols/tls-http-reencrypt.yaml",
    "protocols/tls-mtls-both.yaml",
    "protocols/tls-mtls-listener-request.yaml",
    "protocols/tls-mtls-listener.yaml",
    "protocols/tls-mtls-spiffe.yaml",
    "protocols/tls-mtls-upstream.yaml",
    "protocols/tls-multi-cert.yaml",
    "protocols/tls-verify-disabled.yaml",
    "protocols/tls-version-constraint.yaml",
    "protocols/upstream-ca-file.yaml",
    "protocols/upstream-tls.yaml",
];

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask lint-example-tests`.
#[derive(Parser)]
pub(crate) struct Args;

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Verify that every example config under `examples/configs/` is referenced by
/// at least one test file under `tests/`, and that every [`SKIP`] entry still
/// names an untested config.
pub(crate) fn run(_args: Args) {
    let root = workspace_root();
    let configs = or_exit(collect_yaml_files(&root.join("examples/configs")));
    if configs.is_empty() {
        eprintln!(
            "error: no example configs found under {}",
            root.join("examples/configs").display()
        );
        std::process::exit(1);
    }
    let test_sources = or_exit(read_all_sources(&root.join("tests")));

    let stale = stale_skips(SKIP, &configs, &test_sources);
    let missing: Vec<&str> = configs
        .iter()
        .filter(|c| !SKIP.contains(&c.as_str()))
        .filter(|c| !test_sources.contains(c.as_str()))
        .map(String::as_str)
        .collect();

    if missing.is_empty() && stale.is_empty() {
        let skipped = SKIP.len();
        println!(
            "all {count} example configs have test coverage ({skipped} skipped)",
            count = configs.len() - skipped,
        );
        return;
    }
    report_failures(&stale, &missing);
    std::process::exit(1);
}

/// Print the stale SKIP entries and the untested configs.
fn report_failures(stale: &[&str], missing: &[&str]) {
    if !stale.is_empty() {
        eprintln!(
            "stale SKIP entries (tested or no longer present); remove them from xtask/src/lint_example_tests.rs:"
        );
        for path in stale {
            eprintln!("  {path}");
        }
    }
    if !missing.is_empty() {
        eprintln!("example configs without integration tests:");
        for path in missing {
            eprintln!("  {path}");
        }
        if let Some(eg) = missing.first() {
            eprintln!(
                "\nadd a test that uses load_example_config(\"{eg}\", ...) \
                 or add the path to the SKIP allowlist in xtask/src/lint_example_tests.rs",
            );
        }
    }
}

/// SKIP entries that no longer belong: referenced by a test, or naming a
/// config that does not exist.
fn stale_skips<'a>(skip: &[&'a str], configs: &[String], sources: &str) -> Vec<&'a str> {
    skip.iter()
        .copied()
        .filter(|entry| sources.contains(entry) || !configs.iter().any(|c| c == entry))
        .collect()
}

/// Unwrap an I/O result, or print the error and exit 1.
fn or_exit<T>(result: std::io::Result<T>) -> T {
    result.unwrap_or_else(|err| {
        eprintln!("error: {err}");
        std::process::exit(1);
    })
}

// -----------------------------------------------------------------------------
// File Collection
// -----------------------------------------------------------------------------

/// Collect all `.yaml` file paths relative to `root`.
fn collect_yaml_files(root: &std::path::Path) -> std::io::Result<Vec<String>> {
    let mut files = Vec::new();
    walk_dir(root, root, "yaml", &mut files)?;
    files.sort();
    Ok(files)
}

/// Read all `.rs` files under `root` into a single concatenated string.
fn read_all_sources(root: &std::path::Path) -> std::io::Result<String> {
    let mut paths = Vec::new();
    walk_dir(root, root, "rs", &mut paths)?;

    let mut buf = String::new();
    for rel in &paths {
        let path = root.join(rel);
        let content = std::fs::read_to_string(&path).map_err(|err| with_path(&path, &err))?;
        buf.push_str(&content);
    }
    Ok(buf)
}

/// Recursively collect files with `ext` under `base`, storing paths relative
/// to `root`.
fn walk_dir(base: &std::path::Path, root: &std::path::Path, ext: &str, out: &mut Vec<String>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(base).map_err(|err| with_path(base, &err))? {
        let path = entry.map_err(|err| with_path(base, &err))?.path();
        if path.is_dir() {
            walk_dir(&path, root, ext, out)?;
        } else if path.extension().is_some_and(|e| e == ext)
            && let Ok(rel) = path.strip_prefix(root)
        {
            out.push(rel.to_string_lossy().into_owned());
        }
    }
    Ok(())
}

/// An I/O error prefixed with the path it concerns.
fn with_path(path: &std::path::Path, err: &std::io::Error) -> std::io::Error {
    std::io::Error::new(err.kind(), format!("{}: {err}", path.display()))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_found_in_source() {
        let source = r#"load_example_config("traffic-management/basic.yaml", port)"#;
        assert!(
            source.contains("traffic-management/basic.yaml"),
            "config path should be found in source"
        );
    }

    #[test]
    fn config_not_found_in_source() {
        let source = r#"load_example_config("traffic-management/basic.yaml", port)"#;
        assert!(
            !source.contains("security/missing.yaml"),
            "missing config should not be found"
        );
    }

    #[test]
    fn skip_list_entries_are_sorted() {
        let mut sorted = SKIP.to_vec();
        sorted.sort_unstable();
        assert_eq!(SKIP, sorted.as_slice(), "SKIP allowlist must be sorted");
    }

    #[test]
    fn skip_list_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for entry in SKIP {
            assert!(seen.insert(entry), "duplicate SKIP entry: {entry}");
        }
    }

    #[test]
    fn collect_yaml_finds_real_examples() -> std::io::Result<()> {
        let root = workspace_root();
        let configs = collect_yaml_files(&root.join("examples/configs"))?;
        assert!(
            configs.len() > 50,
            "expected 50+ example configs, found {}",
            configs.len()
        );
        assert!(
            configs.contains(&"traffic-management/basic-reverse-proxy.yaml".to_owned()),
            "basic-reverse-proxy.yaml should be in the config list"
        );
        Ok(())
    }

    #[test]
    fn all_skip_entries_exist_on_disk() -> std::io::Result<()> {
        let root = workspace_root();
        let configs = collect_yaml_files(&root.join("examples/configs"))?;
        for entry in SKIP {
            assert!(
                configs.contains(&(*entry).to_owned()),
                "SKIP entry does not exist: {entry}"
            );
        }
        Ok(())
    }

    #[test]
    fn collect_yaml_fails_on_a_missing_directory() {
        assert!(
            collect_yaml_files(std::path::Path::new("/nonexistent")).is_err(),
            "a missing directory is an error, not an empty list"
        );
    }

    #[test]
    fn stale_skips_reports_a_tested_entry() {
        let configs = vec!["a.yaml".to_owned(), "b.yaml".to_owned()];
        let sources = r#"load_example_config("a.yaml", port)"#;
        assert_eq!(
            stale_skips(&["a.yaml", "b.yaml"], &configs, sources),
            vec!["a.yaml"],
            "an entry a test references is stale"
        );
    }

    #[test]
    fn stale_skips_reports_a_nonexistent_entry() {
        let configs = vec!["b.yaml".to_owned()];
        assert_eq!(
            stale_skips(&["gone.yaml", "b.yaml"], &configs, ""),
            vec!["gone.yaml"],
            "an entry naming no config is stale"
        );
    }
}
