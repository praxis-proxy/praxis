// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask lint-example-tests` enforce that every example config has a
//! corresponding integration test.

use clap::Parser;

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

/// Example configs that are intentionally exempt from the integration test
/// requirement. Each entry must have a justification. Shrink this list over
/// time by adding tests.
const SKIP: &[&str] = &[
    // --- Observability: TCP access log not yet integration-tested ---
    "observability/tcp-access-log.yaml",
    // --- Operations: runtime/container configs that don't exercise filters ---
    "operations/container-default.yaml",
    "operations/hot-reload.yaml",
    "operations/log-overrides.yaml",
    "operations/multi-listener.yaml",
    // --- Payload processing ---
    "payload-processing/compression.yaml",
    "payload-processing/stream-buffer.yaml",
    // --- Pipeline ---
    "pipeline/composed-chains.yaml",
    "pipeline/failure-mode.yaml",
    // --- Protocols: TLS/mTLS variants requiring cert infrastructure ---
    "protocols/mixed-protocol.yaml",
    "protocols/tcp-proxy.yaml",
    "protocols/tcp-timeouts.yaml",
    "protocols/tcp-tls-mtls.yaml",
    "protocols/tcp-tls-termination.yaml",
    "protocols/tls-cipher-suites.yaml",
    "protocols/tls-http-reencrypt.yaml",
    "protocols/tls-mtls-both.yaml",
    "protocols/tls-mtls-listener-request.yaml",
    "protocols/tls-mtls-listener.yaml",
    "protocols/tls-mtls-upstream.yaml",
    "protocols/tls-multi-cert.yaml",
    "protocols/tls-termination.yaml",
    "protocols/tls-verify-disabled.yaml",
    "protocols/tls-version-constraint.yaml",
    "protocols/upstream-ca-file.yaml",
    "protocols/upstream-tls.yaml",
    // --- Security: configs needing specialized test harness ---
    "security/cors.yaml",
    "security/downstream-read-timeout.yaml",
    "security/forwarded-headers.yaml",
    // --- Traffic management ---
    "traffic-management/rate-limiting.yaml",
    "traffic-management/timeout.yaml",
];

// ---------------------------------------------------------------------------
// CLI Arguments
// ---------------------------------------------------------------------------

/// CLI arguments for `cargo xtask lint-example-tests`.
#[derive(Parser)]
pub(crate) struct Args;

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------

/// Verify that every example config under `examples/configs/` is referenced by
/// at least one test file under `tests/`.
pub(crate) fn run(_args: Args) {
    let root = workspace_root();
    let configs = collect_yaml_files(&root.join("examples/configs"));
    let test_sources = read_all_sources(&root.join("tests"));

    let missing: Vec<&str> = configs
        .iter()
        .filter(|c| !SKIP.contains(&c.as_str()))
        .filter(|c| !test_sources.contains(c.as_str()))
        .map(String::as_str)
        .collect();

    if missing.is_empty() {
        println!(
            "all {count} example configs have test coverage ({skip} skipped)",
            count = configs.len() - SKIP.iter().filter(|s| configs.contains(&(**s).to_owned())).count(),
            skip = SKIP.iter().filter(|s| configs.contains(&(**s).to_owned())).count(),
        );
    } else {
        eprintln!("example configs without integration tests:");
        for path in &missing {
            eprintln!("  {path}");
        }
        if let Some(eg) = missing.first() {
            eprintln!(
                "\nadd a test that uses load_example_config(\"{eg}\", ...) \
                 or add the path to the SKIP allowlist in xtask/src/lint_example_tests.rs",
            );
        }
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// File Collection
// ---------------------------------------------------------------------------

/// Collect all `.yaml` file paths relative to `root`.
fn collect_yaml_files(root: &std::path::Path) -> Vec<String> {
    let mut files = Vec::new();
    walk_dir(root, root, "yaml", &mut files);
    files.sort();
    files
}

/// Read all `.rs` files under `root` into a single concatenated string.
fn read_all_sources(root: &std::path::Path) -> String {
    let mut paths = Vec::new();
    walk_dir(root, root, "rs", &mut paths);

    let mut buf = String::new();
    for rel in &paths {
        if let Ok(content) = std::fs::read_to_string(root.join(rel)) {
            buf.push_str(&content);
        }
    }
    buf
}

/// Recursively collect files with `ext` under `base`, storing paths relative
/// to `root`.
fn walk_dir(base: &std::path::Path, root: &std::path::Path, ext: &str, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_dir(&path, root, ext, out);
        } else if path.extension().is_some_and(|e| e == ext)
            && let Ok(rel) = path.strip_prefix(root)
        {
            out.push(rel.to_string_lossy().into_owned());
        }
    }
}

/// Locate the workspace root directory.
fn workspace_root() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    std::path::Path::new(&manifest_dir)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
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
    fn collect_yaml_finds_real_examples() {
        let root = workspace_root();
        let configs = collect_yaml_files(&root.join("examples/configs"));
        assert!(
            configs.len() > 50,
            "expected 50+ example configs, found {}",
            configs.len()
        );
        assert!(
            configs.contains(&"traffic-management/basic-reverse-proxy.yaml".to_owned()),
            "basic-reverse-proxy.yaml should be in the config list"
        );
    }

    #[test]
    fn all_skip_entries_exist_on_disk() {
        let root = workspace_root();
        let configs = collect_yaml_files(&root.join("examples/configs"));
        for entry in SKIP {
            assert!(
                configs.contains(&(*entry).to_owned()),
                "SKIP entry does not exist: {entry}"
            );
        }
    }
}
