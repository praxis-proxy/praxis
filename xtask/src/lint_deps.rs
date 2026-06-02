// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask lint-deps` — enforce three-component semver in workspace
//! dependencies.

use clap::Parser;

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask lint-deps`.
#[derive(Parser)]
pub(crate) struct Args {}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Validate that all version strings in `[workspace.dependencies]` use
/// three-component semver (`MAJOR.MINOR.PATCH`).
pub(crate) fn run(_args: Args) {
    let workspace_root = workspace_root();
    let cargo_toml_path = workspace_root.join("Cargo.toml");
    let content = std::fs::read_to_string(&cargo_toml_path).unwrap_or_else(|err| {
        eprintln!("failed to read {}: {err}", cargo_toml_path.display());
        std::process::exit(1);
    });

    let violations = check_workspace_deps(&content);

    if violations.is_empty() {
        println!("all workspace dependency versions use three-component semver");
    } else {
        eprintln!("workspace dependency version violations:");
        for (crate_name, version) in &violations {
            eprintln!("  {crate_name} = \"{version}\" (expected MAJOR.MINOR.PATCH)");
        }
        std::process::exit(1);
    }
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Check all version strings in `[workspace.dependencies]` and return any
/// that do not have exactly three dot-separated components.
///
/// Lines preceded by a `# semver:ignore` comment or containing an inline
/// `# semver:ignore` are skipped.
fn check_workspace_deps(content: &str) -> Vec<(String, String)> {
    let mut violations = Vec::new();
    let mut in_workspace_deps = false;
    let mut skip_next = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('[') {
            in_workspace_deps = trimmed == "[workspace.dependencies]";
            skip_next = false;
            continue;
        }

        if !in_workspace_deps || trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with('#') {
            skip_next = has_ignore_directive(trimmed);
            continue;
        }

        if skip_next || has_ignore_directive(trimmed) {
            skip_next = false;
            continue;
        }
        skip_next = false;

        if let Some((name, version)) = extract_dep_version(trimmed)
            && !is_three_component(&version)
        {
            violations.push((name, version));
        }
    }

    violations
}

/// Check whether a line contains the `semver:ignore` directive.
fn has_ignore_directive(line: &str) -> bool {
    line.contains("semver:ignore")
}

/// Extract the crate name and version from a dependency line.
///
/// Returns `None` for lines without a parseable version (e.g. path-only
/// dependencies).
fn extract_dep_version(line: &str) -> Option<(String, String)> {
    let (crate_name, rest) = line.split_once('=')?;
    let crate_name = crate_name.trim();
    let rest = rest.trim();

    let version = if rest.starts_with('"') {
        extract_quoted(rest)
    } else if rest.starts_with('{') {
        extract_table_version(rest)
    } else {
        None
    };

    version.map(|v| (crate_name.to_owned(), v))
}

/// Check whether a version string has exactly three dot-separated
/// components.
fn is_three_component(version: &str) -> bool {
    let base = version.split(['-', '+']).next().unwrap_or(version);
    base.split('.').count() == 3
}

// -----------------------------------------------------------------------------
// Parsing Utilities
// -----------------------------------------------------------------------------

/// Extract the content of the first quoted string in `s`.
///
/// Expects `s` to start with `"`, e.g. `"1.2.3"`.
fn extract_quoted(s: &str) -> Option<String> {
    let inner = s.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some(inner[..end].to_owned())
}

/// Extract the `version = "..."` value from an inline TOML table string.
///
/// Expects the table form: `{ version = "1.2.3", ... }`.
fn extract_table_version(s: &str) -> Option<String> {
    let idx = s.find("version")?;
    if idx > 0 && s.as_bytes().get(idx - 1).is_some_and(u8::is_ascii_alphanumeric) {
        return None;
    }
    let after_key = s[idx + "version".len()..].trim_start();
    let after_eq = after_key.strip_prefix('=')?;
    extract_quoted(after_eq.trim_start())
}

/// Locate the workspace root directory.
///
/// Uses `CARGO_MANIFEST_DIR` (set by cargo for the xtask crate) and
/// navigates one level up to reach the workspace root.
fn workspace_root() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    std::path::Path::new(&manifest_dir)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_owned()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn three_component_version_passes() {
        let toml = "[workspace.dependencies]\nfoo = \"1.2.3\"\n";
        let violations = check_workspace_deps(toml);
        assert!(violations.is_empty(), "three-component version should pass");
    }

    #[test]
    fn two_component_version_fails() {
        let toml = "[workspace.dependencies]\nfoo = \"1.2\"\n";
        let violations = check_workspace_deps(toml);
        assert_eq!(violations.len(), 1, "two-component version should fail");
        assert_eq!(violations[0].0, "foo");
        assert_eq!(violations[0].1, "1.2");
    }

    #[test]
    fn one_component_version_fails() {
        let toml = "[workspace.dependencies]\nfoo = \"1\"\n";
        let violations = check_workspace_deps(toml);
        assert_eq!(violations.len(), 1, "one-component version should fail");
        assert_eq!(violations[0].0, "foo");
        assert_eq!(violations[0].1, "1");
    }

    #[test]
    fn path_only_dep_is_skipped() {
        let toml = "[workspace.dependencies]\nfoo = { path = \"crates/foo\" }\n";
        let violations = check_workspace_deps(toml);
        assert!(violations.is_empty(), "path-only dep should be skipped");
    }

    #[test]
    fn table_dep_with_version_is_checked() {
        let toml = "[workspace.dependencies]\nfoo = { version = \"1.2.3\", features = [\"bar\"] }\n";
        let violations = check_workspace_deps(toml);
        assert!(violations.is_empty(), "three-component table version should pass");
    }

    #[test]
    fn table_dep_with_short_version_fails() {
        let toml = "[workspace.dependencies]\nfoo = { version = \"1.2\", features = [\"bar\"] }\n";
        let violations = check_workspace_deps(toml);
        assert_eq!(violations.len(), 1, "two-component table version should fail");
        assert_eq!(violations[0].0, "foo");
        assert_eq!(violations[0].1, "1.2");
    }

    #[test]
    fn only_checks_workspace_dependencies_section() {
        let toml = "[package]\nversion = \"1\"\n\n[workspace.dependencies]\nfoo = \"1.2.3\"\n\n[profile.release]\nopt-level = 3\n";
        let violations = check_workspace_deps(toml);
        assert!(
            violations.is_empty(),
            "should only check [workspace.dependencies] section"
        );
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let toml = "[workspace.dependencies]\n# A comment\n\nfoo = \"1.2.3\"\n";
        let violations = check_workspace_deps(toml);
        assert!(violations.is_empty(), "comments and blank lines should be skipped");
    }

    #[test]
    fn preceding_semver_ignore_skips_next_dep() {
        let toml = "[workspace.dependencies]\n# semver:ignore\nfoo = \"1.2\"\nbar = \"3.4\"\n";
        let violations = check_workspace_deps(toml);
        assert_eq!(violations.len(), 1, "only non-ignored dep should fail");
        assert_eq!(violations[0].0, "bar");
    }

    #[test]
    fn inline_semver_ignore_skips_dep() {
        let toml = "[workspace.dependencies]\nfoo = \"1.2\" # semver:ignore\nbar = \"3.4\"\n";
        let violations = check_workspace_deps(toml);
        assert_eq!(violations.len(), 1, "only non-ignored dep should fail");
        assert_eq!(violations[0].0, "bar");
    }

    #[test]
    fn semver_ignore_does_not_carry_past_one_line() {
        let toml = "[workspace.dependencies]\n# semver:ignore\nfoo = \"1.2\"\nbar = \"3.4\"\nbaz = \"5.6.7\"\n";
        let violations = check_workspace_deps(toml);
        assert_eq!(violations.len(), 1, "ignore should only apply to the next dep");
        assert_eq!(violations[0].0, "bar");
    }
}
