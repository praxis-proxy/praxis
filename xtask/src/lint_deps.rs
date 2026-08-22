// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask lint-deps` — enforce three-component semver in workspace
//! dependencies and workspace inheritance in member manifests.

use clap::Parser;

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask lint-deps`.
#[derive(Parser)]
pub(crate) struct Args;

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Validate that all version strings in `[workspace.dependencies]` use
/// three-component semver (`MAJOR.MINOR.PATCH`) and that member crate
/// manifests inherit their dependencies from the workspace.
pub(crate) fn run(_args: Args) {
    let workspace_root = workspace_root();
    let cargo_toml_path = workspace_root.join("Cargo.toml");
    let content = std::fs::read_to_string(&cargo_toml_path).unwrap_or_else(|err| {
        eprintln!("failed to read {}: {err}", cargo_toml_path.display());
        std::process::exit(1);
    });

    let version_violations = check_workspace_deps(&content);
    let member_violations = check_member_manifests(&workspace_root, &content);

    if !version_violations.is_empty() {
        eprintln!("workspace dependency version violations:");
        for (crate_name, version) in &version_violations {
            eprintln!("  {crate_name} = \"{version}\" (expected MAJOR.MINOR.PATCH)");
        }
    }

    if !member_violations.is_empty() {
        eprintln!("member crates declaring dependencies outside [workspace.dependencies]:");
        for (manifest, dep_line) in &member_violations {
            eprintln!("  {manifest}: {dep_line}");
        }
        eprintln!("  (use `workspace = true` or add `# workspace:ignore`)");
    }

    if !version_violations.is_empty() || !member_violations.is_empty() {
        std::process::exit(1);
    }

    println!("all workspace dependency versions use three-component semver");
    println!("all member crate dependencies inherit from [workspace.dependencies]");
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

/// Walk every `[workspace] members` manifest and return dependency lines
/// that neither inherit from the workspace (`workspace = true`) nor point
/// at a workspace-local path (`path = ...`).
///
/// Returns `(manifest display path, offending line)` pairs.
fn check_member_manifests(root: &std::path::Path, workspace_toml: &str) -> Vec<(String, String)> {
    let mut violations = Vec::new();
    for member in workspace_members(workspace_toml) {
        let manifest_path = root.join(&member).join("Cargo.toml");
        let Ok(content) = std::fs::read_to_string(&manifest_path) else {
            eprintln!("failed to read {}", manifest_path.display());
            std::process::exit(1);
        };
        let display = format!("{member}/Cargo.toml");
        for line in non_workspace_dep_lines(&content) {
            violations.push((display.clone(), line));
        }
    }
    violations
}

/// Parse the `members` array of the `[workspace]` section.
///
/// Handles both single-line (`members = ["a", "b"]`) and multi-line array
/// layouts. Glob patterns are not supported (this workspace lists members
/// explicitly).
fn workspace_members(content: &str) -> Vec<String> {
    let mut members = Vec::new();
    let mut in_workspace = false;
    let mut in_members = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('[') {
            in_workspace = trimmed == "[workspace]";
            in_members = false;
            continue;
        }

        if !in_workspace {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("members") {
            let rest = rest.trim_start();
            if let Some(array) = rest.strip_prefix('=') {
                in_members = true;
                collect_member_entries(array, &mut members, &mut in_members);
            }
            continue;
        }

        if in_members {
            collect_member_entries(trimmed, &mut members, &mut in_members);
        }
    }

    members
}

/// Append quoted entries from a fragment of a TOML `members` array,
/// clearing `in_members` when the closing bracket is reached.
fn collect_member_entries(fragment: &str, members: &mut Vec<String>, in_members: &mut bool) {
    let mut rest = fragment;
    while let Some(start) = rest.find('"') {
        let Some(inner) = rest.get(start + 1..) else {
            break;
        };
        let Some(end) = inner.find('"') else {
            break;
        };
        if let Some(entry) = inner.get(..end) {
            members.push(entry.to_owned());
        }
        rest = inner.get(end + 1..).unwrap_or("");
    }
    if fragment.contains(']') {
        *in_members = false;
    }
}

/// Return dependency lines in `[dependencies]`, `[dev-dependencies]`, and
/// `[build-dependencies]` sections that neither set `workspace = true` nor
/// use a `path` dependency.
///
/// Lines with an inline `# workspace:ignore` comment, or preceded by one,
/// are skipped.
fn non_workspace_dep_lines(content: &str) -> Vec<String> {
    let mut offending = Vec::new();
    let mut in_dep_section = false;
    let mut skip_next = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('[') {
            in_dep_section = is_dependency_section(trimmed);
            skip_next = false;
            continue;
        }

        if !in_dep_section || trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with('#') {
            skip_next = trimmed.contains("workspace:ignore");
            continue;
        }

        if skip_next || trimmed.contains("workspace:ignore") {
            skip_next = false;
            continue;
        }
        skip_next = false;

        if lacks_workspace_inheritance(trimmed) {
            offending.push(trimmed.to_owned());
        }
    }

    offending
}

/// Whether a TOML section header declares dependencies.
///
/// Covers the plain sections and platform-specific tables like
/// `[target.'cfg(unix)'.dependencies]`, which a fixed-list match would
/// silently exempt from the workspace-inheritance rule.
fn is_dependency_section(header: &str) -> bool {
    let name = header.trim_start_matches('[').trim_end_matches(']');
    name == "dependencies"
        || name == "dev-dependencies"
        || name == "build-dependencies"
        || (name.starts_with("target.")
            && (name.ends_with(".dependencies")
                || name.ends_with(".dev-dependencies")
                || name.ends_with(".build-dependencies")))
}

/// Check whether a dependency line declares its source directly instead
/// of inheriting from the workspace (`workspace = true`) or using a
/// workspace-local `path` dependency.
fn lacks_workspace_inheritance(line: &str) -> bool {
    line.contains('=') && !line.contains("workspace = true") && !line.contains("path =")
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
    Some(inner.get(..end)?.to_owned())
}

/// Extract the `version = "..."` value from an inline TOML table string.
///
/// Expects the table form: `{ version = "1.2.3", ... }`.
fn extract_table_version(s: &str) -> Option<String> {
    let idx = s.find("version")?;
    if idx > 0 && s.as_bytes().get(idx - 1).is_some_and(u8::is_ascii_alphanumeric) {
        return None;
    }
    let after_key = s.get(idx + "version".len()..)?.trim_start();
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
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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

    #[test]
    fn parses_multi_line_members_array() {
        let toml = "[workspace]\nmembers = [\n    \"core\",\n    \"filter\",\n]\nresolver = \"2\"\n";
        let members = workspace_members(toml);
        assert_eq!(members, vec!["core".to_owned(), "filter".to_owned()]);
    }

    #[test]
    fn parses_single_line_members_array() {
        let toml = "[workspace]\nmembers = [\"a\", \"b/c\"]\n";
        let members = workspace_members(toml);
        assert_eq!(members, vec!["a".to_owned(), "b/c".to_owned()]);
    }

    #[test]
    fn members_outside_workspace_section_are_ignored() {
        let toml = "[package]\nmembers = [\"nope\"]\n\n[workspace]\nmembers = [\"yes\"]\n";
        let members = workspace_members(toml);
        assert_eq!(members, vec!["yes".to_owned()]);
    }

    #[test]
    fn workspace_inherited_deps_pass() {
        let toml = "[dependencies]\nserde = { workspace = true }\ntokio = { workspace = true, features = [\"rt\"] }\n";
        let offending = non_workspace_dep_lines(toml);
        assert!(offending.is_empty(), "workspace-inherited deps should pass");
    }

    #[test]
    fn path_deps_pass() {
        let toml = "[dependencies]\npraxis-core = { path = \"../core\" }\n";
        let offending = non_workspace_dep_lines(toml);
        assert!(offending.is_empty(), "path deps should pass");
    }

    #[test]
    fn direct_version_dep_is_flagged() {
        let toml = "[dependencies]\nserde = \"1.0.200\"\n\n[dev-dependencies]\ntempfile = { version = \"3.23.0\" }\n";
        let offending = non_workspace_dep_lines(toml);
        assert_eq!(offending.len(), 2, "direct version deps should be flagged");
        assert_eq!(offending[0], "serde = \"1.0.200\"");
        assert_eq!(offending[1], "tempfile = { version = \"3.23.0\" }");
    }

    #[test]
    fn non_dependency_sections_are_ignored() {
        let toml = "[package]\nname = \"foo\"\nversion = \"0.1.0\"\n\n[features]\ndefault = []\n\n[dependencies]\nserde = { workspace = true }\n";
        let offending = non_workspace_dep_lines(toml);
        assert!(offending.is_empty(), "package/features sections should be ignored");
    }

    #[test]
    fn workspace_ignore_directive_skips_dep() {
        let toml = "[dependencies]\nspecial = \"1.0.0\" # workspace:ignore\n# workspace:ignore\nother = \"2.0.0\"\nflagged = \"3.0.0\"\n";
        let offending = non_workspace_dep_lines(toml);
        assert_eq!(offending.len(), 1, "ignored deps should be skipped");
        assert_eq!(offending[0], "flagged = \"3.0.0\"");
    }

    #[test]
    fn build_dependencies_are_checked() {
        let toml = "[build-dependencies]\ncc = \"1.2.0\"\n";
        let offending = non_workspace_dep_lines(toml);
        assert_eq!(offending.len(), 1, "build-dependencies should be checked");
    }
}
