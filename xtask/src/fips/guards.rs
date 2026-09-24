// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Source guards section of the report: the application must never enable a
//! FIPS provider itself, must not use OpenSSL's legacy (non-provider) APIs,
//! and must not vendor or statically link OpenSSL.

use std::path::{Path, PathBuf};

use regex::Regex;

use super::report::{Finding, Report};

/// How many hits a guard reports at most.
const MAX_HITS: usize = 10;

/// One guard: a pattern that must not appear outside comments in the given
/// paths.
struct Guard {
    /// Name in the report.
    label: &'static str,
    /// Regex matched against every non-comment line.
    pattern: &'static str,
    /// Why it matters.
    why: &'static str,
    /// What to do.
    fix: &'static str,
    /// Files or directories, relative to the workspace root, to scan.
    paths: &'static [&'static str],
}

/// The guards, mirroring what Red Hat's guidance forbids.
const GUARDS: &[Guard] = &[
    Guard {
        label: "application enables a FIPS provider itself",
        pattern: r#"fips::enable\(|Provider::load\([^)]*"fips""#,
        why: "Red Hat requires FIPS mode to come from the host; an application that loads or enables the provider is \
              in an unsupported state",
        fix: "query only: CryptoProvider::fips(), config.fips(), /proc/sys/crypto/fips_enabled",
        paths: &["crates"],
    },
    Guard {
        label: "legacy OpenSSL digest API",
        pattern: "openssl::sha::",
        why: "openssl::sha::* wraps SHA256_Init and friends, which never dispatch through the provider and so bypass \
              the FIPS module",
        fix: "use openssl::hash (EVP_Digest*)",
        paths: &["crates"],
    },
    Guard {
        label: "vendored OpenSSL",
        pattern: r"^[^#]*\bvendored\b",
        why: "a vendored libcrypto is compiled into the binary and is not the validated module",
        fix: "drop the feature; build with OPENSSL_NO_VENDOR=1",
        paths: &["Cargo.toml", "crates"],
    },
    Guard {
        label: "static OpenSSL linking in shipped build files",
        pattern: "OPENSSL_STATIC",
        why: "statically linked libcrypto defines OPENSSL_* symbols in the binary and fails the symbol scan",
        fix: "remove OPENSSL_STATIC from build files",
        paths: &["Containerfile", "Containerfile.fips", "Makefile", ".github"],
    },
];

/// Append the source guards section.
pub(crate) fn section(report: &mut Report, root: &Path) {
    report.section("Source guards");
    for guard in GUARDS {
        let hits = hits(root, guard);
        let missing = missing_paths(root, guard);
        if hits.is_empty() && missing.is_empty() {
            report.ok(&format!("{}: none", guard.label));
        } else if hits.is_empty() {
            // The report image copies only the sources, so the build-file
            // guard cannot see its files there; `make fips-deps` checks them.
            report.warn(&format!(
                "{}: not checked, {} not present here (make fips-deps checks them)",
                guard.label,
                missing.join(", ")
            ));
        } else {
            report.fail(Finding {
                title: guard.label.to_owned(),
                why: guard.why.to_owned(),
                location: hits.iter().take(3).cloned().collect::<Vec<_>>().join(";"),
                fix: guard.fix.to_owned(),
            });
        }
    }
    if std::fs::read_to_string(root.join("Containerfile.test")).is_ok_and(|text| text.contains("OPENSSL_STATIC")) {
        report.warn(
            "Containerfile.test sets OPENSSL_STATIC (test image only, not shipped); do not copy that into a shipped \
             image",
        );
    }
}

/// The guard's paths that do not exist under `root`.
fn missing_paths(root: &Path, guard: &Guard) -> Vec<&'static str> {
    guard
        .paths
        .iter()
        .copied()
        .filter(|path| !root.join(path).exists())
        .collect()
}

/// Up to [`MAX_HITS`] `path:line:text` hits for a guard.
fn hits(root: &Path, guard: &Guard) -> Vec<String> {
    let regex = Regex::new(guard.pattern).expect("guard patterns are valid");
    let mut hits = Vec::new();
    for path in guard.paths {
        for file in files(&root.join(path)) {
            scan(&regex, root, &file, &mut hits);
            if hits.len() >= MAX_HITS {
                return hits;
            }
        }
    }
    hits
}

/// Append the non-comment lines of `file` that match `regex`.
fn scan(regex: &Regex, root: &Path, file: &Path, hits: &mut Vec<String>) {
    let Ok(text) = std::fs::read_to_string(file) else {
        return;
    };
    let display = file.strip_prefix(root).unwrap_or(file).display().to_string();
    for (index, line) in text.lines().enumerate() {
        if is_comment(line) {
            continue;
        }
        if regex.is_match(line) {
            hits.push(format!("{display}:{}:{line}", index + 1));
        }
    }
}

/// Whether a line is a comment in any of the scanned file types.
fn is_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with('#')
}

/// Every file to scan under `path`: the path itself when it is a file,
/// otherwise the source, manifest, container and workflow files below it.
fn files(path: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if path.is_file() {
        out.push(path.to_owned());
    } else if path.is_dir() {
        walk(path, &mut out);
    }
    out
}

/// Recursive helper for [`files`], skipping build output.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = entries.filter_map(Result::ok).map(|entry| entry.path()).collect();
    entries.sort();
    for entry in entries {
        if entry.is_dir() {
            if entry.file_name().is_some_and(|name| name != "target") {
                walk(&entry, out);
            }
        } else if scannable(&entry) {
            out.push(entry);
        }
    }
}

/// Whether a file is one the guards look at.
fn scannable(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    let extension = path.extension().and_then(|extension| extension.to_str()).unwrap_or("");
    matches!(extension, "rs" | "toml" | "yaml" | "yml") || name.starts_with("Containerfile") || name == "Makefile"
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_patterns_compile_and_match_what_they_should() {
        let vendored = Regex::new(GUARDS[2].pattern).expect("valid");
        assert!(
            vendored.is_match(r#"openssl = { version = "0.10", features = ["vendored"] }"#),
            "a vendored feature"
        );
        assert!(
            !vendored.is_match("openssl = \"0.10\" # never vendored"),
            "a comment after code does not count"
        );
        let enable = Regex::new(GUARDS[0].pattern).expect("valid");
        assert!(
            enable.is_match(r#"let p = Provider::load(None, "fips");"#),
            "loading the provider"
        );
        assert!(enable.is_match("openssl::fips::enable(true)"), "enabling FIPS mode");
        assert!(!enable.is_match("provider.fips()"), "querying is fine");
    }

    #[test]
    fn scanning_skips_comment_lines_and_reports_positions() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("lib.rs");
        std::fs::write(
            &file,
            "// OPENSSL_STATIC in a comment\n  # also a comment OPENSSL_STATIC\nlet x = OPENSSL_STATIC;\n",
        )
        .expect("write");
        let regex = Regex::new("OPENSSL_STATIC").expect("valid");
        let mut hits = Vec::new();
        scan(&regex, dir.path(), &file, &mut hits);
        assert_eq!(
            hits,
            ["lib.rs:3:let x = OPENSSL_STATIC;"],
            "only the code line, with its position"
        );
    }

    #[test]
    fn only_source_manifest_container_and_workflow_files_are_scanned() {
        for scanned in [
            "a/b.rs",
            "Cargo.toml",
            "ci.yaml",
            "x.yml",
            "Containerfile.fips",
            "Makefile",
        ] {
            assert!(scannable(Path::new(scanned)), "{scanned} is scanned");
        }
        for skipped in ["README.md", "praxis", "key.asc", "script.sh"] {
            assert!(!scannable(Path::new(skipped)), "{skipped} is skipped");
        }
    }

    #[test]
    fn a_guard_whose_files_are_absent_warns_instead_of_passing() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir_all(dir.path().join("crates")).expect("mkdir");
        let mut report = Report::default();
        section(&mut report, dir.path());
        let text = report.text();
        assert!(
            text.contains("WARN  static OpenSSL linking in shipped build files: not checked"),
            "a guard with nothing to scan must not report ok:\n{text}"
        );
        assert!(!report.failed(), "a missing path is a warning, not a finding");
    }

    #[test]
    fn walking_skips_target_directories() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir_all(dir.path().join("target/debug")).expect("mkdir");
        std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
        std::fs::write(dir.path().join("target/debug/gen.rs"), "").expect("write");
        std::fs::write(dir.path().join("src/lib.rs"), "").expect("write");
        std::fs::write(dir.path().join("notes.md"), "").expect("write");
        let found = files(dir.path());
        assert_eq!(
            found,
            [dir.path().join("src/lib.rs")],
            "build output and prose are skipped"
        );
    }
}
