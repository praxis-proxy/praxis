// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask fips report`: FIPS compliance report for a praxis build.
//!
//! Prints a report with a reason and a pointer for every finding, so a
//! developer can see where to look. The exit status is 0 when there are no
//! findings and 1 otherwise; warnings never change it.
//!
//! What is checked, and why it matters for Red Hat's gate
//! (openshift/check-payload, Rust support in its PR #360):
//!
//! 1. dependency graph: crates on the scanner's `rust_denied_crypto` list must not be in the shipped binary's normal
//!    dependency graph
//! 2. binary: must link the system libcrypto dynamically, define no symbol of a bundled crypto backend, and carry a
//!    cargo-auditable manifest
//! 3. source: the application must never enable a FIPS provider itself, must not use OpenSSL's legacy (non-provider)
//!    APIs, and must not vendor OpenSSL
//!
//! Runs on a developer host (any Linux) or inside the UBI 9 check image built
//! from `Containerfile.fips`.

use std::path::{Path, PathBuf};

use clap::Parser;

use super::{binary, environment, graph, guards};

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask fips report`.
#[derive(Parser)]
pub(crate) struct Args {
    /// The praxis binary to assess; omit together with --deps-only.
    binary: Option<PathBuf>,

    /// Report on the dependency graph and source guards only (seconds, no
    /// build); what `make fips-deps` runs.
    #[arg(long)]
    deps_only: bool,

    /// Cargo features the binary was built with (`--no-default-features
    /// --features ...`); omit for the standard default build.
    #[arg(long)]
    features: Option<String>,

    /// Pass --offline to cargo (the UBI check image does this).
    #[arg(long)]
    offline: bool,

    /// Also write the report to this file.
    #[arg(long)]
    out: Option<PathBuf>,
}

// -----------------------------------------------------------------------------
// Context
// -----------------------------------------------------------------------------

/// What every section needs to know about the build under assessment.
pub(crate) struct Context {
    /// Workspace root, where cargo runs.
    pub(crate) root: PathBuf,
    /// Cargo features the binary was built with; `None` is the default build.
    pub(crate) features: Option<String>,
    /// Whether cargo runs with `--offline`.
    pub(crate) offline: bool,
}

impl Context {
    /// Feature flags for cargo that match the assessed build.
    pub(crate) fn feature_flags(&self) -> Vec<String> {
        self.features.as_ref().map_or_else(Vec::new, |features| {
            vec![
                "--no-default-features".to_owned(),
                "--features".to_owned(),
                features.clone(),
            ]
        })
    }

    /// Human-readable name of the feature set.
    pub(crate) fn feature_label(&self) -> String {
        self.features.as_ref().map_or_else(
            || "default features".to_owned(),
            |features| format!("features: {features} (no defaults)"),
        )
    }

    /// `--offline` when requested.
    pub(crate) fn cargo_flags(&self) -> Vec<&'static str> {
        if self.offline { vec!["--offline"] } else { Vec::new() }
    }
}

// -----------------------------------------------------------------------------
// Report
// -----------------------------------------------------------------------------

/// One finding: what failed, why it matters for the gate, where to look and
/// what to do.
pub(crate) struct Finding {
    /// One line naming the failure.
    pub(crate) title: String,
    /// Why Red Hat's scanner cares.
    pub(crate) why: String,
    /// Where in the tree to look.
    pub(crate) location: String,
    /// What to change.
    pub(crate) fix: String,
}

impl Finding {
    /// The finding as a numbered summary entry with its reason, location and fix.
    fn explained(&self, number: usize) -> String {
        format!(
            "  {number}. {}\n    why:   {}\n    where: {}\n    fix:   {}",
            self.title, self.why, self.location, self.fix
        )
    }
}

/// The report under construction: its lines so far plus the findings and
/// warnings they contain.
#[derive(Default)]
pub(crate) struct Report {
    /// Report lines, in order.
    lines: Vec<String>,
    /// Every finding, in order of discovery.
    findings: Vec<Finding>,
    /// How many warnings were emitted.
    warnings: usize,
}

impl Report {
    /// Start a section.
    pub(crate) fn section(&mut self, title: &str) {
        self.lines.push(String::new());
        self.lines.push(format!("== {title}"));
    }

    /// A check that passed.
    pub(crate) fn ok(&mut self, message: &str) {
        self.lines.push(format!("  ok    {message}"));
    }

    /// Context that is neither a pass nor a failure.
    pub(crate) fn info(&mut self, message: &str) {
        self.lines.push(format!("  info  {message}"));
    }

    /// Something worth attention that does not fail the report.
    pub(crate) fn warn(&mut self, message: &str) {
        self.lines.push(format!("  WARN  {message}"));
        self.warnings += 1;
    }

    /// A check that failed.
    pub(crate) fn fail(&mut self, finding: Finding) {
        self.lines.push(format!("  FAIL  {}", finding.title));
        self.findings.push(finding);
    }

    /// Verbatim lines (a tree excerpt), indented under the check they belong to.
    pub(crate) fn raw(&mut self, text: &str) {
        self.lines.extend(text.lines().map(|line| format!("        {line}")));
    }

    /// Whether any finding's title contains `needle`.
    pub(crate) fn has_finding(&self, needle: &str) -> bool {
        self.findings.iter().any(|finding| finding.title.contains(needle))
    }

    /// Whether the report has findings, and so a failing exit status.
    pub(crate) fn failed(&self) -> bool {
        !self.findings.is_empty()
    }

    /// The summary section: the verdict, each finding with its reason,
    /// location and fix, and the references.
    fn summary(&mut self) {
        self.section("Summary");
        if self.findings.is_empty() {
            self.lines.push(
                "  RESULT: no findings. This build is structurally FIPS-ready; run it on a FIPS-enabled RHEL host and \
                 Red Hat's scanner for the verification result."
                    .to_owned(),
            );
            if self.warnings > 0 {
                self.lines.push(format!("  {} warning(s) above.", self.warnings));
            }
        } else {
            self.lines.push(format!(
                "  RESULT: {} finding(s), {} warning(s). This build is NOT FIPS compliant yet. What to fix:",
                self.findings.len(),
                self.warnings
            ));
            self.lines.extend(
                self.findings
                    .iter()
                    .enumerate()
                    .map(|(index, finding)| finding.explained(index + 1)),
            );
        }
        self.references();
    }

    /// The closing reference lines.
    fn references(&mut self) {
        self.lines.push(String::new());
        self.lines.push(
            "  Reference: denylist and symbol rules mirror openshift/check-payload (Rust support, PR #360);".to_owned(),
        );
        self.lines.push(
            "  validated module: RHEL 9 OpenSSL FIPS Provider 3.0.7 (CMVP #4857). See docs/developing/fips.md."
                .to_owned(),
        );
    }

    /// The whole report as text.
    pub(crate) fn text(&self) -> String {
        let mut text = self.lines.join("\n");
        text.push('\n');
        text
    }
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Assemble and print the report; exit 1 when it has findings.
pub(crate) fn run(args: &Args) {
    let context = Context {
        root: workspace_root(),
        features: args.features.clone(),
        offline: args.offline,
    };
    let mut report = Report::default();
    environment::section(&mut report, &context);
    graph::section(&mut report, &context);
    if !args.deps_only {
        binary::section(&mut report, args.binary.as_deref());
    }
    guards::section(&mut report, &context.root);
    report.summary();
    let text = report.text();
    print!("{text}");
    if let Some(out) = &args.out {
        write_report(out, &text);
    }
    if report.failed() {
        std::process::exit(1);
    }
}

/// Write the report to `out`, creating its parent directories.
fn write_report(out: &Path, text: &str) {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Err(err) = std::fs::write(out, text) {
        eprintln!("fips report: cannot write {}: {err}", out.display());
    }
}

/// The workspace root: the parent of the xtask crate, fixed at compile time
/// so the binary works when run directly as well as through `cargo run`.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_owned)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A context for the FIPS feature set.
    fn fips_context() -> Context {
        Context {
            root: PathBuf::from("."),
            features: Some("config-reload,admin-api".to_owned()),
            offline: true,
        }
    }

    #[test]
    fn feature_flags_match_the_assessed_build() {
        let context = fips_context();
        assert_eq!(
            context.feature_flags(),
            ["--no-default-features", "--features", "config-reload,admin-api"],
            "the FIPS build is built without defaults"
        );
        assert_eq!(context.cargo_flags(), ["--offline"], "offline was requested");
        assert_eq!(
            context.feature_label(),
            "features: config-reload,admin-api (no defaults)",
            "the label names the features"
        );
        let default = Context {
            features: None,
            offline: false,
            ..fips_context()
        };
        assert!(
            default.feature_flags().is_empty(),
            "the default build passes no feature flags"
        );
        assert!(default.cargo_flags().is_empty(), "online by default");
        assert_eq!(
            default.feature_label(),
            "default features",
            "the default build is named as such"
        );
    }

    #[test]
    fn a_finding_fails_the_report_and_is_listed_in_the_summary() {
        let mut report = Report::default();
        report.section("Binary");
        report.ok("fine");
        report.warn("hmm");
        report.fail(Finding {
            title: "bad thing".to_owned(),
            why: "because".to_owned(),
            location: "here".to_owned(),
            fix: "do this".to_owned(),
        });
        assert!(report.failed(), "a finding fails the report");
        assert!(report.has_finding("bad"), "findings are searchable by title");
        report.summary();
        let text = report.text();
        assert!(
            text.contains("== Binary\n  ok    fine\n  WARN  hmm\n  FAIL  bad thing"),
            "sections list checks in order: {text}"
        );
        assert!(
            text.contains("RESULT: 1 finding(s), 1 warning(s)"),
            "the verdict counts findings and warnings: {text}"
        );
        assert!(
            text.contains("  1. bad thing\n    why:   because\n    where: here\n    fix:   do this"),
            "each finding is explained: {text}"
        );
    }

    #[test]
    fn a_clean_report_says_so() {
        let mut report = Report::default();
        report.raw("a\nb");
        report.summary();
        let text = report.text();
        assert!(!report.failed(), "no findings");
        assert!(
            text.starts_with("        a\n        b\n"),
            "raw lines are indented: {text}"
        );
        assert!(text.contains("RESULT: no findings."), "the verdict is clean: {text}");
    }
}
