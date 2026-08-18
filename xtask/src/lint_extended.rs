// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask lint-extended` — diff-scoped heuristic checks for common
//! low-quality-code patterns that automated compiler lints can't catch
//! structurally.
//!
//! Clippy already denies the machine-checkable half of this class of issue
//! (unwrap/expect, panic, `todo!()`/`unimplemented!()`, dead code, missing
//! docs, print/dbg macros, and more, depending on the crate's own lint
//! config). What lint tooling structurally cannot check is comment
//! *content* and diff-local *repetition* -- two common low-effort-code
//! tells. This checks only lines added/changed versus the diff base so
//! pre-existing code is never relitigated.
//!
//! Checks (block = fails; warn = printed, does not fail):
//!   - block: leftover `TODO`/`FIXME`/`XXX`/`HACK` markers in comments
//!   - block: commented-out code
//!   - warn: narrating "what the code does" comments
//!   - warn: the same numeric/string literal repeated 3+ times without a named constant
//!   - warn: weak/generic identifier names introduced by a new let/fn binding
//!   - warn: new clippy lint suppressions added
//!
//! Diff base resolution: CLI arg, else `$EXTENDED_LINT_BASE`, else
//! `origin/$GITHUB_BASE_REF` in a `GitHub` Actions PR, else `origin/main`.
//!
//! This module's own source is excluded from the scanned diff (see
//! [`SELF_PATH`]): unlike the prior tooling for this class of check, which
//! lived in a non-Rust script and was naturally out of the `*.rs` scan
//! scope, this checker is itself a `.rs` file. Its doc comments and test
//! fixtures necessarily mention `TODO`/`FIXME`/etc. literally, which would
//! otherwise self-block on introduction.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    process::Command,
    sync::LazyLock,
};

use clap::Parser;
use regex::Regex;

// -----------------------------------------------------------------------------
// Regex Patterns
// -----------------------------------------------------------------------------

/// Matches leftover `TODO`/`FIXME`/`XXX`/`HACK` markers anywhere in a
/// comment.
static TODO_MARKER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)//.*\b(TODO|FIXME|XXX|HACK)\b").expect("valid regex"));

/// Matches comments shaped like commented-out Rust statements.
static COMMENTED_CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^//+\s*(let\s+\w|fn\s+\w|if\s*\(|for\s*\(|match\s+\w|return\b|\w+\s*\([^)]*\)\s*;?\s*$|\w+\.\w+\(.*\)\s*;?\s*$|[\w:<>]+\s*=\s*.+;\s*$)",
    )
    .expect("valid regex")
});

/// Matches a new `let`/`fn` binding using a weak, generic identifier name.
static WEAK_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(let(?:\s+mut)?|fn)\s+(temp|tmp|foo|bar|thing|val|obj|stuff)\b").expect("valid regex")
});

/// Matches a numeric or string literal worth tracking for repetition.
static LIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:^|[^\w.])(\d{2,}|"[^"]{4,}")(?:$|[^\w])"#).expect("valid regex"));

/// Matches a `const`/`static` declaration line.
static CONST_LINE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(const|static)\s+\w+").expect("valid regex"));

/// Matches a new `#[allow(clippy::...)]`/`#[expect(clippy::...)]` suppression.
static SUPPRESSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"#\[(allow|expect)\(clippy::").expect("valid regex"));

/// Matches the start of a file's test module.
static TEST_MODULE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(#\[cfg\(test\)\]|mod tests\b)").expect("valid regex"));

/// Matches a unified diff hunk header (`@@ -a,b +c,d @@`), capturing the
/// starting line number of the post-diff side.
static HUNK_HEADER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^@@ -\d+(?:,\d+)? \+(\d+)").expect("valid regex"));

/// Path to this module's own source file, relative to the repo root.
///
/// Excluded from the scanned diff -- see the module doc comment for why.
const SELF_PATH: &str = "xtask/src/lint_extended.rs";

/// Comment-body prefixes that indicate a "what does this code do" narration
/// rather than useful *why* context.
const NARRATING_OPENERS: &[&str] = &[
    "increment",
    "decrement",
    "loop through",
    "iterate over",
    "iterate through",
    "return the",
    "returns the",
    "create a",
    "creates a",
    "initialize",
    "set the",
    "sets the",
    "get the",
    "gets the",
    "parse the",
    "parses the",
    "convert ",
    "converts ",
    "check if",
    "checks if",
    "validate that",
    "validates that",
    "call ",
    "calls ",
    "define ",
    "defines ",
    "import ",
    "imports ",
    "declare ",
    "declares ",
    "instantiate",
    "loop over",
    "append ",
    "appends ",
    "remove ",
    "removes ",
    "add ",
    "adds ",
];

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask lint-extended`.
#[derive(Parser)]
pub(crate) struct Args {
    /// Git ref to diff against. Defaults to `$EXTENDED_LINT_BASE`, then
    /// `origin/$GITHUB_BASE_REF` in a `GitHub` Actions PR, then `origin/main`.
    #[arg(long)]
    base: Option<String>,
}

// -----------------------------------------------------------------------------
// Data Types
// -----------------------------------------------------------------------------

/// One line added or changed in the diff, with its file and post-diff line
/// number.
struct AddedLine {
    /// Path to the file the line belongs to, relative to the repo root.
    file: String,
    /// 1-based line number in the post-diff version of `file`.
    lineno: usize,
    /// Line content with the leading `+` diff marker stripped.
    content: String,
}

/// Blocking and warning findings collected from the diff.
#[derive(Default)]
struct Findings {
    /// Findings that fail the check.
    blocking: Vec<String>,
    /// Findings that are printed but do not fail the check.
    warnings: Vec<String>,
}

/// A `(file path, literal text)` key identifying one tracked literal.
type LiteralKey = (String, String);

/// One literal sighting: the line content it appeared on and its line
/// number.
type LiteralSighting = (String, usize);

/// Accumulates literal sightings and named-constant declarations across the
/// diff, to flag literals repeated 3+ times without a named constant.
#[derive(Default)]
struct LiteralTracker {
    /// Literal sightings, keyed by `(file, literal)`.
    sites: BTreeMap<LiteralKey, Vec<LiteralSighting>>,
    /// Literals declared via a `const`/`static` line, keyed by file.
    declared: BTreeMap<String, BTreeSet<String>>,
    /// Cached test-module start line per file.
    test_module_start_cache: BTreeMap<String, usize>,
}

impl LiteralTracker {
    /// Record every literal on `stripped` as declared via a named constant
    /// in `file`.
    fn declare_literals(&mut self, file: &str, stripped: &str) {
        for caps in LIT_RE.captures_iter(stripped) {
            if let Some(lit) = caps.get(1) {
                self.declared
                    .entry(file.to_owned())
                    .or_default()
                    .insert(lit.as_str().to_owned());
            }
        }
    }

    /// Record every literal on `stripped` as a repetition sighting at
    /// `lineno` in `file`.
    fn record_sightings(&mut self, file: &str, lineno: usize, stripped: &str) {
        for caps in LIT_RE.captures_iter(stripped) {
            if let Some(lit) = caps.get(1) {
                self.sites
                    .entry((file.to_owned(), lit.as_str().to_owned()))
                    .or_default()
                    .push((stripped.to_owned(), lineno));
            }
        }
    }

    /// Return the cached (or freshly computed) test-module start line for
    /// `file`.
    fn test_module_start(&mut self, file: &str) -> usize {
        if let Some(&lineno) = self.test_module_start_cache.get(file) {
            return lineno;
        }
        let lineno = test_module_start_line(file);
        self.test_module_start_cache.insert(file.to_owned(), lineno);
        lineno
    }
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Run the diff-scoped heuristic lint checks.
///
/// Prints warnings (non-blocking) and blocking findings to stderr, then
/// exits the process with status 1 if any blocking findings were found.
pub(crate) fn run(args: &Args) {
    let diff_base = resolve_diff_base(args.base.as_deref());
    let added = run_diff(&diff_base);
    if added.is_empty() {
        println!("[lint-extended] no added Rust lines vs {diff_base}; nothing to check.");
        return;
    }

    let findings = collect_findings(&added);
    report_warnings(&findings.warnings);

    if findings.blocking.is_empty() {
        println!("[lint-extended] no blocking findings.");
        return;
    }
    report_blocking(&findings.blocking);
    std::process::exit(1);
}

/// Print non-blocking warnings to stderr, if any.
fn report_warnings(warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    eprintln!("[lint-extended] warnings (review, does not block):");
    for w in warnings {
        eprintln!("  - {w}");
    }
    eprintln!();
}

/// Print blocking findings to stderr.
fn report_blocking(blocking: &[String]) {
    eprintln!("[lint-extended] BLOCKING findings:");
    for b in blocking {
        eprintln!("  - {b}");
    }
    eprintln!();
    eprintln!("[lint-extended] fix the above, or if a match is a false positive, note why in the PR description.");
}

// -----------------------------------------------------------------------------
// Diff Base Resolution
// -----------------------------------------------------------------------------

/// Resolve the diff base ref: CLI arg, else `$EXTENDED_LINT_BASE`, else
/// `origin/$GITHUB_BASE_REF` in a `GitHub` Actions PR, else `origin/main`.
fn resolve_diff_base(cli_arg: Option<&str>) -> String {
    if let Some(base) = cli_arg {
        return base.to_owned();
    }
    if let Ok(base) = std::env::var("EXTENDED_LINT_BASE") {
        return base;
    }
    if let Ok(base_ref) = std::env::var("GITHUB_BASE_REF") {
        return format!("origin/{base_ref}");
    }
    "origin/main".to_owned()
}

// -----------------------------------------------------------------------------
// Diff Parsing
// -----------------------------------------------------------------------------

/// Run `git diff --unified=0 <diff_base> -- *.rs` and parse it into added
/// lines with their file and post-diff line number.
fn run_diff(diff_base: &str) -> Vec<AddedLine> {
    parse_diff(&git_diff_stdout(diff_base))
}

/// Parse unified diff output into added lines, skipping [`SELF_PATH`].
fn parse_diff(stdout: &str) -> Vec<AddedLine> {
    let mut added = Vec::new();
    let mut current_file = String::new();
    let mut new_lineno: usize = 0;

    for line in stdout.lines() {
        if let Some(path) = line.strip_prefix("+++ b/") {
            path.clone_into(&mut current_file);
            continue;
        }
        if let Some(lineno) = hunk_start_lineno(line) {
            new_lineno = lineno;
            continue;
        }
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if let Some(content) = line.strip_prefix('+') {
            if current_file != SELF_PATH {
                added.push(AddedLine {
                    file: current_file.clone(),
                    lineno: new_lineno,
                    content: content.to_owned(),
                });
            }
            new_lineno += 1;
        } else if !line.starts_with('-') {
            new_lineno += 1;
        }
    }
    added
}

/// Run `git diff --unified=0 <diff_base> -- *.rs` and return its stdout.
///
/// Exits the process with status 1 if the `git` command cannot be spawned.
fn git_diff_stdout(diff_base: &str) -> String {
    let output = Command::new("git")
        .args(["diff", "--unified=0", diff_base, "--", "*.rs"])
        .output()
        .unwrap_or_else(|err| {
            eprintln!("failed to run git diff: {err}");
            std::process::exit(1);
        });
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Parse the starting line number from a unified diff hunk header, if
/// `line` is one.
fn hunk_start_lineno(line: &str) -> Option<usize> {
    let caps = HUNK_HEADER_RE.captures(line)?;
    caps.get(1)?.as_str().parse().ok()
}

/// Return the 1-based line number where a `#[cfg(test)]` attribute or
/// `mod tests` declaration starts in `file`, or `usize::MAX` if not found or
/// the file cannot be read.
fn test_module_start_line(file: &str) -> usize {
    let Ok(text) = fs::read_to_string(file) else {
        return usize::MAX;
    };
    text.lines()
        .position(|line| TEST_MODULE_RE.is_match(line))
        .map_or(usize::MAX, |i| i + 1)
}

/// Extract the trimmed comment starting at the first `//` in a line's raw
/// content, if any.
fn line_comment(content: &str) -> Option<String> {
    let (_, after) = content.split_once("//")?;
    Some(format!("//{after}").trim_end().to_owned())
}

/// Return whether a comment is a doc comment (`///` or `//!`), which is
/// exempt from the narration and commented-out-code heuristics.
fn is_doc_comment(comment: &str) -> bool {
    comment.starts_with("///") || comment.starts_with("//!")
}

// -----------------------------------------------------------------------------
// Checks
// -----------------------------------------------------------------------------

/// Run all heuristic checks against the diff's added lines.
fn collect_findings(added: &[AddedLine]) -> Findings {
    let mut findings = Findings::default();
    let mut literals = LiteralTracker::default();

    for line in added {
        check_line(line, &mut literals, &mut findings);
    }
    check_literal_repetition(&literals, &mut findings);
    findings
}

/// Run all per-line heuristic checks against one added line.
fn check_line(line: &AddedLine, literals: &mut LiteralTracker, findings: &mut Findings) {
    let stripped = line.content.trim();
    let comment = line_comment(&line.content);

    check_todo_marker(line, stripped, comment.as_deref(), findings);
    check_commented_code(line, stripped, comment.as_deref(), findings);
    check_narrating_comment(line, stripped, comment.as_deref(), findings);
    check_weak_name(line, stripped, findings);
    check_suppression(line, stripped, findings);
    record_literal_sites(line, stripped, literals);
}

/// Block leftover `TODO`/`FIXME`/`XXX`/`HACK` markers in comments.
fn check_todo_marker(line: &AddedLine, stripped: &str, comment: Option<&str>, findings: &mut Findings) {
    let Some(comment) = comment else { return };
    if TODO_MARKER_RE.is_match(comment) {
        findings.blocking.push(format!(
            "{}:{}: leftover TODO/FIXME/XXX/HACK marker: {stripped:?}",
            line.file, line.lineno
        ));
    }
}

/// Block comments that look like commented-out code, excluding doc
/// comments.
fn check_commented_code(line: &AddedLine, stripped: &str, comment: Option<&str>, findings: &mut Findings) {
    let Some(comment) = comment else { return };
    if is_doc_comment(comment) || !COMMENTED_CODE_RE.is_match(comment) {
        return;
    }
    findings.blocking.push(format!(
        "{}:{}: looks like commented-out code: {stripped:?}",
        line.file, line.lineno
    ));
}

/// Warn about comments that narrate "what" the following code does rather
/// than providing useful "why" context.
fn check_narrating_comment(line: &AddedLine, stripped: &str, comment: Option<&str>, findings: &mut Findings) {
    let Some(comment) = comment else { return };
    if is_doc_comment(comment) {
        return;
    }
    let body = comment.trim_start_matches('/').trim().to_lowercase();
    if !NARRATING_OPENERS.iter().any(|opener| body.starts_with(opener)) {
        return;
    }
    findings.warnings.push(format!(
        "{}:{}: narrating 'what' comment, prefer self-explanatory code or a doc comment on why: {stripped:?}",
        line.file, line.lineno
    ));
}

/// Warn about weak/generic identifier names introduced by a new `let`/`fn`
/// binding.
fn check_weak_name(line: &AddedLine, stripped: &str, findings: &mut Findings) {
    let Some(caps) = WEAK_NAME_RE.captures(stripped) else {
        return;
    };
    let Some(name) = caps.get(2) else { return };
    findings.warnings.push(format!(
        "{}:{}: weak/generic identifier name {:?}: {stripped:?}",
        line.file,
        line.lineno,
        name.as_str()
    ));
}

/// Warn about newly added clippy lint suppressions.
fn check_suppression(line: &AddedLine, stripped: &str, findings: &mut Findings) {
    if !SUPPRESSION_RE.is_match(stripped) {
        return;
    }
    findings.warnings.push(format!(
        "{}:{}: new clippy suppression added, double-check the reason: {stripped:?}",
        line.file, line.lineno
    ));
}

/// Record `const`/`static` literal declarations and literal-repetition
/// sightings for a stripped line, skipping lines at or after the file's
/// test module and attribute lines.
fn record_literal_sites(line: &AddedLine, stripped: &str, literals: &mut LiteralTracker) {
    if CONST_LINE_RE.is_match(stripped) {
        literals.declare_literals(&line.file, stripped);
    }

    let test_start = literals.test_module_start(&line.file);
    if line.lineno >= test_start || stripped.starts_with("#[") {
        return;
    }
    literals.record_sightings(&line.file, line.lineno, stripped);
}

/// Flag literals that appear 3+ times in one file's added lines without a
/// matching named-constant declaration.
fn check_literal_repetition(tracker: &LiteralTracker, findings: &mut Findings) {
    for ((file, literal), sites) in &tracker.sites {
        if sites.len() < 3 || tracker.declared.get(file).is_some_and(|set| set.contains(literal)) {
            continue;
        }
        let lines: Vec<String> = sites.iter().map(|(_, lineno)| lineno.to_string()).collect();
        findings.warnings.push(format!(
            "{file}: literal {literal} repeated {count}x at lines {joined} without a named constant -- consider hoisting it",
            count = sites.len(),
            joined = lines.join(", ")
        ));
    }
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
    fn detects_todo_marker() {
        assert!(TODO_MARKER_RE.is_match("// TODO: fix this later"));
        assert!(!TODO_MARKER_RE.is_match("// this is fine"));
    }

    #[test]
    fn detects_commented_out_code_but_not_doc_comments() {
        assert!(COMMENTED_CODE_RE.is_match("// let x = compute();"));
        assert!(!COMMENTED_CODE_RE.is_match("/// Returns the computed value."));
    }

    #[test]
    fn detects_weak_names() {
        let caps = WEAK_NAME_RE.captures("let temp = 5;").expect("should match");
        assert_eq!(caps.get(2).map(|m| m.as_str()), Some("temp"));
        assert!(WEAK_NAME_RE.captures("let value = 5;").is_none());
    }

    #[test]
    fn detects_narrating_comment_openers() {
        assert!(
            NARRATING_OPENERS
                .iter()
                .any(|o| "increment the counter by one".starts_with(o))
        );
        assert!(
            !NARRATING_OPENERS
                .iter()
                .any(|o| "guards against a torn write".starts_with(o))
        );
    }

    #[test]
    fn resolve_diff_base_prefers_cli_arg() {
        assert_eq!(resolve_diff_base(Some("upstream/main")), "upstream/main");
    }

    #[test]
    fn line_comment_extracts_trailing_comment() {
        assert_eq!(line_comment("let x = 1; // TODO: fix"), Some("// TODO: fix".to_owned()));
        assert_eq!(line_comment("let x = 1;"), None);
    }

    #[test]
    fn line_comment_identifies_doc_comments() {
        let comment = line_comment("/// Returns the computed value.").expect("comment present");
        assert!(is_doc_comment(&comment));
        let comment = line_comment("// plain comment").expect("comment present");
        assert!(!is_doc_comment(&comment));
    }

    #[test]
    fn hunk_start_lineno_parses_header() {
        assert_eq!(hunk_start_lineno("@@ -12,3 +18,5 @@ fn foo() {"), Some(18));
        assert_eq!(hunk_start_lineno("+let x = 1;"), None);
    }

    #[test]
    fn parse_diff_tracks_file_and_line_number() {
        let diff = "diff --git a/foo.rs b/foo.rs\n\
                     +++ b/foo.rs\n\
                     @@ -1,0 +5,2 @@\n\
                     +let x = 1;\n\
                     +let y = 2;\n";
        let added = parse_diff(diff);
        assert_eq!(added.len(), 2);
        assert_eq!(added[0].file, "foo.rs");
        assert_eq!(added[0].lineno, 5);
        assert_eq!(added[1].lineno, 6);
    }

    #[test]
    fn parse_diff_excludes_own_source_file() {
        let diff = format!(
            "+++ b/{SELF_PATH}\n\
             @@ -0,0 +1,1 @@\n\
             +// TODO: this must not self-block\n"
        );
        assert!(
            parse_diff(&diff).is_empty(),
            "own source file must be excluded from the scan"
        );
    }

    #[test]
    fn check_literal_repetition_flags_three_or_more_uses() {
        let mut tracker = LiteralTracker::default();
        for lineno in 1..=3 {
            tracker.record_sightings("foo.rs", lineno, &format!("sleep_ms(42); // call {lineno}"));
        }
        let mut findings = Findings::default();
        check_literal_repetition(&tracker, &mut findings);
        assert_eq!(findings.warnings.len(), 1, "three sightings should trigger one warning");
        assert!(findings.warnings[0].contains("repeated 3x"));
    }

    #[test]
    fn check_literal_repetition_skips_declared_constants() {
        let mut tracker = LiteralTracker::default();
        tracker.declare_literals("foo.rs", "const RETRY_DELAY_MS: u64 = 4242;");
        for lineno in 1..=3 {
            tracker.record_sightings("foo.rs", lineno, "sleep_ms(4242);");
        }
        let mut findings = Findings::default();
        check_literal_repetition(&tracker, &mut findings);
        assert!(
            findings.warnings.is_empty(),
            "declared constant should suppress the warning"
        );
    }
}

// TODO: fix this
