// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask lint-ai-isolation` — verify AI-specific code stays
//! inside `filter/src/builtins/` and does not leak into general-purpose
//! infrastructure layers (`core/`, `protocol/`, non-builtin `filter/`).

use std::path::{Path, PathBuf};

use clap::Parser;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AI-specific import path fragments that must not appear in
/// infrastructure code outside of `#[cfg(feature = "ai-inference")]`
/// blocks.
const AI_IMPORT_MARKERS: &[&str] = &[
    "::ai::store",
    "::ai::token_usage",
    "::ai::classifier",
    "::ai::anthropic",
    "::ai::openai",
    "::ai::guardrails",
    "::ai::inference",
    "::ai::prompt_enrich",
];

/// AI domain type names that should not appear as bare identifiers
/// in infrastructure code (outside of cfg-gated or re-export context).
const AI_TYPE_NAMES: &[&str] = &[
    "ResponseStoreRegistry",
    "TokenUsageProvider",
    "ResponseStoreFilter",
    "ResponsesFormatFilter",
    "AnthropicMessagesFormatFilter",
    "AnthropicMessagesProtocolFilter",
    "AnthropicStreamEventsFilter",
    "AnthropicToOpenaiFilter",
    "AnthropicValidateFilter",
    "OpenaiResponsesValidateFilter",
    "AiGuardrailsFilter",
    "PromptEnrichFilter",
    "ModelToHeaderFilter",
    "ModelRewriteFilter",
];

/// Method or field names that encode AI-specific semantics.
const AI_METHOD_NAMES: &[&str] = &["set_token_usage", "extract_token_usage"];

/// Files that are allowed to reference AI types for structural
/// reasons (re-exports, registry, pipeline plumbing).
const ALLOWED_FILES: &[&str] = &[
    "filter/src/lib.rs",
    "filter/src/registry.rs",
    "filter/src/pipeline/mod.rs",
    "filter/src/pipeline/build.rs",
    "filter/src/pipeline/tcp.rs",
    "filter/src/pipeline/tests.rs",
];

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// CLI arguments for `cargo xtask lint-ai-isolation`.
#[derive(Parser)]
pub(crate) struct Args;

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------

/// Scan infrastructure crate sources for AI-specific code leaks.
pub(crate) fn run(_args: Args) {
    let root = workspace_root();
    let violations = scan_infrastructure(&root);

    if violations.is_empty() {
        println!("no AI-specific code found in infrastructure layers");
    } else {
        eprintln!("AI isolation violations:");
        for v in &violations {
            eprintln!("  {}:{}: {}", v.file, v.line, v.message);
        }
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// A single violation found during scanning.
#[derive(Debug, PartialEq, Eq)]
struct Violation {
    /// Relative path of the offending file.
    file: String,

    /// 1-based line number.
    line: usize,

    /// Human-readable description of the violation.
    message: String,
}

/// Scan all infrastructure source files and return violations.
fn scan_infrastructure(root: &Path) -> Vec<Violation> {
    let mut violations = Vec::new();
    let dirs = [
        root.join("core/src"),
        root.join("protocol/src"),
        root.join("filter/src"),
    ];

    for dir in &dirs {
        if !dir.exists() {
            continue;
        }
        collect_rs_files(dir, &mut |path| {
            if should_skip_file(root, path) {
                return;
            }
            let rel = path.strip_prefix(root).unwrap_or(path);
            let rel_str = rel.to_string_lossy();
            let Ok(content) = std::fs::read_to_string(path) else {
                return;
            };
            violations.extend(check_file(&rel_str, &content));
        });
    }

    violations
}

/// Recursively find `.rs` files and call `visitor` on each.
fn collect_rs_files(dir: &Path, visitor: &mut impl FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, visitor);
        } else if path.extension().is_some_and(|e| e == "rs") {
            visitor(&path);
        }
    }
}

/// Whether a file should be excluded from scanning.
fn should_skip_file(root: &Path, path: &Path) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let rel_str = rel.to_string_lossy().replace('\\', "/");

    if rel_str.starts_with("filter/src/builtins/") {
        return true;
    }

    ALLOWED_FILES.iter().any(|f| rel_str == *f)
}

/// Check a single file for AI-specific code leaks.
///
/// Skips lines that are inside `#[cfg(feature = "ai-inference")]`
/// or `#[cfg(feature = "response-store")]` blocks, and lines inside
/// `#[cfg(test)]` modules.
fn check_file(path: &str, content: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut ai_block = CfgBlockState::default();
    let mut test_block = CfgBlockState::default();

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        track_cfg_block(trimmed, &["ai-inference", "response-store"], &mut ai_block);
        track_cfg_block(trimmed, &["test"], &mut test_block);

        if ai_block.active || test_block.active || trimmed.starts_with("//") {
            continue;
        }

        let line_num = line_idx + 1;
        check_ai_imports(path, line_num, trimmed, &mut violations);
        check_ai_types(path, line_num, trimmed, &mut violations);
        check_ai_methods(path, line_num, trimmed, &mut violations);
    }

    violations
}

/// Mutable state for tracking a `#[cfg(...)]` block.
#[derive(Default)]
struct CfgBlockState {
    /// Whether we are currently inside the gated block.
    active: bool,

    /// Brace depth counter (-1 = pending first brace).
    depth: i32,
}

/// Track entry/exit of `#[cfg(feature = "...")]` or `#[cfg(test)]`
/// blocks by counting brace depth.
///
/// Uses -1 as a "pending" sentinel: the cfg annotation was seen
/// but no opening brace yet. The next line with braces starts
/// tracking; a line without braces is a single-line gated item.
fn track_cfg_block(line: &str, features: &[&str], state: &mut CfgBlockState) {
    if !state.active {
        if is_cfg_gate(line, features) {
            state.active = true;
            state.depth = count_braces(line);
            if state.depth <= 0 {
                state.depth = -1; // pending
            }
        }
        return;
    }

    if state.depth == -1 {
        let depth = count_braces(line);
        if depth > 0 {
            state.depth = depth;
        } else {
            *state = CfgBlockState::default();
        }
        return;
    }

    state.depth += count_braces(line);
    if state.depth <= 0 {
        *state = CfgBlockState::default();
    }
}

/// Check whether a line is a `#[cfg(...)]` gate for any of the
/// given features.
fn is_cfg_gate(line: &str, features: &[&str]) -> bool {
    features.iter().any(|f| {
        if *f == "test" {
            line.contains("#[cfg(test)]")
        } else {
            line.contains(&format!("cfg(feature = \"{f}\")"))
        }
    })
}

/// Count net brace depth change for a line (`{` = +1, `}` = -1).
fn count_braces(line: &str) -> i32 {
    line.chars()
        .map(|ch| match ch {
            '{' => 1,
            '}' => -1,
            _ => 0,
        })
        .sum()
}

/// Check for AI-specific import paths.
fn check_ai_imports(path: &str, line_num: usize, line: &str, violations: &mut Vec<Violation>) {
    if !line.starts_with("use ") && !line.contains("use ") {
        return;
    }
    for marker in AI_IMPORT_MARKERS {
        if line.contains(marker) {
            violations.push(Violation {
                file: path.to_owned(),
                line: line_num,
                message: format!("AI-specific import `{marker}` in infrastructure code"),
            });
        }
    }
}

/// Check for AI domain type names.
fn check_ai_types(path: &str, line_num: usize, line: &str, violations: &mut Vec<Violation>) {
    for type_name in AI_TYPE_NAMES {
        if contains_word(line, type_name) {
            violations.push(Violation {
                file: path.to_owned(),
                line: line_num,
                message: format!("AI domain type `{type_name}` in infrastructure code"),
            });
        }
    }
}

/// Check for AI-specific method/field names.
fn check_ai_methods(path: &str, line_num: usize, line: &str, violations: &mut Vec<Violation>) {
    for method in AI_METHOD_NAMES {
        if contains_word(line, method) {
            violations.push(Violation {
                file: path.to_owned(),
                line: line_num,
                message: format!("AI-specific symbol `{method}` in infrastructure code"),
            });
        }
    }
}

/// Check whether `haystack` contains `word` as a whole word (not a
/// substring of a larger identifier).
fn contains_word(haystack: &str, word: &str) -> bool {
    let bytes = haystack.as_bytes();
    let word_len = word.len();

    let mut start = 0;
    while let Some(pos) = haystack.get(start..).and_then(|s| s.find(word)) {
        let abs = start + pos;
        let before_ok = abs == 0
            || bytes
                .get(abs - 1)
                .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_');
        let after_ok = bytes
            .get(abs + word_len)
            .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_');
        if before_ok && after_ok {
            return true;
        }
        start = abs + 1;
    }
    false
}

/// Locate the workspace root directory.
fn workspace_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    Path::new(&manifest_dir)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn clean_infrastructure_code_passes() {
        let content = "
use std::collections::HashMap;
use praxis_core::kv::KvStoreRegistry;

pub struct MyContext {
    pub kv_stores: Option<KvStoreRegistry>,
}
";
        let violations = check_file("filter/src/context.rs", content);
        assert!(violations.is_empty(), "clean code should produce no violations");
    }

    #[test]
    fn ai_import_detected() {
        let content = "use crate::builtins::http::ai::store::ResponseStoreRegistry;\n";
        let violations = check_file("filter/src/context.rs", content);
        assert_eq!(violations.len(), 2, "should flag AI import and type name");
        assert!(
            violations[0].message.contains("::ai::store"),
            "should identify the AI import marker"
        );
    }

    #[test]
    fn ai_type_name_detected() {
        let content = "pub response_stores: Option<ResponseStoreRegistry>,\n";
        let violations = check_file("filter/src/context.rs", content);
        assert_eq!(violations.len(), 1, "should flag AI type name");
        assert!(violations[0].message.contains("ResponseStoreRegistry"));
    }

    #[test]
    fn ai_method_name_detected() {
        let content = "ctx.set_token_usage(100, 50, None);\n";
        let violations = check_file("filter/src/context.rs", content);
        assert_eq!(violations.len(), 1, "should flag AI method name");
        assert!(violations[0].message.contains("set_token_usage"));
    }

    #[test]
    fn cfg_ai_inference_block_skipped() {
        let content = r#"
#[cfg(feature = "ai-inference")]
pub fn response_stores(&self) -> Option<&ResponseStoreRegistry> {
    self.response_stores.as_ref()
}
"#;
        let violations = check_file("filter/src/context.rs", content);
        assert!(violations.is_empty(), "cfg-gated AI code should be skipped");
    }

    #[test]
    fn cfg_response_store_block_skipped() {
        let content = r#"
#[cfg(feature = "response-store")]
if let Some(stores) = pipeline.response_stores() {
    fctx.extensions.insert(stores.clone());
}
"#;
        let violations = check_file("protocol/src/context.rs", content);
        assert!(violations.is_empty(), "response-store cfg block should be skipped");
    }

    #[test]
    fn cfg_test_block_skipped() {
        let content = "
#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_ctx() -> HttpFilterContext {
        let registry = ResponseStoreRegistry::new();
    }
}
";
        let violations = check_file("filter/src/context.rs", content);
        assert!(violations.is_empty(), "test module code should be skipped");
    }

    #[test]
    fn comments_skipped() {
        let content = "// ResponseStoreRegistry is used by AI filters\n";
        let violations = check_file("filter/src/context.rs", content);
        assert!(violations.is_empty(), "comments should be skipped");
    }

    #[test]
    fn doc_comments_skipped() {
        let content = "/// See [`ResponseStoreRegistry`] for details.\n";
        let violations = check_file("filter/src/context.rs", content);
        assert!(violations.is_empty(), "doc comments should be skipped");
    }

    #[test]
    fn word_boundary_prevents_false_positives() {
        let content = "let my_token_usage_counter = 0;\n";
        let violations = check_file("filter/src/context.rs", content);
        assert!(
            violations.is_empty(),
            "substring matches should not trigger (word boundary check)"
        );
    }

    #[test]
    fn contains_word_basic() {
        assert!(contains_word("foo bar baz", "bar"));
        assert!(!contains_word("foobar baz", "bar"));
        assert!(!contains_word("foo bar_baz", "bar"));
        assert!(contains_word("bar", "bar"));
        assert!(contains_word("(bar)", "bar"));
        assert!(contains_word("x.set_token_usage(", "set_token_usage"));
        assert!(!contains_word("my_set_token_usage", "set_token_usage"));
    }

    #[test]
    fn non_ai_code_after_cfg_block_is_checked() {
        let content = r#"
#[cfg(feature = "ai-inference")]
fn ai_stuff() {
    let x = ResponseStoreRegistry::new();
}

fn normal_stuff() {
    let y = ResponseStoreRegistry::new();
}
"#;
        let violations = check_file("filter/src/context.rs", content);
        assert_eq!(violations.len(), 1, "code after cfg block should be checked");
        assert_eq!(violations[0].line, 8, "violation should be on the non-gated line");
    }

    #[test]
    fn allowed_file_skipped() {
        let root = Path::new("/workspace");
        let path = root.join("filter/src/registry.rs");
        assert!(should_skip_file(root, &path), "registry.rs should be in the allow list");
    }

    #[test]
    fn builtin_file_skipped() {
        let root = Path::new("/workspace");
        let path = root.join("filter/src/builtins/http/ai/store/mod.rs");
        assert!(should_skip_file(root, &path), "builtins/ files should be skipped");
    }

    #[test]
    fn infrastructure_file_not_skipped() {
        let root = Path::new("/workspace");
        let path = root.join("filter/src/context.rs");
        assert!(!should_skip_file(root, &path), "context.rs should NOT be skipped");
    }

    #[test]
    fn line_number_is_correct() {
        let content = "line one\nline two\nlet x = ResponseStoreRegistry::new();\n";
        let violations = check_file("test.rs", content);
        assert_eq!(violations[0].line, 3, "violation should be on line 3");
    }
}
