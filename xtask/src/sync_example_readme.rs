// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask sync-example-readme` generates the table section of
//! `examples/README.md` from YAML config header comments.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use clap::Parser;

use crate::paths::workspace_root;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Title overrides for category directories whose display name cannot be
/// derived by simple title-casing. All other directories are converted
/// automatically (e.g. `"traffic-management"` → `"Traffic Management"`).
const TITLE_OVERRIDES: &[(&str, &str)] = &[];

/// Comment-line prefixes that begin a non-description block. Paragraphs
/// whose first line starts with any of these are skipped during description
/// extraction.
const SKIP_PREFIXES: &[&str] = &[
    "Backend endpoints ",
    "Example:",
    "Flow:",
    "Pipeline:",
    "Requires ",
    "Test:",
    "Try it:",
    "Usage:",
    "What reloads ",
    "What requires ",
];

/// Entries that live outside `examples/configs/` but belong in the README.
/// `(category, filename, link_path, description)`.
const SPECIAL_ENTRIES: &[(&str, &str, &str, &str)] = &[(
    "pipeline",
    "default.yaml",
    "../crates/core/src/config/default.yaml",
    "Built-in default config (static JSON on /)",
)];

/// Marker line that separates the hand-maintained header from the
/// auto-generated tables.
const CONFIGS_MARKER: &str = "## Configs";

// -----------------------------------------------------------------------------
// CLI
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask sync-example-readme`.
#[derive(Parser)]
pub(crate) struct Args {
    /// Write the generated tables instead of checking for drift.
    #[arg(long)]
    fix: bool,
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Verify or regenerate the table section of `examples/README.md`.
pub(crate) fn run(args: &Args) {
    let root = workspace_root();
    let readme_path = root.join("examples/README.md");
    let configs_dir = root.join("examples/configs");

    let categories = discover_categories(&configs_dir);
    let entries = collect_entries(&configs_dir);
    let new_tables = generate_tables(&categories, &entries);

    match sync_readme(&readme_path, &new_tables, args.fix) {
        Ok(SyncOutcome::Written) => println!("wrote {}", readme_path.display()),
        Ok(SyncOutcome::UpToDate) => println!("examples/README.md tables are up to date"),
        Err(reason) => {
            eprintln!("{reason}");
            std::process::exit(1);
        },
    }
}

/// Result of a successful README synchronization.
enum SyncOutcome {
    /// The generated section already matches.
    UpToDate,
    /// The generated section was written.
    Written,
}

/// Check or replace the generated tables without mutating an invalid README.
fn sync_readme(path: &Path, tables: &str, fix: bool) -> Result<SyncOutcome, String> {
    let current = std::fs::read_to_string(path).map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    let (header, old_tables) = split_at_marker(&current).ok_or_else(|| {
        format!(
            "{} has no `## Configs` marker; restore that heading before regenerating",
            path.display()
        )
    })?;
    if fix {
        std::fs::write(path, format!("{header}{tables}"))
            .map_err(|err| format!("cannot write {}: {err}", path.display()))?;
        return Ok(SyncOutcome::Written);
    }
    if old_tables == tables {
        Ok(SyncOutcome::UpToDate)
    } else {
        Err("examples/README.md tables are out of date; run `cargo xtask sync-example-readme --fix`".to_owned())
    }
}

// -----------------------------------------------------------------------------
// Private Types
// -----------------------------------------------------------------------------

/// A parsed example config entry for the README table.
struct ExampleEntry {
    /// One-line description extracted from the header comment.
    description: String,
    /// Filename only (e.g. `full-flow.yaml`).
    filename: String,
    /// Relative link path from `examples/` (e.g. `configs/security/cors.yaml`).
    link_path: String,
}

// -----------------------------------------------------------------------------
// Collection
// -----------------------------------------------------------------------------

/// Discover category directories under `configs_dir` and derive display
/// titles. Returns `(dir_name, title)` pairs sorted alphabetically.
fn discover_categories(configs_dir: &Path) -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir(configs_dir) else {
        return Vec::new();
    };
    let mut categories: Vec<(String, String)> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let title = category_title(&name);
            (name, title)
        })
        .collect();
    categories.sort();
    categories
}

/// Derive a display title from a directory name. Checks [`TITLE_OVERRIDES`]
/// first, then falls back to title-casing each hyphen-separated word.
fn category_title(dir_name: &str) -> String {
    if let Some((_, title)) = TITLE_OVERRIDES.iter().find(|(d, _)| *d == dir_name) {
        return (*title).to_owned();
    }
    dir_name
        .split('-')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(c) => {
                    let upper: String = c.to_uppercase().collect();
                    format!("{upper}{rest}", rest = chars.as_str())
                },
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Collect all example config entries grouped by category directory.
fn collect_entries(configs_dir: &Path) -> BTreeMap<String, Vec<ExampleEntry>> {
    let mut by_category: BTreeMap<String, Vec<ExampleEntry>> = BTreeMap::new();

    let mut paths = Vec::new();
    walk_yaml(configs_dir, &mut paths);
    paths.sort();

    for path in &paths {
        let rel = path.strip_prefix(configs_dir).unwrap();
        let category = rel
            .components()
            .next()
            .unwrap()
            .as_os_str()
            .to_string_lossy()
            .into_owned();

        let filename = path.file_name().unwrap().to_string_lossy().into_owned();
        let link_path = format!("configs/{}", rel.to_string_lossy());
        let description = extract_description(path);

        by_category.entry(category).or_default().push(ExampleEntry {
            description,
            filename,
            link_path,
        });
    }

    by_category
}

/// Recursively find all `.yaml` files under `dir`.
fn walk_yaml(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_yaml(&path, out);
        } else if path.extension().is_some_and(|e| e == "yaml") {
            out.push(path);
        }
    }
}

// -----------------------------------------------------------------------------
// Generation
// -----------------------------------------------------------------------------

/// Render the table section (everything after `## Configs`).
fn generate_tables(categories: &[(String, String)], entries: &BTreeMap<String, Vec<ExampleEntry>>) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();

    for (dir_name, section_title) in categories {
        let Some(items) = entries.get(dir_name.as_str()) else {
            continue;
        };

        _ = write!(out, "\n### {section_title}\n\n");
        out.push_str("| File | Description |\n");
        out.push_str("| ------ | ------------- |\n");

        for (cat, fname, path, desc) in SPECIAL_ENTRIES {
            if *cat == dir_name.as_str() {
                _ = writeln!(out, "| [{fname}]({path}) | {desc} |");
            }
        }

        for e in items {
            _ = writeln!(out, "| [{}]({}) | {} |", e.filename, e.link_path, e.description);
        }
    }

    out
}

// -----------------------------------------------------------------------------
// Description Extraction
// -----------------------------------------------------------------------------

/// Extract a one-line description from a YAML file's header comments.
fn extract_description(path: &Path) -> String {
    let content = std::fs::read_to_string(path).unwrap();
    description_from_header(&content)
}

/// Core extraction logic, separated for testability.
///
/// Parses the leading comment block into paragraphs, skips the title and
/// any `Requires`/`Usage`/etc. blocks, and returns the first sentence of
/// the first remaining paragraph. Falls back to the title when no
/// description paragraph exists.
fn description_from_header(content: &str) -> String {
    let paragraphs = parse_comment_paragraphs(content);

    let desc = paragraphs.iter().skip(1).find(|p| !is_skip_paragraph(p));

    let text = match desc {
        Some(para) => para.join(" "),
        None => match paragraphs.first() {
            Some(title) => title.join(" "),
            None => return String::new(),
        },
    };

    normalize_description(&first_sentence(&text))
}

/// Parse the leading comment block into paragraphs separated by blank
/// comment lines (`#` with no text). Lines indented by two or more spaces
/// (after `# `) are skipped to exclude embedded code examples.
fn parse_comment_paragraphs(content: &str) -> Vec<Vec<String>> {
    let mut paragraphs: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = Vec::new();

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix('#') {
            let text = rest.strip_prefix(' ').unwrap_or(rest);
            if text.is_empty() {
                if !current.is_empty() {
                    paragraphs.push(std::mem::take(&mut current));
                }
            } else if !text.starts_with("  ") {
                current.push(text.to_owned());
            }
        } else {
            break;
        }
    }

    if !current.is_empty() {
        paragraphs.push(current);
    }

    paragraphs
}

/// Return `true` if the paragraph starts with a non-description prefix.
fn is_skip_paragraph(para: &[String]) -> bool {
    para.first()
        .is_some_and(|first| SKIP_PREFIXES.iter().any(|prefix| first.starts_with(prefix)) || first.ends_with(':'))
}

/// Extract the first sentence from `s`. A sentence boundary is a period
/// followed by a space and an uppercase letter, or a period at end of string.
/// Periods immediately preceded by a digit are not treated as sentence
/// endings to avoid splitting on decimals (e.g. `"Retry-After: 1. TCP …"`).
fn first_sentence(s: &str) -> String {
    let s = s.trim();
    let bytes = s.as_bytes();

    for (i, &b) in bytes.iter().enumerate() {
        if b != b'.' {
            continue;
        }
        if bytes.get(i.wrapping_sub(1)).is_some_and(u8::is_ascii_digit) {
            continue;
        }
        if i + 1 == bytes.len() {
            return s.get(..i).unwrap_or(s).to_owned();
        }
        if bytes.get(i + 1) == Some(&b' ') && bytes.get(i + 2).is_some_and(u8::is_ascii_uppercase) {
            return s.get(..i).unwrap_or(s).to_owned();
        }
    }

    s.to_owned()
}

/// Normalize a generated table description.
fn normalize_description(s: &str) -> String {
    s.trim().trim_end_matches(['.', ':']).trim_end().to_owned()
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Split at a standalone Configs heading outside code and HTML comments.
/// The returned header includes the heading's original newline.
fn split_at_marker(content: &str) -> Option<(&str, &str)> {
    let mut offset = 0_usize;
    let mut fence = None;
    let mut comment = false;
    for segment in content.split_inclusive('\n') {
        let line = segment.trim_end_matches(['\r', '\n']);
        let body = line.trim_start_matches(' ');
        let indent = line.len().saturating_sub(body.len());
        if indent <= 3 || comment {
            if let Some((symbol, minimum)) = fence {
                if let Some((found, length, rest)) = fence_run(body)
                    && found == symbol
                    && length >= minimum
                    && rest.trim().is_empty()
                {
                    fence = None;
                }
            } else if comment {
                comment = comment_state_after_line(body, comment);
            } else if let Some((symbol, length, _)) = fence_run(body) {
                fence = Some((symbol, length));
            } else if body.contains("<!--") {
                comment = comment_state_after_line(body, comment);
            } else if segment.ends_with('\n') && body.trim_end() == CONFIGS_MARKER {
                let split = offset.checked_add(segment.len())?;
                return Some((content.get(..split)?, content.get(split..)?));
            }
        }
        offset = offset.checked_add(segment.len())?;
    }
    None
}

/// Process comment delimiters in source order, including close then open.
fn comment_state_after_line(line: &str, mut inside: bool) -> bool {
    let mut rest = line;
    loop {
        let delimiter = if inside { "-->" } else { "<!--" };
        let Some((_, after)) = rest.split_once(delimiter) else {
            return inside;
        };
        rest = after;
        inside = !inside;
    }
}

/// Return an opening or closing Markdown fence run and its trailing content.
fn fence_run(line: &str) -> Option<(u8, usize, &str)> {
    let symbol = match line.as_bytes().first()? {
        b'`' => b'`',
        b'~' => b'~',
        _ => return None,
    };
    let length = line.bytes().take_while(|byte| *byte == symbol).count();
    if length < 3 {
        return None;
    }
    Some((symbol, length, line.get(length..)?))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::indexing_slicing, reason = "tests assert lengths before indexing")]
mod tests {
    use super::*;

    #[test]
    fn standard_header_parsed() {
        let input = "\
# Title Here
#
# Description line one
# and line two.
#
# Usage:
#   cargo run
listeners:
";
        let paras = parse_comment_paragraphs(input);
        assert_eq!(paras.len(), 3, "expected title + desc + usage paragraphs");
        assert_eq!(paras[0], vec!["Title Here"]);
        assert_eq!(paras[1], vec!["Description line one", "and line two."]);
    }

    #[test]
    fn single_line_header_parsed() {
        let input = "\
# One-liner description.
listeners:
";
        let paras = parse_comment_paragraphs(input);
        assert_eq!(paras.len(), 1, "expected single paragraph");
        assert_eq!(paras[0], vec!["One-liner description."]);
    }

    #[test]
    fn requires_block_skipped() {
        let input = "\
# Title
#
# Requires the cpex feature:
#   cargo build --features cpex
#
# Real description here.
";
        let desc = description_from_header(input);
        assert_eq!(desc, "Real description here");
    }

    #[test]
    fn placeholder_block_skipped() {
        let input = "\
# Static Catalog
#
# Pipeline: json_rpc -> load_balancer.
#
# Backend endpoints are placeholders for a future flow.
";
        let desc = description_from_header(input);
        assert_eq!(desc, "Static Catalog");
    }

    #[test]
    fn colon_intro_block_skipped() {
        let input = "\
# Failure Mode
#
# Each filter can specify `failure_mode` to control what happens:
#
# Demonstrates open and closed behavior.
";
        let desc = description_from_header(input);
        assert_eq!(desc, "Demonstrates open and closed behavior");
    }

    #[test]
    fn fallback_to_title() {
        let input = "\
# TCP round-robin load balancing across replicas.
listeners:
";
        let desc = description_from_header(input);
        assert_eq!(desc, "TCP round-robin load balancing across replicas");
    }

    #[test]
    fn multi_sentence_takes_first() {
        let input = "\
# Title
#
# First sentence. Second sentence.
";
        let desc = description_from_header(input);
        assert_eq!(desc, "First sentence");
    }

    #[test]
    fn first_sentence_strips_trailing_period() {
        assert_eq!(first_sentence("Hello world."), "Hello world");
    }

    #[test]
    fn normalize_description_strips_trailing_colon() {
        assert_eq!(normalize_description("Hello world:"), "Hello world");
    }

    #[test]
    fn first_sentence_multi_sentences() {
        assert_eq!(first_sentence("First sentence. Second sentence."), "First sentence");
    }

    #[test]
    fn first_sentence_no_period() {
        assert_eq!(first_sentence("No period here"), "No period here");
    }

    #[test]
    fn first_sentence_preserves_version_numbers() {
        assert_eq!(
            first_sentence("Supports version 1.0 and 2.0 formats."),
            "Supports version 1.0 and 2.0 formats"
        );
    }

    #[test]
    fn first_sentence_preserves_abbreviations() {
        assert_eq!(first_sentence("e.g. this is an example."), "e.g. this is an example");
    }

    #[test]
    fn first_sentence_skips_decimal_boundary() {
        assert_eq!(
            first_sentence("Returns 503 with Retry-After: 1. TCP listeners close immediately."),
            "Returns 503 with Retry-After: 1. TCP listeners close immediately"
        );
    }

    #[test]
    fn skip_prefixes_are_sorted() {
        let mut sorted = SKIP_PREFIXES.to_vec();
        sorted.sort_unstable();
        assert_eq!(SKIP_PREFIXES, sorted.as_slice(), "SKIP_PREFIXES must be sorted");
    }

    #[test]
    fn title_from_hyphenated_dir() {
        assert_eq!(category_title("traffic-management"), "Traffic Management");
        assert_eq!(category_title("payload-processing"), "Payload Processing");
    }

    #[test]
    fn title_from_single_word_dir() {
        assert_eq!(category_title("security"), "Security");
        assert_eq!(category_title("protocols"), "Protocols");
    }

    #[test]
    fn split_at_marker_found() {
        let content = "# Header\n\n## Configs\nsome tables\n";
        let (header, tables) = split_at_marker(content).expect("marker exists");
        assert_eq!(header, "# Header\n\n## Configs\n");
        assert_eq!(tables, "some tables\n");
    }

    #[test]
    fn split_at_marker_not_found() {
        let content = "# No configs section\n";
        assert!(split_at_marker(content).is_none(), "missing marker is explicit");
    }

    #[test]
    fn marker_inside_code_or_longer_heading_is_not_a_configs_section() {
        for content in [
            "# Guide\n```markdown\n## Configs\n```\nold data\n",
            "# Guide\n~~~yaml\n## Configs\n~~~\nold data\n",
            "# Guide\n    ## Configs\nold data\n",
            "# Guide\n<!--\n## Configs\n    -->\nold data\n",
            "# Guide\n<!-- closed --> <!-- open\n## Configs\n-->\nold data\n",
            "# Guide\n<!-- first\n--> <!-- second\n## Configs\n-->\nold data\n",
            "# Guide\n### Configs\nold data\n",
            "# Guide\n## Configs and notes\nold data\n",
        ] {
            assert!(split_at_marker(content).is_none(), "false marker: {content}");
            let dir = tempfile::tempdir().expect("temp dir");
            let path = dir.path().join("README.md");
            std::fs::write(&path, content).expect("write fixture");
            for fix in [false, true] {
                let error = sync_readme(&path, "replacement\n", fix)
                    .err()
                    .expect("false marker must fail");
                assert!(error.contains("no `## Configs` marker"), "{error}");
                assert_eq!(std::fs::read_to_string(&path).expect("read fixture"), content);
            }
        }
    }

    #[test]
    fn real_marker_after_code_fences_is_repaired_without_clobbering_header() {
        for opening in ["```markdown", "~~~yaml"] {
            let closing = if opening.starts_with('`') { "```" } else { "~~~" };
            let header = format!("# Guide\n{opening}\n## Configs\n{closing}\n\n  ## Configs  \n");
            let original = format!("{header}stale\n");
            let dir = tempfile::tempdir().expect("temp dir");
            let path = dir.path().join("README.md");
            std::fs::write(&path, original).expect("write fixture");
            assert!(matches!(sync_readme(&path, "fresh\n", true), Ok(SyncOutcome::Written)));
            assert_eq!(
                std::fs::read_to_string(&path).expect("read repair"),
                format!("{header}fresh\n")
            );
            assert!(matches!(
                sync_readme(&path, "fresh\n", false),
                Ok(SyncOutcome::UpToDate)
            ));
        }
    }

    #[test]
    fn real_marker_after_html_comment_ignores_commented_heading() {
        for comments in [
            "<!--\n## Configs\n-->\n",
            "<!-- closed --> <!-- open\n## Configs\n-->\n",
            "<!-- first\n--> <!-- second\n## Configs\n-->\n",
        ] {
            let header = format!("# Guide\n{comments}\n## Configs\n");
            let dir = tempfile::tempdir().expect("temp dir");
            let path = dir.path().join("README.md");
            std::fs::write(&path, format!("{header}stale\n")).expect("write fixture");
            assert!(matches!(sync_readme(&path, "fresh\n", true), Ok(SyncOutcome::Written)));
            assert_eq!(
                std::fs::read_to_string(&path).expect("read repair"),
                format!("{header}fresh\n")
            );
        }
    }

    #[test]
    fn missing_marker_repair_preserves_input() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("README.md");
        let original = b"# Custom heading\n\nOld table data\n";
        std::fs::write(&path, original).expect("write fixture");
        for attempt in 1..=2 {
            let error = sync_readme(&path, "new tables\n", true)
                .err()
                .expect("repair must fail");
            assert!(error.contains("## Configs"), "attempt {attempt}: {error}");
            assert_eq!(
                std::fs::read(&path).expect("read fixture"),
                original,
                "attempt {attempt} left bytes unchanged"
            );
        }
    }

    #[test]
    fn valid_marker_repair_is_idempotent() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("README.md");
        std::fs::write(&path, "# Hand header\n\n## Configs\nstale\n").expect("write fixture");
        assert!(matches!(sync_readme(&path, "fresh\n", true), Ok(SyncOutcome::Written)));
        let first = std::fs::read(&path).expect("read repaired README");
        assert_eq!(first, b"# Hand header\n\n## Configs\nfresh\n");
        assert!(matches!(
            sync_readme(&path, "fresh\n", false),
            Ok(SyncOutcome::UpToDate)
        ));
        assert!(matches!(sync_readme(&path, "fresh\n", true), Ok(SyncOutcome::Written)));
        assert_eq!(std::fs::read(&path).expect("read repeated repair"), first);
    }

    #[test]
    fn missing_readme_is_not_silently_generated() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("README.md");
        for fix in [false, true] {
            let error = sync_readme(&path, "fresh\n", fix)
                .err()
                .expect("missing file must fail");
            assert!(error.contains("cannot read"), "missing file error: {error}");
            assert!(!path.exists(), "no README is created");
        }
    }

    #[test]
    fn discover_finds_real_categories() {
        let root = workspace_root();
        let categories = discover_categories(&root.join("examples/configs"));
        assert!(
            categories.len() > 4,
            "expected 4+ categories, found {}",
            categories.len()
        );
    }

    #[test]
    fn collect_finds_real_configs() {
        let root = workspace_root();
        let entries = collect_entries(&root.join("examples/configs"));
        assert!(
            entries.values().map(Vec::len).sum::<usize>() > 50,
            "expected 50+ configs"
        );
    }
}
