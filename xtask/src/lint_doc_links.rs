// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `cargo xtask lint-doc-links`: check that relative Markdown links resolve
//! to files that exist on disk.

use std::path::{Path, PathBuf};

use clap::Parser;

use crate::paths::workspace_root;

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask lint-doc-links`.
#[derive(Parser)]
pub(crate) struct Args;

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Verify that every relative link in Markdown files under the scanned
/// directories points to a file that exists on disk.
pub(crate) fn run(_args: Args) {
    let root = workspace_root();
    let md_files = discover_markdown(&root);
    let broken = check_links(&root, &md_files);

    if broken.is_empty() {
        println!("all relative Markdown links resolve ({} files scanned)", md_files.len(),);
        return;
    }

    eprintln!("broken relative links:");
    for (file, line, target) in &broken {
        eprintln!("  {file}:{line}: {target}");
    }
    eprintln!("\n{count} broken link(s) found", count = broken.len());
    std::process::exit(1);
}

/// Collect every `.md` file under the scanned directories.
fn discover_markdown(root: &Path) -> Vec<PathBuf> {
    let scan_dirs: &[&str] = &["docs", "examples"];
    let mut md_files = Vec::new();
    for dir in scan_dirs {
        let abs = root.join(dir);
        if abs.is_dir() {
            collect_markdown(&abs, &mut md_files);
        }
    }
    md_files.sort();
    if md_files.is_empty() {
        eprintln!("error: no Markdown files found under {scan_dirs:?}");
        std::process::exit(1);
    }
    md_files
}

/// Return `(file, line, target)` triples for every broken relative
/// Markdown link found in `md_files`.
fn check_links(root: &Path, md_files: &[PathBuf]) -> Vec<(String, usize, String)> {
    let mut broken = Vec::new();
    for path in md_files {
        let content = read_or_exit(path);
        let rel_display = path.strip_prefix(root).unwrap_or(path).to_string_lossy().into_owned();
        let dir = path.parent().unwrap_or(path);
        check_file_links(&content, dir, &rel_display, &mut broken);
    }
    broken
}

/// Read a file or exit with an error message.
fn read_or_exit(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| {
        eprintln!("error: cannot read {}: {err}", path.display());
        std::process::exit(1);
    })
}

/// Check all links in one file, appending broken entries to `broken`.
fn check_file_links(
    content: &str,
    dir: &Path,
    rel_display: &str,
    broken: &mut Vec<(String, usize, String)>,
) {
    let mut in_fenced_block = false;
    for (line_no, line) in content.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            in_fenced_block = !in_fenced_block;
            continue;
        }
        if in_fenced_block {
            continue;
        }
        for target in extract_md_links(line) {
            if is_relative_md_link(target) {
                let (file_part, _fragment) = split_fragment(target);
                if !dir.join(file_part).is_file() {
                    broken.push((rel_display.to_owned(), line_no + 1, target.to_owned()));
                }
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Link Extraction
// -----------------------------------------------------------------------------

/// Extract all link targets from a single line of Markdown.
///
/// Finds `[text](target)` patterns. Does not extract reference-style links
/// (`[text][ref]`) — those are rare in this codebase and would require
/// multi-pass parsing.
fn extract_md_links(line: &str) -> Vec<&str> {
    let mut links = Vec::new();
    let mut rest = line;

    while let Some(open) = rest.find("](") {
        let Some(after) = rest.get(open + 2..) else {
            break;
        };
        // Find the matching close paren, respecting nested parens.
        if let Some(target) = balanced_paren(after) {
            links.push(target);
            rest = after.get(target.len() + 1..).unwrap_or("");
        } else {
            rest = after;
        }
    }

    links
}

/// Return the content up to the matching `)`, allowing one level of nested
/// parens (e.g. for percent-encoded URLs). Returns `None` when no closing
/// paren is found.
fn balanced_paren(s: &str) -> Option<&str> {
    let mut depth: u32 = 1;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return s.get(..i);
                }
            },
            _ => {},
        }
    }
    None
}

/// Whether a link target looks like a relative Markdown path (not a URL
/// and not an anchor-only link).
fn is_relative_md_link(target: &str) -> bool {
    if target.is_empty() || target.starts_with('#') {
        return false;
    }
    if target.contains("://") || target.starts_with("mailto:") {
        return false;
    }
    let (file_part, _) = split_fragment(target);
    file_part.ends_with(".md")
}

/// Split a link target into the file path and an optional `#fragment`.
fn split_fragment(target: &str) -> (&str, Option<&str>) {
    match target.find('#') {
        Some(pos) => (target.get(..pos).unwrap_or(target), target.get(pos + 1..)),
        None => (target, None),
    }
}

// -----------------------------------------------------------------------------
// File Collection
// -----------------------------------------------------------------------------

/// Recursively collect all `.md` files under `dir`.
fn collect_markdown(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_markdown(&path, out);
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_link() {
        let links = extract_md_links("see [Foo](../bar.md) for details");
        assert_eq!(links, vec!["../bar.md"]);
    }

    #[test]
    fn extracts_multiple_links() {
        let links = extract_md_links("[A](a.md) and [B](../b.md#section)");
        assert_eq!(links, vec!["a.md", "../b.md#section"]);
    }

    #[test]
    fn skips_url_links() {
        assert!(!is_relative_md_link("https://example.com/foo.md"));
        assert!(!is_relative_md_link("http://example.com"));
        assert!(!is_relative_md_link("mailto:x@y.com"));
    }

    #[test]
    fn skips_anchor_only_links() {
        assert!(!is_relative_md_link("#section"));
    }

    #[test]
    fn accepts_relative_md_link() {
        assert!(is_relative_md_link("../docs/foo.md"));
        assert!(is_relative_md_link("foo.md#section"));
        assert!(is_relative_md_link("./bar/baz.md"));
    }

    #[test]
    fn rejects_non_md_link() {
        assert!(!is_relative_md_link("image.png"));
        assert!(!is_relative_md_link("configs/foo.yaml"));
    }

    #[test]
    fn split_fragment_with_hash() {
        let (file, frag) = split_fragment("foo.md#bar");
        assert_eq!(file, "foo.md");
        assert_eq!(frag, Some("bar"));
    }

    #[test]
    fn split_fragment_without_hash() {
        let (file, frag) = split_fragment("foo.md");
        assert_eq!(file, "foo.md");
        assert_eq!(frag, None);
    }

    #[test]
    fn balanced_paren_simple() {
        assert_eq!(balanced_paren("foo.md)rest"), Some("foo.md"));
    }

    #[test]
    fn balanced_paren_nested() {
        assert_eq!(balanced_paren("foo(1).md)rest"), Some("foo(1).md"),);
    }

    #[test]
    fn balanced_paren_unmatched() {
        assert_eq!(balanced_paren("no close paren"), None);
    }

    #[test]
    fn no_links_in_plain_text() {
        let links = extract_md_links("just some text, no links");
        assert!(links.is_empty());
    }

    #[test]
    fn links_inside_fenced_blocks_are_ignored() {
        let content = "\
# Title

See [real](real.md) link.

```markdown
A [fake](fake.md) link inside a code block.
```

Another [real2](real2.md) link.
";
        let mut found = Vec::new();
        let mut in_fence = false;
        for line in content.lines() {
            if line.trim_start().starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            if in_fence {
                continue;
            }
            found.extend(extract_md_links(line));
        }
        assert_eq!(found, vec!["real.md", "real2.md"]);
    }

    #[test]
    fn scans_real_docs() {
        let root = workspace_root();
        let docs_dir = root.join("docs");
        if !docs_dir.is_dir() {
            return;
        }
        let mut files = Vec::new();
        collect_markdown(&docs_dir, &mut files);
        assert!(
            files.len() > 10,
            "expected 10+ docs Markdown files, found {}",
            files.len(),
        );
    }

    #[test]
    fn scans_real_examples() {
        let root = workspace_root();
        let examples_dir = root.join("examples");
        if !examples_dir.is_dir() {
            return;
        }
        let mut files = Vec::new();
        collect_markdown(&examples_dir, &mut files);
        assert!(!files.is_empty(), "expected at least one Markdown file under examples/",);
    }
}
