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
        if !abs.is_dir() {
            eprintln!("error: scan root {dir}/ does not exist or is not a directory");
            std::process::exit(1);
        }
        collect_markdown(&abs, &mut md_files);
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
        check_file_links(&content, root, dir, &rel_display, &mut broken);
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

/// Per-file context passed to link-checking helpers.
struct FileCtx<'a> {
    /// Workspace root for resolving leading-slash links.
    root: &'a Path,
    /// Parent directory of the current file.
    dir: &'a Path,
    /// Relative display path of the current file.
    rel_display: &'a str,
    /// Accumulator for broken-link entries.
    broken: &'a mut Vec<(String, usize, String)>,
}

/// Check all links in one file, appending broken entries to `broken`.
/// Leading-slash targets resolve from `root`; others resolve from `dir`.
fn check_file_links(
    content: &str,
    root: &Path,
    dir: &Path,
    rel_display: &str,
    broken: &mut Vec<(String, usize, String)>,
) {
    let mut ctx = FileCtx {
        root,
        dir,
        rel_display,
        broken,
    };
    let mut fence: Option<(char, usize)> = None;
    for (line_no, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        if let Some((marker, len)) = fence {
            let stripped = trimmed.trim_end();
            let run = stripped.chars().take_while(|&c| c == marker).count();
            if run >= len && run == stripped.len() {
                fence = None;
            }
            continue;
        }
        if let Some(f) = parse_fence_open(trimmed) {
            fence = Some(f);
            continue;
        }
        check_line_links(line, line_no, &mut ctx);
    }
}

/// Validate every link target on a single line.
fn check_line_links(line: &str, line_no: usize, ctx: &mut FileCtx<'_>) {
    for target in extract_md_links(line) {
        if !is_relative_local_link(&target) {
            continue;
        }
        let dest = strip_title(&target);
        let (file_part, _) = split_fragment(dest);
        let resolved = resolve_link(ctx.root, ctx.dir, file_part);
        if !resolved.is_file() && !resolved.is_dir() {
            ctx.broken.push((ctx.rel_display.to_owned(), line_no + 1, target));
        }
    }
}

/// Resolve a link target: leading-slash from `root`, otherwise from `dir`.
fn resolve_link(root: &Path, dir: &Path, file_part: &str) -> PathBuf {
    if file_part.starts_with('/') {
        root.join(file_part.trim_start_matches('/'))
    } else {
        dir.join(file_part)
    }
}

/// If `trimmed` is a fenced-code opening line, return `(marker_char, count)`.
fn parse_fence_open(trimmed: &str) -> Option<(char, usize)> {
    let first = trimmed.chars().next()?;
    if first != '`' && first != '~' {
        return None;
    }
    let count = trimmed.chars().take_while(|&c| c == first).count();
    (count >= 3).then_some((first, count))
}

// -----------------------------------------------------------------------------
// Link Extraction
// -----------------------------------------------------------------------------

/// Extract all link targets from a single line of Markdown.
///
/// Strips inline code spans (`` `...` ``) before scanning so that a
/// link pattern inside backticks is not treated as a live link.
/// Does not extract reference-style links (`[text][ref]`).
fn extract_md_links(line: &str) -> Vec<String> {
    let stripped = strip_inline_code(line);
    let mut links = Vec::new();
    let mut rest = stripped.as_str();

    while let Some(open) = rest.find("](") {
        let Some(after) = rest.get(open + 2..) else {
            break;
        };
        if let Some(target) = balanced_paren(after) {
            links.push(target.to_owned());
            rest = after.get(target.len() + 1..).unwrap_or("");
        } else {
            rest = after;
        }
    }

    links
}

/// Replace every inline code span (`` `...` ``) with spaces so link
/// patterns inside backticks are invisible to the extractor.
fn strip_inline_code(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.char_indices().peekable();
    while let Some((i, ch)) = chars.next() {
        if ch == '`' {
            let close = line.get(i + 1..).and_then(|rest| rest.find('`'));
            if let Some(span_len) = close {
                for _ in 0..span_len + 2 {
                    out.push(' ');
                    chars.next();
                }
                continue;
            }
        }
        out.push(ch);
    }
    out
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

/// Whether a link target is a relative local path (not a URL, not
/// anchor-only). Covers all extensions and directories.
fn is_relative_local_link(target: &str) -> bool {
    let dest = strip_title(target);
    if dest.is_empty() || dest.starts_with('#') {
        return false;
    }
    !dest.contains("://") && !dest.starts_with("mailto:")
}

/// Return the destination portion of a link target, stripping an optional
/// quoted title such as `"Read more"` or `'tooltip'`.
fn strip_title(target: &str) -> &str {
    let t = target.trim_end();
    for quote in ['"', '\''] {
        if !t.ends_with(quote) {
            continue;
        }
        let found = t
            .get(..t.len() - 1)
            .and_then(|before| before.rfind(quote))
            .and_then(|pos| t.get(..pos));
        if let Some(dest) = found {
            return dest.trim_end();
        }
    }
    t
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

/// Recursively collect all `.md` files under `dir`, skipping symlink
/// directories to avoid rescanning ancestor trees.
fn collect_markdown(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|err| {
        eprintln!("error: cannot read directory {}: {err}", dir.display());
        std::process::exit(1);
    });
    for entry in entries {
        let entry = entry.unwrap_or_else(|err| {
            eprintln!("error: directory entry under {}: {err}", dir.display());
            std::process::exit(1);
        });
        let ft = entry.file_type().unwrap_or_else(|err| {
            eprintln!("error: file type for {}: {err}", entry.path().display());
            std::process::exit(1);
        });
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        if ft.is_dir() {
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
        assert_eq!(links, ["../bar.md"]);
    }

    #[test]
    fn extracts_multiple_links() {
        let links = extract_md_links("[A](a.md) and [B](../b.md#section)");
        assert_eq!(links, ["a.md", "../b.md#section"]);
    }

    #[test]
    fn skips_url_links() {
        assert!(!is_relative_local_link("https://example.com/foo.md"));
        assert!(!is_relative_local_link("http://example.com"));
        assert!(!is_relative_local_link("mailto:x@y.com"));
    }

    #[test]
    fn skips_anchor_only_links() {
        assert!(!is_relative_local_link("#section"));
    }

    #[test]
    fn accepts_relative_links() {
        assert!(is_relative_local_link("../docs/foo.md"));
        assert!(is_relative_local_link("foo.md#section"));
        assert!(is_relative_local_link("./bar/baz.md"));
        assert!(is_relative_local_link("image.png"));
        assert!(is_relative_local_link("configs/foo.yaml"));
        assert!(is_relative_local_link("some-dir/"));
    }

    #[test]
    fn link_with_title_is_detected() {
        assert!(is_relative_local_link("missing.md \"Read more\""));
        assert!(is_relative_local_link("missing.md 'tooltip'"));
    }

    #[test]
    fn titled_link_resolves_file_part() {
        let content = "See [details](nonexistent.md \"Read more\") here.\n";
        let mut broken = Vec::new();
        let dir = Path::new("/tmp");
        check_file_links(content, dir, dir, "test.md", &mut broken);
        assert_eq!(broken.len(), 1, "titled link should be checked");
    }

    #[test]
    fn strip_title_works() {
        assert_eq!(strip_title("foo.md \"title\""), "foo.md");
        assert_eq!(strip_title("foo.md 'title'"), "foo.md");
        assert_eq!(strip_title("foo.md"), "foo.md");
        assert_eq!(strip_title("foo.md#frag"), "foo.md#frag");
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
    fn inline_code_links_are_skipped() {
        let links = extract_md_links("see `[example](missing.md)` in code and [real](real.md) outside");
        assert_eq!(links, ["real.md"]);
    }

    #[test]
    fn inline_code_link_does_not_produce_broken_entry() {
        let content = "A `[fake](nonexistent.md)` inline code link.\n";
        let mut broken = Vec::new();
        let dir = Path::new("/tmp");
        check_file_links(content, dir, dir, "test.md", &mut broken);
        assert!(broken.is_empty(), "inline code link should not be checked: {broken:?}");
    }

    #[test]
    fn links_inside_fenced_blocks_are_ignored() {
        let content = "\
See [real](real.md) link.

```markdown
A [fake](fake.md) link inside a backtick fence.
```

~~~markdown
A [fake2](fake2.md) link inside a tilde fence.
~~~

Another [real2](real2.md) link.
";
        let mut broken = Vec::new();
        let dir = Path::new("/tmp");
        check_file_links(content, dir, dir, "test.md", &mut broken);
        let targets: Vec<&str> = broken.iter().map(|(_, _, t)| t.as_str()).collect();
        assert_eq!(targets, ["real.md", "real2.md"]);
    }

    #[test]
    fn nested_fence_does_not_close_outer() {
        let content = "\
````markdown
A sample fenced block:
```
[fake](fake.md)
```
Still inside the outer fence: [fake2](fake2.md)
````

[real](real.md) outside.
";
        let mut broken = Vec::new();
        let dir = Path::new("/tmp");
        check_file_links(content, dir, dir, "test.md", &mut broken);
        let targets: Vec<&str> = broken.iter().map(|(_, _, t)| t.as_str()).collect();
        assert_eq!(targets, ["real.md"]);
    }

    #[test]
    fn tilde_inside_backtick_fence_does_not_close() {
        let content = "\
```markdown
~~~
[fake](fake.md)
~~~
Still fenced: [fake2](fake2.md)
```

[real](real.md) outside.
";
        let mut broken = Vec::new();
        let dir = Path::new("/tmp");
        check_file_links(content, dir, dir, "test.md", &mut broken);
        let targets: Vec<&str> = broken.iter().map(|(_, _, t)| t.as_str()).collect();
        assert_eq!(targets, ["real.md"]);
    }

    #[test]
    fn leading_slash_resolves_from_root() {
        let root = workspace_root();
        let content = "See [guide](/docs/architecture/pipeline-concepts.md) here.\n";
        let sub = root.join("examples/some-example");
        let dir = if sub.is_dir() { &sub } else { &root };
        let mut broken = Vec::new();
        check_file_links(content, &root, dir, "test.md", &mut broken);
        assert!(
            broken.is_empty(),
            "leading-slash link should resolve from root: {broken:?}"
        );
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
