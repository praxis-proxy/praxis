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

/// An open fence, the quote depth it was opened at, and its list column.
struct OpenFence {
    /// Fence marker, backtick or tilde.
    marker: char,
    /// Marker length of the opening run.
    len: usize,
    /// Block-quote depth of the opening line.
    depth: usize,
    /// List content column when the fence opened inside a list.
    list_indent: Option<usize>,
}

/// How an open raw HTML block ends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HtmlBlockKind {
    /// Ends at the next blank line.
    Blank,
    /// Ends on the line that contains this marker.
    Marker(&'static str),
}

/// Lookahead and in-progress span state for one paragraph.
struct MaskIn<'a> {
    /// Length of an inline-code run that has not closed yet.
    code_open: &'a mut Option<usize>,
    /// HTML comment that started on an earlier line.
    html: &'a mut HtmlSpan,
    /// Source after this paragraph. Used to see if a backtick run closes.
    lookahead: &'a str,
}

/// Whether an HTML comment is still open across lines.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HtmlSpan {
    /// No comment is open.
    Closed,
    /// `<!--` has not been closed with `-->`.
    Open,
}

/// Scan state for one Markdown file.
struct Scan<'a, 'b> {
    /// Link resolution context.
    ctx: FileCtx<'a>,
    /// Source not yet consumed, including the current line until it is advanced.
    tail: &'b str,
    /// Fences currently open, outermost first.
    fences: Vec<OpenFence>,
    /// Length of an inline-code run that has not closed yet.
    code_open: Option<usize>,
    /// HTML comment that started on an earlier line.
    html: HtmlSpan,
    /// Raw HTML block that has not ended yet.
    html_block: Option<HtmlBlockKind>,
    /// Content column of the current list item, when one is open.
    list_indent: Option<usize>,
    /// The previous physical line was empty.
    prev_blank: bool,
    /// The current line continues an indented code block.
    in_indented: bool,
    /// Paragraph text accumulated so far.
    para: String,
    /// First line index of `para`.
    para_start: usize,
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
    let mut scan = Scan {
        ctx: FileCtx {
            root,
            dir,
            rel_display,
            broken,
        },
        tail: content,
        fences: Vec::new(),
        code_open: None,
        html: HtmlSpan::Closed,
        html_block: None,
        list_indent: None,
        prev_blank: true,
        in_indented: false,
        para: String::new(),
        para_start: 0,
    };
    for (line_no, line) in content.lines().enumerate() {
        scan.advance_tail(line);
        scan.consume_line(line_no, line);
    }
    scan.flush();
}

impl Scan<'_, '_> {
    /// Drop `line` and its terminator from the unconsumed tail.
    fn advance_tail(&mut self, line: &str) {
        let Some(rest) = self.tail.strip_prefix(line) else {
            return;
        };
        self.tail = rest
            .strip_prefix("\r\n")
            .or_else(|| rest.strip_prefix('\n'))
            .unwrap_or(rest);
    }

    /// Handle one physical line.
    fn consume_line(&mut self, line_no: usize, line: &str) {
        let (depth, content) = quoted_content(line);
        self.pop_shallow_fences(depth);
        self.end_list_fences(content);
        if self.inside_fence(depth, content) || self.continue_html_block(content) {
            self.finish_block(content);
            return;
        }
        self.drop_finished_list(content);
        if self.skip_indented(content) {
            self.leave_block();
            self.prev_blank = false;
            return;
        }
        if self.begin_html_block(content) {
            self.leave_block();
            self.prev_blank = false;
            return;
        }
        if let Some(opened) = open_fence(content, self.list_indent, depth) {
            self.leave_block();
            self.fences.push(opened);
            self.prev_blank = false;
            return;
        }
        self.take_text(line_no, content);
    }

    /// Drop list context when a non-blank line is outdented from the active item.
    fn drop_finished_list(&mut self, content: &str) {
        if content.trim().is_empty() {
            return;
        }
        if self.list_indent.is_some_and(|column| indent_columns(content) < column) {
            self.list_indent = None;
        }
    }

    /// Close fences whose list ended on this unindented line.
    fn end_list_fences(&mut self, content: &str) {
        if content.trim().is_empty() {
            return;
        }
        let indent = indent_columns(content);
        while self
            .fences
            .last()
            .is_some_and(|fence| fence.list_indent.is_some_and(|col| indent < col))
        {
            self.fences.pop();
        }
    }

    /// Stay inside a raw HTML block, clearing it when its end condition hits.
    fn continue_html_block(&mut self, content: &str) -> bool {
        let Some(kind) = self.html_block else {
            return false;
        };
        if html_block_ends(content, kind) {
            self.html_block = None;
        }
        true
    }

    /// Start a raw HTML block when `content` is one. A one-line block does not stay open.
    fn begin_html_block(&mut self, content: &str) -> bool {
        let Some(kind) = html_block_start(content) else {
            return false;
        };
        if matches!(kind, HtmlBlockKind::Marker(_)) && html_block_ends(content, kind) {
            return true;
        }
        self.html_block = Some(kind);
        true
    }

    /// Check the open paragraph and remember whether this line was blank.
    fn finish_block(&mut self, content: &str) {
        self.leave_block();
        self.prev_blank = content.trim().is_empty();
    }

    /// Check the open paragraph, then drop an inline span at a block boundary.
    fn leave_block(&mut self) {
        self.flush();
        self.code_open = None;
    }

    /// Forget fences opened in a deeper quote than `depth`.
    fn pop_shallow_fences(&mut self, depth: usize) {
        while self.fences.last().is_some_and(|fence| depth < fence.depth) {
            self.fences.pop();
        }
    }

    /// Whether `content` belongs to an already open fence.
    fn inside_fence(&mut self, depth: usize, content: &str) -> bool {
        let Some(top) = self.fences.last() else {
            return false;
        };
        if depth < top.depth {
            return false;
        }
        let base = top.list_indent.unwrap_or(0);
        let marker = top.marker;
        let len = top.len;
        if indent_columns(content).saturating_sub(base) < 4 && closes_fence(content, marker, len) {
            self.fences.pop();
        }
        true
    }

    /// Skip an indented code block without swallowing the following line.
    fn skip_indented(&mut self, content: &str) -> bool {
        if content.trim().is_empty() {
            self.in_indented = false;
            return false;
        }
        let indented = is_block_indent(content, self.list_indent);
        if self.in_indented && indented {
            return true;
        }
        if self.prev_blank && indented {
            self.in_indented = true;
            return true;
        }
        self.in_indented = false;
        false
    }

    /// Record prose. Inline-code state is applied when the paragraph is checked.
    fn take_text(&mut self, line_no: usize, content: &str) {
        if content.trim().is_empty() {
            self.flush();
            self.prev_blank = true;
            return;
        }
        self.note_list(content);
        if self.para.is_empty() {
            self.para_start = line_no;
        } else {
            self.para.push('\n');
        }
        self.para.push_str(content);
        self.prev_blank = false;
    }

    /// Track a list item so its continuation is not treated as indented code.
    fn note_list(&mut self, line: &str) {
        if let Some(column) = list_content_column(line, self.list_indent) {
            self.list_indent = Some(column);
        } else if self.list_indent.is_some_and(|column| indent_columns(line) < column) {
            self.list_indent = None;
        }
    }

    /// Check the accumulated paragraph and clear it.
    fn flush(&mut self) {
        if self.para.is_empty() {
            return;
        }
        let lookahead = self.tail;
        let start = self.para_start;
        check_line_links(
            &self.para,
            start,
            &mut self.ctx,
            MaskIn {
                code_open: &mut self.code_open,
                html: &mut self.html,
                lookahead,
            },
        );
        self.para.clear();
    }
}

/// Split a leading block-quote prefix into `(depth, content)`.
fn quoted_content(line: &str) -> (usize, &str) {
    let bytes = line.as_bytes();
    let mut index = 0_usize;
    let mut depth = 0_usize;
    loop {
        let mut spaces = 0_usize;
        while spaces < 3 && bytes.get(index + spaces) == Some(&b' ') {
            spaces += 1;
        }
        if bytes.get(index + spaces) != Some(&b'>') {
            break;
        }
        depth += 1;
        index += spaces + 1;
        if bytes.get(index) == Some(&b' ') {
            index += 1;
        }
    }
    (depth, line.get(index..).unwrap_or(""))
}

/// Whether `content` is indented as a code block relative to the current list.
fn is_block_indent(content: &str, list_indent: Option<usize>) -> bool {
    indent_columns(content) >= list_indent.unwrap_or(0) + 4
}

/// Open a fence indented by at most three spaces past the list content column.
fn open_fence(content: &str, list_indent: Option<usize>, depth: usize) -> Option<OpenFence> {
    let base = list_indent.unwrap_or(0);
    let (columns, bytes) = indent_parts(content);
    if columns < base || columns - base >= 4 {
        return None;
    }
    let rest = content.get(bytes..)?.trim_start();
    let (marker, len) = parse_fence_open(rest)?;
    Some(OpenFence {
        marker,
        len,
        depth,
        list_indent,
    })
}

/// Whether `line`, after at most three spaces, opens a raw HTML block.
fn html_block_start(line: &str) -> Option<HtmlBlockKind> {
    let (columns, bytes) = indent_parts(line);
    if columns > 3 {
        return None;
    }
    let rest = line.get(bytes..)?.trim_end();
    raw_tag_block(rest).or_else(|| other_html_block(rest))
}

/// Whether `content` meets the end condition of `kind`.
fn html_block_ends(content: &str, kind: HtmlBlockKind) -> bool {
    match kind {
        HtmlBlockKind::Blank => content.trim().is_empty(),
        HtmlBlockKind::Marker(marker) => content.to_ascii_lowercase().contains(marker),
    }
}

/// `<script>`, `<pre>`, `<style>`, or `<textarea`, closed by its end tag.
fn raw_tag_block(rest: &str) -> Option<HtmlBlockKind> {
    let lower = rest.to_ascii_lowercase();
    for (start, end) in [
        ("<script", "</script>"),
        ("<pre", "</pre>"),
        ("<style", "</style>"),
        ("<textarea", "</textarea>"),
    ] {
        if lower.starts_with(start) && tag_boundary(&lower, start.len()) {
            return Some(HtmlBlockKind::Marker(end));
        }
    }
    None
}

/// Comment, processing instruction, declaration, cdata, or a block tag.
fn other_html_block(rest: &str) -> Option<HtmlBlockKind> {
    if rest.starts_with("<!--") {
        return Some(HtmlBlockKind::Marker("-->"));
    }
    if rest.starts_with("<?") {
        return Some(HtmlBlockKind::Marker("?>"));
    }
    if rest.starts_with("<![CDATA[") {
        return Some(HtmlBlockKind::Marker("]]>"));
    }
    if rest.starts_with("<!") && rest.as_bytes().get(2).is_some_and(u8::is_ascii_uppercase) {
        return Some(HtmlBlockKind::Marker(">"));
    }
    block_tag(rest)
}

/// A block-level tag. The block ends at the next blank line.
fn block_tag(rest: &str) -> Option<HtmlBlockKind> {
    let name = html_tag_name(rest)?;
    is_block_tag(&name).then_some(HtmlBlockKind::Blank)
}

/// Tag name after an optional `/`, when the next byte can follow a tag name.
fn html_tag_name(rest: &str) -> Option<String> {
    let body = rest.strip_prefix('<')?;
    let body = body.strip_prefix('/').unwrap_or(body);
    let name_len = body
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        .count();
    if name_len == 0 || !tag_boundary(body, name_len) {
        return None;
    }
    Some(body.get(..name_len)?.to_ascii_lowercase())
}

/// Whether byte `at` may follow a raw tag name.
fn tag_boundary(text: &str, at: usize) -> bool {
    matches!(text.as_bytes().get(at), None | Some(b' ' | b'\t' | b'>' | b'/'))
}

/// Whether `name` is a `CommonMark` HTML block tag.
fn is_block_tag(name: &str) -> bool {
    let tags = " address article aside base basefont blockquote body caption center col colgroup \
                dd details dialog dir div dl dt fieldset figcaption figure footer form frame \
                frameset h1 h2 h3 h4 h5 h6 head header hr html iframe legend li link main menu \
                menuitem nav noframes ol optgroup option p param search section summary table \
                tbody td tfoot th thead title tr track ul ";
    tags.contains(&format!(" {name} "))
}

/// Whether `content` closes a fence of `marker` repeated `len` times.
fn closes_fence(content: &str, marker: char, len: usize) -> bool {
    let stripped = content.trim();
    let run = stripped.chars().take_while(|&ch| ch == marker).count();
    run >= len && run == stripped.len()
}

/// Display columns of the leading indent. A tab advances to the next stop of 4.
fn indent_columns(line: &str) -> usize {
    indent_parts(line).0
}

/// `(columns, bytes)` of the leading spaces and tabs.
fn indent_parts(line: &str) -> (usize, usize) {
    let mut columns = 0_usize;
    let mut bytes = 0_usize;
    for byte in line.bytes() {
        match byte {
            b' ' => columns += 1,
            b'\t' => columns += 4 - (columns % 4),
            _ => break,
        }
        bytes += 1;
    }
    (columns, bytes)
}

/// Content column of a list marker, including one nested past three spaces.
fn list_content_column(line: &str, list_indent: Option<usize>) -> Option<usize> {
    let (columns, bytes) = indent_parts(line);
    if !marker_column_ok(columns, list_indent) {
        return None;
    }
    let rest = line.get(bytes..)?;
    let marker = marker_len(rest.as_bytes())?;
    let after = bytes + marker;
    let follow = indent_columns(line.get(after..)?);
    if follow == 0 {
        return None;
    }
    let follow = if follow > 4 { 1 } else { follow };
    Some(columns + marker + follow)
}

/// Whether a marker at `columns` starts a top-level or nested item.
fn marker_column_ok(columns: usize, list_indent: Option<usize>) -> bool {
    if columns <= 3 {
        return true;
    }
    list_indent.is_some_and(|base| columns >= base && columns < base + 4)
}

/// Byte length of a bullet or ordered-list marker.
fn marker_len(rest: &[u8]) -> Option<usize> {
    if matches!(rest.first(), Some(b'-' | b'+' | b'*')) {
        return Some(1);
    }
    let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
    ((1..=9).contains(&digits) && matches!(rest.get(digits), Some(b'.' | b')'))).then_some(digits + 1)
}

/// Validate every link target in one paragraph.
fn check_line_links(line: &str, line_no: usize, ctx: &mut FileCtx<'_>, mask: MaskIn<'_>) {
    let MaskIn {
        code_open,
        html,
        lookahead,
    } = mask;
    let masked = mask_html_comments(&mask_inline_code(line, code_open, lookahead), html);
    let mut found = inline_link_spans(&masked);
    found.extend(leading_def_spans(&masked));
    for (at, raw) in found {
        let target: String = raw.chars().filter(|ch| !matches!(ch, '\n' | '\r')).collect();
        record_target(target, line_no + newlines_before(&masked, at), ctx);
    }
}

/// Newline count in `text` before byte `at`.
fn newlines_before(text: &str, at: usize) -> usize {
    text.get(..at)
        .map_or(0, |prefix| prefix.bytes().filter(|byte| *byte == b'\n').count())
}

/// Resolve one destination and record it when it is missing or outside `root`.
fn record_target(target: String, line_no: usize, ctx: &mut FileCtx<'_>) {
    if !is_relative_local_link(&target) {
        return;
    }
    let dest = unescape_punctuation(strip_angle_brackets(strip_title(&target)));
    let (file_part, _) = split_fragment(&dest);
    let file_part = strip_query(file_part);
    let resolved = resolve_link(ctx.root, ctx.dir, file_part);
    let missing = resolved.as_ref().is_none_or(|path| !path.is_file() && !path.is_dir());
    if missing {
        ctx.broken.push((ctx.rel_display.to_owned(), line_no + 1, target));
    }
}

/// Resolve a link target. Leading-slash paths start at `root`.
///
/// Returns `None` when the normalized path leaves the workspace root.
fn resolve_link(root: &Path, dir: &Path, file_part: &str) -> Option<PathBuf> {
    let joined = if file_part.starts_with('/') {
        root.join(file_part.trim_start_matches('/'))
    } else {
        dir.join(file_part)
    };
    let normalized = normalize_lexical(&joined);
    normalized.starts_with(root).then_some(normalized)
}

/// Collapse `.` and `..` without touching the filesystem.
fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {},
            std::path::Component::ParentDir => {
                out.pop();
            },
            other => out.push(other.as_os_str()),
        }
    }
    out
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
/// Strips inline code spans (`` `...` ``) and HTML comments before scanning
/// so that a link pattern inside them is not treated as a live link.
/// Does not extract reference-style links (`[text][ref]`).
#[cfg(test)]
fn extract_md_links(line: &str) -> Vec<String> {
    let mut code_open = None;
    let mut html = HtmlSpan::Closed;
    let masked = mask_inline_code(line, &mut code_open, "");
    let stripped = mask_html_comments(&masked, &mut html);
    inline_link_spans(&stripped)
        .into_iter()
        .map(|(_, target)| target)
        .collect()
}

/// `(byte offset, destination)` of inline links whose `]` is unescaped and has an opening `[`.
fn inline_link_spans(text: &str) -> Vec<(usize, String)> {
    let mut spans = Vec::new();
    let mut base = 0_usize;
    while let Some(rel) = text.get(base..).and_then(|rest| rest.find("](")) {
        let close = base + rel;
        let after = close + 2;
        if !is_escaped(text, close)
            && matching_bracket(text, close).is_some()
            && let Some(target) = text.get(after..).and_then(balanced_paren)
        {
            spans.push((close, target.to_owned()));
            base = after + target.len() + 1;
            continue;
        }
        base = close + 1;
    }
    spans
}

/// Whether the character at `index` is escaped by an odd run of backslashes.
fn is_escaped(text: &str, index: usize) -> bool {
    let bytes = text.as_bytes();
    let mut slashes = 0_usize;
    let mut at = index;
    while at > 0 && bytes.get(at - 1) == Some(&b'\\') {
        slashes += 1;
        at -= 1;
    }
    slashes % 2 == 1
}

/// Index of the `[` that matches the `]` at `close`.
fn matching_bracket(text: &str, close: usize) -> Option<usize> {
    let mut depth = 1_i32;
    let mut at = close;
    while at > 0 {
        let prev = floor_char(text, at - 1);
        let ch = text.get(prev..)?.chars().next()?;
        if !is_escaped(text, prev) {
            depth += match ch {
                ']' => 1,
                '[' => -1,
                _ => 0,
            };
            if depth == 0 {
                return Some(prev);
            }
        }
        at = prev;
    }
    None
}

/// Start of the char that contains `index`.
fn floor_char(text: &str, index: usize) -> usize {
    let mut at = index;
    while at > 0
        && text
            .as_bytes()
            .get(at)
            .is_some_and(|byte| byte & 0b1100_0000 == 0b1000_0000)
    {
        at -= 1;
    }
    at
}

/// Definitions that begin a paragraph, or follow another definition in it.
fn leading_def_spans(text: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = Vec::new();
    let mut index = 0_usize;
    let mut offset = 0_usize;
    while index < lines.len() {
        let mut found = Vec::new();
        let used = push_reference_def(&lines, index, &mut found);
        if found.is_empty() {
            break;
        }
        out.push((offset, found.remove(0)));
        for step in 0..used {
            offset += lines[index + step].len() + 1;
        }
        index += used;
    }
    out
}

/// Push the definition at `lines[index]`, if any, and return how many lines it used.
fn push_reference_def(lines: &[&str], index: usize, defs: &mut Vec<String>) -> usize {
    let line = lines[index];
    if let Some(dest) = reference_destination(line) {
        defs.push(dest);
        return 1;
    }
    if label_only(line)
        && let Some(dest) = lines.get(index + 1).and_then(|next| continuation_destination(next))
    {
        defs.push(dest);
        return 2;
    }
    1
}

/// Destination on a `[label]: destination` line, when one is present.
fn reference_destination(line: &str) -> Option<String> {
    accept_destination(definition_after(line)?.trim_start())
}

/// Whether `line` is a `[label]:` with no destination yet.
fn label_only(line: &str) -> bool {
    definition_after(line).is_some_and(|after| after.trim().is_empty())
}

/// Text after the `]:` of a definition line indented by at most three spaces.
fn definition_after(line: &str) -> Option<&str> {
    let (columns, bytes) = indent_parts(line);
    if columns > 3 {
        return None;
    }
    let rest = line.get(bytes..)?;
    if !rest.starts_with('[') {
        return None;
    }
    let close = rest.find("]:")?;
    rest.get(close + 2..)
}

/// A destination continued onto its own line.
fn continuation_destination(line: &str) -> Option<String> {
    if indent_columns(line) > 3 || line.trim_start().starts_with('[') {
        return None;
    }
    accept_destination(line.trim())
}

/// Keep a destination whose path does not contain raw spaces.
fn accept_destination(dest: &str) -> Option<String> {
    if dest.is_empty() {
        return None;
    }
    let target = strip_title(dest);
    let bare = strip_angle_brackets(target);
    let angled = target.starts_with('<') && target.ends_with('>');
    if bare.is_empty() || (!angled && bare.chars().any(char::is_whitespace)) {
        return None;
    }
    Some(dest.to_owned())
}

/// Blank inline code and remember an opener that has not closed yet.
fn mask_inline_code(line: &str, open: &mut Option<usize>, lookahead: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let index = mask_pending(line, open, &mut out);
    if index < line.len() {
        mask_fresh_spans(line, index, open, lookahead, &mut out);
    }
    out
}

/// Blank a span carried in from an earlier line. Returns the index to resume at.
fn mask_pending(line: &str, open: &mut Option<usize>, out: &mut String) -> usize {
    let Some(opener) = *open else {
        return 0;
    };
    if let Some(end) = find_code_span_end(line, 0, opener) {
        push_spaces(out, line, 0, end);
        *open = None;
        end
    } else {
        push_spaces(out, line, 0, line.len());
        line.len()
    }
}

/// Blank spans that open at or after `index`.
fn mask_fresh_spans(line: &str, mut index: usize, open: &mut Option<usize>, lookahead: &str, out: &mut String) {
    while index < line.len() {
        if line.as_bytes().get(index) != Some(&b'`') {
            let ch = next_char(line, index);
            out.push(ch);
            index += ch.len_utf8();
            continue;
        }
        let opener = backtick_run_len(line, index);
        let content_at = index + opener;
        if let Some(end) = find_code_span_end(line, content_at, opener) {
            push_spaces(out, line, index, end);
            index = end;
        } else if find_code_span_end(lookahead, 0, opener).is_some() {
            push_spaces(out, line, index, line.len());
            *open = Some(opener);
            break;
        } else {
            out.extend(std::iter::repeat_n('`', opener));
            index = content_at;
        }
    }
}

/// Append `line[start..end]` as spaces, counted in characters.
fn push_spaces(out: &mut String, line: &str, start: usize, end: usize) {
    for ch in line.get(start..end).unwrap_or("").chars() {
        out.push(if ch == '\n' { '\n' } else { ' ' });
    }
}

/// Blank HTML comments and remember one that has not closed yet.
fn mask_html_comments(line: &str, open: &mut HtmlSpan) -> String {
    let mut out = String::with_capacity(line.len());
    let index = mask_open_comment(line, open, &mut out);
    if index < line.len() {
        mask_new_comments(line, index, open, &mut out);
    }
    out
}

/// Blank a comment carried in from an earlier line. Returns the resume index.
fn mask_open_comment(line: &str, open: &mut HtmlSpan, out: &mut String) -> usize {
    if *open != HtmlSpan::Open {
        return 0;
    }
    if let Some(end) = comment_end(line, 0) {
        push_spaces(out, line, 0, end);
        *open = HtmlSpan::Closed;
        end
    } else {
        push_spaces(out, line, 0, line.len());
        line.len()
    }
}

/// Blank comments that open at or after `index`.
fn mask_new_comments(line: &str, mut index: usize, open: &mut HtmlSpan, out: &mut String) {
    while index < line.len() {
        if !starts_with_at(line, index, "<!--") {
            let ch = next_char(line, index);
            out.push(ch);
            index += ch.len_utf8();
            continue;
        }
        if let Some(end) = comment_end(line, index + 4) {
            push_spaces(out, line, index, end);
            index = end;
        } else {
            push_spaces(out, line, index, line.len());
            *open = HtmlSpan::Open;
            break;
        }
    }
}

/// Byte index just past `-->`, searching from `from`.
fn comment_end(line: &str, from: usize) -> Option<usize> {
    line.get(from..)?.find("-->").map(|at| from + at + 3)
}

/// Whether `line` at `index` begins with `needle`.
fn starts_with_at(line: &str, index: usize, needle: &str) -> bool {
    line.get(index..).is_some_and(|rest| rest.starts_with(needle))
}

/// The character at `index`, or a space when `index` is out of range.
fn next_char(line: &str, index: usize) -> char {
    line.get(index..).and_then(|rest| rest.chars().next()).unwrap_or(' ')
}

/// Byte length of the maximal backtick run starting at `at`.
fn backtick_run_len(line: &str, at: usize) -> usize {
    line.get(at..)
        .map_or(0, |rest| rest.bytes().take_while(|b| *b == b'`').count())
}

/// Byte offset just past a closing run of exactly `opener` backticks.
fn find_code_span_end(line: &str, mut pos: usize, opener: usize) -> Option<usize> {
    while pos < line.len() {
        if line.as_bytes().get(pos).copied() == Some(b'`') {
            let run = backtick_run_len(line, pos);
            if run == opener {
                return Some(pos + run);
            }
            pos += run;
            continue;
        }
        let ch = line.get(pos..)?.chars().next()?;
        pos += ch.len_utf8();
    }
    None
}

/// Return the content up to the matching unescaped `)`.
///
/// A parenthesis preceded by `\` does not change nesting. Returns `None`
/// when no closing paren is found.
fn balanced_paren(s: &str) -> Option<&str> {
    let mut depth: u32 = 1;
    let mut escaped = false;
    for (i, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
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

/// Remove backslashes that escape ASCII punctuation, so `foo\(1\).md` resolves as `foo(1).md`.
fn unescape_punctuation(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\'
            && chars.peek().is_some_and(char::is_ascii_punctuation)
            && let Some(punct) = chars.next()
        {
            out.push(punct);
            continue;
        }
        out.push(ch);
    }
    out
}

/// Whether a link target is a relative local path (not a URL, not
/// anchor-only). Covers all extensions and directories.
fn is_relative_local_link(target: &str) -> bool {
    let dest = strip_angle_brackets(strip_title(target));
    if dest.is_empty() || dest.starts_with('#') || dest.starts_with("//") {
        return false;
    }
    !has_uri_scheme(dest)
}

/// Whether `dest` begins with a scheme such as `https:` or `mailto:`.
fn has_uri_scheme(dest: &str) -> bool {
    let Some((scheme, _)) = dest.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic() && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
}

/// Return the destination portion of a link target, stripping an optional
/// quoted title such as `"Read more"` or `'tooltip'`, or a parenthesized
/// title whose `(` is preceded by whitespace.
fn strip_title(target: &str) -> &str {
    let t = target.trim_end();
    strip_quoted_title(t).or_else(|| strip_paren_title(t)).unwrap_or(t)
}

/// Strip a trailing `"..."` or `'...'` title.
fn strip_quoted_title(t: &str) -> Option<&str> {
    for quote in ['"', '\''] {
        if !t.ends_with(quote) {
            continue;
        }
        let dest = t
            .get(..t.len() - 1)
            .and_then(|before| before.rfind(quote))
            .and_then(|pos| t.get(..pos))
            .filter(|dest| dest.ends_with(char::is_whitespace));
        if let Some(dest) = dest {
            return Some(dest.trim_end());
        }
    }
    None
}

/// Strip a trailing `(title)` only when `(` is preceded by whitespace.
fn strip_paren_title(t: &str) -> Option<&str> {
    if !t.ends_with(')') {
        return None;
    }
    let mut end = t.len();
    while let Some(pos) = t.get(..end)?.rfind('(') {
        let preceded_by_ws = t.get(..pos)?.chars().next_back().is_some_and(char::is_whitespace);
        if preceded_by_ws {
            return t.get(..pos).map(str::trim_end);
        }
        end = pos;
    }
    None
}

/// Strip surrounding angle brackets from a destination
/// such as `<docs/foo.md>` or `<docs/foo.md#frag>`.
fn strip_angle_brackets(dest: &str) -> &str {
    let t = dest.trim();
    t.strip_prefix('<')
        .and_then(|inner| inner.strip_suffix('>'))
        .map_or(t, str::trim)
}

/// Split a link target into the file path and an optional `#fragment`.
fn split_fragment(target: &str) -> (&str, Option<&str>) {
    match target.find('#') {
        Some(pos) => (target.get(..pos).unwrap_or(target), target.get(pos + 1..)),
        None => (target, None),
    }
}

/// Drop a `?query` from the path portion so `guide.md?plain=1` resolves to `guide.md`.
fn strip_query(file_part: &str) -> &str {
    file_part.split_once('?').map_or(file_part, |(path, _)| path)
}

// -----------------------------------------------------------------------------
// File Collection
// -----------------------------------------------------------------------------

/// Recursively collect all `.md` files under `dir`.
///
/// Symlinked directories are not walked, so an alias to an ancestor cannot
/// rescan the tree. Symlinked Markdown files are collected.
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
        let path = entry.path();
        if ft.is_dir() {
            collect_markdown(&path, out);
        } else if !symlink_dir(ft, &path) && path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
}

/// Whether `path` is a symlink whose target is a directory.
fn symlink_dir(ft: std::fs::FileType, path: &Path) -> bool {
    ft.is_symlink() && path.is_dir()
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
        assert!(!is_relative_local_link("//example.com/a.md"));
        assert!(!is_relative_local_link("mailto:x@y.com"));
        assert!(!is_relative_local_link("ftp:notes.md"));
        assert!(!is_relative_local_link("git+ssh:repo"));
        assert!(!is_relative_local_link("data:text/plain,hi"));
        assert!(!is_relative_local_link("data:text/markdown,foo.md"));
        assert!(!is_relative_local_link(""));
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
        assert_eq!(strip_title("foo.md (Read more)"), "foo.md");
        assert_eq!(strip_title("foo.md\t(title)"), "foo.md");
        assert_eq!(strip_title("foo(1).md"), "foo(1).md");
        assert_eq!(strip_title("foo(1).md)"), "foo(1).md)");
        assert_eq!(strip_title("x\"y\""), "x\"y\"");
    }

    #[test]
    fn strip_angle_brackets_works() {
        assert_eq!(strip_angle_brackets("<foo.md>"), "foo.md");
        assert_eq!(strip_angle_brackets("<foo.md#frag>"), "foo.md#frag");
        assert_eq!(strip_angle_brackets("foo.md"), "foo.md");
        assert_eq!(strip_angle_brackets("<https://example.com>"), "https://example.com");
    }

    #[test]
    fn angled_destination_resolves_without_brackets() {
        let root = workspace_root();
        let content = "See [guide](<docs/architecture/pipeline-concepts.md>) here.\n";
        let mut broken = Vec::new();
        check_file_links(content, &root, &root, "test.md", &mut broken);
        assert!(
            broken.is_empty(),
            "angle-bracket destination should resolve: {broken:?}"
        );
    }

    #[test]
    fn angled_destination_with_fragment_still_splits() {
        let dest = strip_angle_brackets("<foo.md#section>");
        let (file, frag) = split_fragment(dest);
        assert_eq!(file, "foo.md");
        assert_eq!(frag, Some("section"));
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
    fn query_is_stripped_before_resolve() {
        let root = workspace_root();
        let content = "See [guide](docs/architecture/pipeline-concepts.md?plain=1) here.\n";
        let mut broken = Vec::new();
        check_file_links(content, &root, &root, "test.md", &mut broken);
        assert!(broken.is_empty(), "query should not be part of the path: {broken:?}");
    }

    #[test]
    fn query_with_fragment_keeps_file_path() {
        let (file, frag) = split_fragment("guide.md?plain=1#section");
        assert_eq!(strip_query(file), "guide.md");
        assert_eq!(frag, Some("section"));
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
    fn balanced_paren_ignores_escaped() {
        assert_eq!(balanced_paren(r"foo\(1\).md)rest"), Some(r"foo\(1\).md"));
    }

    #[test]
    fn unescape_punctuation_removes_escaped_parens() {
        assert_eq!(unescape_punctuation(r"foo\(1\).md"), "foo(1).md");
        assert_eq!(unescape_punctuation("foo.md"), "foo.md");
    }

    #[test]
    fn escaped_parens_resolve_to_filename() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path();
        std::fs::write(dir.join("foo(1).md"), "x").unwrap();
        let content = "See [f](foo\\(1\\).md) here.\n";
        let mut broken = Vec::new();
        check_file_links(content, dir, dir, "test.md", &mut broken);
        assert!(broken.is_empty(), "escaped parens should resolve: {broken:?}");
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
    fn longer_backtick_run_does_not_close_span() {
        let links = extract_md_links("`[hidden](missing.md)```still` [real](real.md)");
        assert_eq!(links, ["real.md"]);
    }

    #[test]
    fn backtick_run_suffix_does_not_close_span() {
        let links = extract_md_links("``[hidden](missing.md)```no`` [real](real.md)");
        assert_eq!(links, ["real.md"]);
    }

    #[test]
    fn multibyte_code_span_leaves_following_link() {
        let links = extract_md_links("`café` [real](real.md)");
        assert_eq!(links, ["real.md"]);
    }

    #[test]
    fn inline_code_links_are_skipped() {
        let links = extract_md_links("see `[example](missing.md)` in code and [real](real.md) outside");
        assert_eq!(links, ["real.md"]);
    }

    #[test]
    fn inline_code_label_destination_is_checked() {
        let content = "See [`code`](missing.md) here.\n";
        let mut broken = Vec::new();
        let dir = Path::new("/tmp");
        check_file_links(content, dir, dir, "test.md", &mut broken);
        assert_eq!(
            broken.len(),
            1,
            "inline-code label must not hide the destination: {broken:?}"
        );
        assert!(broken[0].2.contains("missing.md"));
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
    fn multiline_missing_destination_is_reported() {
        let content = "See [missing](\nmissing.md) here.\n";
        let mut broken = Vec::new();
        let dir = Path::new("/tmp");
        check_file_links(content, dir, dir, "test.md", &mut broken);
        assert_eq!(broken.len(), 1, "multiline destination should be reported: {broken:?}");
        assert!(broken[0].2.contains("missing.md"));
    }

    #[test]
    fn multiline_link_inside_fence_is_ignored() {
        let content = "```\n[missing](\nmissing.md)\n```\n[real](real.md)\n";
        let mut broken = Vec::new();
        let dir = Path::new("/tmp");
        check_file_links(content, dir, dir, "test.md", &mut broken);
        let targets: Vec<&str> = broken.iter().map(|(_, _, t)| t.as_str()).collect();
        assert_eq!(targets, ["real.md"]);
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
    fn collects_symlinked_markdown_but_not_symlinked_dirs() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let docs = tmp.path().join("docs");
        let nested = docs.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(docs.join("real.md"), "x").unwrap();
        std::fs::write(nested.join("inner.md"), "y").unwrap();
        std::os::unix::fs::symlink(docs.join("real.md"), docs.join("link.md")).unwrap();
        std::os::unix::fs::symlink(&nested, docs.join("linkdir")).unwrap();

        let mut files = Vec::new();
        collect_markdown(&docs, &mut files);

        let names: Vec<_> = files.iter().map(|p| p.file_name().unwrap().to_owned()).collect();
        assert!(names.contains(&std::ffi::OsString::from("real.md")));
        assert!(names.contains(&std::ffi::OsString::from("link.md")));
        assert_eq!(names.iter().filter(|n| *n == "inner.md").count(), 1);
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

    fn broken_targets(content: &str) -> Vec<String> {
        let mut broken = Vec::new();
        let dir = Path::new("/tmp");
        check_file_links(content, dir, dir, "test.md", &mut broken);
        broken.into_iter().map(|(_, _, target)| target).collect()
    }

    #[test]
    fn inline_code_span_carries_across_lines() {
        let content = "\
`[hidden](hidden.md)`
[shown](shown.md)

`[missing](missing.md)

still`
[real](real.md)
";
        assert_eq!(broken_targets(content), ["shown.md", "real.md"]);
    }

    #[test]
    fn indented_code_does_not_hide_the_next_line() {
        let content = "intro\n\n    ```\n    [fake](fake.md)\n[real](real.md)\n";
        assert_eq!(broken_targets(content), ["real.md"]);
    }

    #[test]
    fn list_continuation_is_checked_and_indented_code_is_not() {
        let content = "\
- item

      [fake](fake.md)
    [real](real.md)
";
        assert_eq!(broken_targets(content), ["real.md"]);
    }

    #[test]
    fn fence_nested_in_list_item_is_recognized() {
        let content = "\
- item
  ```
  [fake](fake.md)
  ```
[real](real.md)
";
        assert_eq!(broken_targets(content), ["real.md"]);
    }

    #[test]
    fn unquoted_link_after_quoted_fence_is_checked() {
        let content = "\
> ```
> [fake](fake.md)
> ```
[real](real.md)
";
        assert_eq!(broken_targets(content), ["real.md"]);
    }

    #[test]
    fn outer_quote_link_after_nested_fence_is_checked() {
        let content = "\
> > ```
> > [fake](fake.md)
> [outer](outer.md)
> > [after](after.md)
";
        assert_eq!(broken_targets(content), ["outer.md", "after.md"]);
    }

    #[test]
    fn normalized_path_outside_root_is_broken() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let base = tmp.path();
        let docs = base.join("docs");
        let nested = docs.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(docs.join("guide.md"), "x").unwrap();
        std::fs::write(base.join("outside.md"), "x").unwrap();

        let mut outside = Vec::new();
        let escaped = "See [out](../outside.md) and [abs](/../outside.md).\n";
        check_file_links(escaped, &docs, &docs, "test.md", &mut outside);

        let mut inside = Vec::new();
        let kept = "See [rel](../guide.md) and [abs](/guide.md) and [dot](../nested/../guide.md).\n";
        check_file_links(kept, &docs, &nested, "test.md", &mut inside);

        assert_eq!(outside.len(), 2, "escaped paths are broken: {outside:?}");
        assert!(inside.is_empty(), "in-root paths stay valid: {inside:?}");
    }

    #[test]
    fn reference_definition_targets_are_checked() {
        let content = "\
[inline](inline.md)

[label]: defined.md
[later]:
missing.md
```
[hidden]: secret.md
```
[url]: https://example.com/a
";
        assert_eq!(broken_targets(content), ["inline.md", "defined.md", "missing.md"]);
    }

    #[test]
    fn html_comment_is_not_a_link() {
        let links = extract_md_links("<!-- [hidden](hidden.md) --> [real](real.md)");
        assert_eq!(links, ["real.md"]);
    }

    #[test]
    fn html_comment_hides_links_across_lines() {
        let content = [
            "<!-- [hidden](hidden.md) -->",
            "[shown](shown.md)",
            "",
            "<!--",
            "[missing](missing.md)",
            "[label]: hidden.md",
            "",
            "still -->",
            "[real](real.md)",
        ]
        .join("\n");
        assert_eq!(broken_targets(&content), ["shown.md", "real.md"]);
    }

    #[test]
    fn html_comment_markers_in_code_stay_literal() {
        let fenced = "```\n<!-- [fake](fake.md)\n```\n[real](real.md)\n";
        assert_eq!(broken_targets(fenced), ["real.md"]);
        let inline = "`<!--` [real](real.md)\n";
        assert_eq!(broken_targets(inline), ["real.md"]);
    }

    #[test]
    fn bare_or_escaped_brackets_are_not_links() {
        assert!(extract_md_links("](missing.md) and \\](missing.md)").is_empty());
        assert_eq!(extract_md_links("[real](real.md)"), ["real.md"]);
    }

    #[test]
    fn unmatched_backtick_does_not_hide_later_links() {
        assert_eq!(broken_targets("`[real](real.md)\n"), ["real.md"]);
    }

    #[test]
    fn broken_link_uses_its_physical_line() {
        let content = "intro [first](first.md)\ncontinues [second](second.md)\n";
        let mut broken = Vec::new();
        let dir = Path::new("/tmp");
        check_file_links(content, dir, dir, "test.md", &mut broken);
        let lines: Vec<_> = broken
            .iter()
            .map(|(_, line, target)| (*line, target.as_str()))
            .collect();
        assert_eq!(lines, [(1, "first.md"), (2, "second.md")]);
    }

    #[test]
    fn definition_after_prose_is_not_a_definition() {
        let content = "See the note\n[label]: missing.md\n\n[label]: also.md\n";
        assert_eq!(broken_targets(content), ["also.md"]);
    }

    #[test]
    fn angled_reference_destination_may_contain_spaces() {
        assert_eq!(broken_targets("[guide]: <missing guide.md>\n"), ["<missing guide.md>"]);
    }

    #[test]
    fn escaped_hash_still_finds_the_file() {
        let tmp = tempfile::tempdir().expect("temp dir");
        std::fs::write(tmp.path().join("guide.md"), "x").unwrap();
        let mut broken = Vec::new();
        let content = "See [g](guide.md\\#section) and [q](guide.md\\?plain=1).\n";
        check_file_links(content, tmp.path(), tmp.path(), "test.md", &mut broken);
        assert!(broken.is_empty(), "{broken:?}");
    }

    #[test]
    fn tab_indented_code_is_skipped() {
        assert_eq!(
            broken_targets("intro\n\n\t[fake](fake.md)\n[real](real.md)\n"),
            ["real.md"]
        );
    }

    #[test]
    fn nested_list_continuation_is_not_indented_code() {
        let content = "- item\n\n    - nested\n\n      [real](real.md)\n";
        assert_eq!(broken_targets(content), ["real.md"]);
    }

    #[test]
    fn fence_ends_when_its_list_ends() {
        let content = "- item\n  ```\n  [fake](fake.md)\n[real](real.md)\n";
        assert_eq!(broken_targets(content), ["real.md"]);
    }

    #[test]
    fn unindented_fence_after_list_is_top_level() {
        let content = "- item\n```\n[fake](fake.md)\n```\n[real](real.md)\n";
        assert_eq!(broken_targets(content), ["real.md"]);
    }

    #[test]
    fn indented_backticks_do_not_close_a_fence() {
        let content = "```\n    ```\n[fake](fake.md)\n```\n[real](real.md)\n";
        assert_eq!(broken_targets(content), ["real.md"]);
    }

    #[test]
    fn raw_html_block_hides_links_until_it_ends() {
        let div = "<div>\n[fake](fake.md)\n</div>\n\n[real](real.md)\n";
        assert_eq!(broken_targets(div), ["real.md"]);
        let script = "<script>\n[fake](fake.md)\n</script>\n[real](real.md)\n";
        assert_eq!(broken_targets(script), ["real.md"]);
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
