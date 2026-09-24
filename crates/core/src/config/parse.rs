// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! YAML input safety checks: size limits and alias bomb guards.
//!
//! Prevents denial-of-service via crafted YAML by enforcing a raw
//! file size ceiling (`MAX_YAML_BYTES`, 4 MiB) and by rejecting YAML
//! alias nodes (`*anchor`) before the document is parsed. Aliases are
//! the mechanism behind "billion laughs" expansion, and a post-parse
//! size check cannot help: the expansion happens *inside* the parser,
//! so the memory blowup is already done by the time the result can be
//! measured. Praxis configs do not use YAML anchors/aliases, so
//! rejecting alias nodes up front removes the expansion vector entirely
//! without affecting any real configuration. (Anchors without a
//! matching alias expand nothing and are left alone.)

use std::{io::Read as _, path::Path};

use crate::errors::ProxyError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum raw YAML input size (4 MiB).
const MAX_YAML_BYTES: usize = 4_194_304;

/// Byte ceiling for reading a config file: `MAX_YAML_BYTES` plus one.
///
/// Reading one byte past the maximum lets a file exactly at the limit load
/// fully while anything larger is detected and rejected by
/// [`check_yaml_size`] rather than read without bound. A special file such
/// as `/dev/zero` reports size 0 to `metadata()`, so the metadata ceiling
/// alone cannot stop it; the bounded read is what actually neutralizes it.
const MAX_YAML_READ_BYTES: u64 = 4_194_305; // MAX_YAML_BYTES + 1

// -----------------------------------------------------------------------------
// Safety Checks
// -----------------------------------------------------------------------------

/// Reject a config file whose on-disk size exceeds `MAX_YAML_BYTES`.
///
/// Checks file metadata before reading, preventing memory exhaustion
/// from oversized files.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] when the file is too large or its
/// metadata cannot be read.
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
pub(crate) fn check_file_size(path: &Path) -> Result<(), ProxyError> {
    let meta = std::fs::metadata(path).map_err(|err| {
        let display = path.display();
        ProxyError::Config(format!("failed to read metadata for {display}: {err}"))
    })?;

    // Reject non-regular files (character devices, FIFOs, sockets,
    // directories). A `/dev/zero` or FIFO reports size 0 and would otherwise
    // pass the ceiling below and then be read without bound. `metadata()`
    // follows symlinks, so a symlink to a regular file still passes.
    if !meta.is_file() {
        let display = path.display();
        return Err(ProxyError::Config(format!(
            "config path {display} is not a regular file"
        )));
    }

    let len = meta.len();
    if len > MAX_YAML_READ_BYTES {
        return Err(ProxyError::Config(format!(
            "config file too large ({len} bytes, max {MAX_YAML_BYTES})"
        )));
    }
    Ok(())
}

/// Read a config file safely into a string.
///
/// Rejects non-regular files and caps the number of bytes read at
/// `MAX_YAML_READ_BYTES`, so a special file (e.g. `/dev/zero`) or a
/// symlink to one cannot exhaust memory. Used by both the initial load and
/// the hot-reload path.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] when the path is not a regular file, is
/// too large, or cannot be read.
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
pub fn read_config_file(path: &Path) -> Result<String, ProxyError> {
    check_file_size(path)?;
    let file = std::fs::File::open(path).map_err(|err| {
        let display = path.display();
        ProxyError::Config(format!("failed to read {display}: {err}"))
    })?;
    let mut content = String::new();
    file.take(MAX_YAML_READ_BYTES)
        .read_to_string(&mut content)
        .map_err(|err| {
            let display = path.display();
            ProxyError::Config(format!("failed to read {display}: {err}"))
        })?;
    Ok(content)
}

/// Reject raw YAML input that exceeds `MAX_YAML_BYTES`.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] when the input is too large.
///
/// ```ignore
/// use praxis_core::config::check_yaml_safety;
///
/// let small = "listeners: []";
/// check_yaml_safety(small).unwrap();
/// ```
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
pub(crate) fn check_yaml_safety(raw: &str) -> Result<(), ProxyError> {
    check_yaml_size(raw)?;
    reject_yaml_aliases(raw)
}

/// Reject raw YAML that exceeds the size limit.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] when the input exceeds `MAX_YAML_BYTES`.
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
fn check_yaml_size(raw: &str) -> Result<(), ProxyError> {
    if raw.len() > MAX_YAML_BYTES {
        return Err(ProxyError::Config(format!(
            "YAML input too large ({} bytes, max {MAX_YAML_BYTES})",
            raw.len()
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Alias Scanning
// -----------------------------------------------------------------------------

/// Reject YAML alias nodes (`*anchor`) before parsing.
///
/// Aliases drive "billion laughs" expansion, and the blowup happens
/// during `from_str` — so this must run before any parse. Praxis
/// configs never use aliases, so any alias node is rejected outright.
///
/// The scan is quote- and comment-aware so that a `*` inside a string
/// scalar (e.g. `pattern: "a*"`) or a `#` comment is not mistaken for
/// an alias. An alias node is a `*` at a value/node boundary followed
/// by an anchor-name character.
///
/// A quoted scalar may continue onto the next line, but a line that
/// merely looks like it opens one may be block-scalar text. So each
/// line is scanned from every quote state the previous line could have
/// left open, and any reading that finds an alias rejects the input.
/// A reading is never retired early: libyaml continues a flow quoted
/// scalar at any indentation. The cost is that an unbalanced quote in
/// block-scalar text can make a later `*name` inside a string look like
/// an alias, which rejects that config rather than admitting a bomb.
///
/// `?` is treated as a node boundary in block context too, where
/// libyaml only reads it as a key indicator when a blank follows, so a
/// plain scalar such as `url: http://h/?*x` is rejected as well: a
/// fail-closed false positive.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] when an alias node is present.
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
fn reject_yaml_aliases(raw: &str) -> Result<(), ProxyError> {
    let mut open_quotes: Vec<u8> = Vec::new();
    for (idx, numbered_line) in raw.split('\n').enumerate() {
        for line in numbered_line.split(is_yaml_line_break) {
            let mut still_open = Vec::new();
            for start in std::iter::once(None).chain(open_quotes.iter().copied().map(Some)) {
                match scan_line(line, start) {
                    LineScan::Alias => {
                        return Err(ProxyError::Config(format!(
                            "YAML alias nodes (`*anchor`) are not supported (line {}); \
                             they enable alias-expansion denial-of-service and are not used by any Praxis config",
                            idx.saturating_add(1)
                        )));
                    },
                    LineScan::Clean {
                        open_quote: Some(quote),
                    } if !still_open.contains(&quote) => still_open.push(quote),
                    LineScan::Clean { .. } => {},
                }
            }
            open_quotes = still_open;
        }
    }
    Ok(())
}

/// Whether `ch` ends a line for libyaml, which also breaks on CR, NEL,
/// LS, and PS; `\n` is split on first so line numbers stay accurate.
fn is_yaml_line_break(ch: char) -> bool {
    matches!(ch, '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// Result of scanning one line from a given starting quote state.
enum LineScan {
    /// An alias node appears outside strings and comments.
    Alias,

    /// No alias; `open_quote` is the quote still open at the end of the line.
    Clean {
        /// Quote character left open, if any.
        open_quote: Option<u8>,
    },
}

/// Scan one line for an alias node, starting inside `start_quote` when
/// the previous line may have left a quoted scalar open.
///
/// A false positive from a `*` inside a block scalar only rejects an
/// unusual config, never admits a bomb.
fn scan_line(line: &str, start_quote: Option<u8>) -> LineScan {
    let (mut at_boundary, mut prev_ws) = (start_quote.is_none(), true);
    let mut quote = start_quote;
    let (mut prev_star, mut escaped) = (false, false);
    for &byte in line.as_bytes() {
        // An alias node is `*` at a node boundary followed by an
        // anchor-name character; check the char after a boundary `*`.
        // libyaml accepts `-` anywhere in an anchor name, including first.
        if prev_star && (byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-') {
            return LineScan::Alias;
        }
        prev_star = false;
        if let Some(quote_char) = quote {
            let close = byte == quote_char && !escaped;
            escaped = quote_char == b'"' && byte == b'\\' && !escaped;
            quote = (!close).then_some(quote_char);
            at_boundary = false;
        } else {
            match byte {
                // A comment only starts after whitespace (or line start);
                // a mid-scalar `#` (e.g. `a#b`) is scalar content.
                b'#' if prev_ws => return LineScan::Clean { open_quote: None },
                // A quoted scalar only starts at a node boundary; a
                // mid-scalar quote (e.g. `don't`) is scalar content.
                b'\'' | b'"' if at_boundary => (quote, at_boundary) = (Some(byte), false),
                b'*' if at_boundary => prev_star = true,
                _ => at_boundary = matches!(byte, b' ' | b'\t' | b'[' | b'{' | b',' | b':' | b'-' | b'?'),
            }
        }
        prev_ws = matches!(byte, b' ' | b'\t');
    }
    LineScan::Clean { open_quote: quote }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn reject_oversized_yaml() {
        let huge = "x".repeat(5 * 1024 * 1024);
        let err = check_yaml_size(&huge).unwrap_err();
        assert!(err.to_string().contains("too large"), "should reject oversized YAML");
    }

    #[test]
    fn accept_small_yaml() {
        check_yaml_size("a: 1\n").expect("small YAML should pass size check");
    }

    #[test]
    fn read_config_file_reads_regular_file() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("praxis.yaml");
        std::fs::write(&path, "listeners: []\n").expect("write config");
        let content = read_config_file(&path).expect("regular file should read");
        assert_eq!(content, "listeners: []\n", "content should round-trip");
    }

    #[test]
    fn read_config_file_rejects_non_regular_file() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let err = read_config_file(dir.path()).expect_err("non-regular file must be rejected");
        assert!(
            err.to_string().contains("not a regular file"),
            "error should name the non-regular-file cause, got: {err}"
        );
    }

    #[test]
    fn check_file_size_rejects_directory() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let err = check_file_size(dir.path()).expect_err("directory must be rejected");
        assert!(
            err.to_string().contains("not a regular file"),
            "error should name the non-regular-file cause, got: {err}"
        );
    }

    #[test]
    fn reject_yaml_alias_bomb() {
        let err = reject_yaml_aliases("a: &a x\nb: &b [*a,*a,*a]\nlisteners: []\n");
        assert!(err.is_err(), "should reject alias nodes before parsing");
        assert!(
            err.unwrap_err().to_string().contains("alias nodes"),
            "error message should mention alias nodes"
        );
    }

    #[test]
    fn reject_single_alias() {
        let err = reject_yaml_aliases("a: &a x\nb: *a\nlisteners: []\n");
        assert!(err.is_err(), "any alias node should be rejected");
    }

    #[test]
    fn reject_alias_with_leading_hyphen() {
        let err = reject_yaml_aliases("a: &-x 1\nb: *-x\nlisteners: []\n");
        assert!(
            err.is_err(),
            "an alias whose anchor name starts with '-' must be rejected"
        );
    }

    #[test]
    fn accept_anchor_without_alias() {
        reject_yaml_aliases("a: &a x\nlisteners: []\n").expect("unused anchor should pass");
    }

    #[test]
    fn accept_asterisk_in_string_and_comment() {
        reject_yaml_aliases("pattern: \"a*b\"\nglob: '*.txt'\nnote: ok # *not an alias\n")
            .expect("asterisks in strings/comments are not alias nodes");
    }

    #[test]
    fn accept_bare_asterisk_value() {
        reject_yaml_aliases("wildcard: /*\n").expect("glob-like value should pass");
    }

    #[test]
    fn reject_alias_after_mid_scalar_apostrophe() {
        let err = reject_yaml_aliases("a: &a x\nb: [don't, *a]\n");
        assert!(err.is_err(), "alias after mid-scalar apostrophe should be rejected");
    }

    #[test]
    fn reject_alias_after_unindented_flow_quote_continuation() {
        let err = reject_yaml_aliases("x: &x 1\nk: ['a\n', *x]\n");
        assert!(
            err.is_err(),
            "libyaml continues a flow quoted scalar at any indentation, so the alias after it must be caught"
        );
    }

    #[test]
    fn reject_alias_after_mid_scalar_hash() {
        let err = reject_yaml_aliases("a: &a x\nb: [a#b, *a]\n");
        assert!(err.is_err(), "alias after mid-scalar hash should be rejected");
    }

    #[test]
    fn accept_escaped_quote_in_double_quoted_scalar() {
        reject_yaml_aliases("k: \"a\\\" *not-an-alias b\"\n").expect("escaped quote should not end the string");
    }

    #[test]
    fn safety_check_rejects_oversized() {
        let huge = "x".repeat(5 * 1024 * 1024);
        let err = check_yaml_safety(&huge).unwrap_err();
        assert!(err.to_string().contains("too large"), "should reject oversized YAML");
    }

    #[test]
    fn accept_yaml_at_exact_max_size() {
        let exact = "x".repeat(MAX_YAML_BYTES);
        check_yaml_size(&exact).expect("YAML at exactly MAX_YAML_BYTES should pass");
    }

    #[test]
    fn reject_yaml_one_byte_over_max() {
        let over = "x".repeat(MAX_YAML_BYTES + 1);
        let err = check_yaml_size(&over).unwrap_err();
        assert!(err.to_string().contains("too large"), "got: {err}");
    }

    #[test]
    fn safety_check_passes_valid_yaml() {
        check_yaml_safety("a: 1\n").expect("valid small YAML should pass all safety checks");
    }

    #[test]
    fn alias_check_ignores_unparseable_non_alias_yaml() {
        reject_yaml_aliases("{{{{invalid yaml").expect("non-alias garbage passes the alias check");
    }

    #[test]
    fn alias_line_number_reported() {
        let err = reject_yaml_aliases("listeners: []\nfoo: bar\nbomb: *a\n").unwrap_err();
        assert!(err.to_string().contains("line 3"), "got: {err}");
    }

    #[test]
    fn check_file_size_nonexistent_file() {
        let path = Path::new("/nonexistent/path/to/file.yaml");
        let err = check_file_size(path).unwrap_err();
        assert!(
            err.to_string().contains("failed to read metadata"),
            "error should mention metadata failure, got: {err}"
        );
    }

    #[test]
    fn read_config_file_nonexistent() {
        let path = Path::new("/nonexistent/path/to/file.yaml");
        let err = read_config_file(path).unwrap_err();
        assert!(
            err.to_string().contains("failed to read metadata") || err.to_string().contains("failed to read"),
            "error should mention read failure, got: {err}"
        );
    }

    #[test]
    fn read_config_file_oversized() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("huge.yaml");
        let huge_content = "x".repeat(5 * 1024 * 1024);
        std::fs::write(&path, huge_content).expect("write huge file");

        let err = read_config_file(&path).expect_err("oversized file should be rejected");
        assert!(
            err.to_string().contains("too large"),
            "error should mention size limit, got: {err}"
        );
    }

    #[test]
    fn reject_alias_on_first_line() {
        let err = reject_yaml_aliases("bomb: *anchor\nlisteners: []\n");
        assert!(err.is_err(), "alias on first line should be rejected");
        let err_msg = err.unwrap_err().to_string();
        assert!(
            err_msg.contains("line 1"),
            "error should reference line 1, got: {err_msg}"
        );
    }

    #[test]
    fn reject_alias_on_last_line() {
        let err = reject_yaml_aliases("listeners: []\nfoo: bar\nlast: *ref");
        assert!(err.is_err(), "alias on last line should be rejected");
    }

    #[test]
    fn reject_multiple_aliases_same_line() {
        let err = reject_yaml_aliases("a: &a x\nb: [*a, *a, *a]\n");
        assert!(err.is_err(), "multiple aliases on same line should be rejected");
    }

    #[test]
    fn accept_asterisk_after_colon() {
        reject_yaml_aliases("url: http://*\n").expect("asterisk after colon in URL should pass");
    }

    #[test]
    fn accept_asterisk_in_bracket() {
        reject_yaml_aliases("patterns: [*.txt, *.md]\n").expect("asterisk in array should pass");
    }

    #[test]
    fn reject_alias_after_comma() {
        let err = reject_yaml_aliases("a: &a x\nb: [foo, *a]\n");
        assert!(err.is_err(), "alias after comma should be rejected");
    }

    #[test]
    fn reject_alias_after_bracket() {
        let err = reject_yaml_aliases("a: &a x\nb: [*a]\n");
        assert!(err.is_err(), "alias after opening bracket should be rejected");
    }

    #[test]
    fn reject_alias_after_brace() {
        let err = reject_yaml_aliases("a: &a x\nb: {key: *a}\n");
        assert!(err.is_err(), "alias after opening brace should be rejected");
    }

    #[test]
    fn reject_alias_after_dash() {
        let err = reject_yaml_aliases("a: &a x\nlist:\n  - *a\n");
        assert!(err.is_err(), "alias after dash should be rejected");
    }

    #[test]
    fn accept_single_quoted_asterisk() {
        reject_yaml_aliases("pattern: '*'\n").expect("single-quoted asterisk should pass");
    }

    #[test]
    fn accept_double_quoted_asterisk() {
        reject_yaml_aliases("pattern: \"*\"\n").expect("double-quoted asterisk should pass");
    }

    #[test]
    fn accept_asterisk_with_spaces() {
        reject_yaml_aliases("glob: * .txt\n").expect("asterisk followed by space should pass (not anchor name)");
    }

    #[test]
    fn reject_alias_with_underscore() {
        let err = reject_yaml_aliases("a: &my_anchor x\nb: *my_anchor\n");
        assert!(err.is_err(), "alias with underscore should be rejected");
    }

    #[test]
    fn reject_alias_with_digits() {
        let err = reject_yaml_aliases("a: &anchor123 x\nb: *anchor123\n");
        assert!(err.is_err(), "alias with digits should be rejected");
    }

    #[test]
    fn accept_asterisk_before_non_anchor_char() {
        reject_yaml_aliases("math: 2 * 3\n").expect("asterisk before space should pass");
        reject_yaml_aliases("glob: *.\n").expect("asterisk before dot should pass (not alphanumeric or underscore)");
    }

    #[test]
    fn reject_alias_at_line_start() {
        let err = reject_yaml_aliases("a: &a x\n*a\n");
        assert!(err.is_err(), "alias at line start should be rejected");
    }

    #[test]
    fn accept_double_asterisk_glob() {
        reject_yaml_aliases("pattern: '**/*.txt'\n").expect("double asterisk in glob pattern should pass");
    }

    #[test]
    fn accept_escaped_backslash_in_double_quote() {
        reject_yaml_aliases("path: \"C:\\\\*\"\n").expect("escaped backslash with asterisk should pass");
    }

    #[test]
    fn accept_multiple_quotes_same_line() {
        reject_yaml_aliases("a: \"x\" b: 'y' c: \"*\"\n").expect("multiple quoted values with asterisk should pass");
    }

    #[test]
    fn accept_comment_with_asterisk_after_whitespace() {
        reject_yaml_aliases("key: value  # *not an alias\n").expect("asterisk in comment after spaces should pass");
    }

    #[test]
    fn accept_comment_with_asterisk_after_tab() {
        reject_yaml_aliases("key: value\t# *not an alias\n").expect("asterisk in comment after tab should pass");
    }

    #[test]
    fn check_yaml_safety_combines_checks() {
        check_yaml_safety("listeners: []\n").expect("valid YAML should pass all safety checks");

        let huge = "x".repeat(5 * 1024 * 1024);
        let err = check_yaml_safety(&huge).unwrap_err();
        assert!(
            err.to_string().contains("too large"),
            "oversized should fail safety check"
        );

        let alias_err = check_yaml_safety("a: &a x\nb: *a\n").unwrap_err();
        assert!(
            alias_err.to_string().contains("alias"),
            "alias should fail safety check"
        );
    }

    #[test]
    fn scan_line_handles_tabs() {
        assert!(
            !matches!(scan_line("key:\t*.txt", None), LineScan::Alias),
            "tab before asterisk-glob should pass"
        );
        assert!(
            matches!(scan_line("\t*anchor", None), LineScan::Alias),
            "tab before alias should detect"
        );
    }

    #[test]
    fn scan_line_escaped_backslash_then_asterisk() {
        assert!(
            !matches!(scan_line("path: \"\\\\*\"", None), LineScan::Alias),
            "escaped backslash followed by asterisk inside quotes should pass"
        );
    }

    #[test]
    fn reject_alias_after_carriage_return_comment() {
        let err = reject_yaml_aliases("# c\rb: &b [1,2]\ra: *b\r");
        assert!(
            err.is_err(),
            "a bare CR ends a comment, so the alias after it must be rejected"
        );
    }

    #[test]
    fn reject_alias_after_unicode_line_breaks() {
        for brk in ['\u{85}', '\u{2028}', '\u{2029}'] {
            let raw = format!("# c{brk}b: &b [1,2]{brk}a: *b");
            assert!(
                reject_yaml_aliases(&raw).is_err(),
                "U+{:04X} ends a comment, so the alias after it must be rejected",
                u32::from(brk)
            );
        }
    }

    #[test]
    fn reject_alias_after_multiline_double_quoted_scalar() {
        let err = reject_yaml_aliases("b: &b [1,2]\na: [\"x\n #\", *b]\n");
        assert!(
            err.is_err(),
            "a '#' inside a continued quoted scalar must not hide the alias"
        );
    }

    #[test]
    fn reject_alias_after_multiline_quote_with_apostrophe() {
        let err = reject_yaml_aliases("b: &b [1,2]\na: [\"x\n 'y\", *b]\n");
        assert!(
            err.is_err(),
            "an apostrophe inside a continued quoted scalar must not hide the alias"
        );
    }

    #[test]
    fn reject_alias_after_flow_key_indicator() {
        let err = reject_yaml_aliases("a: &x [1]\nb: {?*x : 1}\n");
        assert!(
            err.is_err(),
            "an alias right after a flow '?' key indicator must be rejected"
        );
    }

    #[test]
    fn reject_alias_after_block_scalar_opening_a_quote() {
        let err = reject_yaml_aliases("note: |\n  'unbalanced\nb: &b [1]\na: *b\n");
        assert!(
            err.is_err(),
            "a quote left open by block text must not hide a later alias"
        );
    }

    #[test]
    fn accept_quoted_scalar_spanning_lines() {
        reject_yaml_aliases("a: \"one *x\n  two\"\nb: ok\n")
            .expect("a '*' inside a multi-line quoted scalar is not an alias");
    }

    #[test]
    fn crlf_line_numbers_count_newlines() {
        let err = reject_yaml_aliases("listeners: []\r\nfoo: bar\r\nbomb: *a\r\n").unwrap_err();
        assert!(
            err.to_string().contains("line 3"),
            "CRLF input should report line 3, got: {err}"
        );
    }

    #[test]
    fn accept_yaml_with_only_anchor_no_alias() {
        reject_yaml_aliases("a: &anchor value\nb: &another value\nlisteners: []\n")
            .expect("multiple anchors without aliases should pass");
    }

    #[test]
    fn file_at_exact_boundary() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("exact.yaml");
        let exact_content = "x".repeat(MAX_YAML_BYTES);
        std::fs::write(&path, &exact_content).expect("write exact size file");

        let content = read_config_file(&path).expect("file at exact MAX_YAML_BYTES should be readable");
        assert_eq!(content.len(), MAX_YAML_BYTES, "content should be complete");
    }

    #[test]
    fn file_two_bytes_over_boundary() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("over.yaml");
        let over_content = "x".repeat(MAX_YAML_BYTES + 2);
        std::fs::write(&path, over_content).expect("write over-size file");

        let err = read_config_file(&path).expect_err("file two bytes over MAX_YAML_BYTES should be rejected");
        assert!(
            err.to_string().contains("too large"),
            "error should mention size limit, got: {err}"
        );
    }
}
