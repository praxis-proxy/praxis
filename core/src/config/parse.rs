// SPDX-License-Identifier: MIT
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
    let meta = std::fs::metadata(path).map_err(|e| {
        let display = path.display();
        ProxyError::Config(format!("failed to read metadata for {display}: {e}"))
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
/// [`MAX_YAML_READ_BYTES`], so a special file (e.g. `/dev/zero`) or a
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
    let file = std::fs::File::open(path).map_err(|e| {
        let display = path.display();
        ProxyError::Config(format!("failed to read {display}: {e}"))
    })?;
    let mut content = String::new();
    file.take(MAX_YAML_READ_BYTES)
        .read_to_string(&mut content)
        .map_err(|e| {
            let display = path.display();
            ProxyError::Config(format!("failed to read {display}: {e}"))
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
/// # Errors
///
/// Returns [`ProxyError::Config`] when an alias node is present.
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
fn reject_yaml_aliases(raw: &str) -> Result<(), ProxyError> {
    match raw.lines().position(line_contains_alias) {
        Some(idx) => Err(ProxyError::Config(format!(
            "YAML alias nodes (`*anchor`) are not supported (line {}); \
             they enable alias-expansion denial-of-service and are not used by any Praxis config",
            idx + 1
        ))),
        None => Ok(()),
    }
}

/// Whether a single line contains an alias node outside strings/comments.
///
/// Single-line scan only: an alias node is always single-line, and a
/// false positive from a `*` inside a multi-line block scalar would only
/// reject an unusual config, never admit a bomb.
fn line_contains_alias(line: &str) -> bool {
    let (mut at_boundary, mut prev_ws) = (true, true);
    let mut quote: Option<u8> = None;
    let (mut prev_star, mut escaped) = (false, false);
    for &c in line.as_bytes() {
        // An alias node is `*` at a node boundary followed by an
        // anchor-name character; check the char after a boundary `*`.
        if prev_star && (c.is_ascii_alphanumeric() || c == b'_') {
            return true;
        }
        prev_star = false;
        if let Some(q) = quote {
            let close = c == q && !escaped;
            escaped = q == b'"' && c == b'\\' && !escaped;
            quote = (!close).then_some(q);
            at_boundary = false;
        } else {
            match c {
                // A comment only starts after whitespace (or line start);
                // a mid-scalar `#` (e.g. `a#b`) is scalar content.
                b'#' if prev_ws => return false,
                // A quoted scalar only starts at a node boundary; a
                // mid-scalar quote (e.g. `don't`) is scalar content.
                b'\'' | b'"' if at_boundary => (quote, at_boundary) = (Some(c), false),
                b'*' if at_boundary => prev_star = true,
                _ => at_boundary = matches!(c, b' ' | b'\t' | b'[' | b'{' | b',' | b':' | b'-'),
            }
        }
        prev_ws = matches!(c, b' ' | b'\t');
    }
    false
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
        // A directory (like a character device or FIFO) is not a regular file.
        // Special files such as /dev/zero report size 0 to metadata() and would
        // otherwise be read without bound; the is_file() guard rejects them all.
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
    fn accept_anchor_without_alias() {
        // An anchor with no matching alias expands nothing and is allowed.
        reject_yaml_aliases("a: &a x\nlisteners: []\n").expect("unused anchor should pass");
    }

    #[test]
    fn accept_asterisk_in_string_and_comment() {
        reject_yaml_aliases("pattern: \"a*b\"\nglob: '*.txt'\nnote: ok # *not an alias\n")
            .expect("asterisks in strings/comments are not alias nodes");
    }

    #[test]
    fn accept_bare_asterisk_value() {
        // `*` not followed by an anchor-name char is not an alias node.
        reject_yaml_aliases("wildcard: /*\n").expect("glob-like value should pass");
    }

    #[test]
    fn reject_alias_after_mid_scalar_apostrophe() {
        // A plain-scalar apostrophe is not a quote opener; the alias
        // after it must still be caught.
        let err = reject_yaml_aliases("a: &a x\nb: [don't, *a]\n");
        assert!(err.is_err(), "alias after mid-scalar apostrophe should be rejected");
    }

    #[test]
    fn reject_alias_after_mid_scalar_hash() {
        // `#` without preceding whitespace is scalar content, not a
        // comment; the alias after it must still be caught.
        let err = reject_yaml_aliases("a: &a x\nb: [a#b, *a]\n");
        assert!(err.is_err(), "alias after mid-scalar hash should be rejected");
    }

    #[test]
    fn accept_escaped_quote_in_double_quoted_scalar() {
        // `\"` does not close the string, so the `*` stays inside it.
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
        // No alias node present; the real parse error is reported later.
        reject_yaml_aliases("{{{{invalid yaml").expect("non-alias garbage passes the alias check");
    }

    #[test]
    fn alias_line_number_reported() {
        let err = reject_yaml_aliases("listeners: []\nfoo: bar\nbomb: *a\n").unwrap_err();
        assert!(err.to_string().contains("line 3"), "got: {err}");
    }
}
