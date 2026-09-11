// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! RFC 6901 JSON Pointer compilation and overlap checks.

use super::JsonError;

// -----------------------------------------------------------------------------
// Pointer compilation
// -----------------------------------------------------------------------------

/// Decode an RFC 6901 JSON Pointer into path tokens.
///
/// The empty string is the document root (no tokens). Every other
/// pointer must start with `/`. `~1` is unescaped to `/` before `~0`
/// is unescaped to `~`.
///
/// # Errors
///
/// Returns [`JsonError::Compile`] when the pointer does not start with `/`
/// (unless it is empty) or contains an invalid `~` escape.
pub(super) fn compile_pointer(raw: &str) -> Result<Vec<String>, JsonError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let Some(rest) = raw.strip_prefix('/') else {
        return Err(JsonError::compile(format!(
            "JSON Pointer '{raw}' must be empty or start with '/'"
        )));
    };

    rest.split('/').map(unescape_token).collect::<Result<Vec<_>, _>>()
}

/// Unescape one JSON Pointer token.
fn unescape_token(token: &str) -> Result<String, JsonError> {
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(ch) = chars.next() {
        if ch != '~' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('0') => out.push('~'),
            Some('1') => out.push('/'),
            Some(other) => {
                return Err(JsonError::compile(format!("invalid JSON Pointer escape '~{other}'")));
            },
            None => return Err(JsonError::compile("truncated JSON Pointer escape")),
        }
    }
    Ok(out)
}

/// Whether `a` and `b` overlap: equal, or one is a prefix of the other.
pub(super) fn pointers_overlap(a: &[String], b: &[String]) -> bool {
    let n = a.len().min(b.len());
    a.get(..n) == b.get(..n)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn empty_pointer_is_root() {
        assert!(compile_pointer("").unwrap().is_empty(), "empty pointer is the root");
    }

    #[test]
    fn slash_only_is_empty_key() {
        assert_eq!(
            compile_pointer("/").unwrap(),
            vec![String::new()],
            "a trailing slash is an empty-string token"
        );
    }

    #[test]
    fn unescapes_tilde_and_slash() {
        assert_eq!(
            compile_pointer("/a~1b/~0c").unwrap(),
            vec!["a/b".to_owned(), "~c".to_owned()],
            "~1 then ~0 unescape order"
        );
    }

    #[test]
    fn rejects_missing_slash() {
        let err = compile_pointer("foo").unwrap_err();
        assert!(
            err.to_string().contains("must be empty or start with '/'"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_bad_escape() {
        let err = compile_pointer("/a~2b").unwrap_err();
        assert!(err.to_string().contains("invalid JSON Pointer escape"), "got: {err}");
    }

    #[test]
    fn overlap_equal_and_prefix() {
        let foo = compile_pointer("/foo").unwrap();
        let foo_bar = compile_pointer("/foo/bar").unwrap();
        let baz = compile_pointer("/baz").unwrap();
        assert!(pointers_overlap(&foo, &foo), "equal pointers overlap");
        assert!(pointers_overlap(&foo, &foo_bar), "parent overlaps child");
        assert!(pointers_overlap(&foo_bar, &foo), "child overlaps parent");
        assert!(!pointers_overlap(&foo, &baz), "siblings do not overlap");
    }
}
