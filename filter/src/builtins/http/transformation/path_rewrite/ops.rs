// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Rewrite operations: `strip_prefix`, `add_prefix`, and regex replace.

use std::borrow::Cow;

use regex::{Regex, RegexBuilder};

use super::config::PathRewriteOperation;
use crate::FilterError;

// -----------------------------------------------------------------------------
// PathRewriteOp
// -----------------------------------------------------------------------------

/// Compiled path rewrite operation.
#[derive(Debug)]
pub(super) enum PathRewriteOp {
    /// Strip a leading prefix from the path.
    StripPrefix(String),

    /// Prepend a prefix to the path.
    AddPrefix(String),

    /// Regex replacement on the path.
    Replace {
        /// Compiled regex pattern.
        pattern: Regex,

        /// Replacement template.
        replacement: String,
    },
}

// -----------------------------------------------------------------------------
// Build Operation
// -----------------------------------------------------------------------------

/// Build a compiled operation from the deserialized config.
pub(super) fn build_op(operation: PathRewriteOperation) -> Result<PathRewriteOp, FilterError> {
    match operation {
        PathRewriteOperation::StripPrefix(prefix) => Ok(PathRewriteOp::StripPrefix(prefix)),
        PathRewriteOperation::AddPrefix(prefix) => Ok(PathRewriteOp::AddPrefix(prefix)),
        PathRewriteOperation::Replace { pattern, replacement } => {
            let compiled = RegexBuilder::new(&pattern)
                .size_limit(1 << 20)
                .build()
                .map_err(|e| -> FilterError { format!("path_rewrite: invalid regex: {e}").into() })?;
            Ok(PathRewriteOp::Replace {
                pattern: compiled,
                replacement,
            })
        },
    }
}

// -----------------------------------------------------------------------------
// Rewrite Logic
// -----------------------------------------------------------------------------

/// Apply the rewrite operation to a path, returning a borrowed path
/// when no rewrite occurs or an owned path when it does.
pub(super) fn rewrite_path<'a>(op: &PathRewriteOp, path: &'a str) -> Cow<'a, str> {
    match op {
        PathRewriteOp::StripPrefix(prefix) => strip_prefix(path, prefix),
        PathRewriteOp::AddPrefix(prefix) => add_prefix(path, prefix),
        PathRewriteOp::Replace { pattern, replacement } => {
            let result = pattern.replace(path, replacement.as_str());
            match result {
                Cow::Borrowed(_) => Cow::Borrowed(path),
                Cow::Owned(s) if s == path => Cow::Borrowed(path),
                Cow::Owned(s) => Cow::Owned(s),
            }
        },
    }
}

/// Strip a prefix from the path at a segment boundary.
///
/// The prefix matches only when what follows is `/` or end-of-path.
/// Returns [`Cow::Borrowed`] when the prefix does not match.
///
/// [`Cow::Borrowed`]: std::borrow::Cow::Borrowed
pub(super) fn strip_prefix<'a>(path: &'a str, prefix: &str) -> Cow<'a, str> {
    if let Some(rest) = path.strip_prefix(prefix) {
        if rest.is_empty() {
            Cow::Owned("/".to_owned())
        } else if rest.starts_with('/') {
            Cow::Owned(rest.to_owned())
        } else {
            Cow::Borrowed(path)
        }
    } else {
        Cow::Borrowed(path)
    }
}

/// Prepend a prefix to the path, avoiding double slashes.
///
/// Always produces a new string, so returns [`Cow::Owned`].
///
/// [`Cow::Owned`]: std::borrow::Cow::Owned
pub(super) fn add_prefix<'a>(path: &'a str, prefix: &str) -> Cow<'a, str> {
    let prefix = prefix.trim_end_matches('/');
    if path.starts_with('/') {
        Cow::Owned(format!("{prefix}{path}"))
    } else {
        Cow::Owned(format!("{prefix}/{path}"))
    }
}

/// Re-attach the query string to a rewritten path.
pub(super) fn append_query(path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_owned(),
    }
}
