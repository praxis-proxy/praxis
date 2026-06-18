// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Deserialized YAML configuration types for the path rewrite filter.

use serde::Deserialize;

use crate::FilterError;

// -----------------------------------------------------------------------------
// PathRewriteOperation
// -----------------------------------------------------------------------------

/// Which rewrite operation to apply to the request path.
///
/// Exactly one variant must appear in the YAML config.
#[derive(Debug)]
pub(super) enum PathRewriteOperation {
    /// Remove this prefix from the request path.
    StripPrefix(String),

    /// Prepend this prefix to the request path.
    AddPrefix(String),

    /// Regex find/replace on the request path.
    Replace {
        /// Regex pattern to match.
        pattern: String,
        /// Replacement string (supports `$1`, `$name` capture groups).
        replacement: String,
    },
}

// -----------------------------------------------------------------------------
// PathRewriteConfig (raw)
// -----------------------------------------------------------------------------

/// Raw deserialized YAML config for the path rewrite filter.
///
/// Exactly one of the three operation fields must be set.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PathRewriteConfig {
    /// Remove this prefix from the request path.
    #[serde(default)]
    strip_prefix: Option<String>,

    /// Prepend this prefix to the request path.
    #[serde(default)]
    add_prefix: Option<String>,

    /// Regex find/replace on the request path.
    #[serde(default)]
    replace: Option<ReplaceConfig>,

    /// When `true`, suppresses the duplicate-rewrite validation
    /// error if another rewrite filter precedes this one.
    ///
    /// Consumed by pipeline validation via the raw YAML config.
    #[serde(default)]
    #[expect(dead_code, reason = "consumed by pipeline validation")]
    pub allow_rewrite_override: bool,
}

impl PathRewriteConfig {
    /// Convert the raw config into a validated [`PathRewriteOperation`].
    pub(super) fn into_operation(self) -> Result<PathRewriteOperation, FilterError> {
        let count = u8::from(self.strip_prefix.is_some())
            + u8::from(self.add_prefix.is_some())
            + u8::from(self.replace.is_some());

        if count == 0 {
            return Err("path_rewrite: exactly one of strip_prefix, add_prefix, or replace must be set".into());
        }
        if count > 1 {
            return Err("path_rewrite: only one of strip_prefix, add_prefix, or replace may be set".into());
        }

        if let Some(prefix) = self.strip_prefix {
            return Ok(PathRewriteOperation::StripPrefix(prefix));
        }
        if let Some(prefix) = self.add_prefix {
            return Ok(PathRewriteOperation::AddPrefix(prefix));
        }
        if let Some(replace) = self.replace {
            return Ok(PathRewriteOperation::Replace {
                pattern: replace.pattern,
                replacement: replace.replacement,
            });
        }

        unreachable!("count check guarantees at least one field is set")
    }
}

// -----------------------------------------------------------------------------
// ReplaceConfig
// -----------------------------------------------------------------------------

/// Regex find/replace configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplaceConfig {
    /// Regex pattern to match.
    pattern: String,

    /// Replacement string (supports `$1`, `$name` capture groups).
    replacement: String,
}
