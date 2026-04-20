// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Deserialized YAML configuration types for the path rewrite filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// PathRewriteConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the path rewrite filter.
///
/// Exactly one operation must be specified.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PathRewriteConfig {
    /// Remove this prefix from the request path.
    #[serde(default)]
    pub strip_prefix: Option<String>,

    /// Prepend this prefix to the request path.
    #[serde(default)]
    pub add_prefix: Option<String>,

    /// Regex find/replace on the request path.
    #[serde(default)]
    pub replace: Option<ReplaceConfig>,

    /// When `true`, suppresses the duplicate-rewrite validation
    /// error if another rewrite filter precedes this one.
    ///
    /// Consumed by pipeline validation via the raw YAML config.
    #[serde(default)]
    #[allow(dead_code, reason = "consumed by pipeline validation")]
    pub allow_rewrite_override: bool,
}

// -----------------------------------------------------------------------------
// ReplaceConfig
// -----------------------------------------------------------------------------

/// Regex find/replace configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplaceConfig {
    /// Regex pattern to match.
    pub pattern: String,

    /// Replacement string (supports `$1`, `$name` capture groups).
    pub replacement: String,
}
