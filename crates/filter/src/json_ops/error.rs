// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Errors and limits for JSON Pointer compilation and rewriting.

/// Maximum object/array nesting while rewriting.
pub(crate) const MAX_JSON_DEPTH: u32 = 128;

/// Failure compiling ops or walking a document.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum JsonError {
    /// Input is not a single JSON value.
    #[error("invalid JSON")]
    InvalidJson,
    /// Nesting exceeded the maximum JSON nesting depth.
    #[error("JSON nesting exceeds maximum depth")]
    Depth,
    /// Pointer, overlap, or source validation failed.
    #[error("{0}")]
    Compile(String),
}

impl JsonError {
    /// Compile-time validation failure.
    pub(crate) fn compile(msg: impl Into<String>) -> Self {
        Self::Compile(msg.into())
    }

    /// Human-readable reason for logs and `on_invalid: error`.
    pub fn as_str(&self) -> &str {
        match self {
            Self::InvalidJson => "invalid JSON",
            Self::Depth => "JSON nesting exceeds maximum depth",
            Self::Compile(msg) => msg.as_str(),
        }
    }
}
