// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Shared error types for the Praxis workspace.
//!
//! [`ProxyError`] is the primary error type, re-exported from `praxis_core`.

use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during proxy operation.
///
/// Runtime routing failures (no route matched, no healthy upstream) are
/// not `ProxyError` variants: the router and load balancer short-circuit
/// with filter rejections, and upstream connect failures surface through
/// the protocol layer's error classification.
///
/// ```
/// use praxis_core::ProxyError;
///
/// let e = ProxyError::Config("bad yaml".into());
/// assert_eq!(e.to_string(), "config: bad yaml");
/// ```
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Configuration loading or validation error.
    ///
    /// Raised during startup or hot-reload when YAML parsing or
    /// validation fails. Not retriable; fix the configuration.
    /// The server continues running with the previous config on
    /// hot-reload failures.
    #[error("config: {0}")]
    Config(String),
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let e = ProxyError::Config("bad yaml".into());
        assert_eq!(e.to_string(), "config: bad yaml", "Config error display mismatch");
    }
}
