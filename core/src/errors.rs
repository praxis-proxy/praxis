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
/// ```
/// use praxis_core::ProxyError;
///
/// let e = ProxyError::Config("bad yaml".into());
/// assert_eq!(e.to_string(), "config: bad yaml");
///
/// let e = ProxyError::NoRoute("GET /missing".into());
/// assert_eq!(e.to_string(), "no route for GET /missing");
///
/// let e = ProxyError::NoUpstream("backend".into());
/// assert_eq!(e.to_string(), "no upstream in cluster 'backend'");
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

    /// No route matched the incoming request.
    ///
    /// Raised during request routing when no filter chain's
    /// router matches the method, path, and headers. Returns
    /// 404 to the client. Not retriable for the same request.
    #[error("no route for {0}")]
    NoRoute(String),

    /// No upstream available in the given cluster.
    ///
    /// Raised when a route matched but all endpoints in the
    /// target cluster are unhealthy or the cluster is empty.
    /// Returns 503 to the client. Retriable after health checks
    /// recover an endpoint.
    #[error("no upstream in cluster '{0}'")]
    NoUpstream(String),
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

        let e = ProxyError::NoRoute("GET /missing".into());
        assert_eq!(
            e.to_string(),
            "no route for GET /missing",
            "NoRoute error display mismatch"
        );

        let e = ProxyError::NoUpstream("backend".into());
        assert_eq!(
            e.to_string(),
            "no upstream in cluster 'backend'",
            "NoUpstream error display mismatch"
        );
    }
}
