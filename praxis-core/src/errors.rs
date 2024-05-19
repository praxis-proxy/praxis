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
    #[error("config: {0}")]
    Config(String),

    /// No route matched the incoming request.
    #[error("no route for {0}")]
    NoRoute(String),

    /// No upstream available in the given cluster.
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
        assert_eq!(e.to_string(), "config: bad yaml");

        let e = ProxyError::NoRoute("GET /missing".into());
        assert_eq!(e.to_string(), "no route for GET /missing");

        let e = ProxyError::NoUpstream("backend".into());
        assert_eq!(e.to_string(), "no upstream in cluster 'backend'");
    }
}
