// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared HTTP connector for sub-request execution.
//!
//! Wraps a Pingora [`Connector`] in an [`Arc`] so it can be cloned
//! cheaply and shared across filter pipelines and config reloads.
//! The connector provides connection pooling, HTTP/2 ALPN
//! negotiation, and TLS — the same transport layer that Pingora
//! uses for normal upstream exchanges.
//!
//! ```
//! use praxis_core::subrequest::SubRequestConnector;
//!
//! let connector = SubRequestConnector::new(128);
//! let clone = connector.clone(); // Arc bump, same pool
//! ```
//!
//! [`Arc`]: std::sync::Arc
//! [`Connector`]: pingora_core::connectors::http::Connector

use std::sync::Arc;

use pingora_core::connectors::{ConnectorOptions, http::Connector};

// ---------------------------------------------------------------------------
// SubRequestConnector
// ---------------------------------------------------------------------------

/// Shared HTTP connector for iterative sub-requests.
///
/// Wraps Pingora's [`Connector`] behind an [`Arc`] so that all
/// `iterative_request_router` filter instances share a single
/// connection pool. Created once at server startup and passed
/// through unchanged on config reload (same pattern as
/// [`KvStoreRegistry`]).
///
/// ```
/// use praxis_core::subrequest::SubRequestConnector;
///
/// let connector = SubRequestConnector::new(128);
/// let _clone = connector.clone();
/// ```
///
/// [`Arc`]: std::sync::Arc
/// [`Connector`]: pingora_core::connectors::http::Connector
/// [`KvStoreRegistry`]: crate::kv::KvStoreRegistry
#[derive(Clone)]
pub struct SubRequestConnector {
    /// Shared Pingora HTTP connector.
    inner: Arc<Connector<()>>,
}

impl SubRequestConnector {
    /// Create a connector with the given keepalive pool size.
    ///
    /// ```
    /// use praxis_core::subrequest::SubRequestConnector;
    ///
    /// let connector = SubRequestConnector::new(64);
    /// ```
    pub fn new(keepalive_pool_size: usize) -> Self {
        let options = ConnectorOptions::new(keepalive_pool_size);
        Self {
            inner: Arc::new(Connector::new(Some(options))),
        }
    }

    /// Access the underlying Pingora [`Connector`].
    ///
    /// [`Connector`]: pingora_core::connectors::http::Connector
    pub fn connector(&self) -> &Connector<()> {
        &self.inner
    }
}

impl std::fmt::Debug for SubRequestConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubRequestConnector")
            .field("pool", &"Connector<()>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn clone_shares_same_arc() {
        let a = SubRequestConnector::new(16);
        let b = a.clone();
        assert!(
            Arc::ptr_eq(&a.inner, &b.inner),
            "cloned connectors should share the same Arc"
        );
    }

    #[test]
    fn debug_impl_does_not_panic() {
        let connector = SubRequestConnector::new(8);
        let debug = format!("{connector:?}");
        assert!(
            debug.contains("SubRequestConnector"),
            "debug output should contain type name"
        );
    }
}
