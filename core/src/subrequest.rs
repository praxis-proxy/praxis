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
//! let connector = SubRequestConnector::new(128, None);
//! let clone = connector.clone(); // Arc bump, same pool
//! ```
//!
//! [`Arc`]: std::sync::Arc
//! [`Connector`]: pingora_core::connectors::http::Connector

use std::sync::Arc;

use pingora_core::connectors::{ConnectorOptions, http::Connector};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

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
/// An optional admission semaphore limits the number of
/// concurrently active sub-request exchanges. When set, callers
/// must acquire a permit before starting an exchange and hold it
/// until the response is fully read.
///
/// ```
/// use praxis_core::subrequest::SubRequestConnector;
///
/// let connector = SubRequestConnector::new(128, None);
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

    /// Admission semaphore bounding concurrently active exchanges.
    admission: Option<Arc<Semaphore>>,
}

impl SubRequestConnector {
    /// Create a connector with the given keepalive pool size and
    /// optional active-connection limit.
    ///
    /// ```
    /// use praxis_core::subrequest::SubRequestConnector;
    ///
    /// let connector = SubRequestConnector::new(64, None);
    /// let bounded = SubRequestConnector::new(64, Some(256));
    /// ```
    pub fn new(keepalive_pool_size: usize, max_connections: Option<usize>) -> Self {
        let options = ConnectorOptions::new(keepalive_pool_size);
        Self {
            inner: Arc::new(Connector::new(Some(options))),
            admission: max_connections.map(|n| Arc::new(Semaphore::new(n))),
        }
    }

    /// Access the underlying Pingora [`Connector`].
    ///
    /// [`Connector`]: pingora_core::connectors::http::Connector
    pub fn connector(&self) -> &Connector<()> {
        &self.inner
    }

    /// Acquire an admission permit if a concurrency limit is
    /// configured. Returns `None` when no limit is set.
    ///
    /// The returned permit must be held for the entire sub-request
    /// exchange. Dropping it releases the slot.
    pub async fn acquire_permit(&self) -> Option<OwnedSemaphorePermit> {
        let semaphore = self.admission.as_ref()?;
        Arc::clone(semaphore).acquire_owned().await.ok()
    }
}

impl std::fmt::Debug for SubRequestConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubRequestConnector")
            .field("pool", &"Connector<()>")
            .field(
                "max_connections",
                &self.admission.as_ref().map(|s| s.available_permits()),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn clone_shares_same_arc() {
        let a = SubRequestConnector::new(16, None);
        let b = a.clone();
        assert!(
            Arc::ptr_eq(&a.inner, &b.inner),
            "cloned connectors should share the same Arc"
        );
    }

    #[test]
    fn debug_impl_does_not_panic() {
        let connector = SubRequestConnector::new(8, None);
        let debug = format!("{connector:?}");
        assert!(
            debug.contains("SubRequestConnector"),
            "debug output should contain type name"
        );
    }

    #[test]
    fn unbounded_connector_has_no_admission() {
        let connector = SubRequestConnector::new(8, None);
        assert!(
            connector.admission.is_none(),
            "no max_connections should mean no semaphore"
        );
    }

    #[test]
    fn bounded_connector_has_admission_semaphore() {
        let connector = SubRequestConnector::new(8, Some(16));
        let semaphore = connector
            .admission
            .as_ref()
            .expect("max_connections should create semaphore");
        assert_eq!(
            semaphore.available_permits(),
            16,
            "semaphore should have the configured permits"
        );
    }

    #[tokio::test]
    async fn acquire_permit_returns_none_without_limit() {
        let connector = SubRequestConnector::new(4, None);
        assert!(
            connector.acquire_permit().await.is_none(),
            "unbounded connector should return None"
        );
    }

    #[tokio::test]
    async fn acquire_permit_returns_some_with_limit() {
        let connector = SubRequestConnector::new(4, Some(2));
        assert!(
            connector.acquire_permit().await.is_some(),
            "bounded connector should return a permit"
        );
    }

    #[tokio::test]
    async fn dropping_permit_restores_capacity() {
        let connector = SubRequestConnector::new(4, Some(1));
        let permit = connector.acquire_permit().await.unwrap();
        assert_eq!(
            connector.admission.as_ref().unwrap().available_permits(),
            0,
            "all permits should be taken"
        );
        drop(permit);
        assert_eq!(
            connector.admission.as_ref().unwrap().available_permits(),
            1,
            "dropping permit should restore capacity"
        );
    }

    #[test]
    fn clone_shares_admission_semaphore() {
        let a = SubRequestConnector::new(4, Some(8));
        let b = a.clone();
        assert!(
            Arc::ptr_eq(a.admission.as_ref().unwrap(), b.admission.as_ref().unwrap()),
            "cloned connectors should share the semaphore"
        );
    }
}
