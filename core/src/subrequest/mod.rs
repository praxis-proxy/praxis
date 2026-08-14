// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Sub-request types, hardened executor, and shared HTTP connector.
//!
//! Defines the `SubRequest` and `SubResponse` data types used by
//! sub-request exchanges, the `SubRequestConnector` that wraps a
//! Pingora `Connector` for connection pooling, and the
//! `SubRequestClient` that owns the shared connector and provides
//! a safe, bounded execution API.
//!
//! ```
//! use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};
//!
//! let connector = SubRequestConnector::new(128, None);
//! let client = SubRequestClient::new(connector);
//! ```
//!
//! [`Connector`]: pingora_core::connectors::http::Connector

/// Streaming body handle implementation.
mod body;
/// Hardened sub-request client and executor.
mod client;
/// Connector, circuit guard, header sanitization, and shared helpers.
pub(crate) mod internals;
/// Data types for sub-request exchanges.
mod types;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]
mod tests;

pub use client::SubRequestClient;
pub use internals::{SubRequestConnector, SubRequestConnectorOptions};
pub use types::{
    DEPTH_HEADER, FrameworkHeaders, StreamLimits, StreamingSubResponse, SubRequest, SubRequestError, SubResponse,
    SubResponseBody,
};
