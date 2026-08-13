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

mod client;
mod internals;
mod types;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]
mod tests;

pub use client::{SubRequestClient, SubRequestConnector, SubRequestConnectorOptions};
pub use types::{DEPTH_HEADER, FrameworkHeaders, SubRequest, SubRequestError, SubResponse};
