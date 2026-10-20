// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Sub-request types, hardened executor, and shared HTTP connector.
//!
//! Defines the `SubRequest` and `SubResponse` data types used by
//! sub-request exchanges, the `SubRequestConnector` that wraps the build's
//! egress [`Connector`] for connection pooling, and the `SubRequestClient`
//! that owns the shared connector and provides a safe, bounded execution
//! API. Peers are addressed as [`PeerSpec`]s, so none of this depends on
//! which network backend the build carries.
//!
//! ```
//! use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};
//! praxis_tls::provider::install(); // required before any connector is built
//!
//! let connector = SubRequestConnector::new(128, None);
//! let client = SubRequestClient::new(connector);
//! ```
//!
//! [`Connector`]: crate::egress::Connector
//! [`PeerSpec`]: crate::egress::PeerSpec

/// Streaming body handle implementation.
mod body;
/// Hardened sub-request client and executor.
mod client;
/// Connector, circuit guard, header sanitization, and shared utilities.
pub(crate) mod internals;
/// Data types for sub-request exchanges.
mod types;

/// Backend-neutral buffered completion contract regression tests.
#[cfg(test)]
mod completion_tests;

// The exchange tests dial a local listener through the build's connector, so
// they need a network backend compiled in.
#[cfg(test)]
#[cfg(feature = "pingora")]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]
mod tests;

pub use client::{SubRequestClient, record_http_client_status};
pub use internals::{SubRequestConnector, SubRequestConnectorOptions};
pub use types::{
    DEPTH_HEADER, FrameworkHeaders, StreamLimits, StreamingSubResponse, SubRequest, SubRequestError, SubResponse,
    SubResponseBody, UrlSubRequestError,
};
