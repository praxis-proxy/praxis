// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The request a management handler sees, independent of the backend that
//! parsed it.
//!
//! The admin, health, metrics and KV handlers decide what to answer from
//! the method, target and headers, and read the body only for the few
//! `PUT` routes that carry one. A backend implements this for its own
//! request type and serves whatever the handler returns, so the handlers
//! never change when the backend does.

use http::{HeaderMap, Method, Uri};

// -----------------------------------------------------------------------------
// AdminRequest
// -----------------------------------------------------------------------------

/// One management request as the admin handlers see it.
pub trait AdminRequest: Send {
    /// The request method.
    fn method(&self) -> &Method;

    /// The request target, including any `:authority` carried in it.
    fn uri(&self) -> &Uri;

    /// The request headers.
    fn headers(&self) -> &HeaderMap;

    /// Read the whole request body, refusing more than `limit` bytes.
    fn read_body(&mut self, limit: usize) -> impl Future<Output = Result<Vec<u8>, BodyReadError>> + Send;
}

// -----------------------------------------------------------------------------
// BodyReadError
// -----------------------------------------------------------------------------

/// Why a management request's body could not be read.
#[derive(Debug, thiserror::Error)]
pub enum BodyReadError {
    /// The body is larger than the handler's limit.
    #[error("request body exceeds the limit")]
    TooLarge,

    /// The transport failed before the body was complete.
    #[error("request body read failed: {0}")]
    Io(String),
}
