// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Filter-facing contracts for locally managed WebSocket sessions.

use async_trait::async_trait;
use bytes::Bytes;
use http::Uri;

use crate::{AuthenticatedIdentity, FilterError, Rejection};

/// Immutable request metadata projected by the downstream protocol before takeover.
pub struct ManagedWebSocketContext {
    /// Approved request target.
    target: Uri,
    /// Identity established by authentication filters, when present.
    identity: Option<AuthenticatedIdentity>,
}

impl ManagedWebSocketContext {
    /// Build the context from the approved target and authenticated identity.
    #[must_use]
    pub const fn new(target: Uri, identity: Option<AuthenticatedIdentity>) -> Self {
        Self { target, identity }
    }

    /// Return the approved request target.
    #[must_use]
    pub const fn target(&self) -> &Uri {
        &self.target
    }

    /// Return the identity established for the request.
    #[must_use]
    pub const fn identity(&self) -> Option<&AuthenticatedIdentity> {
        self.identity.as_ref()
    }
}

/// Decision from a filter participating in managed WebSocket admission.
#[must_use]
pub enum ManagedWebSocketDecision {
    /// Leave the handshake unclaimed by this filter.
    Pass,
    /// Reject the handshake with an HTTP response before switching protocols.
    Reject(Rejection),
    /// Claim the connection with an application owned by this session.
    Claim(Box<dyn ManagedWebSocketApplication>),
}

/// A complete application message. Control frames belong to the protocol layer.
pub enum ManagedWebSocketMessage {
    /// A UTF-8 text message.
    Text(String),
    /// A binary message.
    Binary(Bytes),
}

/// Message I/O supplied by the protocol layer for the lifetime of a session.
#[async_trait]
pub trait ManagedWebSocketIo: Send {
    /// Receive a complete message or return `None` when the peer closes.
    ///
    /// # Errors
    /// Returns an error on protocol or transport failure.
    async fn receive(&mut self) -> Result<Option<ManagedWebSocketMessage>, FilterError>;

    /// Send a complete message, awaiting transport capacity.
    ///
    /// # Errors
    /// Returns an error if the message is rejected or cannot be sent.
    async fn send(&mut self, message: ManagedWebSocketMessage) -> Result<(), FilterError>;
}

/// An owned application selected during handshake admission.
#[async_trait]
pub trait ManagedWebSocketApplication: Send + 'static {
    /// Run after the protocol layer commits the upgrade.
    ///
    /// # Errors
    /// Returns an application failure, which ends the upgraded session.
    async fn run(
        self: Box<Self>,
        context: ManagedWebSocketContext,
        io: &mut dyn ManagedWebSocketIo,
    ) -> Result<(), FilterError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FilterAction, HttpFilter, HttpFilterContext};

    /// A regular HTTP filter with no managed WebSocket implementation.
    struct HttpOnly;

    #[async_trait]
    impl HttpFilter for HttpOnly {
        fn name(&self) -> &'static str {
            "http_only"
        }

        async fn on_request(&self, _: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    #[tokio::test]
    async fn existing_filters_do_not_claim_websockets() {
        let context = ManagedWebSocketContext::new(Uri::from_static("/v1/responses"), None);
        assert!(!HttpOnly.can_claim_managed_websocket());
        assert!(matches!(
            HttpOnly.on_managed_websocket(&context).await,
            ManagedWebSocketDecision::Pass
        ));
    }
}
