// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

#![deny(unsafe_code)]
#![deny(unreachable_pub)]

//! Protocol adapters for Praxis.

use praxis_core::{PingoraServerRuntime, ProxyError, config::Config};

mod pipelines;
pub use pipelines::ListenerPipelines;

/// HTTP protocol implementations.
pub mod http;
/// Raw TCP/L4 forwarding protocol.
pub mod tcp;

// -----------------------------------------------------------------------------
// Protocol
// -----------------------------------------------------------------------------

/// A protocol implementation that registers services onto a shared server runtime.
pub trait Protocol: Send {
    /// Register this protocol's services. Does not block.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] if listener binding or setup fails.
    ///
    /// [`ProxyError`]: praxis_core::ProxyError
    fn register(
        self: Box<Self>,
        server: &mut PingoraServerRuntime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<(), ProxyError>;
}
