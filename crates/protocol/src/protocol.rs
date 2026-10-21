// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! The [`Protocol`] trait implemented by each listener protocol adapter.
//!
//! An implementor binds its listeners and registers the matching services
//! onto the shared backend [`Runtime`]. The server crate calls
//! [`Protocol::register`] once per configured protocol at startup; the HTTP
//! and TCP adapters of the selected backend are exposed as [`Http`] and
//! [`Tcp`].
//!
//! [`Http`]: crate::backend::Http
//! [`Runtime`]: praxis_core::backend::Runtime
//! [`Tcp`]: crate::backend::Tcp

use praxis_core::{ProxyError, backend::Runtime, config::Config};
use tokio::sync::watch;

use crate::ListenerPipelines;

/// A protocol implementation that registers services onto a shared server runtime.
pub trait Protocol: Send {
    /// Register this protocol's services. Does not block.
    ///
    /// Returns any TLS certificate watcher shutdown senders. The caller keeps
    /// these alive to retain the ability to stop a watcher early via
    /// `send(true)`; the watcher tasks otherwise run for the process lifetime
    /// (dropping the senders does not stop them).
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] if listener binding or setup fails.
    ///
    /// [`ProxyError`]: praxis_core::ProxyError
    fn register(
        self: Box<Self>,
        server: &mut Runtime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<Vec<watch::Sender<bool>>, ProxyError>;
}
