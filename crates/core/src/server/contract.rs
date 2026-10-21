// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The server runtime contract a network backend implements.

use std::pin::Pin;

use crate::config::Config;

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/// A boxed, sendable future the runtime waits on for a shutdown request.
pub type ShutdownFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

// -----------------------------------------------------------------------------
// ServerRuntime
// -----------------------------------------------------------------------------

/// Owns the process's async runtime, its listening services and shutdown.
///
/// Protocol adapters bind their listeners onto the runtime (the `Protocol`
/// trait in `praxis-proxy-protocol`), background services hang off it, and
/// then exactly one of the `run_*` methods takes over the calling thread
/// until the server has stopped. Nothing is bound until a protocol registers.
///
/// ```
/// use praxis_core::{
///     config::{Config, DEFAULT_CONFIG},
///     server::{ServerRuntime as _, UnavailableRuntime},
/// };
///
/// let config = Config::from_yaml(DEFAULT_CONFIG).unwrap();
/// let runtime = UnavailableRuntime::from_config(&config);
/// runtime.run_with_shutdown(Box::pin(std::future::ready(())));
/// ```
pub trait ServerRuntime: Sized {
    /// Build the runtime from the loaded configuration.
    fn from_config(config: &Config) -> Self;

    /// Serve until the process receives a shutdown signal, then return once
    /// the graceful shutdown has completed.
    fn run_until_shutdown(self);

    /// Serve until `shutdown` resolves, then return once shutdown completes.
    /// For harnesses that stop the server themselves. Pingora shuts down
    /// immediately on this path and may drop active work.
    fn run_with_shutdown(self, shutdown: ShutdownFuture);
}
