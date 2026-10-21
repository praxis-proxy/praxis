// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Server factory and lifecycle management.

/// The runtime contract every network backend implements.
mod contract;
/// Pingora-specific server factory and runtime.
#[cfg(feature = "pingora")]
pub mod pingora;
/// Runtime options and worker-thread sizing shared by every backend.
mod runtime;
/// The stand-in runtime for a build with no backend.
mod unavailable;

pub use contract::{ServerRuntime, ShutdownFuture};
#[cfg(feature = "pingora")]
pub use pingora::{PingoraServerRuntime, build_http_server};
pub use runtime::{RuntimeOptions, resolve_thread_count};
pub use unavailable::UnavailableRuntime;
