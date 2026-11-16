// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Server factory and lifecycle management.

/// The runtime contract every network backend implements.
mod contract;
/// The hyper backend's runtime: a tokio runtime, listeners and shutdown.
#[cfg(feature = "hyper")]
pub mod hyper;
/// Shared process lifecycle state and transition contract.
pub mod lifecycle;
/// Pingora-specific server factory and runtime.
#[cfg(feature = "pingora")]
pub mod pingora;
/// Runtime options and worker-thread sizing shared by every backend.
mod runtime;
/// The stand-in runtime for a build with no backend.
mod unavailable;

pub use contract::{ServerRuntime, ShutdownFuture};
#[cfg(feature = "hyper")]
pub use hyper::HyperRuntime;
pub use lifecycle::{LifecycleError, LifecycleHandle, LifecyclePhase};
#[cfg(feature = "pingora")]
pub use pingora::{PingoraServerRuntime, build_http_server};
pub use runtime::{RuntimeOptions, resolve_thread_count};
pub use unavailable::UnavailableRuntime;
