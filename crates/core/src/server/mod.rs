// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Server factory and lifecycle management.

/// Pingora-specific server factory and runtime.
pub mod pingora;
mod runtime;

pub use pingora::{PingoraServerRuntime, build_http_server};
pub use runtime::RuntimeOptions;
