// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

#![deny(unreachable_pub)]

//! Core configuration, error types, and server factory for Praxis.

/// YAML configuration parsing and validation.
pub mod config;
/// Upstream connection options and endpoint types.
pub mod connectivity;
/// Error types shared across the workspace.
pub mod errors;
/// Shared health state types for active health checking.
pub mod health;
/// Key-value store trait and registry.
pub mod kv;
/// Tracing subscriber setup.
pub mod logging;
/// Process-wide memory pressure monitoring.
pub mod memory;
/// Server factory and runtime options.
pub mod server;

pub use errors::ProxyError;
pub use server::{PingoraServerRuntime, RuntimeOptions};
