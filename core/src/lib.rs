// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

#![deny(unreachable_pub)]
#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::impl_trait_in_params,
    clippy::iter_over_hash_type,
    clippy::min_ident_chars,
    clippy::mod_module_files,
    clippy::shadow_unrelated,
    clippy::single_char_lifetime_names,
    clippy::struct_field_names,
    reason = "TODO(conventions-sync): fix violations and remove"
)]

//! Core configuration, error types, and server factory for Praxis.

/// Circuit breaker state machine for sub-request fault isolation.
pub mod circuit;
/// YAML configuration parsing and validation.
pub mod config;
/// Upstream connection options and endpoint types.
pub mod connectivity;
/// Error types shared across the workspace.
pub mod errors;
/// Shared health state types for active health checking.
pub mod health;
/// Per-instance request ID generation.
pub mod id;
/// Key-value store trait and registry.
pub mod kv;
/// Tracing subscriber setup.
pub mod logging;
/// Process-wide memory pressure monitoring.
pub mod memory;
/// Reserved internal header prefixes for proxy-internal metadata.
pub mod reserved_headers;
/// Server factory and runtime options.
pub mod server;
/// Shared HTTP connector for sub-request execution.
pub mod subrequest;
/// Wall-clock time abstraction for filters.
pub mod time;

pub use errors::ProxyError;
pub use logging::TracingGuard;
pub use server::{PingoraServerRuntime, RuntimeOptions};
