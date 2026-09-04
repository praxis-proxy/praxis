// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

#![deny(unreachable_pub)]
#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::iter_over_hash_type,
    clippy::min_ident_chars,
    clippy::mod_module_files,
    clippy::shadow_unrelated,
    clippy::single_char_lifetime_names,
    clippy::struct_field_names,
    reason = "TODO(conventions-sync): fix violations and remove"
)]

//! Core configuration, error types, and server factory for Praxis.
//!
//! `praxis-core` is the leaf of the crate dependency flow
//! `server -> protocol -> filter -> core -> tls`: it depends only on
//! [`praxis_tls`] and is depended on by every other Praxis crate. It
//! exists to give the filter, protocol, and server layers a single
//! source of truth for what a valid proxy looks like, so a parsed
//! configuration can be treated as already well-formed downstream.
//!
//! Responsibilities:
//! - YAML configuration parsing and validation with serde ([`config`]).
//! - Error types shared across the workspace ([`errors`], re-exported as [`ProxyError`]).
//! - Health state for active health checking ([`health`]) and the key-value store trait and registry ([`kv`]).
//! - The Pingora-backed server factory and runtime options ([`PingoraServerRuntime`], [`RuntimeOptions`]) plus tracing
//!   setup ([`TracingGuard`], [`logging`]).
//!
//! Configuration types validate at load time, upholding the invariant
//! that higher layers never re-check structural validity of a [`config`]
//! value they receive.

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
/// Shared retry budget and per-cluster active-request tracking.
pub mod retry;
/// Server factory and runtime options.
pub mod server;
/// Shared HTTP connector for sub-request execution.
pub mod subrequest;
/// Wall-clock time abstraction for filters.
pub mod time;

pub use errors::ProxyError;
pub use logging::TracingGuard;
pub use server::{PingoraServerRuntime, RuntimeOptions};
