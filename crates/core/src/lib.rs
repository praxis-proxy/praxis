// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

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
/// Process-wide file descriptor pressure monitoring.
pub mod fd;
/// Shared gRPC protocol utilities.
pub mod grpc;
/// Shared health state types for active health checking.
pub mod health;
/// Hedge-copy admission budget and the per-request race.
pub mod hedge;
/// Per-instance request ID generation.
pub mod id;
/// Key-value store trait and registry.
pub mod kv;
/// Tracing subscriber setup.
pub mod logging;
/// Process-wide memory pressure monitoring.
pub mod memory;
/// Hop-by-hop and reserved-header stripping for the next HTTP hop.
pub mod next_hop_headers;
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
/// W3C trace-context extraction and injection when the `otel` feature is enabled.
#[cfg(feature = "otel")]
pub mod trace_context;
/// Shared W3C `tracestate` validation and normalization.
pub mod trace_state;

pub use errors::ProxyError;
pub use logging::TracingGuard;
pub use server::{PingoraServerRuntime, RuntimeOptions};
