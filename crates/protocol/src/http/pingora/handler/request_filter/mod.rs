// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Request-phase filter execution.
//!
//! The request phase is decomposed into themed sibling modules: the
//! `pipeline` module holds the entry point and pipeline runner, and
//! delegates validation, pre-read buffering, header mutation, body
//! handling, request-scoped utilities, and terminal response delivery to
//! the remaining modules.

/// Request body handling for the selected-upstream phase.
mod body_handling;
/// Pre-read error classification and client disconnect handling.
#[cfg(feature = "pingora")]
mod error_handling;
/// Header mutation application for pre-read and request-phase filters.
pub(in crate::http) mod header_mutations;
/// Hedged upstream attempts for a route that configured `hedge_policy`.
#[cfg(all(feature = "pingora", feature = "hedged-requests"))]
mod hedge;
/// Request-phase entry point and pipeline runner.
pub(in crate::http) mod pipeline;
/// Request-head phase execution, before `StreamBuffer` pre-read.
pub(in crate::http) mod request_head;
/// Request utilities: span creation, snapshotting, and validation.
pub(in crate::http) mod request_utils;
/// StreamBuffer pre-read logic and TRACE response construction.
pub(in crate::http) mod stream_buffer;
/// Terminal response delivery (buffered and streaming).
pub(in crate::http) mod terminal_responses;
/// Max-Forwards handling for TRACE and OPTIONS.
pub(in crate::http) mod validation;

#[cfg(feature = "pingora")]
pub(in crate::http) use pipeline::execute;
