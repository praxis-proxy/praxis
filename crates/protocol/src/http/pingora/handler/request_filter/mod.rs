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
mod error_handling;
/// Header mutation application for pre-read and request-phase filters.
mod header_mutations;
/// Request-phase entry point and pipeline runner.
mod pipeline;
/// Request-head phase execution, before `StreamBuffer` pre-read.
mod request_head;
/// Request utilities: span creation, snapshotting, and validation.
mod request_utils;
/// StreamBuffer pre-read logic and TRACE response construction.
mod stream_buffer;
/// Terminal response delivery (buffered and streaming).
mod terminal_responses;
/// Max-Forwards handling for TRACE and OPTIONS.
mod validation;

pub(in crate::http) use pipeline::execute;
