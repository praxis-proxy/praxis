// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Conversations filter: local `/v1/conversations` endpoints.
//!
//! Handles all 8 conversation and item CRUD operations locally
//! via `FilterAction::Reject`, backed by the `ConversationItemStore`
//! trait. Requests never reach upstream.

mod config;
mod filter;
mod handlers;
mod validate;

pub use filter::OpenaiConversationsFilter;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests;
