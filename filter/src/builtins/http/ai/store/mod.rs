// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Response store persistence layer for AI API filters.
//!
//! Provides the [`ResponseStore`] async trait, [`SqliteResponseStore`]
//! backend, and supporting types. Used by AI API filters for
//! persisting response records and conversation history.

mod schemas;
mod sqlite;
mod trait_def;
mod types;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests;

#[allow(unused_imports, reason = "re-exports for upcoming store filter and registry")]
pub use self::{
    sqlite::SqliteResponseStore,
    trait_def::ResponseStore,
    types::{ConversationRecord, ResponseRecord, StoreError},
};
