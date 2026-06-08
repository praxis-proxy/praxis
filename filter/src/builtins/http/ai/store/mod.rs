// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Response store persistence layer for AI API filters.
//!
//! Provides the [`ResponseStore`] async trait and supporting
//! types. Used by Responses API filters for persisting response
//! records and conversation history.

mod trait_def;
mod types;

#[allow(unused_imports, reason = "re-exports for upcoming store backend and filter")]
pub use self::{
    trait_def::ResponseStore,
    types::{ConversationRecord, ResponseRecord, StoreError},
};
