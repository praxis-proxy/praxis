// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `OpenAI` Responses API store utilities.
//!
//! Helpers that operate on the generic [`ResponseStore`] but are
//! specific to the `OpenAI` Responses API (e.g., input item
//! pagination for the `/v1/responses/{id}/input_items` endpoint).
//!
//! [`ResponseStore`]: crate::builtins::http::ai::store::ResponseStore

mod config;
mod filter;
mod input_items;

#[allow(unused_imports, reason = "re-export for DELETE (#459) response endpoint")]
pub use input_items::InputItemPage;
pub use input_items::{ListParams, Order, list_input_items};

pub use self::filter::ResponseStoreFilter;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "tests"
)]
mod tests;
