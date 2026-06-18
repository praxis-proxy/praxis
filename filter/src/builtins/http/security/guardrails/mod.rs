// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Rejects requests matching string or regex guardrail rules.

mod config;
mod filter;
mod pii;
mod rule;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    reason = "tests"
)]
mod tests;

pub use self::{
    config::{ContainsValue, GuardrailsAction, RuleTargetKind},
    filter::GuardrailsFilter,
    pii::PiiKind,
};
