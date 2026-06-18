// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Injects per-cluster API credentials into upstream requests.

mod config;
mod filter;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;

pub use self::filter::CredentialInjectionFilter;
