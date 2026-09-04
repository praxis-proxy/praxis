// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! HTTP Basic Authentication filter (RFC 7617).
//!
//! Deprecated: slated for removal in favor of the authentication support in the
//! Praxis policy engine (<https://github.com/praxis-proxy/policy>). It stays
//! gated behind the experimental `basic-auth-filter` cargo feature until then.

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

pub use self::filter::BasicAuthFilter;
