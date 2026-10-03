// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Build-level guarantee about the policy engine.
//!
//! A per-crate test rather than a case in the shared `tests/integration`
//! suite: it only holds when compiled against this crate, with its own feature
//! resolution. It is deliberately ungated so feature unification cannot mask
//! it.

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// This crate's own manifest, embedded so the assertion reads the shipped
/// feature declaration rather than a `cfg` derived from it.
const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[expect(
    clippy::expect_used,
    clippy::tests_outside_test_module,
    reason = "integration tests are in tests/ directory, not in src"
)]
#[test]
fn the_default_feature_set_includes_the_policy_engine() {
    let declaration = default_feature_declaration().expect("[features] must declare a `default` array");

    assert!(
        declaration.contains("\"policy-engine\""),
        "`policy-engine` must stay in this crate's default features: the binary's own feature set \
         is what decides whether the `policy` filter is nameable in config, and no cfg-based test \
         can catch its removal — tests/integration turns praxis-filter/policy-engine on through \
         its own default, so every suite would stay green while the shipped binary lost the \
         filter. Got: {declaration}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The right-hand side of `default = [...]` in this crate's `[features]` table.
///
/// A line scan rather than a TOML parse: the workspace carries no TOML parser,
/// and adding one for a single-line assertion is not worth the dependency.
fn default_feature_declaration() -> Option<&'static str> {
    MANIFEST
        .lines()
        .skip_while(|line| line.trim() != "[features]")
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('['))
        .find_map(|line| line.trim().strip_prefix("default"))
        .and_then(|rest| rest.trim_start().strip_prefix('='))
}
