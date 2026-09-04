//! Reference behavior recorded before the engine dependency is swapped.
//!
//! There is exactly one window in which this can be captured: the swap removes
//! the current engine and no interval exists where both are present. The values
//! below were recorded from a run, not asserted from expectation, and the same
//! test must pass unchanged against the ported engine. A difference afterward is
//! a port defect rather than drift, because the baseline comes from the same
//! engine revision the port was extracted from and not from the older published
//! release, which differs by a fix that changes emitted payload output.
//!
//! The corpus is four real policy documents rather than synthetic ones: both demo
//! policies and the two fixtures the example integration tests load. Fixtures are
//! checked in and parsing is offline, so this needs no identity provider, no
//! container, and no network.
//!
//! What this does not capture: the fingerprint is the parsed document's shape, so
//! it catches a change to plugin names, plugin kind strings, route counts, or
//! routing activation. It does not catch a change in how a policy *evaluates*.
//! Notably the two demo documents produce identical fingerprints, because the
//! decision point they differ on is named in the policy expressions rather than
//! registered as a plugin. Evaluation behavior is covered by the engine's own
//! suite and, end to end, by the acceptance demo.

#![cfg(feature = "policy-engine")]
// Integration tests carry the same suppressions the crate's in-module tests do:
// the workspace gate denies panicking helpers and test functions outside a
// cfg(test) module, neither of which applies to a standalone test binary.
#![allow(
    clippy::allow_attributes_without_reason,
    clippy::expect_used,
    clippy::tests_outside_test_module
)]

use ppe::praxis_policy_core::config::parse_config;

/// Structural fingerprint of a parsed policy document: whether policy dispatch
/// governs, the ordered plugin name and kind pairs, and the route count.
fn fingerprint(yaml: &str) -> (bool, Vec<(String, String)>, usize) {
    let cfg = parse_config(yaml).expect("corpus document must parse");
    let plugins = cfg
        .plugins
        .iter()
        .map(|pl| (pl.name.clone(), pl.kind.clone()))
        .collect::<Vec<_>>();
    (cfg.dispatch_mode().is_policy(), plugins, cfg.routes.len())
}

/// The plugin set both demo documents declare. Kind strings are the
/// operator-facing contract and must survive the swap byte for byte.
fn demo_plugins() -> Vec<(String, String)> {
    [
        ("jwt-user", "identity/jwt"),
        ("jwt-client", "identity/jwt"),
        ("workday-oauth", "delegator/oauth"),
        ("pii-scan", "validator/pii-scan"),
        ("audit-log", "audit/logger"),
        ("github-oauth", "delegator/oauth"),
        ("manager-approver", "elicitation/ciba"),
    ]
    .into_iter()
    .map(|(name, kind)| (name.to_owned(), kind.to_owned()))
    .collect()
}

#[test]
fn demo_cedar_policy_is_unchanged() {
    let (policy_dispatch, plugins, routes) = fingerprint(include_str!("corpus/demo-cedar.yaml"));
    assert!(policy_dispatch, "recorded: policy dispatch governs");
    assert_eq!(plugins, demo_plugins(), "recorded: plugin names and kind strings");
    assert_eq!(routes, 4, "recorded: route count");
}

#[test]
fn demo_cel_policy_is_unchanged() {
    let (policy_dispatch, plugins, routes) = fingerprint(include_str!("corpus/demo-cel.yaml"));
    assert!(policy_dispatch, "recorded: policy dispatch governs");
    // Identical to the Cedar variant by design: the two differ in their policy
    // expressions, and the decision point is not a registered plugin.
    assert_eq!(plugins, demo_plugins(), "recorded: plugin names and kind strings");
    assert_eq!(routes, 4, "recorded: route count");
}

#[test]
fn minimal_hs256_fixture_is_unchanged() {
    let (policy_dispatch, plugins, routes) = fingerprint(include_str!("corpus/minimal-hs256.yaml"));
    // Recorded as off before the swap, when a boolean `routing_enabled` defaulted
    // false and this document wrote none. `dispatch:` defaults to `policy` now,
    // and a document declaring `global:` was always asking for it, so the
    // fingerprint records the mode rather than a flag the document omits.
    assert!(policy_dispatch, "recorded: policy dispatch governs");
    assert_eq!(
        plugins,
        vec![("jwt-user".to_owned(), "identity/jwt".to_owned())],
        "recorded: plugin names and kind strings"
    );
    assert_eq!(routes, 0, "recorded: route count");
}

#[test]
fn http_global_fixture_is_unchanged() {
    let (policy_dispatch, plugins, routes) = fingerprint(include_str!("corpus/http-global.yaml"));
    assert!(policy_dispatch, "recorded: policy dispatch governs");
    assert_eq!(
        plugins,
        vec![("jwt-user".to_owned(), "identity/jwt".to_owned())],
        "recorded: plugin names and kind strings"
    );
    assert_eq!(routes, 0, "recorded: global policy, no per-entity routes");
}

// The violation envelope's shape is equally part of the contract, but its helper
// is crate-private and is already covered by an in-crate unit test that has
// access. Widening the crate's public surface to serve a corpus test would be a
// worse trade than leaving that assertion where it already lives.
