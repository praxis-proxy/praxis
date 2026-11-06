// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the compiled crypto capability assessment behind
//! `fips_crypto_blocker`. Provider readiness is not checked here: it fails
//! filter construction, which the construction tests cover.

use super::{assess_fips, fips_crypto_blocker};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn an_unsafe_policy_report_blocks_fips() {
    let report = ppe::crypto_capability_report();
    if !report.fips_profile_is_safe() {
        assert!(
            fips_crypto_blocker().is_some(),
            "an unsafe Policy capability report must block required FIPS mode: {report:?}"
        );
    }
}

#[cfg(any(feature = "policy-builtins", feature = "policy-crypto-default"))]
#[test]
fn the_default_backend_is_never_fips_safe() {
    let report = ppe::crypto_capability_report();
    assert!(
        !report.fips_profile_is_safe(),
        "the RustCrypto backend must not pass as FIPS: {report:?}"
    );
    assert!(fips_crypto_blocker().is_some(), "the default backend must block FIPS");
}

#[cfg(any(feature = "policy-builtins", feature = "policy-api-key"))]
#[test]
fn an_api_key_build_reports_its_backend() {
    let report = ppe::crypto_capability_report();
    assert_eq!(
        report.api_key_backend,
        Some(report.policy_backend),
        "API-key hashing must run on the shared Policy backend"
    );
}

#[cfg(not(any(feature = "policy-api-key", feature = "policy-builtins")))]
#[test]
fn a_build_without_api_key_reports_no_api_key_backend() {
    assert_eq!(
        ppe::crypto_capability_report().api_key_backend,
        None,
        "a build without the API-key builtin must report no API-key backend"
    );
}

#[cfg(all(feature = "policy-crypto-fips", not(feature = "policy-experimental-ratelimit")))]
#[test]
fn a_fips_selection_without_the_limiter_is_not_blocked() {
    let report = ppe::crypto_capability_report();
    assert!(
        report.fips_profile_is_safe(),
        "a Policy FIPS selection must report a safe profile: {report:?}"
    );
    assert_eq!(
        super::unvalidated_fips_combination(),
        None,
        "no unvalidated combination is compiled"
    );
    assert_eq!(
        assess_fips(0, &report),
        None,
        "a safe FIPS selection without host plugins must not block"
    );
}

#[cfg(all(feature = "policy-crypto-fips", feature = "policy-experimental-ratelimit"))]
#[test]
fn the_limiter_with_the_fips_backend_blocks_fips() {
    let Some(reason) = super::unvalidated_fips_combination() else {
        panic!("the limiter with FIPS must be an unvalidated combination");
    };
    assert!(
        reason.contains("policy-experimental-ratelimit") && reason.contains("unvalidated"),
        "the refusal must name the limiter and say it is unvalidated: {reason}"
    );
    assert!(
        assess_fips(0, &ppe::crypto_capability_report()).is_some(),
        "the combination must block FIPS even without host plugins"
    );
}

#[test]
fn a_registered_host_plugin_blocks_fips_even_with_a_safe_report() {
    let report = ppe::crypto_capability_report();
    let Some(reason) = assess_fips(1, &report) else {
        panic!("an unreviewed host plugin must block FIPS");
    };
    assert!(
        reason.contains("host policy plugin"),
        "the refusal must name the host plugins: {reason}"
    );
}
