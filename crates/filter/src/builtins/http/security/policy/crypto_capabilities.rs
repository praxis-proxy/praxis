// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for Policy's compiled crypto capability assessment.

/// Refuse any compiled graph that Policy does not mark as FIPS-safe.
#[test]
fn an_unsafe_policy_report_blocks_fips() {
    let report = ppe::crypto_capability_report();
    if !report.fips_profile_is_safe() {
        assert!(
            super::fips_crypto_blocker().is_some(),
            "unsafe Policy capability report must block required FIPS mode: {report:?}"
        );
    }
}

/// The API-key-only FIPS selection reports the approved Policy backend.
#[cfg(feature = "policy-api-key-fips")]
#[test]
fn api_key_fips_feature_selects_a_safe_policy_profile() {
    let report = ppe::crypto_capability_report();
    assert!(
        report.fips_profile_is_safe(),
        "API-key FIPS features must select a safe Policy graph: {report:?}"
    );
}

/// Check OpenSSL availability in addition to the compile-time FIPS report.
#[cfg(feature = "policy-api-key-fips")]
#[test]
fn api_key_fips_profile_reports_provider_unavailability() {
    let expected_blocker = super::host_plugins::host_plugin_count() > 0 || ppe::validate_api_key_crypto().is_err();
    assert_eq!(
        super::fips_crypto_blocker().is_some(),
        expected_blocker,
        "FIPS startup assessment must include provider availability and host plugins"
    );
}
