// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! FIPS mode as the test harness sees it.
//!
//! Two questions, answered from the signals the proxy itself reports at
//! startup ([`praxis_tls::provider::status`]):
//!
//! - [`approved_mode`]: does the installed OpenSSL provider offer FIPS-approved algorithms only? That is what decides
//!   which algorithms a handshake can use, so the FIPS behavior tests key their expectations on it and assert both
//!   branches, wherever they run.
//! - [`fips_host`]: is the process in FIPS mode the way a deployment requires it, provider and kernel flag both?
//!
//! `PRAXIS_FIPS_HOST=1` declares that the suites are running on a FIPS-enabled
//! host (`make test-fips-host` sets it). The harness then fails closed the
//! first time it installs the provider on a host that is not in FIPS mode, and
//! every FIPS behavior test insists on its approved-mode branch, so a green
//! run on the FIPS runner cannot have quietly happened on OpenSSL's default
//! provider.

/// Environment variable that declares the host to be in FIPS mode.
pub const FIPS_HOST_ENV: &str = "PRAXIS_FIPS_HOST";

/// Whether the environment declares this a FIPS host. Only an empty value,
/// `0`, `false`, `no` or `off` leave it undeclared, the spellings
/// `PRAXIS_REQUIRE_FIPS` treats as off.
pub fn fips_host_declared() -> bool {
    std::env::var(FIPS_HOST_ENV).is_ok_and(|value| {
        !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        )
    })
}

/// Whether the installed provider offers FIPS-approved algorithms only
/// (rustls' `CryptoProvider::fips`, which the OpenSSL provider answers from
/// OpenSSL's default properties). Installs the provider first, as every
/// harness entry point does.
pub fn approved_mode() -> bool {
    praxis_tls::provider::install();
    praxis_tls::provider::status().provider_fips
}

/// Whether the process is in FIPS mode by both signals: the provider reports
/// approved algorithms only and the kernel flag reads `1`.
pub fn fips_host() -> bool {
    praxis_tls::provider::install();
    praxis_tls::provider::status().unmet().is_empty()
}

/// Panic unless the process is in FIPS mode, when the environment declares
/// the host to be one. A no-op otherwise.
///
/// # Panics
///
/// Panics with every unmet signal when [`FIPS_HOST_ENV`] is set on a host
/// that is not in FIPS mode.
pub fn assert_fips_host_if_declared() {
    if !fips_host_declared() {
        return;
    }
    let unmet = praxis_tls::provider::status().unmet();
    assert!(
        unmet.is_empty(),
        "{FIPS_HOST_ENV} is set but the process is not in FIPS mode: {}",
        unmet.join("; ")
    );
}

/// The branch a FIPS behavior test must take: approved mode when the
/// provider is in it, and always approved mode when the host is declared
/// FIPS, so a declared FIPS host that somehow serves non-approved algorithms
/// fails rather than passes the non-FIPS branch.
///
/// # Panics
///
/// Panics when [`FIPS_HOST_ENV`] is set and the provider is not in approved
/// mode.
pub fn expect_approved_mode() -> bool {
    let approved = approved_mode();
    assert!(
        approved || !fips_host_declared(),
        "{FIPS_HOST_ENV} is set but the installed provider does not offer FIPS-approved algorithms only"
    );
    approved
}
