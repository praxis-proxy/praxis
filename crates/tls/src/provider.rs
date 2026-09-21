// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Crypto provider selection.
//!
//! rustls performs no cryptography of its own: it drives the TLS protocol and
//! delegates every primitive to a [`CryptoProvider`]. Praxis chooses that
//! provider at build time and installs it once during startup.
//!
//! # Why the choice lives here
//!
//! The Pingora fork installs no provider, and enables rustls'
//! `custom-provider` feature, which removes rustls' implicit fallback to
//! whichever built-in its features happen to enable. Nothing below this crate
//! has an opinion, so a provider that is not installed here is not installed
//! at all — and the process fails loudly rather than picking one silently.
//!
//! # Selecting a provider
//!
//! At least one of the `openssl` and `aws-lc-rs` features must be enabled;
//! selecting neither is a compile error. Enabling both is permitted and
//! `openssl` wins, so that `--all-features` builds work; see the note beside
//! the `compile_error!` below.
//!
//! - `openssl` (default) — [`rustls_openssl`], backed by the system OpenSSL library. The cryptography is performed by
//!   `libcrypto.so`, which on a FIPS-enabled host is the platform's validated module. This is the configuration Praxis
//!   targets for FIPS 140-3.
//! - `aws-lc-rs` — rustls' built-in AWS-LC provider. Statically linked, so it builds anywhere without system OpenSSL,
//!   but the module is AWS's rather than the platform's.
//!
//! ```console
//! cargo build                                                  # OpenSSL
//! cargo build --no-default-features --features aws-lc-rs       # AWS-LC
//! ```
//!
//! # Install early
//!
//! [`install`] must run before any listener or upstream connector is built.
//! Pingora constructs its upstream connectors while the proxy *service* is
//! created, which is earlier than most callers expect: "before
//! `run_forever()`" is too late. Praxis installs during server bootstrap,
//! ahead of service registration.
//!
//! [`CryptoProvider`]: rustls::crypto::CryptoProvider

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

#[cfg(not(any(feature = "openssl", feature = "aws-lc-rs")))]
compile_error!("no crypto provider selected: enable exactly one of the `openssl` or `aws-lc-rs` features");

// Enabling both is allowed, and `openssl` wins. It is not made a compile
// error because `cargo test --workspace --all-features` — how this repo runs
// its suite — turns on every feature by definition, and there is no way to
// exclude one. rustls takes the same position with its own `ring` and
// `aws_lc_rs` features.
//
// Allowing both is safe because it does not make the choice ambiguous at
// runtime: exactly one provider is ever installed, `name()` reports which,
// and Task 5's assertion checks it. The cost is that a both-features build
// *links* the unused provider, so a release build must select one — which
// `default = ["openssl"]` does.
//
// The dangerous case, selecting neither, stays a hard error: that build would
// compile and then panic on the first TLS operation.

/// Name of the provider compiled into this build.
///
/// Intended for startup logging and for the runtime assertion that the
/// expected provider is the one actually serving connections.
///
/// ```
/// assert!(!praxis_tls::provider::name().is_empty());
/// ```
#[must_use]
pub const fn name() -> &'static str {
    #[cfg(feature = "openssl")]
    {
        "openssl"
    }
    #[cfg(all(feature = "aws-lc-rs", not(feature = "openssl")))]
    {
        "aws-lc-rs"
    }
}

/// Build the provider compiled into this build.
fn build() -> CryptoProvider {
    #[cfg(feature = "openssl")]
    {
        rustls_openssl::default_provider()
    }
    #[cfg(all(feature = "aws-lc-rs", not(feature = "openssl")))]
    {
        rustls::crypto::aws_lc_rs::default_provider()
    }
}

/// Install the compiled-in provider as the process-wide default.
///
/// Idempotent: returns `false` when a provider was already installed, which
/// happens when a test installs one before the server bootstrap runs. The
/// first caller wins, so this must be called before anything builds a
/// `ServerConfig` or `ClientConfig`.
///
/// Installing is not the same as verifying. Use [`installed`] to assert that a
/// provider is present, and fail startup when it is not.
///
/// ```
/// praxis_tls::provider::install();
/// assert!(praxis_tls::provider::installed());
/// ```
pub fn install() -> bool {
    build().install_default().is_ok()
}

/// Whether a process-wide provider has been installed.
///
/// ```
/// praxis_tls::provider::install();
/// assert!(praxis_tls::provider::installed());
/// ```
#[must_use]
pub fn installed() -> bool {
    CryptoProvider::get_default().is_some()
}

/// The installed process-wide provider.
///
/// Returns [`TlsError::NoCryptoProvider`] when none has been installed. There
/// is deliberately no fallback: silently substituting a provider nobody chose
/// is the failure this module exists to prevent.
///
/// [`TlsError::NoCryptoProvider`]: crate::TlsError::NoCryptoProvider
pub(crate) fn installed_provider() -> Result<Arc<CryptoProvider>, crate::TlsError> {
    CryptoProvider::get_default()
        .cloned()
        .ok_or(crate::TlsError::NoCryptoProvider)
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn install_is_idempotent_and_leaves_a_provider() {
        install();
        assert!(installed(), "a provider must be installed after install()");
        // Second call finds one already there and reports that it did not
        // perform the install, rather than failing.
        assert!(!install(), "repeat install must report no-op, not panic");
        assert!(installed());
    }

    #[test]
    fn installed_provider_resolves() {
        install();
        let provider = installed_provider().expect("provider installed above");
        assert!(!provider.cipher_suites.is_empty(), "provider must offer cipher suites");
    }

    #[test]
    fn name_matches_the_selected_feature() {
        // `openssl` takes precedence when both are enabled, as under
        // `--all-features`.
        #[cfg(feature = "openssl")]
        assert_eq!(name(), "openssl");
        #[cfg(all(feature = "aws-lc-rs", not(feature = "openssl")))]
        assert_eq!(name(), "aws-lc-rs");
    }
}
