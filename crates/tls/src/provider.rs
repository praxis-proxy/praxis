// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! The rustls crypto provider.
//!
//! rustls performs no cryptography of its own: it drives the TLS protocol and
//! delegates every primitive to a [`CryptoProvider`]. Praxis uses exactly one,
//! the OpenSSL-backed [`rustls_openssl`] provider, and installs it once during
//! startup.
//!
//! # Why one provider, and why this one
//!
//! Every hash, MAC, key derivation, key exchange, signature, verification and
//! random byte goes through the system `libcrypto.so`. On a FIPS-enabled Red
//! Hat Enterprise Linux host that library's provider is the platform's
//! validated module, which is the deployment Praxis targets for FIPS 140-3. A
//! second, statically linked provider would only give a build that cannot make
//! that claim, so there is no feature to pick one.
//!
//! The Pingora fork installs no provider and enables rustls' `custom-provider`
//! feature, which removes rustls' implicit fallback to a built-in. Nothing
//! below this crate has an opinion, so a provider that is not installed here
//! is not installed at all, and the process fails loudly rather than picking
//! one silently.
//!
//! # Install early
//!
//! [`install`] must run before any listener or upstream connector is built.
//! Pingora constructs its upstream connectors while the proxy *service* is
//! created, which is earlier than most callers expect: "before
//! `run_forever()`" is too late. Praxis installs during server bootstrap,
//! ahead of service registration, and on every CLI path that builds a
//! connector.
//!
//! [`CryptoProvider`]: rustls::crypto::CryptoProvider

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

/// Name of the provider compiled into this build.
///
/// Intended for startup logging and for the runtime assertion that the
/// expected provider is the one actually serving connections.
///
/// ```
/// assert_eq!(praxis_tls::provider::name(), "openssl");
/// ```
#[must_use]
pub const fn name() -> &'static str {
    "openssl"
}

/// Build the provider compiled into this build.
fn build() -> CryptoProvider {
    rustls_openssl::default_provider()
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
    fn name_is_the_openssl_provider() {
        assert_eq!(name(), "openssl");
    }
}
