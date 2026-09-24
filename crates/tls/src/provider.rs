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

use std::sync::{
    Arc, Once,
    atomic::{AtomicBool, Ordering},
};

use rustls::crypto::CryptoProvider;

/// Set once [`install`] has made this module's provider the process default.
static INSTALLED_HERE: AtomicBool = AtomicBool::new(false);

/// Runs the install attempt once, so a concurrent caller waits for the
/// winner to record [`INSTALLED_HERE`] instead of reading it early.
static INSTALL: Once = Once::new();

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
/// Installing is not the same as verifying. Use [`any_installed`] to assert
/// that a provider is present and fail startup when it is not, and
/// [`installed`] to tell whether it is this one.
///
/// ```
/// praxis_tls::provider::install();
/// assert!(praxis_tls::provider::installed());
/// ```
pub fn install() -> bool {
    let mut installed = false;
    INSTALL.call_once(|| {
        installed = build().install_default().is_ok();
        if installed {
            INSTALLED_HERE.store(true, Ordering::Release);
        }
    });
    installed
}

/// Whether the compiled-in provider is the process-wide default.
///
/// False when nothing is installed, and also when an embedder installed a
/// different provider first, since that one would then serve every
/// connection.
///
/// ```
/// praxis_tls::provider::install();
/// assert!(praxis_tls::provider::installed());
/// ```
#[must_use]
pub fn installed() -> bool {
    CryptoProvider::get_default().is_some() && INSTALLED_HERE.load(Ordering::Acquire)
}

/// Whether any process-wide provider is installed, compiled-in or not.
///
/// ```
/// praxis_tls::provider::install();
/// assert!(praxis_tls::provider::any_installed());
/// ```
#[must_use]
pub fn any_installed() -> bool {
    CryptoProvider::get_default().is_some()
}

/// What the process knows about FIPS at startup.
///
/// Two independent signals, reported separately so a log line says which one
/// is missing: the kernel's FIPS mode, which on Red Hat Enterprise Linux is
/// what activates the validated OpenSSL provider and the system crypto
/// policy, and the installed rustls provider's own view of whether every
/// primitive it offers is FIPS approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    /// Name of the compiled-in provider.
    pub name: &'static str,
    /// Whether the compiled-in provider is the process-wide default; see
    /// [`installed`].
    pub installed: bool,
    /// Whether the installed provider reports every cipher suite, key exchange
    /// and signature algorithm as FIPS approved (rustls' `CryptoProvider::fips`).
    /// `false` when the compiled-in provider is not installed.
    pub provider_fips: bool,
    /// Whether the kernel is in FIPS mode, from `/proc/sys/crypto/fips_enabled`.
    /// `None` where that file does not exist (a non-Linux host, or a container
    /// without `/proc` mounted).
    pub kernel_fips: Option<bool>,
}

/// Path of the kernel's FIPS mode flag.
const KERNEL_FIPS_FLAG: &str = "/proc/sys/crypto/fips_enabled";

/// Environment variable that makes FIPS mode a hard requirement.
///
/// Set it and praxis refuses to start unless [`Status::unmet`] is empty. Only
/// an empty value, `0`, `false`, `no` or `off` (case-insensitive) leave it
/// off; any other value, a typo included, requires FIPS, so a mistake fails
/// closed. It is a check, never a switch:
/// FIPS mode itself comes from the host (on Red Hat Enterprise Linux, the
/// kernel flag activates the validated OpenSSL provider and the system crypto
/// policy), and praxis never enables a provider on its own.
pub const REQUIRE_FIPS_ENV: &str = "PRAXIS_REQUIRE_FIPS";

/// Whether this deployment requires FIPS mode; see [`REQUIRE_FIPS_ENV`].
#[must_use]
pub fn required() -> bool {
    std::env::var_os(REQUIRE_FIPS_ENV).is_some_and(|value| !is_negative(&value))
}

/// The spellings that leave [`REQUIRE_FIPS_ENV`] off; a value that is not
/// UTF-8 is not one of them.
fn is_negative(value: &std::ffi::OsStr) -> bool {
    value.to_str().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        )
    })
}

impl Status {
    /// Why the process is not in FIPS mode, one reason per missing signal.
    /// Empty when both signals are present.
    #[must_use]
    pub fn unmet(&self) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if !self.installed {
            reasons.push("the OpenSSL provider is not the installed crypto provider");
        } else if !self.provider_fips {
            reasons
                .push("the OpenSSL provider does not report FIPS-approved algorithms (is the fips provider active?)");
        }
        match self.kernel_fips {
            Some(true) => {},
            Some(false) => reasons.push("the kernel is not in FIPS mode (/proc/sys/crypto/fips_enabled is 0)"),
            None => reasons.push("the kernel FIPS flag cannot be read (/proc/sys/crypto/fips_enabled)"),
        }
        reasons
    }
}

/// Read the process's FIPS status.
///
/// Reads the kernel flag on every call; it is cheap and cannot change once the
/// system has booted, so callers may cache it or not as they like.
///
/// ```
/// praxis_tls::provider::install();
/// let status = praxis_tls::provider::status();
/// assert!(status.installed);
/// ```
#[must_use]
pub fn status() -> Status {
    let installed = installed();
    Status {
        name: name(),
        installed,
        provider_fips: installed && CryptoProvider::get_default().is_some_and(|provider| provider.fips()),
        kernel_fips: std::fs::read_to_string(KERNEL_FIPS_FLAG)
            .ok()
            .and_then(|contents| kernel_fips_from(&contents)),
    }
}

/// Interpret the contents of the kernel's FIPS flag.
///
/// The kernel writes a single digit and a newline; anything else is treated as
/// unknown rather than as "off", so a corrupt or unexpected file never reads as
/// a positive or negative claim.
fn kernel_fips_from(contents: &str) -> Option<bool> {
    match contents.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// Fail closed when the deployment requires FIPS mode and a TLS config would
/// not operate in it. `fips` is rustls' answer for that config.
pub(crate) fn check_config_fips(fips: bool, context: &'static str) -> Result<(), crate::TlsError> {
    if required() && !fips {
        return Err(crate::TlsError::FipsRequired { context });
    }
    Ok(())
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

    #[test]
    fn kernel_flag_is_read_strictly() {
        assert_eq!(kernel_fips_from("1\n"), Some(true));
        assert_eq!(kernel_fips_from("0\n"), Some(false));
        assert_eq!(kernel_fips_from("1"), Some(true));
        assert_eq!(kernel_fips_from(""), None, "an empty file is unknown, not off");
        assert_eq!(kernel_fips_from("2\n"), None, "an unexpected value is unknown");
        assert_eq!(kernel_fips_from("garbage"), None);
    }

    #[test]
    fn required_fails_closed_on_unrecognized_values() {
        for value in ["", "0", "false", "FALSE", "no", " Off "] {
            assert!(
                is_negative(std::ffi::OsStr::new(value)),
                "{value:?} should not require FIPS"
            );
        }
        for value in ["1", "true", "yes", "on", "enabled", "y", "maybe"] {
            assert!(
                !is_negative(std::ffi::OsStr::new(value)),
                "{value:?} should require FIPS"
            );
        }
    }

    /// A status with both signals present.
    const SATISFIED: Status = Status {
        name: "openssl",
        installed: true,
        provider_fips: true,
        kernel_fips: Some(true),
    };

    #[test]
    fn unmet_is_empty_when_both_signals_are_present() {
        assert!(SATISFIED.unmet().is_empty());
    }

    #[test]
    fn unmet_names_a_kernel_that_is_not_in_fips_mode() {
        let kernel_off = Status {
            kernel_fips: Some(false),
            ..SATISFIED
        };
        let reasons = kernel_off.unmet();
        assert_eq!(reasons.len(), 1);
        assert!(
            reasons
                .first()
                .is_some_and(|reason| reason.contains("kernel is not in FIPS mode"))
        );
    }

    #[test]
    fn unmet_names_a_provider_that_is_not_fips() {
        let provider_off = Status {
            provider_fips: false,
            ..SATISFIED
        };
        assert!(
            provider_off
                .unmet()
                .first()
                .is_some_and(|reason| reason.contains("OpenSSL provider"))
        );
    }

    #[test]
    fn unmet_reports_a_missing_provider_and_an_unreadable_flag_separately() {
        let nothing = Status {
            installed: false,
            provider_fips: false,
            kernel_fips: None,
            ..SATISFIED
        };
        let reasons = nothing.unmet();
        assert_eq!(reasons.len(), 2);
        assert!(
            reasons
                .first()
                .is_some_and(|reason| reason.contains("not the installed crypto provider"))
        );
        assert!(reasons.get(1).is_some_and(|reason| reason.contains("cannot be read")));
    }

    #[test]
    fn status_reflects_the_installed_provider() {
        install();
        let status = status();
        assert_eq!(status.name, "openssl");
        assert!(status.installed);
        // Whether the provider is FIPS depends on the host's OpenSSL state, so
        // only pin it to what rustls itself says.
        let expected = CryptoProvider::get_default().expect("installed above").fips();
        assert_eq!(status.provider_fips, expected);
        // The kernel flag is host-dependent too; on Linux it is readable and
        // one of the two known values.
        if cfg!(target_os = "linux") && std::path::Path::new(KERNEL_FIPS_FLAG).exists() {
            assert!(status.kernel_fips.is_some(), "the kernel flag must parse on Linux");
        }
    }
}
