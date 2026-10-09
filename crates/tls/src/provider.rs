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
/// Three independent signals, reported separately so a log line says which
/// one is missing: the installed rustls provider's own view of whether every
/// primitive it offers is FIPS approved (on the OpenSSL-backed provider this
/// reflects `EVP_default_properties_is_fips_enabled`, the system's effective
/// FIPS property, queried through the provider's safe API), the kernel's
/// FIPS mode from `/proc/sys/crypto/fips_enabled`, and the system crypto
/// policy from `/etc/crypto-policies/config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// Name of the compiled-in provider.
    pub name: &'static str,
    /// Whether the compiled-in provider is the process-wide default; see
    /// [`installed`].
    pub installed: bool,
    /// Whether the installed provider reports every cipher suite, key exchange
    /// and signature algorithm as FIPS approved (rustls'
    /// `CryptoProvider::fips`). On the OpenSSL-backed provider this reflects
    /// `EVP_default_properties_is_fips_enabled`, the host's effective FIPS
    /// property, queried through the provider's safe API. `false` when the
    /// compiled-in provider is not installed.
    pub provider_fips: bool,
    /// Whether the kernel is in FIPS mode, from `/proc/sys/crypto/fips_enabled`.
    /// `None` where that file does not exist (a non-Linux host, or a container
    /// without `/proc` mounted).
    pub kernel_fips: Option<bool>,
    /// The active system crypto policy from `/etc/crypto-policies/config`,
    /// or `None` on platforms without crypto-policies support.
    pub crypto_policy: Option<String>,
}

/// Path of the kernel's FIPS mode flag.
const KERNEL_FIPS_FLAG: &str = "/proc/sys/crypto/fips_enabled";

/// Path of the system crypto policy configuration.
const CRYPTO_POLICIES_CONFIG: &str = "/etc/crypto-policies/config";

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
    /// Empty when all signals are present.
    #[must_use]
    pub fn unmet(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if !self.installed {
            reasons.push("the OpenSSL provider is not the installed crypto provider".into());
        } else if !self.provider_fips {
            reasons.push(
                "the OpenSSL provider does not report FIPS-approved algorithms (is the fips provider active?)".into(),
            );
        }
        self.push_kernel_reason(&mut reasons);
        self.push_crypto_policy_reason(&mut reasons);
        reasons
    }

    /// `None` means the file is unreadable (e.g. a container without `/proc`),
    /// which is a distinct failure from `Some(false)`.
    fn push_kernel_reason(&self, reasons: &mut Vec<String>) {
        match self.kernel_fips {
            Some(true) => {},
            Some(false) => reasons.push("the kernel is not in FIPS mode (/proc/sys/crypto/fips_enabled is 0)".into()),
            None => reasons.push("the kernel FIPS flag cannot be read (/proc/sys/crypto/fips_enabled)".into()),
        }
    }

    /// `None` covers both absent and empty files, per the `crypto_policy_from`
    /// parser.
    fn push_crypto_policy_reason(&self, reasons: &mut Vec<String>) {
        match &self.crypto_policy {
            Some(policy) if is_fips_policy(policy) => {},
            Some(policy) => reasons.push(format!(
                "the system crypto policy is {policy:?}, not FIPS (/etc/crypto-policies/config)"
            )),
            None => {
                reasons.push(
                    "the system crypto policy cannot be read (/etc/crypto-policies/config is absent or empty)".into(),
                );
            },
        }
    }
}

/// Read the process's FIPS status.
///
/// Reads the kernel flag and the system crypto policy on every call; both
/// are cheap to read. The kernel flag is fixed at boot, but the crypto
/// policy can change at runtime (`update-crypto-policies --set`).
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
        crypto_policy: system_crypto_policy(),
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

/// The active system crypto policy, or `None` on platforms without
/// crypto-policies support.
fn system_crypto_policy() -> Option<String> {
    let contents = std::fs::read_to_string(CRYPTO_POLICIES_CONFIG).ok()?;
    crypto_policy_from(&contents)
}

/// The first non-comment, non-blank line from a crypto-policies config.
fn crypto_policy_from(contents: &str) -> Option<String> {
    contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
}

/// Whether the policy is `FIPS`, alone or restricted by `OSPP`. Any other
/// subpolicy (`NO-ENFORCE-EMS`, `SHA1`) loosens FIPS and is rejected.
fn is_fips_policy(policy: &str) -> bool {
    let mut parts = policy.split(':');
    parts.next() == Some("FIPS") && parts.all(|sub| sub == "OSPP")
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

    /// A status with all signals present and positive.
    fn satisfied() -> Status {
        Status {
            name: "openssl",
            installed: true,
            provider_fips: true,
            kernel_fips: Some(true),
            crypto_policy: Some("FIPS".to_owned()),
        }
    }

    #[test]
    fn unmet_is_empty_when_all_signals_are_present() {
        assert!(
            satisfied().unmet().is_empty(),
            "all signals present means no unmet reasons"
        );
    }

    #[test]
    fn unmet_names_a_kernel_that_is_not_in_fips_mode() {
        let kernel_off = Status {
            kernel_fips: Some(false),
            ..satisfied()
        };
        let reasons = kernel_off.unmet();
        assert_eq!(reasons.len(), 1, "only the kernel signal is unmet");
        assert!(
            reasons
                .first()
                .is_some_and(|reason| reason.contains("kernel is not in FIPS mode")),
            "the reason must name the kernel FIPS flag"
        );
    }

    #[test]
    fn unmet_names_a_provider_that_is_not_fips() {
        let provider_off = Status {
            provider_fips: false,
            ..satisfied()
        };
        assert!(
            provider_off
                .unmet()
                .first()
                .is_some_and(|reason| reason.contains("OpenSSL provider")),
            "the reason must name the OpenSSL provider"
        );
    }

    #[test]
    fn unmet_names_a_non_fips_crypto_policy() {
        let default_policy = Status {
            crypto_policy: Some("DEFAULT".to_owned()),
            ..satisfied()
        };
        let reasons = default_policy.unmet();
        assert_eq!(reasons.len(), 1, "only the crypto policy signal is unmet");
        assert!(
            reasons.first().is_some_and(|reason| reason.contains("crypto policy")),
            "the reason must name the crypto policy"
        );
    }

    #[test]
    fn unmet_names_a_missing_crypto_policy() {
        let no_policy = Status {
            crypto_policy: None,
            ..satisfied()
        };
        let reasons = no_policy.unmet();
        assert_eq!(reasons.len(), 1, "only the crypto policy signal is unmet");
        assert!(
            reasons
                .first()
                .is_some_and(|reason| reason.contains("crypto policy") && reason.contains("absent")),
            "the reason must name the absent crypto policy"
        );
    }

    #[test]
    fn unmet_reports_every_missing_signal_separately() {
        let nothing = Status {
            name: "openssl",
            installed: false,
            provider_fips: false,
            kernel_fips: None,
            crypto_policy: None,
        };
        let reasons = nothing.unmet();
        assert_eq!(reasons.len(), 3, "provider, kernel, and policy: {reasons:?}");
        assert!(
            reasons
                .first()
                .is_some_and(|reason| reason.contains("not the installed crypto provider")),
            "first reason must name the missing provider"
        );
        assert!(
            reasons.get(1).is_some_and(|reason| reason.contains("cannot be read")),
            "second reason must name the unreadable kernel flag"
        );
        assert!(
            reasons.get(2).is_some_and(|reason| reason.contains("crypto policy")),
            "third reason must name the missing crypto policy"
        );
    }

    #[test]
    fn crypto_policy_parser_extracts_the_first_real_line() {
        assert_eq!(
            crypto_policy_from("# comment\n\nFIPS\n").as_deref(),
            Some("FIPS"),
            "skips comments and blanks"
        );
        assert_eq!(
            crypto_policy_from("FIPS:OSPP\n").as_deref(),
            Some("FIPS:OSPP"),
            "preserves subpolicies"
        );
        assert_eq!(
            crypto_policy_from("DEFAULT\n").as_deref(),
            Some("DEFAULT"),
            "non-FIPS policy is still parsed"
        );
        assert_eq!(crypto_policy_from(""), None, "empty file yields None");
        assert_eq!(
            crypto_policy_from("# only comments\n"),
            None,
            "comments-only file yields None"
        );
    }

    #[test]
    fn fips_policy_variants_are_accepted() {
        assert!(is_fips_policy("FIPS"), "bare FIPS must be accepted");
        assert!(
            is_fips_policy("FIPS:OSPP"),
            "FIPS:OSPP tightens FIPS and must be accepted"
        );
    }

    #[test]
    fn fips_policy_lookalikes_are_rejected() {
        assert!(!is_fips_policy("FIPSXYZ"), "FIPSXYZ is not a FIPS policy");
        assert!(!is_fips_policy("FIPS-DRAFT"), "FIPS-DRAFT is not a FIPS policy");
        assert!(!is_fips_policy("fips"), "lowercase fips is not a FIPS policy");
        assert!(
            !is_fips_policy("DEFAULT:FIPS"),
            "FIPS as a subpolicy of DEFAULT is not a FIPS policy"
        );
        assert!(!is_fips_policy("DEFAULT"), "DEFAULT is not a FIPS policy");
        assert!(
            !is_fips_policy("FIPS:NO-ENFORCE-EMS"),
            "NO-ENFORCE-EMS loosens FIPS and must be rejected"
        );
        assert!(!is_fips_policy("FIPS:SHA1"), "SHA1 loosens FIPS and must be rejected");
    }

    #[test]
    fn status_reflects_the_installed_provider() {
        install();
        let status = status();
        assert_eq!(status.name, "openssl");
        assert!(status.installed);
        let expected = CryptoProvider::get_default().expect("installed above").fips();
        assert_eq!(status.provider_fips, expected);
        if cfg!(target_os = "linux") && std::path::Path::new(KERNEL_FIPS_FLAG).exists() {
            assert!(status.kernel_fips.is_some(), "the kernel flag must parse on Linux");
        }
        if std::path::Path::new(CRYPTO_POLICIES_CONFIG).exists() {
            assert!(
                status.crypto_policy.is_some(),
                "the crypto policy must parse when the file exists"
            );
        }
    }
}
