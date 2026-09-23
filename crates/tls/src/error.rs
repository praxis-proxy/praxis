// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! TLS error types.

use thiserror::Error;

use crate::ClientCertMode;

// -----------------------------------------------------------------------------
// TlsError
// -----------------------------------------------------------------------------

/// Errors from TLS configuration validation.
///
/// ```
/// use praxis_tls::TlsError;
///
/// let e = TlsError::PathTraversal {
///     field: "cert_path".to_owned(),
///     path: "/etc/../../tmp/evil.pem".to_owned(),
/// };
/// assert!(e.to_string().contains("path traversal"));
///
/// let e = TlsError::FileLoadError {
///     path: "/etc/ssl/cert.pem".to_owned(),
///     detail: "file not found".to_owned(),
/// };
/// assert!(e.to_string().contains("failed to load TLS file"));
/// ```
#[derive(Debug, Error)]
pub enum TlsError {
    /// A certificate has no `server_names` and `default` is not set to `true`.
    #[error("certificate {path} has no server_names and is not marked default: true; this is ambiguous")]
    AmbiguousCert {
        /// The path of the ambiguous certificate.
        path: String,
    },

    /// TLS client configuration construction failed (e.g. malformed CA bundle,
    /// client cert/key mismatch, or an unsupported protocol version).
    #[cfg(feature = "spiffe")]
    #[error("TLS client config error: {detail}")]
    ClientConfigError {
        /// Underlying error description.
        detail: String,
    },

    /// `build_client_verifier` was called with `ClientCertMode::None`.
    #[error("build_client_verifier must not be called with client_cert_mode=None")]
    ClientVerifierNotRequired,

    /// No crypto provider has been installed for this process.
    ///
    /// Praxis installs one during server bootstrap. Reaching this means TLS
    /// was built before that ran, or the install was skipped. There is no
    /// fallback by design: substituting a provider nobody selected is what
    /// this error exists to prevent.
    #[error(
        "no crypto provider installed; praxis_tls::provider::install() must run during startup, \
         before any listener or upstream connector is built"
    )]
    NoCryptoProvider,

    /// FIPS mode is required (`PRAXIS_REQUIRE_FIPS`) but this TLS config would
    /// not operate in it.
    ///
    /// rustls' `fips()` on a config is false when the provider is not running
    /// FIPS-approved algorithms only, or when TLS 1.2 is allowed without the
    /// Extended Master Secret. Praxis sets the latter unconditionally, so in
    /// practice this means the OpenSSL provider is not in FIPS mode.
    #[error("FIPS mode is required but the {context} TLS config would not operate in FIPS mode")]
    FipsRequired {
        /// Which config: "listener" or "upstream client".
        context: &'static str,
    },

    /// A `server_name` appears more than once across certificates.
    #[error("duplicate server_name '{name}' in certificate {path}")]
    DuplicateServerName {
        /// The duplicated server name.
        name: String,

        /// The certificate path that introduced the duplicate.
        path: String,
    },

    /// `cipher_suites` was set to an empty list.
    #[error("cipher_suites must not be empty; omit the field to accept all suites")]
    EmptyCipherSuites,

    /// Failed to load or parse a TLS file (certificate, key, or CA).
    #[error("failed to load TLS file {path}: {detail}")]
    FileLoadError {
        /// The path that failed to load.
        path: String,

        /// Underlying error description.
        detail: String,
    },

    /// Cannot enable hot-reload with multiple certificates (SNI).
    #[error("hot_reload requires exactly one certificate; multi-cert SNI configs are not supported")]
    HotReloadMultipleCerts,

    /// The cluster SNI value is not a valid DNS hostname.
    #[error("sni must be a valid DNS hostname: {value}")]
    InvalidSni {
        /// The offending SNI value.
        value: String,
    },

    /// `client_cert_mode` is `request` or `require` but `client_ca` is not set.
    #[error("client_ca is required when client_cert_mode is {mode:?}")]
    MissingClientCa {
        /// The mode that requires a CA.
        mode: ClientCertMode,
    },

    /// More than one certificate has `default: true`.
    #[error("multiple certificates are marked default: true; only one default certificate is allowed")]
    MultipleDefaults,

    /// No certificates provided in listener TLS config.
    #[error("at least one certificate is required in listener TLS config")]
    NoCertificates,

    /// A TLS path contains `..` (directory traversal).
    #[error("TLS {field} must not contain path traversal (..): {path}")]
    PathTraversal {
        /// Which field failed validation (e.g. "`cert_path`").
        field: String,

        /// The offending path value.
        path: String,
    },

    /// TLS server configuration construction failed (e.g. cert/key
    /// mismatch, unsupported protocol version).
    #[error("TLS server config error: {detail}")]
    ServerConfigError {
        /// Underlying error description.
        detail: String,
    },

    /// `cipher_suites` contains TLS 1.2 suites but `min_version` is `tls13`.
    #[error("cipher_suites contains TLS 1.2 suites but min_version is tls13; use only TLS 1.3 suites")]
    Tls12SuiteWithTls13Only,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn error_display_path_traversal() {
        let err = TlsError::PathTraversal {
            field: "key_path".to_owned(),
            path: "../secret/key.pem".to_owned(),
        };
        assert!(
            err.to_string().contains("path traversal"),
            "should mention path traversal"
        );
        assert!(err.to_string().contains("key_path"), "should mention key_path field");
    }

    #[test]
    fn error_display_missing_client_ca() {
        let err = TlsError::MissingClientCa {
            mode: ClientCertMode::Require,
        };
        assert!(
            err.to_string().contains("client_ca"),
            "should mention missing client_ca: {err}"
        );
    }

    #[test]
    fn error_display_no_certificates() {
        let err = TlsError::NoCertificates;
        assert!(
            err.to_string().contains("at least one certificate"),
            "should mention certificate requirement"
        );
    }

    #[test]
    fn error_display_duplicate_server_name() {
        let err = TlsError::DuplicateServerName {
            name: "api.example.com".to_owned(),
            path: "/certs/server.pem".to_owned(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate server_name"),
            "should mention duplicate server_name: {msg}"
        );
        assert!(
            msg.contains("api.example.com"),
            "should mention the duplicated name: {msg}"
        );
    }

    #[test]
    fn error_display_hot_reload_multiple_certs() {
        let err = TlsError::HotReloadMultipleCerts;
        assert!(
            err.to_string().contains("hot_reload"),
            "should mention hot_reload: {err}"
        );
    }

    #[test]
    fn error_display_client_verifier_not_required() {
        let err = TlsError::ClientVerifierNotRequired;
        let msg = err.to_string();
        assert!(
            msg.contains("client_cert_mode=None"),
            "should mention client_cert_mode=None: {msg}"
        );
    }

    #[test]
    fn error_display_ambiguous_cert() {
        let err = TlsError::AmbiguousCert {
            path: "/etc/ssl/mystery.pem".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("ambiguous"), "should mention ambiguous: {msg}");
        assert!(msg.contains("default: true"), "should mention default: true: {msg}");
    }

    #[test]
    fn error_display_multiple_defaults() {
        let err = TlsError::MultipleDefaults;
        let msg = err.to_string();
        assert!(msg.contains("multiple"), "should mention multiple: {msg}");
        assert!(
            msg.contains("only one default"),
            "should mention only one default: {msg}"
        );
    }

    #[test]
    fn error_display_empty_cipher_suites() {
        let err = TlsError::EmptyCipherSuites;
        let msg = err.to_string();
        assert!(
            msg.contains("cipher_suites must not be empty"),
            "should mention empty cipher_suites: {msg}"
        );
    }

    #[test]
    fn error_display_server_config_error() {
        let err = TlsError::ServerConfigError {
            detail: "cert/key mismatch".to_owned(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("TLS server config error"),
            "should mention server config error: {msg}"
        );
        assert!(msg.contains("cert/key mismatch"), "should contain detail: {msg}");
    }

    #[test]
    fn error_display_tls12_suite_with_tls13_only() {
        let err = TlsError::Tls12SuiteWithTls13Only;
        let msg = err.to_string();
        assert!(msg.contains("TLS 1.2 suites"), "should mention TLS 1.2 suites: {msg}");
        assert!(msg.contains("tls13"), "should mention tls13: {msg}");
    }

    #[test]
    fn error_display_invalid_sni() {
        let err = TlsError::InvalidSni {
            value: "not a valid hostname!".to_owned(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("sni must be a valid DNS hostname"),
            "should mention SNI validation: {msg}"
        );
        assert!(
            msg.contains("not a valid hostname!"),
            "should contain the invalid value: {msg}"
        );
    }
}
