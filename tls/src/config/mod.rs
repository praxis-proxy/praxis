// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! TLS configuration types: shared primitives and role-specific wrappers.

mod certs;
mod cipher_suite;
mod cluster;
mod listener;

use std::path::{Component, Path};

pub use certs::{CaConfig, CertKeyPair};
pub use cipher_suite::CipherSuiteId;
pub use cluster::ClusterTls;
pub use listener::{ClientCertMode, ListenerTls, TlsVersion};

use crate::TlsError;

// -----------------------------------------------------------------------------
// Path Validation
// -----------------------------------------------------------------------------

/// Check whether a path string contains a [`Component::ParentDir`] (`..`).
///
/// [`Component::ParentDir`]: std::path::Component::ParentDir
pub(crate) fn has_parent_dir_component(path: &str) -> bool {
    Path::new(path).components().any(|c| matches!(c, Component::ParentDir))
}

/// Validate that `sni` is a syntactically valid DNS hostname per [RFC 1035].
///
/// Rejects empty strings, IP literals ([RFC 6066 Section 3]), and
/// hostnames that violate label or length rules.
///
/// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
/// [RFC 6066 Section 3]: https://datatracker.ietf.org/doc/html/rfc6066#section-3
pub(crate) fn validate_sni_hostname(sni: &str) -> Result<(), TlsError> {
    if sni.is_empty() || sni.len() > 253 {
        return Err(TlsError::InvalidSni { value: sni.to_owned() });
    }
    if sni.parse::<std::net::IpAddr>().is_ok() {
        return Err(TlsError::InvalidSni { value: sni.to_owned() });
    }
    for label in sni.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(TlsError::InvalidSni { value: sni.to_owned() });
        }
    }
    Ok(())
}

/// Emit a warning if `path` is a symlink.
pub(crate) fn warn_if_symlink(field: &str, path: &str) {
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        tracing::warn!(field, path, "TLS path is a symlink; the resolved target will be used");
    }
}

// -----------------------------------------------------------------------------
// Serde Utilities
// -----------------------------------------------------------------------------

/// Returning `true` for bool fields that need to default to `true` with Serde.
pub(crate) fn default_true() -> bool {
    true
}

/// Serde skip predicate: true when [`ClientCertMode`] is the default (`None`).
#[expect(clippy::trivially_copy_pass_by_ref, reason = "serde skip_serializing_if requires &T")]
pub(crate) fn is_default_cert_mode(mode: &ClientCertMode) -> bool {
    *mode == ClientCertMode::None
}
