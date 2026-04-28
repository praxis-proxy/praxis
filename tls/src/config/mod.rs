// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! TLS configuration types: shared primitives and role-specific wrappers.

mod certs;
mod cluster;
mod listener;

use std::path::{Component, Path};

pub use certs::{CaConfig, CertKeyPair};
pub use cluster::ClusterTls;
pub use listener::{CipherSuiteId, ClientCertMode, ListenerTls, TlsVersion};

// -----------------------------------------------------------------------------
// Path Validation
// -----------------------------------------------------------------------------

/// Check whether a path string contains a [`Component::ParentDir`] (`..`).
///
/// [`Component::ParentDir`]: std::path::Component::ParentDir
pub(crate) fn has_parent_dir_component(path: &str) -> bool {
    Path::new(path).components().any(|c| matches!(c, Component::ParentDir))
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
pub(crate) fn is_default_cert_mode(mode: &ClientCertMode) -> bool {
    *mode == ClientCertMode::None
}
