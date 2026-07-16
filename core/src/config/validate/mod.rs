// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Configuration validation rules.

use crate::errors::ProxyError;

mod branch_chain;
pub use branch_chain::{MAX_BRANCH_DEPTH, MAX_ITERATIONS_CEILING};
mod cluster;
mod filter_chain;
mod listener;
mod rules;

pub use cluster::is_ssrf_sensitive;

/// Maximum allowed `max_connections` value across listeners, clusters,
/// and the global runtime setting (1 million).
///
/// Modern Linux systems top out at roughly 1M concurrent connections
/// due to file descriptor limits. Values beyond this are almost
/// certainly operator error.
pub(crate) const MAX_CONNECTIONS: u32 = 1_000_000;

// ---------------------------------------------------------------------------
// Shared Name Validation
// ---------------------------------------------------------------------------

/// Reject names containing characters outside `[a-zA-Z0-9_-]`.
///
/// Used for listener, cluster, and filter chain names to ensure
/// compatibility with metrics labels, log parsing, and routing
/// references.
pub(crate) fn validate_name_chars(name: &str, kind: &str) -> Result<(), ProxyError> {
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ProxyError::Config(format!(
            "{kind} name '{name}' must contain only ASCII alphanumeric, '_', or '-'"
        )));
    }
    Ok(())
}
