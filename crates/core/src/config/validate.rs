// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Configuration validation rules.

use crate::errors::ProxyError;

mod branch_chain;
pub use branch_chain::{
    MAX_BRANCH_DEPTH, MAX_ITERATIONS_CEILING, count_build_branches, validate_chain_entries_branch_chains,
};
pub(in crate::config) mod cluster;
mod filter_chain;
mod inline_clusters;
mod listener;
mod rules;

pub use cluster::is_ssrf_sensitive;
pub use filter_chain::{TERMINAL_FILTERS, validate_chain_entries_cardinality, validate_chain_entries_conditions};
pub use inline_clusters::validate_chain_entries_inline_clusters;

/// Maximum allowed `max_connections` value across listeners, clusters,
/// and the global runtime setting (1 million).
///
/// Modern Linux systems top out at roughly 1M concurrent connections
/// due to file descriptor limits. Values beyond this are almost
/// certainly operator error.
pub(crate) const MAX_CONNECTIONS: u32 = 1_000_000;

// -----------------------------------------------------------------------------
// Shared Name Validation
// -----------------------------------------------------------------------------

/// Reject names containing characters outside `[a-zA-Z0-9_-]`.
///
/// Used for listener, cluster, and filter chain names to ensure
/// compatibility with metrics labels, log parsing, and routing
/// references.
pub(crate) fn validate_name_chars(name: &str, kind: &str) -> Result<(), ProxyError> {
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(ProxyError::Config(format!(
            "{kind} name '{name}' must contain only ASCII alphanumeric, '_', or '-'"
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Shared Application Identifier Validation
// -----------------------------------------------------------------------------

/// Maximum length, in bytes, of an application metadata identifier
/// (a cluster's `application_protocol` / `application_provider`, or a
/// `bound_upstream` condition matching against them).
pub(crate) const MAX_APPLICATION_IDENTIFIER_LEN: usize = 64;

/// Validate one opaque application metadata identifier.
///
/// The value must be 1..=[`MAX_APPLICATION_IDENTIFIER_LEN`] bytes of
/// lowercase ASCII letters, digits, `.`, `_`, or `-`, and must start and
/// end with a letter or digit. The value itself stays opaque (no
/// protocol or provider name is recognized here), so the same canonical
/// form is enforced wherever these identifiers are declared or matched.
///
/// `context` names the offending location for the error message
/// (e.g. `cluster 'web'` or `filter 'guardrails' in chain 'main':
/// condition 2`).
pub(crate) fn validate_application_identifier(value: &str, field: &str, context: &str) -> Result<(), ProxyError> {
    if value.is_empty() {
        return Err(ProxyError::Config(format!("{context}: {field} must not be empty")));
    }
    if value.len() > MAX_APPLICATION_IDENTIFIER_LEN {
        return Err(ProxyError::Config(format!(
            "{context}: {field} {value:?} exceeds {MAX_APPLICATION_IDENTIFIER_LEN} bytes"
        )));
    }
    let byte_allowed =
        |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-');
    if !value.bytes().all(byte_allowed) {
        return Err(ProxyError::Config(format!(
            "{context}: {field} {value:?} must use only lowercase ASCII \
             letters, digits, '.', '_', or '-'"
        )));
    }
    let alnum_boundary =
        |maybe_byte: Option<&u8>| maybe_byte.is_some_and(|&byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if !alnum_boundary(value.as_bytes().first()) || !alnum_boundary(value.as_bytes().last()) {
        return Err(ProxyError::Config(format!(
            "{context}: {field} {value:?} must start and end with a letter or digit"
        )));
    }
    Ok(())
}
