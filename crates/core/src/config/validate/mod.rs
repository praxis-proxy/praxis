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

/// Maximum nesting depth for filter entries that carry other filter
/// entries: inline branch chains and `iterative_request_router`
/// `steps[].filters`.
///
/// Both chain-validation walks recurse through those nested entries, so
/// without a ceiling a crafted config nests deep enough to exhaust the
/// stack before any other limit applies. Set to [`MAX_BRANCH_DEPTH`] so a
/// config the branch validator accepts is never rejected here.
pub(crate) const MAX_NESTED_FILTER_DEPTH: usize = MAX_BRANCH_DEPTH;

/// Depth of the entries nested one level below `depth`.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] once the next level would pass
/// [`MAX_NESTED_FILTER_DEPTH`].
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
pub(crate) fn nested_filter_depth(depth: usize, chain_name: &str) -> Result<usize, ProxyError> {
    (depth < MAX_NESTED_FILTER_DEPTH).then_some(depth + 1).ok_or_else(|| {
        ProxyError::Config(format!(
            "chain '{chain_name}': filter nesting depth exceeds maximum \
             ({MAX_NESTED_FILTER_DEPTH}); inline branch chains and \
             iterative_request_router steps nest at most \
             {MAX_NESTED_FILTER_DEPTH} levels deep"
        ))
    })
}

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
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ProxyError::Config(format!(
            "{kind} name '{name}' must contain only ASCII alphanumeric, '_', or '-'"
        )));
    }
    Ok(())
}
