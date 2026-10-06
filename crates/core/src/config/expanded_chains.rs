// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Expanded named filter chains for listener and nested pipeline builds.

use std::collections::HashMap;

use super::{FilterChainConfig, FilterEntry, Listener};

// -----------------------------------------------------------------------------
// Expanded Filter Chains
// -----------------------------------------------------------------------------

/// Named chains with chain-level conditions inherited by every filter entry.
///
/// Use [`Self::for_listener`] for the listener's direct filters and
/// [`Self::as_slices`] for named branch and outbound references. Both paths
/// receive the same effective conditions.
pub struct ExpandedFilterChains<'chains> {
    /// Expanded entries indexed by their declared chain names.
    entries_by_name: HashMap<&'chains str, Vec<FilterEntry>>,
}

impl<'chains> ExpandedFilterChains<'chains> {
    /// Expand each chain once, keeping names borrowed from `chains`.
    #[must_use]
    pub fn new(chains: &'chains [FilterChainConfig]) -> Self {
        let entries_by_name = chains
            .iter()
            .map(|chain| (chain.name.as_str(), chain.expanded_entries()))
            .collect();
        Self { entries_by_name }
    }

    /// Borrow expanded entries for pipeline builders resolving named chains.
    #[must_use]
    pub fn as_slices(&self) -> HashMap<&str, &[FilterEntry]> {
        self.entries_by_name
            .iter()
            .map(|(name, entries)| (*name, entries.as_slice()))
            .collect()
    }

    /// Concatenate the listener's expanded chains in declaration order.
    ///
    /// # Errors
    ///
    /// Returns an error naming the listener and any unknown chain it references.
    pub fn for_listener(&self, listener: &Listener) -> Result<Vec<FilterEntry>, String> {
        listener
            .filter_chains
            .iter()
            .try_fold(Vec::new(), |mut entries, chain_name| {
                let chain_entries = self
                    .entries_by_name
                    .get(chain_name.as_str())
                    .ok_or_else(|| format!("unknown chain '{chain_name}' for listener '{}'", listener.name))?;
                entries.extend_from_slice(chain_entries);
                Ok(entries)
            })
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests use unwrap and indexing for brevity"
)]
mod tests {
    use super::*;
    use crate::config::{Condition, Config};

    #[test]
    fn listener_and_named_refs_share_expanded_conditions() {
        let config = Config::from_yaml(CONDITIONED_CHAINS_YAML).unwrap();
        let expanded = ExpandedFilterChains::new(&config.filter_chains);
        let listener_entries = expanded.for_listener(&config.listeners[0]).unwrap();
        let named_entries = expanded.as_slices();
        let guarded = &named_entries.get("guarded").unwrap()[0];

        assert_eq!(listener_entries.len(), 2, "listener preserves chain order");
        assert_eq!(listener_entries[0].filter_type, "request_id");
        assert_eq!(listener_entries[1].conditions.len(), 2);
        assert_eq!(guarded.conditions.len(), 2, "named references inherit the same gate");
        assert!(
            matches!(&guarded.conditions[0], Condition::When(matcher) if matcher.path_prefix.as_deref() == Some("/api")),
            "the inherited /api condition must precede the filter's own condition"
        );
        assert_eq!(
            config.filter_chains[1].filters[0].conditions.len(),
            1,
            "source remains unchanged"
        );
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// Put a plain chain first so the test can verify listener and condition order.
    const CONDITIONED_CHAINS_YAML: &str = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [plain, guarded]
filter_chains:
  - name: plain
    filters:
      - filter: request_id
  - name: guarded
    conditions:
      - when:
          path_prefix: "/api"
    filters:
      - filter: headers
        conditions:
          - when:
              methods: ["POST"]
"#;
}
