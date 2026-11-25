// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Diagnostics for inline chains identified by application-registered binding factories.

use super::{DEPRECATION_RULES, MAX_SCAN_DEPTH, Scanner, find_filter_deprecations, warn_usage};
use crate::config::{ChainRef, FilterEntry};

/// Reports deprecations in inline outbound chains with a shared per-build budget.
///
/// Application filters decide which fields bind chains. Named chains are already
/// scanned at config load, while inline definitions become visible at binding.
pub struct InlineChainDeprecations {
    /// Completed visits and retained warnings count against subsequent bindings.
    scanner: Scanner<'static, 'static>,
}

impl Default for InlineChainDeprecations {
    fn default() -> Self {
        Self {
            scanner: Scanner {
                rules: DEPRECATION_RULES,
                ..Scanner::default()
            },
        }
    }
}

impl InlineChainDeprecations {
    /// Report newly discovered inline settings after successfully binding a chain.
    pub fn warn(&mut self, chain: &ChainRef) {
        let ChainRef::Inline { name, filters } = chain else {
            return;
        };
        if self.scanner.truncated {
            return;
        }
        let previous = self.scanner.usages.len();
        self.scan_entries(filters, &format!("outbound_chains[{name}].filters"), 0);
        for usage in self.scanner.usages.iter().skip(previous) {
            warn_usage(usage);
        }
        if self.scanner.truncated {
            tracing::warn!(
                item = "deprecation_scan",
                reported = self.scanner.usages.len(),
                "outbound deprecation scan truncated; some deprecated settings may not be reported"
            );
        }
    }

    /// Bound pipelines have already passed branch-depth validation and exclude terminal
    /// filters (including iterative routers). Named branch targets were scanned at load.
    fn scan_entries(&mut self, entries: &[FilterEntry], prefix: &str, depth: usize) {
        if depth >= MAX_SCAN_DEPTH {
            self.scanner.truncated = true;
            return;
        }
        for (index, entry) in entries.iter().enumerate() {
            if !self.scanner.visit() {
                break;
            }
            let path = format!("{prefix}[{index}]");
            find_filter_deprecations(&mut self.scanner, &entry.config, &entry.filter_type, &path, None);
            for (branch_index, branch) in entry.branch_chains.iter().flatten().enumerate() {
                for (chain_index, chain) in branch.chains.iter().enumerate() {
                    if !self.scanner.visit() {
                        return;
                    }
                    if let ChainRef::Inline { filters, .. } = chain {
                        self.scan_entries(
                            filters,
                            &format!("{path}.branch_chains[{branch_index}].chains[{chain_index}].filters"),
                            depth.saturating_add(1),
                        );
                    }
                }
            }
        }
    }
}
