// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Preserve applied policy mutations when a later hook replaces a response.

use http::{HeaderMap, header::HeaderName};

/// Only policy edits survive replacement; handler-originated headers do not.
#[derive(Default)]
pub(crate) struct HeaderEdits {
    /// Final values for fields written by policies.
    written: HeaderMap,
    /// Fields removed by policies.
    removed: Vec<HeaderName>,
}

impl HeaderEdits {
    /// Record changes and explicit writes/removals, even when values match.
    pub(crate) fn record(&mut self, before: &HeaderMap, after: &HeaderMap, touched: &[HeaderName]) {
        for name in before.keys().chain(after.keys()).chain(touched) {
            if !touched.contains(name) && before.get_all(name).iter().eq(after.get_all(name).iter()) {
                continue;
            }
            self.written.remove(name);
            self.removed.retain(|removed| removed != name);
            if after.contains_key(name) {
                for value in after.get_all(name) {
                    self.written.append(name.clone(), value.clone());
                }
            } else {
                self.removed.push(name.clone());
            }
        }
    }

    /// Apply accumulated edits over a new denial's headers in phase order.
    pub(crate) fn apply(&self, headers: &mut HeaderMap) {
        for name in &self.removed {
            headers.remove(name);
        }
        for name in self.written.keys() {
            headers.remove(name);
            for value in self.written.get_all(name) {
                headers.append(name.clone(), value.clone());
            }
        }
    }
}

/// Explicit policy effects cannot be inferred from header value differences.
#[derive(Default)]
pub(crate) struct PolicyHeaders {
    /// Fields written or removed by the current response hook.
    pub(crate) touched: Vec<HeaderName>,
}
