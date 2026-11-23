// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Checked counters for route-scoped payload transfer.

use crate::FilterError;

/// Checked transfer accounting independent of global buffering limits.
pub struct LocalByteCounter {
    /// Accepted bytes.
    total: u64,
    /// Finite route ceiling.
    limit: u64,
}

impl LocalByteCounter {
    /// Start a route-scoped counter.
    pub fn new(limit: u64) -> Self {
        Self { total: 0, limit }
    }

    /// Accepted transfer bytes.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Overflow and limit excess are equivalent violations.
    ///
    /// # Errors
    /// Returns an error without modifying the counter if the limit is exceeded.
    pub fn add(&mut self, bytes: u64) -> Result<(), FilterError> {
        let total = self
            .total
            .checked_add(bytes)
            .filter(|total| *total <= self.limit)
            .ok_or("local transfer limit exceeded")?;
        self.total = total;
        Ok(())
    }
}
