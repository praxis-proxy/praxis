// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Bounded per-request string metadata shared across filters and lifecycle phases.

use std::collections::HashMap;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum byte length of a metadata key.
pub(crate) const MAX_KEY_LEN: usize = 64; // 64 B

/// Maximum byte length of a metadata value.
pub(crate) const MAX_VALUE_LEN: usize = 256; // 256 B

/// Maximum number of entries in one request's metadata.
///
/// Individual keys and values are already size-bounded ([`MAX_KEY_LEN`] /
/// [`MAX_VALUE_LEN`] bytes), but without an entry count cap a filter chain
/// could insert thousands of unique keys per request.
pub(crate) const MAX_ENTRIES: usize = 128;

// -----------------------------------------------------------------------------
// FilterMetadata
// -----------------------------------------------------------------------------

/// Durable per-request string metadata with bounded size.
///
/// Every key is 1 to 64 bytes long, every value at most 256 bytes, and there
/// are at most 128 entries. Writes go through [`insert`], which rejects any
/// write that would break those bounds, so per-request memory can't grow
/// without limit.
///
/// Keys use dot-prefix namespacing by convention (e.g. `json_rpc.kind`,
/// `classifier.label`).
///
/// ```
/// use praxis_filter::FilterMetadata;
///
/// let mut metadata = FilterMetadata::default();
/// metadata.insert("classifier.label", "GetTask").unwrap();
/// assert_eq!(metadata.get("classifier.label"), Some("GetTask"));
/// assert!(
///     metadata
///         .insert("classifier.label", "x".repeat(257))
///         .is_err()
/// );
/// assert_eq!(metadata.get("classifier.label"), Some("GetTask"));
/// ```
///
/// [`insert`]: Self::insert
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FilterMetadata {
    /// Entries, each within the key and value bounds; at most [`MAX_ENTRIES`].
    entries: HashMap<String, String>,
}

impl FilterMetadata {
    /// The value stored under `key`, or `None` if there is no entry.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    /// Whether there is an entry for `key`.
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Store `value` under `key`, returning the value it replaced, if any.
    ///
    /// Replacing the value of an existing key succeeds even when the metadata
    /// already holds the maximum number of entries.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataRejected`], leaving the metadata unchanged, if:
    /// - `key` is empty or longer than 64 bytes
    /// - `value` is longer than 256 bytes
    /// - `key` is new and the metadata already holds 128 entries
    ///
    /// ```
    /// use praxis_filter::{FilterMetadata, MetadataRejected};
    ///
    /// let mut metadata = FilterMetadata::default();
    /// assert_eq!(metadata.insert("request.task_id", "task-1"), Ok(None));
    /// assert_eq!(
    ///     metadata.insert("request.task_id", "task-2"),
    ///     Ok(Some("task-1".to_owned()))
    /// );
    /// assert_eq!(
    ///     metadata.insert("", "value"),
    ///     Err(MetadataRejected::KeyLength { len: 0 })
    /// );
    /// ```
    pub fn insert(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Option<String>, MetadataRejected> {
        let key = key.into();
        let value = value.into();
        if key.is_empty() || key.len() > MAX_KEY_LEN {
            return Err(MetadataRejected::KeyLength { len: key.len() });
        }
        if value.len() > MAX_VALUE_LEN {
            return Err(MetadataRejected::ValueLength { len: value.len(), key });
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_ENTRIES {
            return Err(MetadataRejected::EntryLimit { key });
        }
        Ok(self.entries.insert(key, value))
    }

    /// Remove the entry for `key`, returning its value, or `None` if there
    /// was no entry.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.entries.remove(key)
    }

    /// Keep only the entries for which `keep` returns `true`.
    ///
    /// ```
    /// use praxis_filter::FilterMetadata;
    ///
    /// let mut metadata = FilterMetadata::default();
    /// metadata.insert("token_count.buf", "1").unwrap();
    /// metadata.insert("token.total", "42").unwrap();
    /// metadata.retain(|key, _| !key.starts_with("token_count."));
    /// assert_eq!(metadata.len(), 1);
    /// assert_eq!(metadata.get("token.total"), Some("42"));
    /// ```
    pub fn retain(&mut self, mut keep: impl FnMut(&str, &str) -> bool) {
        self.entries.retain(|key, value| keep(key, value));
    }

    /// Every entry as a `(key, value)` pair, in arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(key, value)| (key.as_str(), value.as_str()))
    }

    /// Every key, in arbitrary order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Every value, in arbitrary order.
    pub fn values(&self) -> impl Iterator<Item = &str> {
        self.entries.values().map(String::as_str)
    }

    /// Number of entries, at most 128.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// -----------------------------------------------------------------------------
// MetadataRejected
// -----------------------------------------------------------------------------

/// Why [`FilterMetadata::insert`] rejected a write.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum MetadataRejected {
    /// The key is empty or longer than 64 bytes.
    #[error("metadata key must be 1-{limit} bytes, got {len}", limit = MAX_KEY_LEN)]
    KeyLength {
        /// Byte length of the rejected key.
        len: usize,
    },

    /// The value is longer than 256 bytes.
    #[error("metadata value for '{key}' must not exceed {limit} bytes, got {len}", limit = MAX_VALUE_LEN)]
    ValueLength {
        /// Key the value was written under.
        key: String,
        /// Byte length of the rejected value.
        len: usize,
    },

    /// The key is new and the metadata already holds 128 entries.
    #[error("metadata for '{key}' rejected: already at {limit} entries", limit = MAX_ENTRIES)]
    EntryLimit {
        /// Key that would have added an entry.
        key: String,
    },
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    /// Metadata holding exactly [`MAX_ENTRIES`] entries `key.0`..`key.127`.
    fn full_metadata() -> FilterMetadata {
        let mut metadata = FilterMetadata::default();
        for i in 0..MAX_ENTRIES {
            metadata.insert(format!("key.{i}"), "value").unwrap();
        }
        metadata
    }

    #[test]
    fn insert_rejects_empty_and_overlong_keys() {
        let mut metadata = FilterMetadata::default();
        assert_eq!(
            metadata.insert("", "value"),
            Err(MetadataRejected::KeyLength { len: 0 }),
            "empty key should be rejected"
        );
        assert_eq!(
            metadata.insert("k".repeat(65), "value"),
            Err(MetadataRejected::KeyLength { len: 65 }),
            "65-byte key should be rejected"
        );
        assert!(metadata.is_empty(), "rejected writes should leave metadata unchanged");
    }

    #[test]
    fn insert_rejects_overlong_value_and_returns_its_key() {
        let mut metadata = FilterMetadata::default();
        assert_eq!(
            metadata.insert("big", "v".repeat(257)),
            Err(MetadataRejected::ValueLength {
                key: "big".to_owned(),
                len: 257
            }),
            "257-byte value should be rejected"
        );
        assert!(!metadata.contains_key("big"), "rejected value should not be stored");
    }

    #[test]
    fn insert_rejects_new_key_when_full_but_allows_overwrite() {
        let mut metadata = full_metadata();
        assert_eq!(
            metadata.insert("overflow", "value"),
            Err(MetadataRejected::EntryLimit {
                key: "overflow".to_owned()
            }),
            "129th key should be rejected"
        );
        assert_eq!(
            metadata.insert("key.0", "new"),
            Ok(Some("value".to_owned())),
            "overwriting at the limit should succeed and return the old value"
        );
        assert_eq!(metadata.len(), MAX_ENTRIES, "overwrite should not add an entry");
    }

    #[test]
    fn remove_frees_room_for_a_new_key() {
        let mut metadata = full_metadata();
        assert_eq!(metadata.remove("key.0"), Some("value".to_owned()));
        assert_eq!(metadata.remove("key.0"), None, "second remove finds nothing");
        assert_eq!(
            metadata.insert("fresh", "value"),
            Ok(None),
            "freed slot should be reusable"
        );
    }

    #[test]
    fn iterators_yield_every_entry() {
        let mut metadata = FilterMetadata::default();
        metadata.insert("a.key", "1").unwrap();
        metadata.insert("b.key", "2").unwrap();

        let mut pairs: Vec<_> = metadata.iter().collect();
        pairs.sort_unstable();
        assert_eq!(pairs, [("a.key", "1"), ("b.key", "2")]);

        let mut keys: Vec<_> = metadata.keys().collect();
        keys.sort_unstable();
        assert_eq!(keys, ["a.key", "b.key"]);

        let mut values: Vec<_> = metadata.values().collect();
        values.sort_unstable();
        assert_eq!(values, ["1", "2"]);
    }

    #[test]
    fn rejection_messages_name_the_limit() {
        assert_eq!(
            MetadataRejected::KeyLength { len: 65 }.to_string(),
            "metadata key must be 1-64 bytes, got 65"
        );
        assert_eq!(
            MetadataRejected::ValueLength {
                key: "big".to_owned(),
                len: 257
            }
            .to_string(),
            "metadata value for 'big' must not exceed 256 bytes, got 257"
        );
        assert_eq!(
            MetadataRejected::EntryLimit {
                key: "overflow".to_owned()
            }
            .to_string(),
            "metadata for 'overflow' rejected: already at 128 entries"
        );
    }
}
