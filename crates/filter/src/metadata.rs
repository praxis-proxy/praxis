// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Bounded per-request string metadata shared across filters and lifecycle phases.

use std::{collections::HashMap, fmt};

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
    /// An owned `key` or `value` whose buffer is larger than its limit is
    /// shrunk to that limit, so the stored entry doesn't keep the excess.
    /// Smaller buffers are stored as they are.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataRejected`], leaving the metadata unchanged and
    /// handing back `key` and `value`, if:
    /// - `key` is empty or longer than 64 bytes
    /// - `value` is longer than 256 bytes
    /// - `key` is new and the metadata already holds 128 entries
    ///
    /// ```
    /// use praxis_filter::{FilterMetadata, MetadataLimit};
    ///
    /// let mut metadata = FilterMetadata::default();
    /// assert_eq!(metadata.insert("request.task_id", "task-1"), Ok(None));
    /// assert_eq!(
    ///     metadata.insert("request.task_id", "task-2"),
    ///     Ok(Some("task-1".to_owned()))
    /// );
    ///
    /// let rejected = metadata.insert("", "value").unwrap_err();
    /// assert_eq!(rejected.limit(), MetadataLimit::KeyLength);
    /// assert_eq!(rejected.into_entry(), (String::new(), "value".to_owned()));
    /// ```
    pub fn insert(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Option<String>, MetadataRejected> {
        let mut key = key.into();
        let mut value = value.into();
        if let Some(limit) = self.exceeded_limit(&key, &value) {
            return Err(MetadataRejected { key, value, limit });
        }
        // A moved-in String keeps its buffer: bound what is retained, not just
        // what is readable. No-op when the capacity is already within the limit.
        key.shrink_to(MAX_KEY_LEN);
        value.shrink_to(MAX_VALUE_LEN);
        Ok(self.entries.insert(key, value))
    }

    /// The limit that storing `value` under `key` would exceed, if any.
    fn exceeded_limit(&self, key: &str, value: &str) -> Option<MetadataLimit> {
        if key.is_empty() || key.len() > MAX_KEY_LEN {
            Some(MetadataLimit::KeyLength)
        } else if value.len() > MAX_VALUE_LEN {
            Some(MetadataLimit::ValueLength)
        } else if !self.entries.contains_key(key) && self.entries.len() >= MAX_ENTRIES {
            Some(MetadataLimit::EntryCount)
        } else {
            None
        }
    }

    /// Drop a write that [`insert`] rejected, logging a warning.
    ///
    /// For writes that may be lost: pass it to [`Result::unwrap_or_else`] on
    /// the result of [`insert`]. It returns `None`, as if the key had no
    /// previous value.
    ///
    /// ```
    /// use praxis_filter::FilterMetadata;
    ///
    /// let mut metadata = FilterMetadata::default();
    /// let replaced = metadata
    ///     .insert("llm.model", "x".repeat(257))
    ///     .unwrap_or_else(FilterMetadata::log_loss);
    /// assert_eq!(replaced, None);
    /// assert!(metadata.is_empty());
    /// ```
    ///
    /// [`insert`]: Self::insert
    pub fn log_loss(rejected: MetadataRejected) -> Option<String> {
        let MetadataRejected { key, value, limit } = rejected;
        match limit {
            MetadataLimit::KeyLength => tracing::warn!(
                key_len = key.len(),
                limit = MAX_KEY_LEN,
                "metadata key rejected (must be 1..=limit bytes)"
            ),
            MetadataLimit::ValueLength => tracing::warn!(
                key = %key,
                value_len = value.len(),
                limit = MAX_VALUE_LEN,
                "metadata value rejected (exceeds limit)"
            ),
            // A rejection for the entry limit means the metadata is full.
            MetadataLimit::EntryCount => tracing::warn!(
                key = %key,
                entries = MAX_ENTRIES,
                "metadata entry rejected (max {} entries)",
                MAX_ENTRIES
            ),
        }
        None
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

/// A write [`FilterMetadata::insert`] rejected, with the key and value it was
/// given, so a caller that moved them in can take them back.
///
/// Its `Display` and `Debug` output show the key and the lengths, never the
/// value, which can be large or sensitive. They omit the key as well when the
/// key itself was rejected.
#[derive(Clone, Eq, PartialEq)]
pub struct MetadataRejected {
    /// The key passed to `insert`, as given.
    key: String,
    /// The value passed to `insert`, as given.
    value: String,
    /// The limit the write exceeded.
    limit: MetadataLimit,
}

impl MetadataRejected {
    /// The limit the write exceeded.
    pub fn limit(&self) -> MetadataLimit {
        self.limit
    }

    /// The key passed to `insert`.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The value passed to `insert`.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The `(key, value)` passed to `insert`, in the buffers they came in.
    pub fn into_entry(self) -> (String, String) {
        (self.key, self.value)
    }
}

impl fmt::Display for MetadataRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.limit {
            MetadataLimit::KeyLength => write!(f, "metadata key must be 1-{MAX_KEY_LEN} bytes, got {}", self.key.len()),
            MetadataLimit::ValueLength => write!(
                f,
                "metadata value for '{}' must not exceed {MAX_VALUE_LEN} bytes, got {}",
                self.key,
                self.value.len()
            ),
            MetadataLimit::EntryCount => write!(
                f,
                "metadata for '{}' rejected: already at {MAX_ENTRIES} entries",
                self.key
            ),
        }
    }
}

impl fmt::Debug for MetadataRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("MetadataRejected");
        debug.field("limit", &self.limit);
        if self.limit != MetadataLimit::KeyLength {
            debug.field("key", &self.key);
        }
        debug
            .field("key_len", &self.key.len())
            .field("value_len", &self.value.len())
            .finish_non_exhaustive()
    }
}

impl std::error::Error for MetadataRejected {}

/// The limit a [`MetadataRejected`] write exceeded.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum MetadataLimit {
    /// The key is empty or longer than 64 bytes.
    KeyLength,
    /// The value is longer than 256 bytes.
    ValueLength,
    /// The key is new and the metadata already holds 128 entries.
    EntryCount,
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
            metadata
                .insert(format!("key.{i}"), "value")
                .expect("entry must fit in the filter's metadata");
        }
        metadata
    }

    #[test]
    fn insert_rejects_empty_and_overlong_keys() {
        let mut metadata = FilterMetadata::default();
        for key in [String::new(), "k".repeat(65)] {
            let len = key.len();
            let rejected = metadata
                .insert(key, "value")
                .expect_err("a key outside 1-64 bytes must be rejected");
            assert_eq!(rejected.limit(), MetadataLimit::KeyLength, "{len}-byte key");
        }
        assert!(metadata.is_empty(), "rejected writes should leave metadata unchanged");
    }

    #[test]
    fn insert_accepts_key_and_value_at_their_limits() {
        let mut metadata = FilterMetadata::default();
        let key = "k".repeat(64);
        let value = "v".repeat(256);
        assert_eq!(
            metadata.insert(key.as_str(), value.as_str()),
            Ok(None),
            "64-byte key and 256-byte value should be accepted"
        );
        assert_eq!(metadata.get(&key), Some(value.as_str()));
    }

    #[test]
    fn insert_rejects_overlong_value() {
        let mut metadata = FilterMetadata::default();
        let rejected = metadata
            .insert("big", "v".repeat(257))
            .expect_err("a 257-byte value must be rejected");
        assert_eq!(rejected.limit(), MetadataLimit::ValueLength);
        assert_eq!(rejected.key(), "big");
        assert_eq!(rejected.value(), "v".repeat(257));
        assert!(!metadata.contains_key("big"), "rejected value should not be stored");
    }

    #[test]
    fn rejected_insert_hands_back_the_moved_buffers() {
        let mut metadata = full_metadata();
        for (key, value, limit) in [
            ("k".repeat(65), "value".to_owned(), MetadataLimit::KeyLength),
            ("big".to_owned(), "v".repeat(257), MetadataLimit::ValueLength),
            ("overflow".to_owned(), "value".to_owned(), MetadataLimit::EntryCount),
        ] {
            let buffers = (key.as_ptr(), value.as_ptr());
            let rejected = metadata.insert(key, value).expect_err("the write must be rejected");
            assert_eq!(rejected.limit(), limit);
            let (key, value) = rejected.into_entry();
            assert_eq!(
                (key.as_ptr(), value.as_ptr()),
                buffers,
                "{limit:?}: the caller gets its own buffers back, not copies"
            );
        }
    }

    #[test]
    fn insert_does_not_retain_excess_capacity() {
        let mut metadata = FilterMetadata::default();
        let mut key = String::with_capacity(4 * MAX_KEY_LEN);
        key.push_str("big.key");
        let mut value = String::with_capacity(1 << 20);
        value.push_str("small");
        metadata
            .insert(key, value)
            .expect("entry must fit in the filter's metadata");

        let (key, value) = metadata.entries.get_key_value("big.key").expect("entry was stored");
        assert!(
            key.capacity() <= MAX_KEY_LEN,
            "key kept {} bytes of capacity",
            key.capacity()
        );
        assert!(
            value.capacity() <= MAX_VALUE_LEN,
            "value kept {} bytes of capacity",
            value.capacity()
        );
    }

    #[test]
    fn insert_keeps_buffers_within_the_limits() {
        let mut metadata = FilterMetadata::default();
        let mut value = String::with_capacity(MAX_VALUE_LEN);
        value.push_str("small");
        let capacity = value.capacity();
        metadata
            .insert("small.key", value)
            .expect("entry must fit in the filter's metadata");

        let value = metadata.entries.get("small.key").expect("entry was stored");
        assert_eq!(value.capacity(), capacity, "a buffer within the limit is moved as is");
    }

    #[test]
    fn insert_rejects_new_key_when_full_but_allows_overwrite() {
        let mut metadata = full_metadata();
        let rejected = metadata
            .insert("overflow", "value")
            .expect_err("a 129th key must be rejected");
        assert_eq!(rejected.limit(), MetadataLimit::EntryCount);
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
        metadata
            .insert("a.key", "1")
            .expect("entry must fit in the filter's metadata");
        metadata
            .insert("b.key", "2")
            .expect("entry must fit in the filter's metadata");

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

    /// A rejection for each limit, each value made of `secret`.
    fn rejections() -> [MetadataRejected; 3] {
        let mut metadata = full_metadata();
        [
            ("k".repeat(65), "secret".to_owned()),
            ("big".to_owned(), "secret".repeat(43)),
            ("overflow".to_owned(), "secret".to_owned()),
        ]
        .map(|(key, value)| metadata.insert(key, value).expect_err("the write must be rejected"))
    }

    #[test]
    fn rejection_messages_name_the_limit_but_not_the_value() {
        let messages = rejections().map(|rejected| rejected.to_string());
        assert_eq!(
            messages,
            [
                "metadata key must be 1-64 bytes, got 65",
                "metadata value for 'big' must not exceed 256 bytes, got 258",
                "metadata for 'overflow' rejected: already at 128 entries",
            ]
        );
    }

    #[test]
    fn rejection_debug_shows_lengths_not_the_value() {
        let debug = rejections().map(|rejected| format!("{rejected:?}"));
        assert_eq!(
            debug,
            [
                "MetadataRejected { limit: KeyLength, key_len: 65, value_len: 6, .. }",
                "MetadataRejected { limit: ValueLength, key: \"big\", key_len: 3, value_len: 258, .. }",
                "MetadataRejected { limit: EntryCount, key: \"overflow\", key_len: 8, value_len: 6, .. }",
            ]
        );
    }
}
