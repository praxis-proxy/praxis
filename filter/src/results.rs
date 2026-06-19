// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Filter result feedback for branch chain evaluation.

use std::{borrow::Cow, collections::HashMap};

use crate::FilterError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of a result key in bytes.
const MAX_KEY_LEN: usize = 64;

/// Maximum length of a result value in bytes.
const MAX_VALUE_LEN: usize = 256;

// ---------------------------------------------------------------------------
// FilterResultSet
// ---------------------------------------------------------------------------

/// Result feedback from a single filter execution.
///
/// Filters populate this to communicate outcomes
/// (e.g. cache hit/miss, auth success/failure)
/// without knowing about branching.
///
/// ```
/// use praxis_filter::FilterResultSet;
///
/// let mut results = FilterResultSet::new();
/// results.set("status", "hit").unwrap();
/// assert_eq!(results.get("status"), Some("hit"));
/// assert!(results.matches("status", "hit"));
/// assert!(!results.matches("status", "miss"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct FilterResultSet {
    /// Key-value result entries.
    entries: HashMap<Cow<'static, str>, Cow<'static, str>>,
}

impl FilterResultSet {
    /// Create an empty result set.
    ///
    /// ```
    /// use praxis_filter::FilterResultSet;
    ///
    /// let rs = FilterResultSet::new();
    /// assert!(rs.is_empty());
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a result value by key.
    ///
    /// ```
    /// use praxis_filter::FilterResultSet;
    ///
    /// let mut rs = FilterResultSet::new();
    /// rs.set("action", "allow").unwrap();
    /// assert_eq!(rs.get("action"), Some("allow"));
    /// assert_eq!(rs.get("missing"), None);
    /// ```
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(AsRef::as_ref)
    }

    /// Whether the result set has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a key-value pair matches.
    ///
    /// ```
    /// use praxis_filter::FilterResultSet;
    ///
    /// let mut rs = FilterResultSet::new();
    /// rs.set("tier", "premium").unwrap();
    /// assert!(rs.matches("tier", "premium"));
    /// assert!(!rs.matches("tier", "free"));
    /// assert!(!rs.matches("missing", "x"));
    /// ```
    pub fn matches(&self, key: &str, value: &str) -> bool {
        self.get(key).is_some_and(|v| v == value)
    }

    /// Set a result key-value pair.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if:
    /// - `key` is empty, exceeds 64 bytes, or contains non-ASCII-alphanumeric characters (besides `_` and `-`)
    /// - `value` exceeds 256 bytes or contains control characters (0x00-0x1F except 0x09/tab)
    ///
    /// ```
    /// use praxis_filter::FilterResultSet;
    ///
    /// let mut rs = FilterResultSet::new();
    /// assert!(rs.set("valid-key_1", "value").is_ok());
    /// assert!(rs.set("", "value").is_err());
    /// ```
    pub fn set(
        &mut self,
        key: impl Into<Cow<'static, str>>,
        value: impl Into<Cow<'static, str>>,
    ) -> Result<(), FilterError> {
        let key = key.into();
        let value = value.into();
        validate_result_key(&key)?;
        validate_result_value(&value)?;
        self.entries.insert(key, value);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a result key.
fn validate_result_key(key: &str) -> Result<(), FilterError> {
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        let len = key.len();
        return Err(format!("result key must be 1-{MAX_KEY_LEN} bytes, got {len}").into());
    }
    if !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Err(format!("result key '{key}' must be ASCII alphanumeric, '_', or '-'").into());
    }
    Ok(())
}

/// Validate a result value.
fn validate_result_value(value: &str) -> Result<(), FilterError> {
    if value.len() > MAX_VALUE_LEN {
        let len = value.len();
        return Err(format!("result value must not exceed {MAX_VALUE_LEN} bytes, got {len}").into());
    }
    if value.bytes().any(|b| (b < 0x20 && b != 0x09) || b == 0x7F) {
        return Err("result value must not contain control characters".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    #[test]
    fn new_is_empty() {
        let rs = FilterResultSet::new();
        assert!(rs.is_empty(), "new result set should be empty");
    }

    #[test]
    fn set_and_get() {
        let mut rs = FilterResultSet::new();
        rs.set("status", "hit").unwrap();
        assert_eq!(rs.get("status"), Some("hit"), "should return set value");
        assert!(!rs.is_empty(), "should not be empty after set");
    }

    #[test]
    fn get_missing_key() {
        let rs = FilterResultSet::new();
        assert_eq!(rs.get("missing"), None, "missing key should return None");
    }

    #[test]
    fn matches_true() {
        let mut rs = FilterResultSet::new();
        rs.set("status", "hit").unwrap();
        assert!(rs.matches("status", "hit"), "exact match should return true");
    }

    #[test]
    fn matches_false_wrong_value() {
        let mut rs = FilterResultSet::new();
        rs.set("status", "hit").unwrap();
        assert!(!rs.matches("status", "miss"), "wrong value should return false");
    }

    #[test]
    fn matches_false_missing_key() {
        let rs = FilterResultSet::new();
        assert!(!rs.matches("status", "hit"), "missing key should return false");
    }

    #[test]
    fn set_overwrites_existing() {
        let mut rs = FilterResultSet::new();
        rs.set("status", "hit").unwrap();
        rs.set("status", "miss").unwrap();
        assert_eq!(rs.get("status"), Some("miss"), "second set should overwrite");
    }

    #[test]
    fn set_multiple_keys() {
        let mut rs = FilterResultSet::new();
        rs.set("status", "hit").unwrap();
        rs.set("tier", "premium").unwrap();
        assert_eq!(rs.get("status"), Some("hit"), "first key should be retained");
        assert_eq!(rs.get("tier"), Some("premium"), "second key should be present");
    }

    #[test]
    fn reject_empty_key() {
        let mut rs = FilterResultSet::new();
        let err = rs.set("", "value").unwrap_err();
        assert!(
            err.to_string().contains("1-64 bytes"),
            "empty key error should mention size constraint: {err}"
        );
    }

    #[test]
    fn reject_key_too_long() {
        let mut rs = FilterResultSet::new();
        let long_key = "a".repeat(65);
        let err = rs.set(long_key, "value").unwrap_err();
        assert!(
            err.to_string().contains("1-64 bytes"),
            "long key error should mention size constraint: {err}"
        );
    }

    #[test]
    fn accept_key_at_max_length() {
        let mut rs = FilterResultSet::new();
        let key = "a".repeat(64);
        assert!(rs.set(key, "value").is_ok(), "64-byte key should be accepted");
    }

    #[test]
    fn reject_key_with_spaces() {
        let mut rs = FilterResultSet::new();
        let err = rs.set("bad key", "value").unwrap_err();
        assert!(
            err.to_string().contains("alphanumeric"),
            "key with spaces should be rejected: {err}"
        );
    }

    #[test]
    fn reject_key_with_special_chars() {
        let mut rs = FilterResultSet::new();
        let err = rs.set("key.dot", "value").unwrap_err();
        assert!(
            err.to_string().contains("alphanumeric"),
            "key with dots should be rejected: {err}"
        );
    }

    #[test]
    fn accept_key_with_underscore_and_hyphen() {
        let mut rs = FilterResultSet::new();
        assert!(
            rs.set("my-key_1", "value").is_ok(),
            "key with underscore and hyphen should be accepted"
        );
    }

    #[test]
    fn reject_value_too_long() {
        let mut rs = FilterResultSet::new();
        let long_value = "x".repeat(257);
        let err = rs.set("key", long_value).unwrap_err();
        assert!(
            err.to_string().contains("256 bytes"),
            "long value error should mention size constraint: {err}"
        );
    }

    #[test]
    fn accept_value_at_max_length() {
        let mut rs = FilterResultSet::new();
        let value = "x".repeat(256);
        assert!(rs.set("key", value).is_ok(), "256-byte value should be accepted");
    }

    #[test]
    fn reject_value_with_control_chars() {
        let mut rs = FilterResultSet::new();
        let err = rs.set("key", "line\x00null").unwrap_err();
        assert!(
            err.to_string().contains("control characters"),
            "value with null byte should be rejected: {err}"
        );
    }

    #[test]
    fn reject_value_with_newline() {
        let mut rs = FilterResultSet::new();
        let err = rs.set("key", "line\nbreak").unwrap_err();
        assert!(
            err.to_string().contains("control characters"),
            "value with newline should be rejected: {err}"
        );
    }

    #[test]
    fn accept_value_with_tab() {
        let mut rs = FilterResultSet::new();
        assert!(rs.set("key", "col1\tcol2").is_ok(), "value with tab should be accepted");
    }

    #[test]
    fn reject_value_with_del() {
        let mut rs = FilterResultSet::new();
        let err = rs.set("key", "before\x7Fafter").unwrap_err();
        assert!(
            err.to_string().contains("control characters"),
            "value with DEL (0x7F) should be rejected: {err}"
        );
    }

    #[test]
    fn accept_empty_value() {
        let mut rs = FilterResultSet::new();
        assert!(rs.set("key", "").is_ok(), "empty value should be accepted");
    }

    #[test]
    fn default_is_empty() {
        let rs = FilterResultSet::default();
        assert!(rs.is_empty(), "default result set should be empty");
    }

    #[test]
    fn clone_preserves_entries() {
        let mut rs = FilterResultSet::new();
        rs.set("a", "1").unwrap();
        let cloned = rs.clone();
        assert_eq!(cloned.get("a"), Some("1"), "clone should preserve entries");
    }

    #[test]
    fn set_with_cow_borrowed() {
        let mut rs = FilterResultSet::new();
        rs.set(Cow::Borrowed("static_key"), Cow::Borrowed("static_val"))
            .unwrap();
        assert_eq!(rs.get("static_key"), Some("static_val"), "Cow::Borrowed should work");
    }

    #[test]
    fn set_with_cow_owned() {
        let mut rs = FilterResultSet::new();
        rs.set(
            Cow::<str>::Owned("owned_key".to_owned()),
            Cow::<str>::Owned("owned_val".to_owned()),
        )
        .unwrap();
        assert_eq!(rs.get("owned_key"), Some("owned_val"), "Cow::Owned should work");
    }
}
