// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! YAML input safety checks: size limits and alias expansion guards.

use crate::errors::ProxyError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum raw YAML input size (4 MiB).
const MAX_YAML_BYTES: usize = 4_194_304;

/// Post-parse expansion threshold (16 MiB).
const MAX_EXPANDED_BYTES: usize = 16_777_216;

// -----------------------------------------------------------------------------
// Safety Checks
// -----------------------------------------------------------------------------

/// Reject raw YAML input that exceeds [`MAX_YAML_BYTES`].
///
/// # Errors
///
/// Returns [`ProxyError::Config`] when the input is too large.
///
/// ```ignore
/// use praxis_core::config::check_yaml_safety;
///
/// let small = "listeners: []";
/// check_yaml_safety(small).unwrap();
/// ```
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
pub(crate) fn check_yaml_safety(raw: &str) -> Result<(), ProxyError> {
    check_yaml_size(raw)?;
    check_yaml_expansion(raw, MAX_EXPANDED_BYTES)
}

/// Reject raw YAML that exceeds the size limit.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] when the input exceeds [`MAX_YAML_BYTES`].
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
fn check_yaml_size(raw: &str) -> Result<(), ProxyError> {
    if raw.len() > MAX_YAML_BYTES {
        return Err(ProxyError::Config(format!(
            "YAML input too large ({} bytes, max {MAX_YAML_BYTES})",
            raw.len()
        )));
    }
    Ok(())
}

/// Reject YAML alias expansion that inflates the document beyond `threshold`.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] when the expanded document exceeds the threshold.
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
fn check_yaml_expansion(raw: &str, threshold: usize) -> Result<(), ProxyError> {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(raw) else {
        // Unparseable YAML cannot contain alias bombs; the real parse
        // error is reported by the subsequent Config deserialization.
        return Ok(());
    };
    let Ok(expanded) = serde_yaml::to_string(&value) else {
        return Err(ProxyError::Config(
            "YAML alias expansion check failed: could not re-serialize parsed document".to_owned(),
        ));
    };
    if expanded.len() > threshold {
        return Err(ProxyError::Config(format!(
            "YAML alias expansion too large ({} bytes expanded from {} bytes raw, \
             max {threshold})",
            expanded.len(),
            raw.len()
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn reject_oversized_yaml() {
        let huge = "x".repeat(5 * 1024 * 1024);
        let err = check_yaml_size(&huge).unwrap_err();
        assert!(err.to_string().contains("too large"), "should reject oversized YAML");
    }

    #[test]
    fn accept_small_yaml() {
        check_yaml_size("a: 1\n").expect("small YAML should pass size check");
    }

    #[test]
    fn reject_yaml_alias_bomb() {
        let err = check_yaml_expansion("a: &a x\nb: &b [*a,*a,*a]\nlisteners: []\n", 5);
        assert!(err.is_err(), "should reject expansion exceeding threshold");
        assert!(
            err.unwrap_err().to_string().contains("alias expansion too large"),
            "error message should mention alias expansion"
        );
    }

    #[test]
    fn accept_yaml_within_expansion_threshold() {
        check_yaml_expansion("a: &a x\nb: *a\nlisteners: []\n", 1_000_000)
            .expect("small expansion within threshold should pass");
    }

    #[test]
    fn safety_check_rejects_oversized() {
        let huge = "x".repeat(5 * 1024 * 1024);
        let err = check_yaml_safety(&huge).unwrap_err();
        assert!(err.to_string().contains("too large"), "should reject oversized YAML");
    }

    #[test]
    fn accept_yaml_at_exact_max_size() {
        let exact = "x".repeat(MAX_YAML_BYTES);
        check_yaml_size(&exact).expect("YAML at exactly MAX_YAML_BYTES should pass");
    }

    #[test]
    fn reject_yaml_one_byte_over_max() {
        let over = "x".repeat(MAX_YAML_BYTES + 1);
        let err = check_yaml_size(&over).unwrap_err();
        assert!(err.to_string().contains("too large"), "got: {err}");
    }

    #[test]
    fn safety_check_passes_valid_yaml() {
        check_yaml_safety("a: 1\n").expect("valid small YAML should pass all safety checks");
    }
}
