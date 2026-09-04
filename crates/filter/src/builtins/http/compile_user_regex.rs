// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Shared compilation of user-provided regex patterns for HTTP filters.

use regex::{Regex, RegexBuilder};

use crate::FilterError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum compiled regex automaton size (bytes, 1 MiB).
const MAX_REGEX_SIZE: usize = 1_048_576; // 1 MiB

// -----------------------------------------------------------------------------
// Compilation
// -----------------------------------------------------------------------------

/// Compile a user-provided regex with a shared size limit.
///
/// Applies a 1 MiB compiled-automaton cap and wraps failures as
/// [`FilterError`] with a consistent `{filter_name}: invalid regex ...` message.
///
/// [`FilterError`]: crate::FilterError
pub(crate) fn compile_user_regex(pattern: &str, filter_name: &str) -> Result<Regex, FilterError> {
    RegexBuilder::new(pattern)
        .size_limit(MAX_REGEX_SIZE)
        .build()
        .map_err(|e| -> FilterError { format!("{filter_name}: invalid regex '{pattern}': {e}").into() })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::compile_user_regex;

    #[test]
    fn compiles_valid_pattern() {
        let re = compile_user_regex("^/api/.*", "path_rewrite").expect("valid regex");
        assert!(re.is_match("/api/v1"), "compiled regex should match /api/v1");
    }

    #[test]
    fn rejects_invalid_pattern_with_filter_name() {
        let err = compile_user_regex("(", "guardrails").expect_err("invalid regex");
        let msg = err.to_string();
        assert!(
            msg.contains("guardrails: invalid regex"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn rejects_pattern_exceeding_size_limit() {
        // Repeated non-capturing groups that exceed the 1 MiB compiled-automaton cap.
        let huge = std::iter::repeat_n("(?:x)", 200_000).collect::<Vec<_>>().join("");
        let err = compile_user_regex(&huge, "test").expect_err("should exceed size limit");
        let msg = err.to_string();
        assert!(
            msg.contains("test: invalid regex"),
            "size-limit error should surface as invalid regex"
        );
    }
}
