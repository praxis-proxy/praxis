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

/// Maximum number of pattern characters echoed in error messages.
const MAX_PATTERN_ECHO_CHARS: usize = 128;

// -----------------------------------------------------------------------------
// Compilation
// -----------------------------------------------------------------------------

/// Compile a user-provided regex with a shared size limit.
///
/// Applies a 1 MiB compiled-automaton cap and wraps failures as
/// [`FilterError`] with a consistent `{filter_name}: invalid regex ...` message.
/// The echoed pattern is truncated to 128 characters and only the final
/// line of the regex error (the diagnosis, without the pattern echo) is
/// included, keeping error messages and logs bounded.
///
/// [`FilterError`]: crate::FilterError
pub(crate) fn compile_user_regex(pattern: &str, filter_name: &str) -> Result<Regex, FilterError> {
    RegexBuilder::new(pattern)
        .size_limit(MAX_REGEX_SIZE)
        .build()
        .map_err(|e| -> FilterError {
            let shown = truncate_chars(pattern, MAX_PATTERN_ECHO_CHARS);
            let ellipsis = if shown.len() < pattern.len() { "..." } else { "" };
            let rendered = e.to_string();
            let reason = rendered.lines().last().unwrap_or_default().trim();
            format!("{filter_name}: invalid regex '{shown}{ellipsis}': {reason}").into()
        })
}

/// Return the prefix of `s` holding at most `max_chars` characters.
fn truncate_chars(s: &str, max_chars: usize) -> &str {
    s.char_indices()
        .nth(max_chars)
        .and_then(|(idx, _)| s.get(..idx))
        .unwrap_or(s)
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

    #[test]
    fn truncates_long_invalid_pattern_in_error() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let long = format!("({}", "a".repeat(500));
        let Err(err) = compile_user_regex(&long, "guardrails") else {
            return Err("unclosed group should fail to compile".into());
        };
        let msg = err.to_string();
        assert!(
            msg.len() < 300,
            "error message should be bounded, got {} bytes",
            msg.len()
        );
        assert!(
            msg.contains("..."),
            "truncated pattern should end with an ellipsis: {msg}"
        );
        assert!(msg.contains("unclosed group"), "error should keep the diagnosis: {msg}");
        Ok(())
    }

    #[test]
    fn short_invalid_pattern_echoed_in_full() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Err(err) = compile_user_regex("(", "guardrails") else {
            return Err("unclosed group should fail to compile".into());
        };
        let msg = err.to_string();
        assert!(
            msg.starts_with("guardrails: invalid regex '(': "),
            "short pattern should be echoed without ellipsis: {msg}"
        );
        Ok(())
    }
}
