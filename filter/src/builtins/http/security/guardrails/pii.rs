//! Built-in PII detection patterns used by guardrail rules.
//!
//! Detection is heuristic and format-specific: patterns match common
//! delimited formats (e.g. `123-45-6789` for SSN) but will not catch
//! reformatted data (e.g. `123456789`). For compliance-critical use
//! cases, use a dedicated DLP solution.

use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;

// -----------------------------------------------------------------------------
// PII Kind
// -----------------------------------------------------------------------------

/// Categories of personally identifiable information detectable via the
/// `pii` matcher on a guardrail rule.
///
/// ```
/// use praxis_filter::PiiKind;
///
/// let kinds: Vec<PiiKind> = serde_yaml::from_str("[ssn, credit_card, phone, email]").unwrap();
/// assert_eq!(kinds.len(), 4);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiKind {
    /// US Social Security Numbers (e.g. `123-45-6789`).
    Ssn,

    /// Credit / debit card numbers (major network prefixes, common delimiters).
    CreditCard,

    /// US phone numbers in formatted form (e.g. `(555) 867-5309`).
    Phone,

    /// Email addresses.
    Email,
}

impl PiiKind {
    /// All built-in PII categories.
    pub const ALL: &[PiiKind] = &[PiiKind::Ssn, PiiKind::CreditCard, PiiKind::Phone, PiiKind::Email];
}

// -----------------------------------------------------------------------------
// Compiled Patterns (lazy, compiled once)
// -----------------------------------------------------------------------------

/// Matches US SSNs in the canonical `NNN-NN-NNNN` format.
#[allow(
    clippy::expect_used,
    reason = "hardcoded regex patterns are known-valid at compile time"
)]
static SSN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("SSN regex"));

/// Matches credit/debit card numbers for major networks.
///
/// Word-boundary guards (`\b`) prevent matching a card-shaped sub-sequence
/// within a longer digit run: e.g. 17 consecutive digits that start with a
/// Visa prefix will not trigger because `\b` fails between two adjacent word
/// characters (both digits are `\w`).
#[allow(
    clippy::expect_used,
    reason = "hardcoded regex patterns are known-valid at compile time"
)]
static CREDIT_CARD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        \b
        (?:
            # Visa 16-digit (4xxx xxxx xxxx xxxx)
            4\d{3}[\ \-]?\d{4}[\ \-]?\d{4}[\ \-]?\d{4}
            # Mastercard 16-digit traditional range (51–55xx)
          | 5[1-5]\d{2}[\ \-]?\d{4}[\ \-]?\d{4}[\ \-]?\d{4}
            # Mastercard 16-digit 2021+ range (2221 to 2720)
          | (?:222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)[\ \-]?\d{4}[\ \-]?\d{4}[\ \-]?\d{4}
            # Amex 15-digit (34xx / 37xx)
          | 3[47]\d{2}[\ \-]?\d{6}[\ \-]?\d{5}
            # Discover 16-digit (6011 / 64x / 65xx)
          | 6(?:011|[45]\d{2})[\ \-]?\d{4}[\ \-]?\d{4}[\ \-]?\d{4}
        )
        \b",
    )
    .expect("credit card regex")
});

/// Matches US phone numbers in formatted form.
///
/// Separators between each group are **required** so that bare digit strings
/// (product codes, IDs) are not mis-detected. A trailing `\b` ensures the
/// subscriber number is not immediately followed by more digits.
#[allow(
    clippy::expect_used,
    reason = "hardcoded regex patterns are known-valid at compile time"
)]
static PHONE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        (?:
            (?:\+?1[\ .\-])?           # optional US country code + separator
            \(?[2-9]\d{2}\)?           # area code (optionally parenthesised)
            [\ .\-]                    # separator required (space, dot, or hyphen)
            [2-9]\d{2}                 # exchange
            [\ .\-]                    # separator required (space, dot, or hyphen)
            \d{4}                      # subscriber
        )
        \b",
    )
    .expect("phone regex")
});

/// Matches email addresses.
#[allow(
    clippy::expect_used,
    reason = "hardcoded regex patterns are known-valid at compile time"
)]
static EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").expect("email regex"));

// -----------------------------------------------------------------------------
// Matching
// -----------------------------------------------------------------------------

/// Return the compiled pattern for a single PII kind.
fn regex_for(kind: PiiKind) -> &'static Regex {
    match kind {
        PiiKind::Ssn => &SSN_RE,
        PiiKind::CreditCard => &CREDIT_CARD_RE,
        PiiKind::Phone => &PHONE_RE,
        PiiKind::Email => &EMAIL_RE,
    }
}

/// Returns the first matching PII category if `haystack` matches any of the given PII categories.
pub(super) fn matches_any(kinds: &[PiiKind], haystack: &str) -> Option<PiiKind> {
    for kind in kinds {
        if regex_for(*kind).is_match(haystack) {
            return Some(*kind);
        }
    }
    None
}
