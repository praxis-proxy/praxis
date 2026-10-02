// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The `grpc-timeout` request header: parsing, re-encoding, and deadlines.

use std::time::{Duration, Instant};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum digits in a `grpc-timeout` value, per the gRPC HTTP/2 spec.
const MAX_TIMEOUT_DIGITS: usize = 8;

/// Largest value expressible in [`MAX_TIMEOUT_DIGITS`] digits.
const MAX_ENCODABLE: u64 = 99_999_999;

/// Ceiling for a proxy-enforced gRPC deadline, in milliseconds.
///
/// Matches the ceiling Praxis applies to cluster timeouts, so a gRPC
/// deadline cannot outlive what any other timeout may be set to.
pub const MAX_DEADLINE_MS: u64 = 3_600_000; // 1 hour

/// Seconds in a minute, for unit conversion.
const SECONDS_PER_MINUTE: u64 = 60;

/// Seconds in an hour, for unit conversion.
const SECONDS_PER_HOUR: u64 = 3_600;

/// Nanoseconds per `grpc-timeout` unit, finest first.
const UNIT_SCALES: [(u64, GrpcTimeoutUnit); 6] = [
    (1, GrpcTimeoutUnit::Nanosecond),
    (1_000, GrpcTimeoutUnit::Microsecond),
    (1_000_000, GrpcTimeoutUnit::Millisecond),
    (1_000_000_000, GrpcTimeoutUnit::Second),
    (60_000_000_000, GrpcTimeoutUnit::Minute),
    (3_600_000_000_000, GrpcTimeoutUnit::Hour),
];

// -----------------------------------------------------------------------------
// GrpcTimeoutUnit
// -----------------------------------------------------------------------------

/// The unit suffix of a `grpc-timeout` header value.
///
/// The suffixes are case-sensitive: `M` is minutes, `m` is milliseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrpcTimeoutUnit {
    /// `H` — hours.
    Hour,

    /// `M` — minutes.
    Minute,

    /// `S` — seconds.
    Second,

    /// `m` — milliseconds.
    Millisecond,

    /// `u` — microseconds.
    Microsecond,

    /// `n` — nanoseconds.
    Nanosecond,
}

impl GrpcTimeoutUnit {
    /// The wire suffix for this unit.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hour => "H",
            Self::Minute => "M",
            Self::Second => "S",
            Self::Millisecond => "m",
            Self::Microsecond => "u",
            Self::Nanosecond => "n",
        }
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Why a `grpc-timeout` header value could not be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GrpcTimeoutParseError {
    /// The value was empty.
    #[error("grpc-timeout is empty")]
    Empty,

    /// The value carried a unit but no digits.
    #[error("grpc-timeout has no digits before its unit")]
    MissingDigits,

    /// A non-digit appeared before the unit suffix.
    #[error("grpc-timeout value must be ASCII digits")]
    NonDigit,

    /// More than eight digits, which the spec forbids.
    #[error("grpc-timeout has {got} digits, at most {MAX_TIMEOUT_DIGITS} allowed")]
    TooManyDigits {
        /// The number of digits found.
        got: usize,
    },

    /// The unit suffix was not one of `H`, `M`, `S`, `m`, `u`, `n`.
    #[error("grpc-timeout has unknown unit {unit:?}")]
    UnknownUnit {
        /// The suffix character found.
        unit: char,
    },

    /// A zero timeout, which cannot be honoured.
    #[error("grpc-timeout is zero")]
    Zero,
}

// -----------------------------------------------------------------------------
// GrpcTimeout
// -----------------------------------------------------------------------------

/// A parsed `grpc-timeout` header value.
///
/// ```
/// use std::time::Duration;
///
/// use praxis_core::grpc::GrpcTimeout;
///
/// let timeout = GrpcTimeout::parse("250m").unwrap();
/// assert_eq!(timeout.as_duration(), Duration::from_millis(250));
///
/// // The units are case-sensitive: `M` is minutes, `m` milliseconds.
/// assert_eq!(
///     GrpcTimeout::parse("2M").unwrap().as_duration(),
///     Duration::from_secs(120)
/// );
/// assert!(GrpcTimeout::parse("10x").is_err());
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrpcTimeout {
    /// The unit suffix.
    unit: GrpcTimeoutUnit,

    /// The numeric value, `1..=99_999_999`.
    value: u64,
}

impl GrpcTimeout {
    /// Parse a `grpc-timeout` header value.
    ///
    /// The wire format is one to eight ASCII digits followed by exactly
    /// one unit character, with no whitespace, sign, or separator.
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcTimeoutParseError`] describing which rule the
    /// value broke.
    pub fn parse(input: &str) -> Result<Self, GrpcTimeoutParseError> {
        let (unit_byte, digits) = input.as_bytes().split_last().ok_or(GrpcTimeoutParseError::Empty)?;
        let unit = match *unit_byte {
            b'H' => GrpcTimeoutUnit::Hour,
            b'M' => GrpcTimeoutUnit::Minute,
            b'S' => GrpcTimeoutUnit::Second,
            b'm' => GrpcTimeoutUnit::Millisecond,
            b'u' => GrpcTimeoutUnit::Microsecond,
            b'n' => GrpcTimeoutUnit::Nanosecond,
            other => {
                return Err(GrpcTimeoutParseError::UnknownUnit {
                    unit: char::from(other),
                });
            },
        };
        if digits.is_empty() {
            return Err(GrpcTimeoutParseError::MissingDigits);
        }
        if digits.len() > MAX_TIMEOUT_DIGITS {
            return Err(GrpcTimeoutParseError::TooManyDigits { got: digits.len() });
        }
        if !digits.iter().all(u8::is_ascii_digit) {
            return Err(GrpcTimeoutParseError::NonDigit);
        }
        let text = str::from_utf8(digits).map_err(|_err| GrpcTimeoutParseError::NonDigit)?;
        let value = text.parse::<u64>().map_err(|_err| GrpcTimeoutParseError::NonDigit)?;
        if value == 0 {
            return Err(GrpcTimeoutParseError::Zero);
        }
        Ok(Self { unit, value })
    }

    /// Read and parse `grpc-timeout` from a header map.
    ///
    /// Returns `None` when the header is absent or not readable as text,
    /// so an absent deadline and a malformed one stay distinguishable.
    pub fn from_headers(headers: &http::HeaderMap) -> Option<Result<Self, GrpcTimeoutParseError>> {
        let value = headers.get("grpc-timeout")?.to_str().ok()?;
        Some(Self::parse(value))
    }

    /// This timeout as a [`Duration`], saturating rather than overflowing.
    pub fn as_duration(self) -> Duration {
        match self.unit {
            GrpcTimeoutUnit::Hour => Duration::from_secs(self.value.saturating_mul(SECONDS_PER_HOUR)),
            GrpcTimeoutUnit::Minute => Duration::from_secs(self.value.saturating_mul(SECONDS_PER_MINUTE)),
            GrpcTimeoutUnit::Second => Duration::from_secs(self.value),
            GrpcTimeoutUnit::Millisecond => Duration::from_millis(self.value),
            GrpcTimeoutUnit::Microsecond => Duration::from_micros(self.value),
            GrpcTimeoutUnit::Nanosecond => Duration::from_nanos(self.value),
        }
    }

    /// The unit this timeout was expressed in.
    pub fn unit(self) -> GrpcTimeoutUnit {
        self.unit
    }

    /// The numeric part of this timeout.
    pub fn value(self) -> u64 {
        self.value
    }

    /// Encode a remaining budget as a `grpc-timeout` header value.
    ///
    /// Prefers the coarsest unit that represents the budget exactly, so
    /// the header reads the way a client would have written it. When no
    /// unit is both exact and within eight digits, the finest unit that
    /// fits wins and the value truncates: rounding up would hand the
    /// upstream a later deadline than the client set.
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use praxis_core::grpc::GrpcTimeout;
    ///
    /// assert_eq!(GrpcTimeout::encode(Duration::from_millis(250)), "250m");
    /// assert_eq!(GrpcTimeout::encode(Duration::from_secs(60)), "1M");
    /// assert_eq!(
    ///     GrpcTimeout::encode(Duration::from_nanos(1_500_001)),
    ///     "1500001n"
    /// );
    /// // Never rounds up past the client's deadline.
    /// assert_eq!(GrpcTimeout::encode(Duration::from_nanos(1)), "1n");
    /// ```
    pub fn encode(remaining: Duration) -> String {
        let nanos = u64::try_from(remaining.as_nanos()).unwrap_or(u64::MAX);

        // Coarsest exact representation first: 250ms reads as "250m",
        // not "250000000n".
        for (scale, unit) in UNIT_SCALES.iter().rev() {
            let value = nanos.checked_div(*scale).unwrap_or(0);
            let exact = nanos.checked_rem(*scale) == Some(0);
            if exact && (1..=MAX_ENCODABLE).contains(&value) {
                return format!("{value}{}", unit.as_str());
            }
        }

        // Nothing was exact and small enough; take the finest unit that
        // fits, truncating downwards.
        for (scale, unit) in &UNIT_SCALES {
            let value = nanos.checked_div(*scale).unwrap_or(0);
            if value <= MAX_ENCODABLE {
                // A budget below one unit truncates to zero, which no
                // client would honour; keep the smallest value it can carry.
                return format!("{}{}", value.max(1), unit.as_str());
            }
        }
        format!("{MAX_ENCODABLE}{}", GrpcTimeoutUnit::Hour.as_str())
    }
}

// -----------------------------------------------------------------------------
// GrpcDeadline
// -----------------------------------------------------------------------------

/// An absolute deadline for one gRPC call.
///
/// Held in the request extensions so the protocol layer can shrink each
/// upstream attempt's budget to what is left, rather than restarting a
/// relative timeout on every retry.
///
/// ```
/// use std::time::{Duration, Instant};
///
/// use praxis_core::grpc::GrpcDeadline;
///
/// let deadline = GrpcDeadline::new(Instant::now() + Duration::from_secs(5), false, true);
/// assert!(!deadline.is_expired());
/// assert!(deadline.remaining().is_some());
/// assert!(!deadline.was_clamped());
/// ```
#[derive(Clone, Copy, Debug)]
pub struct GrpcDeadline {
    /// Whether the client asked for longer than the proxy allows.
    clamped: bool,

    /// The instant the call must be finished by.
    deadline: Instant,

    /// Whether the remaining budget is written onto the upstream
    /// `grpc-timeout`. When `false` the client's header is forwarded
    /// untouched; the proxy still enforces the deadline itself.
    propagate: bool,
}

impl GrpcDeadline {
    /// Build a deadline from an absolute instant.
    pub fn new(deadline: Instant, clamped: bool, propagate: bool) -> Self {
        Self {
            clamped,
            deadline,
            propagate,
        }
    }

    /// The instant this call must finish by.
    pub fn deadline(self) -> Instant {
        self.deadline
    }

    /// Whether the deadline has passed.
    pub fn is_expired(self) -> bool {
        self.remaining().is_none()
    }

    /// Whether the remaining budget should be written onto the upstream
    /// `grpc-timeout` header.
    pub fn propagate(self) -> bool {
        self.propagate
    }

    /// Time left before the deadline, or `None` once it has passed.
    pub fn remaining(self) -> Option<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
    }

    /// Whether the client's requested timeout was reduced to the proxy's
    /// ceiling.
    pub fn was_clamped(self) -> bool {
        self.clamped
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::assertions_on_result_states,
    clippy::uninlined_format_args,
    clippy::shadow_unrelated,
    reason = "tests use unwrap for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn every_unit_parses() {
        for (text, expected) in [
            ("1H", Duration::from_secs(3_600)),
            ("2M", Duration::from_secs(120)),
            ("3S", Duration::from_secs(3)),
            ("4m", Duration::from_millis(4)),
            ("5u", Duration::from_micros(5)),
            ("6n", Duration::from_nanos(6)),
        ] {
            assert_eq!(
                GrpcTimeout::parse(text).unwrap().as_duration(),
                expected,
                "{text} should parse to {expected:?}"
            );
        }
    }

    #[test]
    fn units_are_case_sensitive() {
        assert_eq!(
            GrpcTimeout::parse("1M").unwrap().as_duration(),
            Duration::from_secs(60),
            "uppercase M is minutes"
        );
        assert_eq!(
            GrpcTimeout::parse("1m").unwrap().as_duration(),
            Duration::from_millis(1),
            "lowercase m is milliseconds"
        );
    }

    #[test]
    fn malformed_values_are_rejected() {
        for (text, expected) in [
            ("", GrpcTimeoutParseError::Empty),
            ("S", GrpcTimeoutParseError::MissingDigits),
            ("10x", GrpcTimeoutParseError::UnknownUnit { unit: 'x' }),
            ("1.5S", GrpcTimeoutParseError::NonDigit),
            ("-5S", GrpcTimeoutParseError::NonDigit),
            ("+5S", GrpcTimeoutParseError::NonDigit),
            (" 5S", GrpcTimeoutParseError::NonDigit),
            ("0S", GrpcTimeoutParseError::Zero),
            ("123456789S", GrpcTimeoutParseError::TooManyDigits { got: 9 }),
        ] {
            assert_eq!(
                GrpcTimeout::parse(text).unwrap_err(),
                expected,
                "{text:?} should be rejected as {expected:?}"
            );
        }
    }

    #[test]
    fn eight_digits_are_allowed() {
        assert!(
            GrpcTimeout::parse("99999999n").is_ok(),
            "eight digits is the documented maximum"
        );
    }

    #[test]
    fn hour_values_saturate_rather_than_overflow() {
        let huge = GrpcTimeout::parse("99999999H").unwrap();
        assert!(
            huge.as_duration() > Duration::from_secs(3_600),
            "a huge hour value should still produce a duration"
        );
    }

    #[test]
    fn from_headers_distinguishes_absent_from_malformed() {
        let mut headers = http::HeaderMap::new();
        assert!(
            GrpcTimeout::from_headers(&headers).is_none(),
            "an absent header is not an error"
        );

        let _prev = headers.insert("grpc-timeout", http::HeaderValue::from_static("bogus"));
        assert!(
            GrpcTimeout::from_headers(&headers).is_some_and(|parsed| parsed.is_err()),
            "a malformed header should surface as an error, not as absent"
        );
    }

    #[test]
    fn encode_round_trips_through_parse() {
        for original in [
            Duration::from_nanos(1),
            Duration::from_micros(7),
            Duration::from_millis(250),
            Duration::from_secs(30),
            Duration::from_secs(3_600),
        ] {
            let encoded = GrpcTimeout::encode(original);
            let reparsed = GrpcTimeout::parse(&encoded).unwrap().as_duration();
            assert_eq!(
                reparsed, original,
                "{original:?} encoded as {encoded:?} should round-trip"
            );
        }
    }

    #[test]
    fn encode_never_extends_the_deadline() {
        let awkward = Duration::from_secs(5_400).saturating_add(Duration::from_nanos(1));
        let encoded = GrpcTimeout::encode(awkward);
        let reparsed = GrpcTimeout::parse(&encoded).unwrap().as_duration();
        assert!(
            reparsed <= awkward,
            "{encoded:?} decodes to {reparsed:?}, which is past the {awkward:?} budget"
        );
    }

    #[test]
    fn encode_keeps_a_sub_unit_budget_non_zero() {
        let encoded = GrpcTimeout::encode(Duration::from_nanos(1));
        assert_eq!(encoded, "1n", "a tiny budget must not encode as zero");
    }

    #[test]
    fn deadline_reports_remaining_and_expiry() {
        let live = GrpcDeadline::new(Instant::now() + Duration::from_secs(60), false, true);
        assert!(!live.is_expired(), "a future deadline is not expired");
        assert!(live.remaining().is_some(), "a future deadline has time left");

        let past = GrpcDeadline::new(Instant::now() - Duration::from_secs(1), true, true);
        assert!(past.is_expired(), "a past deadline is expired");
        assert_eq!(past.remaining(), None, "an expired deadline has no time left");
        assert!(past.was_clamped(), "the clamped flag should survive");
    }

    #[test]
    fn timeout_unit_and_value_accessors() {
        let timeout = GrpcTimeout::parse("250m").unwrap();
        assert_eq!(
            timeout.unit(),
            GrpcTimeoutUnit::Millisecond,
            "unit() should return the parsed unit"
        );
        assert_eq!(timeout.value(), 250, "value() should return the parsed value");

        let timeout = GrpcTimeout::parse("5M").unwrap();
        assert_eq!(timeout.unit(), GrpcTimeoutUnit::Minute);
        assert_eq!(timeout.value(), 5);

        let timeout = GrpcTimeout::parse("99999999H").unwrap();
        assert_eq!(timeout.unit(), GrpcTimeoutUnit::Hour);
        assert_eq!(timeout.value(), 99_999_999);
    }

    #[test]
    fn timeout_unit_as_str_coverage() {
        assert_eq!(GrpcTimeoutUnit::Hour.as_str(), "H");
        assert_eq!(GrpcTimeoutUnit::Minute.as_str(), "M");
        assert_eq!(GrpcTimeoutUnit::Second.as_str(), "S");
        assert_eq!(GrpcTimeoutUnit::Millisecond.as_str(), "m");
        assert_eq!(GrpcTimeoutUnit::Microsecond.as_str(), "u");
        assert_eq!(GrpcTimeoutUnit::Nanosecond.as_str(), "n");
    }

    #[test]
    fn all_duration_conversion_paths() {
        // Test each unit's as_duration conversion
        let hour = GrpcTimeout::parse("2H").unwrap();
        assert_eq!(hour.as_duration(), Duration::from_secs(7200));

        let minute = GrpcTimeout::parse("30M").unwrap();
        assert_eq!(minute.as_duration(), Duration::from_secs(1800));

        let second = GrpcTimeout::parse("45S").unwrap();
        assert_eq!(second.as_duration(), Duration::from_secs(45));

        let milli = GrpcTimeout::parse("500m").unwrap();
        assert_eq!(milli.as_duration(), Duration::from_millis(500));

        let micro = GrpcTimeout::parse("1000u").unwrap();
        assert_eq!(micro.as_duration(), Duration::from_micros(1000));

        let nano = GrpcTimeout::parse("5000n").unwrap();
        assert_eq!(nano.as_duration(), Duration::from_nanos(5000));
    }

    #[test]
    fn minute_values_saturate_rather_than_overflow() {
        let huge = GrpcTimeout::parse("99999999M").unwrap();
        let duration = huge.as_duration();
        assert!(
            duration > Duration::from_secs(60),
            "a huge minute value should produce a duration"
        );
        assert_eq!(duration, Duration::from_secs(99_999_999 * 60));
    }

    #[test]
    fn from_headers_with_non_utf8() {
        use http::header::HeaderValue;

        let mut headers = http::HeaderMap::new();
        // Create a header value with non-UTF8 bytes (invalid for grpc-timeout)
        let non_utf8 = HeaderValue::from_bytes(&[0xFF, 0xFE]).unwrap();
        let _prev = headers.insert("grpc-timeout", non_utf8);

        // Should return None because to_str() fails
        assert!(
            GrpcTimeout::from_headers(&headers).is_none(),
            "a non-UTF8 header should be treated as absent, not malformed"
        );
    }

    #[test]
    fn from_headers_with_valid_timeout() {
        let mut headers = http::HeaderMap::new();
        let _prev = headers.insert("grpc-timeout", http::HeaderValue::from_static("100m"));

        let result = GrpcTimeout::from_headers(&headers);
        assert!(result.is_some(), "valid header should parse");
        let timeout = result.unwrap().unwrap();
        assert_eq!(timeout.as_duration(), Duration::from_millis(100));
    }

    #[test]
    fn encode_with_very_large_duration() {
        // Test with Duration that exceeds all unit scales
        let huge = Duration::from_secs(u64::MAX);
        let encoded = GrpcTimeout::encode(huge);
        // Should encode with hours unit, truncating to fit 8 digits
        assert!(encoded.ends_with('H'), "huge durations should use hours");
        assert!(encoded.len() <= 9, "should fit in 8 digits + unit"); // 8 digits + 'H'
    }

    #[test]
    fn encode_with_zero_duration() {
        // Zero duration should encode as smallest possible value (1 nanosecond)
        let zero = Duration::ZERO;
        let encoded = GrpcTimeout::encode(zero);
        assert_eq!(encoded, "1n", "zero duration should encode as 1n to avoid invalid zero");
    }

    #[test]
    fn encode_prefers_coarsest_exact_unit() {
        // 1 hour exactly should encode as "1H", not "3600S" or "60M"
        assert_eq!(GrpcTimeout::encode(Duration::from_secs(3600)), "1H");

        // 1 minute exactly should encode as "1M", not "60S"
        assert_eq!(GrpcTimeout::encode(Duration::from_secs(60)), "1M");

        // Non-exact values should use finest unit that fits
        assert_eq!(
            GrpcTimeout::encode(Duration::from_secs(61)),
            "61S",
            "61 seconds is not exact in minutes"
        );
    }

    #[test]
    fn encode_handles_fractional_units() {
        // 1.5 seconds = 1500 milliseconds (exact)
        assert_eq!(GrpcTimeout::encode(Duration::from_millis(1500)), "1500m");

        // 1500 microseconds = 1500000 nanoseconds (exact)
        assert_eq!(GrpcTimeout::encode(Duration::from_micros(1500)), "1500u");

        // Non-exact: 1500 nanoseconds
        assert_eq!(GrpcTimeout::encode(Duration::from_nanos(1500)), "1500n");
    }

    #[test]
    fn encode_truncates_when_no_exact_fit() {
        // A value that doesn't fit exactly in any unit
        let awkward = Duration::from_nanos(999_999_999_999_999);
        let encoded = GrpcTimeout::encode(awkward);
        let reparsed = GrpcTimeout::parse(&encoded).unwrap().as_duration();

        // Should truncate down, never round up
        assert!(reparsed <= awkward, "encoded value should truncate down, not round up");
    }

    #[test]
    fn deadline_accessors() {
        let instant = Instant::now() + Duration::from_secs(10);
        let deadline = GrpcDeadline::new(instant, true, false);

        assert_eq!(deadline.deadline(), instant, "deadline() should return the instant");
        assert!(deadline.was_clamped(), "was_clamped() should return true");
        assert!(!deadline.propagate(), "propagate() should return false");
    }

    #[test]
    fn deadline_propagate_flag() {
        let instant = Instant::now() + Duration::from_secs(10);

        let propagate_true = GrpcDeadline::new(instant, false, true);
        assert!(propagate_true.propagate(), "propagate should be true");

        let propagate_false = GrpcDeadline::new(instant, false, false);
        assert!(!propagate_false.propagate(), "propagate should be false");
    }

    #[test]
    fn deadline_remaining_excludes_zero() {
        // A deadline at exactly now might have a zero duration remaining
        let instant = Instant::now();
        let deadline = GrpcDeadline::new(instant, false, true);

        // remaining() filters out zero durations
        let remaining = deadline.remaining();
        if let Some(dur) = remaining {
            assert!(!dur.is_zero(), "remaining() should not return zero durations");
        }
    }

    #[test]
    fn error_display_messages() {
        // Test that all error variants produce readable messages
        assert_eq!(GrpcTimeoutParseError::Empty.to_string(), "grpc-timeout is empty");

        assert_eq!(
            GrpcTimeoutParseError::MissingDigits.to_string(),
            "grpc-timeout has no digits before its unit"
        );

        assert_eq!(
            GrpcTimeoutParseError::NonDigit.to_string(),
            "grpc-timeout value must be ASCII digits"
        );

        assert_eq!(
            GrpcTimeoutParseError::TooManyDigits { got: 10 }.to_string(),
            "grpc-timeout has 10 digits, at most 8 allowed"
        );

        assert_eq!(
            GrpcTimeoutParseError::UnknownUnit { unit: 'z' }.to_string(),
            "grpc-timeout has unknown unit 'z'"
        );

        assert_eq!(GrpcTimeoutParseError::Zero.to_string(), "grpc-timeout is zero");
    }

    #[test]
    fn parse_edge_cases_with_whitespace() {
        // Leading whitespace should fail
        assert!(GrpcTimeout::parse(" 10S").is_err());

        // Trailing whitespace should be treated as unknown unit
        assert!(GrpcTimeout::parse("10S ").is_err());

        // Embedded whitespace should fail
        assert!(GrpcTimeout::parse("10 S").is_err());
    }

    #[test]
    fn parse_with_plus_sign() {
        assert!(
            GrpcTimeout::parse("+10S").is_err(),
            "the gRPC spec allows only ASCII digits, so a leading plus is rejected"
        );
    }

    #[test]
    fn parse_maximum_value_for_each_unit() {
        // Test maximum 8-digit value for each unit
        assert!(GrpcTimeout::parse("99999999H").is_ok());
        assert!(GrpcTimeout::parse("99999999M").is_ok());
        assert!(GrpcTimeout::parse("99999999S").is_ok());
        assert!(GrpcTimeout::parse("99999999m").is_ok());
        assert!(GrpcTimeout::parse("99999999u").is_ok());
        assert!(GrpcTimeout::parse("99999999n").is_ok());
    }

    #[test]
    fn parse_single_digit_for_each_unit() {
        // Test minimum 1-digit value for each unit
        assert!(GrpcTimeout::parse("1H").is_ok());
        assert!(GrpcTimeout::parse("1M").is_ok());
        assert!(GrpcTimeout::parse("1S").is_ok());
        assert!(GrpcTimeout::parse("1m").is_ok());
        assert!(GrpcTimeout::parse("1u").is_ok());
        assert!(GrpcTimeout::parse("1n").is_ok());
    }

    #[test]
    fn error_variants_equality() {
        // Test PartialEq implementation for errors
        assert_eq!(GrpcTimeoutParseError::Empty, GrpcTimeoutParseError::Empty);
        assert_eq!(GrpcTimeoutParseError::Zero, GrpcTimeoutParseError::Zero);

        assert_eq!(
            GrpcTimeoutParseError::TooManyDigits { got: 9 },
            GrpcTimeoutParseError::TooManyDigits { got: 9 }
        );

        assert_ne!(
            GrpcTimeoutParseError::TooManyDigits { got: 9 },
            GrpcTimeoutParseError::TooManyDigits { got: 10 }
        );

        assert_eq!(
            GrpcTimeoutParseError::UnknownUnit { unit: 'x' },
            GrpcTimeoutParseError::UnknownUnit { unit: 'x' }
        );
    }

    #[test]
    fn timeout_struct_equality() {
        // Test PartialEq/Eq implementation for GrpcTimeout
        let t1 = GrpcTimeout::parse("100m").unwrap();
        let t2 = GrpcTimeout::parse("100m").unwrap();
        let t3 = GrpcTimeout::parse("100S").unwrap();

        assert_eq!(t1, t2, "identical timeouts should be equal");
        assert_ne!(t1, t3, "different timeouts should not be equal");
    }

    #[test]
    fn timeout_debug_format() {
        let timeout = GrpcTimeout::parse("250m").unwrap();
        let debug = format!("{:?}", timeout);
        assert!(debug.contains("GrpcTimeout"), "debug should show type name");
        assert!(
            debug.contains("250") || debug.contains("Millisecond"),
            "debug should show value or unit"
        );
    }

    #[test]
    fn unit_debug_format() {
        assert!(format!("{:?}", GrpcTimeoutUnit::Hour).contains("Hour"));
        assert!(format!("{:?}", GrpcTimeoutUnit::Minute).contains("Minute"));
        assert!(format!("{:?}", GrpcTimeoutUnit::Second).contains("Second"));
        assert!(format!("{:?}", GrpcTimeoutUnit::Millisecond).contains("Millisecond"));
        assert!(format!("{:?}", GrpcTimeoutUnit::Microsecond).contains("Microsecond"));
        assert!(format!("{:?}", GrpcTimeoutUnit::Nanosecond).contains("Nanosecond"));
    }

    #[test]
    fn unit_equality() {
        assert_eq!(GrpcTimeoutUnit::Hour, GrpcTimeoutUnit::Hour);
        assert_ne!(GrpcTimeoutUnit::Hour, GrpcTimeoutUnit::Minute);
        assert_ne!(GrpcTimeoutUnit::Millisecond, GrpcTimeoutUnit::Microsecond);
    }

    #[test]
    fn unit_clone() {
        let unit = GrpcTimeoutUnit::Second;
        let cloned = unit;
        assert_eq!(unit, cloned);
    }

    #[test]
    fn timeout_clone() {
        let original = GrpcTimeout::parse("100m").unwrap();
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn deadline_clone() {
        let instant = Instant::now() + Duration::from_secs(10);
        let original = GrpcDeadline::new(instant, true, false);
        let cloned = original;

        assert_eq!(original.deadline(), cloned.deadline());
        assert_eq!(original.was_clamped(), cloned.was_clamped());
        assert_eq!(original.propagate(), cloned.propagate());
    }

    #[test]
    fn deadline_debug_format() {
        let deadline = GrpcDeadline::new(Instant::now() + Duration::from_secs(10), true, false);
        let debug = format!("{:?}", deadline);
        assert!(debug.contains("GrpcDeadline"), "debug should show type name");
    }

    #[test]
    fn encode_all_unit_boundaries() {
        // Test encoding at unit boundaries to ensure correct unit selection

        // Just under 1 microsecond: should use nanoseconds
        assert_eq!(GrpcTimeout::encode(Duration::from_nanos(999)), "999n");

        // Exactly 1 microsecond: should use microseconds
        assert_eq!(GrpcTimeout::encode(Duration::from_nanos(1_000)), "1u");

        // Just under 1 millisecond: should use microseconds
        assert_eq!(GrpcTimeout::encode(Duration::from_nanos(999_000)), "999u");

        // Exactly 1 millisecond: should use milliseconds
        assert_eq!(GrpcTimeout::encode(Duration::from_nanos(1_000_000)), "1m");

        // Just under 1 second: should use milliseconds
        assert_eq!(GrpcTimeout::encode(Duration::from_millis(999)), "999m");

        // Exactly 1 second: should use seconds
        assert_eq!(GrpcTimeout::encode(Duration::from_millis(1_000)), "1S");

        // Just under 1 minute: should use seconds
        assert_eq!(GrpcTimeout::encode(Duration::from_secs(59)), "59S");

        // Exactly 1 minute: should use minutes
        assert_eq!(GrpcTimeout::encode(Duration::from_secs(60)), "1M");
    }

    #[test]
    fn parse_all_error_branches() {
        // Ensure all error branches are covered

        // Empty string
        assert!(matches!(GrpcTimeout::parse(""), Err(GrpcTimeoutParseError::Empty)));

        // Only unit, no digits
        assert!(matches!(
            GrpcTimeout::parse("H"),
            Err(GrpcTimeoutParseError::MissingDigits)
        ));

        // Unknown unit
        assert!(matches!(
            GrpcTimeout::parse("10X"),
            Err(GrpcTimeoutParseError::UnknownUnit { unit: 'X' })
        ));

        // Non-digit character
        assert!(matches!(
            GrpcTimeout::parse("1a2S"),
            Err(GrpcTimeoutParseError::NonDigit)
        ));

        // Too many digits
        assert!(matches!(
            GrpcTimeout::parse("123456789S"),
            Err(GrpcTimeoutParseError::TooManyDigits { got: 9 })
        ));

        // Zero value
        assert!(matches!(GrpcTimeout::parse("0S"), Err(GrpcTimeoutParseError::Zero)));
    }
}
