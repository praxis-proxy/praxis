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
    pub fn parse(value: &str) -> Result<Self, GrpcTimeoutParseError> {
        let (unit_byte, digits) = value.as_bytes().split_last().ok_or(GrpcTimeoutParseError::Empty)?;
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
#[allow(clippy::unwrap_used, reason = "tests use unwrap for brevity")]
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
}
