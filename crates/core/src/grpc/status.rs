// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! gRPC completion status carried in response trailers.

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum retained length of `grpc-message`, in bytes.
///
/// The value reaches logs and traces; a server is free to send a much
/// larger one.
const MAX_MESSAGE_BYTES: usize = 1_024; // 1 KiB

/// Maximum retained length of `grpc-status-details-bin`, in bytes.
///
/// Base64-encoded `google.rpc.Status` details are unbounded on the wire.
const MAX_STATUS_DETAILS_BYTES: usize = 4_096; // 4 KiB

/// Bytes that must be percent-encoded in a `grpc-message` value.
///
/// The gRPC HTTP/2 wire spec leaves `%x20-%x24` and `%x26-%x7E` literal
/// and percent-encodes everything else. `CONTROLS` covers `%x00-%x1F`
/// and `%x7F`; adding `%` completes the set, and `percent_encoding`
/// always escapes non-ASCII bytes.
const GRPC_MESSAGE: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS.add(b'%');

// -----------------------------------------------------------------------------
// GrpcStatusCode
// -----------------------------------------------------------------------------

/// A canonical gRPC status code.
///
/// ```
/// use praxis_core::grpc::GrpcStatusCode;
///
/// assert_eq!(GrpcStatusCode::try_from(5), Ok(GrpcStatusCode::NotFound));
/// assert_eq!(GrpcStatusCode::NotFound.as_str(), "NOT_FOUND");
/// assert!(GrpcStatusCode::try_from(42).is_err());
/// ```
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GrpcStatusCode {
    /// `0` — the call completed successfully.
    Ok,

    /// `1` — the operation was cancelled, typically by the caller.
    Cancelled,

    /// `2` — an unknown error.
    Unknown,

    /// `3` — the client specified an invalid argument.
    InvalidArgument,

    /// `4` — the deadline expired before the operation completed.
    DeadlineExceeded,

    /// `5` — the requested entity was not found.
    NotFound,

    /// `6` — the entity a client attempted to create already exists.
    AlreadyExists,

    /// `7` — the caller lacks permission for the operation.
    PermissionDenied,

    /// `8` — a resource has been exhausted.
    ResourceExhausted,

    /// `9` — the system is not in a state required for the operation.
    FailedPrecondition,

    /// `10` — the operation was aborted, typically by a concurrency conflict.
    Aborted,

    /// `11` — the operation was attempted past the valid range.
    OutOfRange,

    /// `12` — the operation is not implemented or supported.
    Unimplemented,

    /// `13` — an internal error.
    Internal,

    /// `14` — the service is currently unavailable.
    Unavailable,

    /// `15` — unrecoverable data loss or corruption.
    DataLoss,

    /// `16` — the request lacks valid authentication credentials.
    Unauthenticated,
}

/// A `grpc-status` value outside the canonical `0..=16` range.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("unknown gRPC status code: {0}")]
pub struct UnknownGrpcStatusCode(pub u32);

impl TryFrom<u32> for GrpcStatusCode {
    type Error = UnknownGrpcStatusCode;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Cancelled),
            2 => Ok(Self::Unknown),
            3 => Ok(Self::InvalidArgument),
            4 => Ok(Self::DeadlineExceeded),
            5 => Ok(Self::NotFound),
            6 => Ok(Self::AlreadyExists),
            7 => Ok(Self::PermissionDenied),
            8 => Ok(Self::ResourceExhausted),
            9 => Ok(Self::FailedPrecondition),
            10 => Ok(Self::Aborted),
            11 => Ok(Self::OutOfRange),
            12 => Ok(Self::Unimplemented),
            13 => Ok(Self::Internal),
            14 => Ok(Self::Unavailable),
            15 => Ok(Self::DataLoss),
            16 => Ok(Self::Unauthenticated),
            other => Err(UnknownGrpcStatusCode(other)),
        }
    }
}

impl GrpcStatusCode {
    /// The canonical uppercase name of this status code.
    ///
    /// ```
    /// use praxis_core::grpc::GrpcStatusCode;
    ///
    /// assert_eq!(GrpcStatusCode::Ok.as_str(), "OK");
    /// assert_eq!(
    ///     GrpcStatusCode::DeadlineExceeded.as_str(),
    ///     "DEADLINE_EXCEEDED"
    /// );
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Cancelled => "CANCELLED",
            Self::Unknown => "UNKNOWN",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Aborted => "ABORTED",
            Self::OutOfRange => "OUT_OF_RANGE",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::DataLoss => "DATA_LOSS",
            Self::Unauthenticated => "UNAUTHENTICATED",
        }
    }

    /// The `grpc-status` header value for this code.
    pub fn as_header_value(self) -> http::HeaderValue {
        http::HeaderValue::from_static(match self {
            Self::Ok => "0",
            Self::Cancelled => "1",
            Self::Unknown => "2",
            Self::InvalidArgument => "3",
            Self::DeadlineExceeded => "4",
            Self::NotFound => "5",
            Self::AlreadyExists => "6",
            Self::PermissionDenied => "7",
            Self::ResourceExhausted => "8",
            Self::FailedPrecondition => "9",
            Self::Aborted => "10",
            Self::OutOfRange => "11",
            Self::Unimplemented => "12",
            Self::Internal => "13",
            Self::Unavailable => "14",
            Self::DataLoss => "15",
            Self::Unauthenticated => "16",
        })
    }

    /// The gRPC status an HTTP error status maps to, per the [gRPC HTTP
    /// mapping].
    ///
    /// Deliberately not the inverse of [`to_http_status`]: the spec maps
    /// `404` to `UNIMPLEMENTED`, while `UNIMPLEMENTED` maps back to
    /// `501`. Anything the table does not name is `UNKNOWN` — inventing
    /// closer-looking codes (`413` to `RESOURCE_EXHAUSTED`, say) would
    /// depart from the spec that clients implement.
    ///
    /// ```
    /// use praxis_core::grpc::GrpcStatusCode;
    ///
    /// assert_eq!(
    ///     GrpcStatusCode::from_http_status(403),
    ///     GrpcStatusCode::PermissionDenied
    /// );
    /// assert_eq!(
    ///     GrpcStatusCode::from_http_status(404),
    ///     GrpcStatusCode::Unimplemented
    /// );
    /// assert_eq!(
    ///     GrpcStatusCode::from_http_status(418),
    ///     GrpcStatusCode::Unknown
    /// );
    /// ```
    ///
    /// [gRPC HTTP mapping]: https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md
    /// [`to_http_status`]: Self::to_http_status
    pub fn from_http_status(status: u16) -> Self {
        match status {
            400 => Self::Internal,
            401 => Self::Unauthenticated,
            403 => Self::PermissionDenied,
            404 => Self::Unimplemented,
            429 | 502..=504 => Self::Unavailable,
            _ => Self::Unknown,
        }
    }

    /// The numeric `grpc-status` value for this code.
    ///
    /// ```
    /// use praxis_core::grpc::GrpcStatusCode;
    ///
    /// assert_eq!(GrpcStatusCode::Unavailable.as_u32(), 14);
    /// ```
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::Cancelled => 1,
            Self::Unknown => 2,
            Self::InvalidArgument => 3,
            Self::DeadlineExceeded => 4,
            Self::NotFound => 5,
            Self::AlreadyExists => 6,
            Self::PermissionDenied => 7,
            Self::ResourceExhausted => 8,
            Self::FailedPrecondition => 9,
            Self::Aborted => 10,
            Self::OutOfRange => 11,
            Self::Unimplemented => 12,
            Self::Internal => 13,
            Self::Unavailable => 14,
            Self::DataLoss => 15,
            Self::Unauthenticated => 16,
        }
    }

    /// The HTTP status this gRPC status maps back to.
    ///
    /// Follows the mapping gRPC gateways use. `499` is the nginx
    /// "Client Closed Request" convention for a cancelled call.
    ///
    /// ```
    /// use praxis_core::grpc::GrpcStatusCode;
    ///
    /// assert_eq!(GrpcStatusCode::Unimplemented.to_http_status(), 501);
    /// ```
    pub fn to_http_status(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::Cancelled => 499,
            Self::Unknown | Self::Internal | Self::DataLoss => 500,
            Self::InvalidArgument | Self::FailedPrecondition | Self::OutOfRange => 400,
            Self::DeadlineExceeded => 504,
            Self::NotFound => 404,
            Self::AlreadyExists | Self::Aborted => 409,
            Self::PermissionDenied => 403,
            Self::ResourceExhausted => 429,
            Self::Unimplemented => 501,
            Self::Unavailable => 503,
            Self::Unauthenticated => 401,
        }
    }
}

// -----------------------------------------------------------------------------
// GrpcCompletion
// -----------------------------------------------------------------------------

/// How a gRPC call ended.
///
/// A gRPC call's outcome does not live in the HTTP status — that is
/// `200` even for a failed call — but in the `grpc-status` trailer sent
/// after the response body, or in the response header block of a
/// Trailers-Only response.
///
/// ```
/// use praxis_core::grpc::{GrpcCompletion, GrpcStatusCode};
///
/// let mut trailers = http::HeaderMap::new();
/// trailers.insert("grpc-status", http::HeaderValue::from_static("5"));
/// trailers.insert(
///     "grpc-message",
///     http::HeaderValue::from_static("no such user"),
/// );
///
/// let completion = GrpcCompletion::from_headers(&trailers).unwrap();
/// assert_eq!(completion.code(), Some(GrpcStatusCode::NotFound));
/// assert_eq!(completion.raw_code(), 5);
/// assert_eq!(completion.message(), Some("no such user"));
/// assert!(!completion.is_ok());
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GrpcCompletion {
    /// The canonical code, absent when `raw_code` is not one of `0..=16`.
    code: Option<GrpcStatusCode>,

    /// The `grpc-message` value, as received.
    message: Option<String>,

    /// The `grpc-status` value as sent, including non-canonical codes.
    raw_code: u32,

    /// The `grpc-status-details-bin` value, as received (base64).
    status_details_bin: Option<String>,
}

impl GrpcCompletion {
    /// Extract the gRPC completion status from a trailer or header map.
    ///
    /// Returns `None` when `grpc-status` is absent or unparseable: a map
    /// without a status is not a gRPC completion, and `grpc-message`
    /// alone says nothing about how the call ended.
    ///
    /// ```
    /// use praxis_core::grpc::GrpcCompletion;
    ///
    /// assert!(GrpcCompletion::from_headers(&http::HeaderMap::new()).is_none());
    /// ```
    pub fn from_headers(headers: &http::HeaderMap) -> Option<Self> {
        let raw_code = headers
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u32>().ok())?;

        Some(Self {
            code: GrpcStatusCode::try_from(raw_code).ok(),
            message: header_text(headers, "grpc-message", MAX_MESSAGE_BYTES),
            raw_code,
            status_details_bin: header_text(headers, "grpc-status-details-bin", MAX_STATUS_DETAILS_BYTES),
        })
    }

    /// The canonical status code, or `None` for a non-canonical value.
    pub fn code(&self) -> Option<GrpcStatusCode> {
        self.code
    }

    /// Whether the call completed successfully (`grpc-status: 0`).
    pub fn is_ok(&self) -> bool {
        self.raw_code == 0
    }

    /// The `grpc-message` value, still percent-encoded as received.
    ///
    /// Decoding is deliberately left to the consumer: the wire form is
    /// percent-encoded precisely so that control characters cannot reach
    /// a log line unescaped.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// The numeric `grpc-status` value as sent.
    pub fn raw_code(&self) -> u32 {
        self.raw_code
    }

    /// The `grpc-status-details-bin` value, base64 as received.
    pub fn status_details_bin(&self) -> Option<&str> {
        self.status_details_bin.as_deref()
    }

    /// The canonical status name, or the raw code when non-canonical.
    ///
    /// ```
    /// use praxis_core::grpc::GrpcCompletion;
    ///
    /// let mut trailers = http::HeaderMap::new();
    /// trailers.insert("grpc-status", http::HeaderValue::from_static("99"));
    /// let completion = GrpcCompletion::from_headers(&trailers).unwrap();
    /// assert_eq!(completion.code_name(), "99");
    /// ```
    pub fn code_name(&self) -> String {
        self.code
            .map_or_else(|| self.raw_code.to_string(), |code| code.as_str().to_owned())
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Percent-encode text for a `grpc-message` header.
///
/// The wire form escapes control characters, which is what keeps a
/// server-supplied message from injecting into a header or a log line.
///
/// ```
/// use praxis_core::grpc::encode_grpc_message;
///
/// assert_eq!(encode_grpc_message("no such user"), "no such user");
/// assert_eq!(encode_grpc_message("bad\r\ninput"), "bad%0D%0Ainput");
/// ```
pub fn encode_grpc_message(message: &str) -> std::borrow::Cow<'_, str> {
    // Cap the unencoded message first: an oversized value would push the
    // header past the client's SETTINGS_MAX_HEADER_LIST_SIZE and cost the
    // response its status. Percent-encoding trebles the length worst case,
    // so the encoded header stays within 3x the cap. Matches the read-back cap.
    let message = truncate_on_char_boundary(message, MAX_MESSAGE_BYTES);
    percent_encoding::utf8_percent_encode(message, GRPC_MESSAGE).into()
}

/// Read a header as UTF-8 text, truncated to `max_bytes` on a character
/// boundary.
///
/// Non-UTF-8 values are dropped rather than lossily converted: a mangled
/// value in a log field is worse than an absent one.
fn header_text(headers: &http::HeaderMap, name: &str, max_bytes: usize) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?;
    if value.is_empty() {
        return None;
    }
    Some(truncate_on_char_boundary(value, max_bytes).to_owned())
}

/// Truncate `value` to at most `max_bytes`, ending on a character boundary.
fn truncate_on_char_boundary(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let end = value
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= max_bytes)
        .last()
        .unwrap_or_default();
    value.get(..end).unwrap_or_default()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests use unwrap for brevity")]
mod tests {
    use super::*;

    /// Build a trailer map from `(name, value)` pairs.
    fn trailers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (name, value) in pairs {
            let name: http::HeaderName = (*name).parse().unwrap();
            let _prev = map.insert(name, http::HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn absent_status_is_not_a_completion() {
        assert!(
            GrpcCompletion::from_headers(&trailers(&[("grpc-message", "lonely")])).is_none(),
            "grpc-message alone says nothing about how the call ended"
        );
    }

    #[test]
    fn unparseable_status_is_not_a_completion() {
        assert!(
            GrpcCompletion::from_headers(&trailers(&[("grpc-status", "not-a-number")])).is_none(),
            "a non-numeric grpc-status must not be reported as an outcome"
        );
    }

    #[test]
    fn ok_status_is_extracted() {
        let completion = GrpcCompletion::from_headers(&trailers(&[("grpc-status", "0")])).unwrap();
        assert_eq!(completion.code(), Some(GrpcStatusCode::Ok), "code should be OK");
        assert!(completion.is_ok(), "grpc-status 0 is a successful call");
        assert_eq!(completion.message(), None, "no message was sent");
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let completion = GrpcCompletion::from_headers(&trailers(&[("grpc-status", " 14 ")])).unwrap();
        assert_eq!(
            completion.code(),
            Some(GrpcStatusCode::Unavailable),
            "padded values should still parse"
        );
    }

    #[test]
    fn non_canonical_code_keeps_its_raw_value() {
        let completion = GrpcCompletion::from_headers(&trailers(&[("grpc-status", "99")])).unwrap();
        assert_eq!(completion.code(), None, "99 is not a canonical gRPC code");
        assert_eq!(completion.raw_code(), 99, "the raw value must survive");
        assert_eq!(completion.code_name(), "99", "an unnamed code renders as its number");
        assert!(!completion.is_ok(), "a non-zero code is a failure");
    }

    #[test]
    fn message_is_kept_percent_encoded() {
        let completion =
            GrpcCompletion::from_headers(&trailers(&[("grpc-status", "3"), ("grpc-message", "bad%20arg%0A")])).unwrap();
        assert_eq!(
            completion.message(),
            Some("bad%20arg%0A"),
            "decoding would put a newline into a log line"
        );
    }

    #[test]
    fn empty_message_is_dropped() {
        let completion =
            GrpcCompletion::from_headers(&trailers(&[("grpc-status", "2"), ("grpc-message", "")])).unwrap();
        assert_eq!(completion.message(), None, "an empty message is not a message");
    }

    #[test]
    fn status_details_are_kept_as_received() {
        let completion = GrpcCompletion::from_headers(&trailers(&[
            ("grpc-status", "9"),
            ("grpc-status-details-bin", "CAkSBG9vcHM"),
        ]))
        .unwrap();
        assert_eq!(
            completion.status_details_bin(),
            Some("CAkSBG9vcHM"),
            "the base64 wire form is what callers want to forward"
        );
    }

    #[test]
    fn long_message_is_truncated() {
        let long = "x".repeat(MAX_MESSAGE_BYTES.saturating_add(64));
        let completion =
            GrpcCompletion::from_headers(&trailers(&[("grpc-status", "13"), ("grpc-message", &long)])).unwrap();
        assert_eq!(
            completion.message().map(str::len),
            Some(MAX_MESSAGE_BYTES),
            "an oversized message must be capped"
        );
    }

    #[test]
    fn long_status_details_are_truncated() {
        let long = "y".repeat(MAX_STATUS_DETAILS_BYTES.saturating_add(64));
        let completion =
            GrpcCompletion::from_headers(&trailers(&[("grpc-status", "13"), ("grpc-status-details-bin", &long)]))
                .unwrap();
        assert_eq!(
            completion.status_details_bin().map(str::len),
            Some(MAX_STATUS_DETAILS_BYTES),
            "oversized status details must be capped"
        );
    }

    #[test]
    fn truncation_lands_on_a_character_boundary() {
        let snowmen = "☃☃☃";
        let truncated = truncate_on_char_boundary(snowmen, 4);
        assert_eq!(truncated, "☃", "truncation must not split a character");
        assert_eq!(
            truncate_on_char_boundary(snowmen, 2),
            "",
            "a cap shorter than the first character yields nothing"
        );
        assert_eq!(
            truncate_on_char_boundary(snowmen, 9),
            snowmen,
            "a value within the cap is returned whole"
        );
    }

    #[test]
    fn non_ascii_message_is_dropped() {
        let mut map = trailers(&[("grpc-status", "2")]);
        let _prev = map.insert("grpc-message", http::HeaderValue::from_bytes(&[0xFF, 0xFE]).unwrap());
        let completion = GrpcCompletion::from_headers(&map).unwrap();
        assert_eq!(completion.raw_code(), 2, "the status still parses");
        assert_eq!(completion.message(), None, "an unreadable message is dropped");
    }

    #[test]
    fn http_statuses_map_to_the_spec_table() {
        for (http, expected) in [
            (400, GrpcStatusCode::Internal),
            (401, GrpcStatusCode::Unauthenticated),
            (403, GrpcStatusCode::PermissionDenied),
            (404, GrpcStatusCode::Unimplemented),
            (429, GrpcStatusCode::Unavailable),
            (502, GrpcStatusCode::Unavailable),
            (503, GrpcStatusCode::Unavailable),
            (504, GrpcStatusCode::Unavailable),
        ] {
            assert_eq!(
                GrpcStatusCode::from_http_status(http),
                expected,
                "HTTP {http} should map to {expected:?}"
            );
        }
    }

    #[test]
    fn unlisted_http_statuses_map_to_unknown() {
        for http in [405, 408, 409, 413, 415, 500, 501] {
            assert_eq!(
                GrpcStatusCode::from_http_status(http),
                GrpcStatusCode::Unknown,
                "HTTP {http} is not in the mapping table, so it is UNKNOWN"
            );
        }
    }

    #[test]
    fn the_two_status_mappings_are_deliberately_not_inverses() {
        let forward = GrpcStatusCode::from_http_status(404);
        assert_eq!(forward, GrpcStatusCode::Unimplemented, "404 maps to UNIMPLEMENTED");
        assert_eq!(forward.to_http_status(), 501, "UNIMPLEMENTED maps back to 501, not 404");
    }

    #[test]
    fn reverse_mapping_covers_every_code() {
        for raw in 0..=16_u32 {
            let code = GrpcStatusCode::try_from(raw).unwrap();
            let http = code.to_http_status();
            assert!(
                (200..=599).contains(&http),
                "{code:?} maps to {http}, which is not a usable HTTP status"
            );
        }
        assert_eq!(GrpcStatusCode::Cancelled.to_http_status(), 499, "nginx's convention");
    }

    #[test]
    fn header_values_match_the_numeric_codes() {
        for raw in 0..=16_u32 {
            let code = GrpcStatusCode::try_from(raw).unwrap();
            assert_eq!(
                code.as_header_value().to_str().unwrap(),
                raw.to_string(),
                "{code:?} header value should be its numeric code"
            );
        }
    }

    #[test]
    fn grpc_message_encoding_escapes_control_characters() {
        assert_eq!(
            encode_grpc_message("plain message"),
            "plain message",
            "printable ASCII passes through unescaped"
        );
        assert_eq!(
            encode_grpc_message("split\r\nheader"),
            "split%0D%0Aheader",
            "CRLF must not survive into a header"
        );
        assert_eq!(encode_grpc_message("100%"), "100%25", "a literal percent is escaped");
        assert!(
            !encode_grpc_message("héllo").contains('é'),
            "non-ASCII must be percent-encoded"
        );
    }

    #[test]
    fn grpc_message_encoding_caps_oversized_input() {
        let unescaped = "x".repeat(MAX_MESSAGE_BYTES.saturating_add(500));
        assert!(
            encode_grpc_message(&unescaped).len() <= MAX_MESSAGE_BYTES,
            "printable input is capped to the byte limit before it can overflow the header list"
        );

        let all_escaped = "\n".repeat(MAX_MESSAGE_BYTES.saturating_add(500));
        assert!(
            encode_grpc_message(&all_escaped).len() <= MAX_MESSAGE_BYTES.saturating_mul(3),
            "every byte escaping to three keeps even the worst case within 3x the cap"
        );
    }

    #[test]
    fn every_canonical_code_round_trips() {
        for raw in 0..=16_u32 {
            let code = GrpcStatusCode::try_from(raw).unwrap();
            assert_eq!(code.as_u32(), raw, "code {raw} should round-trip through as_u32");
            assert!(!code.as_str().is_empty(), "code {raw} should have a name");
        }
        assert!(GrpcStatusCode::try_from(17).is_err(), "17 is past the canonical range");
    }
}
