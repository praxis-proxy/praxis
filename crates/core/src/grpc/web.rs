// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! gRPC-Web classification of the HTTP `content-type` header.

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The `application/grpc-web` prefix, which every variant starts with.
const GRPC_WEB_PREFIX: &str = "application/grpc-web";

/// The `-text` marker distinguishing the base64 variant.
const TEXT_MARKER: &str = "-text";

// -----------------------------------------------------------------------------
// GrpcCodec
// -----------------------------------------------------------------------------

/// The codec suffix on a gRPC or gRPC-Web content type.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GrpcCodec {
    /// `+proto`, or no suffix at all — the protocol's default.
    #[default]
    Proto,

    /// `+json`.
    Json,

    /// Some other `+codec`. The codec name is not preserved: translation
    /// answers bare `application/grpc` (see [`Self::grpc_content_type`]).
    Other,
}

impl GrpcCodec {
    /// Classify a codec suffix, including the empty one.
    ///
    /// Returns `None` for a remainder that is not a suffix at all, so
    /// `application/grpc-webbing` is not read as a gRPC-Web codec.
    fn from_suffix(suffix: &str) -> Option<Self> {
        if suffix.is_empty() || suffix.eq_ignore_ascii_case("+proto") {
            Some(Self::Proto)
        } else if suffix.eq_ignore_ascii_case("+json") {
            Some(Self::Json)
        } else if suffix.starts_with('+') {
            Some(Self::Other)
        } else {
            None
        }
    }

    /// The native gRPC content type for this codec.
    ///
    /// An unrecognised codec answers bare `application/grpc`: the
    /// suffix names a codec Praxis cannot vouch for, and the bare form
    /// is what every gRPC server accepts.
    pub fn grpc_content_type(self) -> &'static str {
        match self {
            Self::Proto => "application/grpc+proto",
            Self::Json => "application/grpc+json",
            Self::Other => "application/grpc",
        }
    }
}

// -----------------------------------------------------------------------------
// GrpcWebKind
// -----------------------------------------------------------------------------

/// The gRPC-Web variant a request or response uses.
///
/// gRPC-Web exists because browsers cannot speak gRPC: they have no
/// access to HTTP/2 trailers, and until recently no way to send a
/// streaming request body. The wire format is the same length-prefixed
/// framing, with the call's trailers appended to the body as one final
/// frame — and, for the `-text` variant, the whole stream base64-encoded
/// so it survives an `XMLHttpRequest`.
///
/// ```
/// use praxis_core::grpc::{GrpcCodec, GrpcWebKind};
///
/// assert_eq!(
///     GrpcWebKind::from_content_type("application/grpc-web+proto"),
///     GrpcWebKind::Binary(GrpcCodec::Proto)
/// );
/// assert_eq!(
///     GrpcWebKind::from_content_type("application/grpc-web-text"),
///     GrpcWebKind::Text(GrpcCodec::Proto)
/// );
/// // Native gRPC is not gRPC-Web.
/// assert_eq!(
///     GrpcWebKind::from_content_type("application/grpc"),
///     GrpcWebKind::None
/// );
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GrpcWebKind {
    /// Not a gRPC-Web request.
    #[default]
    None,

    /// `application/grpc-web[+codec]` — raw length-prefixed frames.
    Binary(GrpcCodec),

    /// `application/grpc-web-text[+codec]` — base64 of the frame stream.
    Text(GrpcCodec),
}

impl GrpcWebKind {
    /// Detect the gRPC-Web variant from a header map.
    pub fn from_headers(headers: &http::HeaderMap) -> Self {
        headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(Self::from_content_type)
            .unwrap_or_default()
    }

    /// Classify a `content-type` value as a gRPC-Web variant.
    pub fn from_content_type(value: &str) -> Self {
        let mime = value.split_once(';').map_or(value, |(before, _rest)| before).trim();
        let Some(suffix) = strip_prefix_ignore_ascii_case(mime, GRPC_WEB_PREFIX) else {
            return Self::None;
        };
        match strip_prefix_ignore_ascii_case(suffix, TEXT_MARKER) {
            Some(codec) => GrpcCodec::from_suffix(codec).map_or(Self::None, Self::Text),
            None => GrpcCodec::from_suffix(suffix).map_or(Self::None, Self::Binary),
        }
    }

    /// The codec this variant carries.
    pub fn codec(self) -> Option<GrpcCodec> {
        match self {
            Self::None => None,
            Self::Binary(codec) | Self::Text(codec) => Some(codec),
        }
    }

    /// Whether this is a gRPC-Web request at all.
    pub fn is_grpc_web(self) -> bool {
        self != Self::None
    }

    /// Whether the body is base64-encoded.
    pub fn is_text(self) -> bool {
        matches!(self, Self::Text(_))
    }

    /// The native gRPC `content-type` to send upstream.
    ///
    /// Returns `None` for a request that is not gRPC-Web.
    pub fn grpc_content_type(self) -> Option<&'static str> {
        self.codec().map(GrpcCodec::grpc_content_type)
    }

    /// The gRPC-Web `content-type` to answer the browser with.
    ///
    /// ```
    /// use praxis_core::grpc::{GrpcCodec, GrpcWebKind};
    ///
    /// assert_eq!(
    ///     GrpcWebKind::Text(GrpcCodec::Json).web_content_type(),
    ///     Some("application/grpc-web-text+json")
    /// );
    /// ```
    pub fn web_content_type(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Binary(GrpcCodec::Proto) => Some("application/grpc-web+proto"),
            Self::Binary(GrpcCodec::Json) => Some("application/grpc-web+json"),
            Self::Binary(GrpcCodec::Other) => Some("application/grpc-web"),
            Self::Text(GrpcCodec::Proto) => Some("application/grpc-web-text+proto"),
            Self::Text(GrpcCodec::Json) => Some("application/grpc-web-text+json"),
            Self::Text(GrpcCodec::Other) => Some("application/grpc-web-text"),
        }
    }

    /// A stable label for metadata and branch conditions.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Binary(GrpcCodec::Proto) => "grpc-web+proto",
            Self::Binary(GrpcCodec::Json) => "grpc-web+json",
            Self::Binary(GrpcCodec::Other) => "grpc-web",
            Self::Text(GrpcCodec::Proto) => "grpc-web-text+proto",
            Self::Text(GrpcCodec::Json) => "grpc-web-text+json",
            Self::Text(GrpcCodec::Other) => "grpc-web-text",
        }
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Strip an ASCII-case-insensitive prefix.
fn strip_prefix_ignore_ascii_case<'input>(value: &'input str, prefix: &str) -> Option<&'input str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| value.get(prefix.len()..))
        .flatten()
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
    fn every_variant_classifies() {
        for (value, expected) in [
            ("application/grpc-web", GrpcWebKind::Binary(GrpcCodec::Proto)),
            ("application/grpc-web+proto", GrpcWebKind::Binary(GrpcCodec::Proto)),
            ("application/grpc-web+json", GrpcWebKind::Binary(GrpcCodec::Json)),
            ("application/grpc-web+thrift", GrpcWebKind::Binary(GrpcCodec::Other)),
            ("application/grpc-web-text", GrpcWebKind::Text(GrpcCodec::Proto)),
            ("application/grpc-web-text+proto", GrpcWebKind::Text(GrpcCodec::Proto)),
            ("application/grpc-web-text+json", GrpcWebKind::Text(GrpcCodec::Json)),
        ] {
            assert_eq!(
                GrpcWebKind::from_content_type(value),
                expected,
                "{value} should classify as {expected:?}"
            );
        }
    }

    #[test]
    fn native_grpc_is_not_grpc_web() {
        for value in ["application/grpc", "application/grpc+proto", "application/grpc+json"] {
            assert_eq!(
                GrpcWebKind::from_content_type(value),
                GrpcWebKind::None,
                "{value} is native gRPC, which needs no translation"
            );
        }
    }

    #[test]
    fn unrelated_content_types_are_not_grpc_web() {
        for value in ["application/json", "text/plain", "", "application/grpc-webbing"] {
            assert_eq!(
                GrpcWebKind::from_content_type(value),
                GrpcWebKind::None,
                "{value:?} should not classify as gRPC-Web"
            );
        }
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(
            GrpcWebKind::from_content_type("APPLICATION/GRPC-WEB-TEXT+JSON"),
            GrpcWebKind::Text(GrpcCodec::Json),
            "content types are case-insensitive"
        );
    }

    #[test]
    fn parameters_are_ignored() {
        assert_eq!(
            GrpcWebKind::from_content_type("application/grpc-web+proto; charset=utf-8"),
            GrpcWebKind::Binary(GrpcCodec::Proto),
            "a charset parameter should not change the classification"
        );
    }

    #[test]
    fn from_headers_reads_the_content_type() {
        let mut headers = http::HeaderMap::new();
        assert_eq!(
            GrpcWebKind::from_headers(&headers),
            GrpcWebKind::None,
            "an absent content-type is not gRPC-Web"
        );

        let _prev = headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/grpc-web-text"),
        );
        assert_eq!(
            GrpcWebKind::from_headers(&headers),
            GrpcWebKind::Text(GrpcCodec::Proto),
            "the header should be classified"
        );
    }

    #[test]
    fn text_and_binary_are_distinguished() {
        assert!(
            GrpcWebKind::from_content_type("application/grpc-web-text").is_text(),
            "the -text variant is base64"
        );
        assert!(
            !GrpcWebKind::from_content_type("application/grpc-web").is_text(),
            "the binary variant is raw frames"
        );
    }

    #[test]
    fn content_types_round_trip_through_both_directions() {
        for value in [
            "application/grpc-web+proto",
            "application/grpc-web+json",
            "application/grpc-web-text+proto",
            "application/grpc-web-text+json",
        ] {
            let kind = GrpcWebKind::from_content_type(value);
            assert_eq!(
                kind.web_content_type(),
                Some(value),
                "{value} should render back to itself"
            );
            assert!(
                kind.grpc_content_type()
                    .is_some_and(|ct| ct.starts_with("application/grpc+")),
                "{value} should map to a native gRPC content type"
            );
        }
    }

    #[test]
    fn an_unknown_codec_falls_back_to_bare_grpc() {
        let kind = GrpcWebKind::from_content_type("application/grpc-web+thrift");
        assert_eq!(
            kind.grpc_content_type(),
            Some("application/grpc"),
            "an uninterpretable codec should not be echoed into the upstream content type"
        );
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(GrpcWebKind::None.as_str(), "none", "the absent case has a label too");
        assert_eq!(
            GrpcWebKind::Text(GrpcCodec::Json).as_str(),
            "grpc-web-text+json",
            "labels name the variant and codec"
        );
    }

    #[test]
    fn all_labels_are_unique() {
        let labels = [
            GrpcWebKind::None.as_str(),
            GrpcWebKind::Binary(GrpcCodec::Proto).as_str(),
            GrpcWebKind::Binary(GrpcCodec::Json).as_str(),
            GrpcWebKind::Binary(GrpcCodec::Other).as_str(),
            GrpcWebKind::Text(GrpcCodec::Proto).as_str(),
            GrpcWebKind::Text(GrpcCodec::Json).as_str(),
            GrpcWebKind::Text(GrpcCodec::Other).as_str(),
        ];
        let unique_count = labels.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, labels.len(), "every variant should have a unique label");
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "comprehensive edge case coverage")]
    fn strip_prefix_utility_edge_cases() {
        use super::strip_prefix_ignore_ascii_case;

        assert_eq!(
            strip_prefix_ignore_ascii_case("", "prefix"),
            None,
            "empty value should not match any prefix"
        );
        assert_eq!(
            strip_prefix_ignore_ascii_case("pre", "prefix"),
            None,
            "value shorter than prefix should return None"
        );
        assert_eq!(
            strip_prefix_ignore_ascii_case("prefix", "prefix"),
            Some(""),
            "exact match should return empty remainder"
        );
        assert_eq!(
            strip_prefix_ignore_ascii_case("PREFIX", "prefix"),
            Some(""),
            "case-insensitive exact match should return empty remainder"
        );
        assert_eq!(
            strip_prefix_ignore_ascii_case("prefixSUFFIX", "prefix"),
            Some("SUFFIX"),
            "should return the suffix after the prefix"
        );
        assert_eq!(
            strip_prefix_ignore_ascii_case("wrong", "prefix"),
            None,
            "mismatched prefix should return None"
        );
        assert_eq!(
            strip_prefix_ignore_ascii_case("application/grpc-web", "application/grpc-web"),
            Some(""),
            "real-world exact match"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "comprehensive suffix variant testing")]
    fn grpc_codec_from_suffix_coverage() {
        use super::GrpcCodec;

        assert_eq!(
            GrpcCodec::from_suffix(""),
            Some(GrpcCodec::Proto),
            "empty suffix means proto"
        );
        assert_eq!(
            GrpcCodec::from_suffix("+proto"),
            Some(GrpcCodec::Proto),
            "explicit +proto suffix"
        );
        assert_eq!(
            GrpcCodec::from_suffix("+PROTO"),
            Some(GrpcCodec::Proto),
            "+proto is case-insensitive"
        );
        assert_eq!(GrpcCodec::from_suffix("+json"), Some(GrpcCodec::Json), "+json suffix");
        assert_eq!(
            GrpcCodec::from_suffix("+JSON"),
            Some(GrpcCodec::Json),
            "+json is case-insensitive"
        );
        assert_eq!(
            GrpcCodec::from_suffix("+thrift"),
            Some(GrpcCodec::Other),
            "unknown codec starting with + is Other"
        );
        assert_eq!(
            GrpcCodec::from_suffix("+avro"),
            Some(GrpcCodec::Other),
            "another unknown codec"
        );
        assert_eq!(
            GrpcCodec::from_suffix("+"),
            Some(GrpcCodec::Other),
            "bare + is treated as Other"
        );
        assert_eq!(GrpcCodec::from_suffix("proto"), None, "suffix without + is not valid");
        assert_eq!(GrpcCodec::from_suffix("json"), None, "json without + is not valid");
        assert_eq!(
            GrpcCodec::from_suffix("garbage"),
            None,
            "arbitrary text is not a suffix"
        );
        assert_eq!(
            GrpcCodec::from_suffix("-text"),
            None,
            "text marker is not a codec suffix"
        );
    }

    #[test]
    fn grpc_codec_content_types() {
        use super::GrpcCodec;

        assert_eq!(GrpcCodec::Proto.grpc_content_type(), "application/grpc+proto");
        assert_eq!(GrpcCodec::Json.grpc_content_type(), "application/grpc+json");
        assert_eq!(
            GrpcCodec::Other.grpc_content_type(),
            "application/grpc",
            "unknown codecs fall back to bare grpc"
        );
    }

    #[test]
    fn grpc_web_kind_codec_method() {
        assert_eq!(GrpcWebKind::None.codec(), None);
        assert_eq!(GrpcWebKind::Binary(GrpcCodec::Proto).codec(), Some(GrpcCodec::Proto));
        assert_eq!(GrpcWebKind::Binary(GrpcCodec::Json).codec(), Some(GrpcCodec::Json));
        assert_eq!(GrpcWebKind::Binary(GrpcCodec::Other).codec(), Some(GrpcCodec::Other));
        assert_eq!(GrpcWebKind::Text(GrpcCodec::Proto).codec(), Some(GrpcCodec::Proto));
        assert_eq!(GrpcWebKind::Text(GrpcCodec::Json).codec(), Some(GrpcCodec::Json));
        assert_eq!(GrpcWebKind::Text(GrpcCodec::Other).codec(), Some(GrpcCodec::Other));
    }

    #[test]
    fn grpc_web_kind_is_grpc_web() {
        assert!(!GrpcWebKind::None.is_grpc_web());
        assert!(GrpcWebKind::Binary(GrpcCodec::Proto).is_grpc_web());
        assert!(GrpcWebKind::Binary(GrpcCodec::Json).is_grpc_web());
        assert!(GrpcWebKind::Binary(GrpcCodec::Other).is_grpc_web());
        assert!(GrpcWebKind::Text(GrpcCodec::Proto).is_grpc_web());
        assert!(GrpcWebKind::Text(GrpcCodec::Json).is_grpc_web());
        assert!(GrpcWebKind::Text(GrpcCodec::Other).is_grpc_web());
    }

    #[test]
    fn grpc_web_kind_grpc_content_type() {
        assert_eq!(GrpcWebKind::None.grpc_content_type(), None);
        assert_eq!(
            GrpcWebKind::Binary(GrpcCodec::Proto).grpc_content_type(),
            Some("application/grpc+proto")
        );
        assert_eq!(
            GrpcWebKind::Binary(GrpcCodec::Json).grpc_content_type(),
            Some("application/grpc+json")
        );
        assert_eq!(
            GrpcWebKind::Binary(GrpcCodec::Other).grpc_content_type(),
            Some("application/grpc")
        );
        assert_eq!(
            GrpcWebKind::Text(GrpcCodec::Proto).grpc_content_type(),
            Some("application/grpc+proto")
        );
        assert_eq!(
            GrpcWebKind::Text(GrpcCodec::Json).grpc_content_type(),
            Some("application/grpc+json")
        );
        assert_eq!(
            GrpcWebKind::Text(GrpcCodec::Other).grpc_content_type(),
            Some("application/grpc")
        );
    }

    #[test]
    fn grpc_web_kind_web_content_type_all_variants() {
        assert_eq!(GrpcWebKind::None.web_content_type(), None);
        assert_eq!(
            GrpcWebKind::Binary(GrpcCodec::Proto).web_content_type(),
            Some("application/grpc-web+proto")
        );
        assert_eq!(
            GrpcWebKind::Binary(GrpcCodec::Json).web_content_type(),
            Some("application/grpc-web+json")
        );
        assert_eq!(
            GrpcWebKind::Binary(GrpcCodec::Other).web_content_type(),
            Some("application/grpc-web")
        );
        assert_eq!(
            GrpcWebKind::Text(GrpcCodec::Proto).web_content_type(),
            Some("application/grpc-web-text+proto")
        );
        assert_eq!(
            GrpcWebKind::Text(GrpcCodec::Json).web_content_type(),
            Some("application/grpc-web-text+json")
        );
        assert_eq!(
            GrpcWebKind::Text(GrpcCodec::Other).web_content_type(),
            Some("application/grpc-web-text")
        );
    }

    #[test]
    fn whitespace_handling_in_content_type() {
        assert_eq!(
            GrpcWebKind::from_content_type("  application/grpc-web  "),
            GrpcWebKind::Binary(GrpcCodec::Proto),
            "leading/trailing whitespace is trimmed"
        );
        assert_eq!(
            GrpcWebKind::from_content_type("application/grpc-web  ; charset=utf-8"),
            GrpcWebKind::Binary(GrpcCodec::Proto),
            "whitespace before semicolon is trimmed"
        );
        assert_eq!(
            GrpcWebKind::from_content_type("application/grpc-web;  charset=utf-8"),
            GrpcWebKind::Binary(GrpcCodec::Proto),
            "parameters after semicolon are ignored"
        );
        assert_eq!(
            GrpcWebKind::from_content_type("  application/grpc-web-text+json  "),
            GrpcWebKind::Text(GrpcCodec::Json),
            "whitespace trimmed for text variant"
        );
    }

    #[test]
    fn invalid_suffix_patterns() {
        assert_eq!(
            GrpcWebKind::from_content_type("application/grpc-webbing"),
            GrpcWebKind::None,
            "grpc-webbing is not a valid grpc-web variant"
        );
        assert_eq!(
            GrpcWebKind::from_content_type("application/grpc-web-textual"),
            GrpcWebKind::None,
            "grpc-web-textual is not the text variant"
        );
        assert_eq!(
            GrpcWebKind::from_content_type("application/grpc-web-text-extra"),
            GrpcWebKind::None,
            "extra suffix after -text is invalid"
        );
        assert_eq!(
            GrpcWebKind::from_content_type("application/grpc-web+"),
            GrpcWebKind::Binary(GrpcCodec::Other),
            "bare + after grpc-web is treated as Other codec"
        );
        assert_eq!(
            GrpcWebKind::from_content_type("application/grpc-web-text+"),
            GrpcWebKind::Text(GrpcCodec::Other),
            "bare + after grpc-web-text is treated as Other codec"
        );
    }

    #[test]
    fn codec_edge_cases() {
        assert_eq!(
            GrpcWebKind::from_content_type("application/grpc-web+avro"),
            GrpcWebKind::Binary(GrpcCodec::Other),
            "avro codec is Other"
        );
        assert_eq!(
            GrpcWebKind::from_content_type("application/grpc-web+flatbuffers"),
            GrpcWebKind::Binary(GrpcCodec::Other),
            "flatbuffers codec is Other"
        );
        assert_eq!(
            GrpcWebKind::from_content_type("application/grpc-web-text+thrift"),
            GrpcWebKind::Text(GrpcCodec::Other),
            "thrift codec with text variant is Other"
        );
    }

    #[test]
    fn from_headers_with_non_utf8() {
        let mut headers = http::HeaderMap::new();
        let non_utf8_bytes = vec![0xFF, 0xFE, 0xFD];
        let _prev = headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_bytes(&non_utf8_bytes).unwrap(),
        );
        assert_eq!(
            GrpcWebKind::from_headers(&headers),
            GrpcWebKind::None,
            "non-UTF8 content-type should not classify"
        );
    }

    #[test]
    fn multiple_semicolons_in_content_type() {
        assert_eq!(
            GrpcWebKind::from_content_type("application/grpc-web;charset=utf-8;boundary=foo"),
            GrpcWebKind::Binary(GrpcCodec::Proto),
            "multiple parameters should be ignored"
        );
        assert_eq!(
            GrpcWebKind::from_content_type("application/grpc-web-text+json;a=1;b=2;c=3"),
            GrpcWebKind::Text(GrpcCodec::Json),
            "many parameters should not affect classification"
        );
    }

    #[test]
    fn grpc_codec_default() {
        assert_eq!(GrpcCodec::default(), GrpcCodec::Proto, "default codec is proto");
    }

    #[test]
    fn grpc_web_kind_default() {
        assert_eq!(GrpcWebKind::default(), GrpcWebKind::None, "default is None");
    }

    #[test]
    fn grpc_codec_debug() {
        let proto_debug = format!("{:?}", GrpcCodec::Proto);
        assert!(proto_debug.contains("Proto"));

        let json_debug = format!("{:?}", GrpcCodec::Json);
        assert!(json_debug.contains("Json"));

        let other_debug = format!("{:?}", GrpcCodec::Other);
        assert!(other_debug.contains("Other"));
    }

    #[test]
    fn grpc_web_kind_debug() {
        let none_debug = format!("{:?}", GrpcWebKind::None);
        assert!(none_debug.contains("None"));

        let binary_debug = format!("{:?}", GrpcWebKind::Binary(GrpcCodec::Proto));
        assert!(binary_debug.contains("Binary"));

        let text_debug = format!("{:?}", GrpcWebKind::Text(GrpcCodec::Json));
        assert!(text_debug.contains("Text"));
    }

    #[test]
    fn grpc_codec_clone_and_copy() {
        let original = GrpcCodec::Json;
        let cloned = original;
        assert_eq!(original, cloned);

        let copied = original;
        assert_eq!(original, copied);
    }

    #[test]
    fn grpc_web_kind_clone_and_copy() {
        let original = GrpcWebKind::Text(GrpcCodec::Proto);
        let cloned = original;
        assert_eq!(original, cloned);

        let copied = original;
        assert_eq!(original, copied);
    }

    #[test]
    fn empty_content_type() {
        assert_eq!(
            GrpcWebKind::from_content_type(""),
            GrpcWebKind::None,
            "empty content type is not gRPC-Web"
        );
    }

    #[test]
    fn bare_application_type() {
        assert_eq!(
            GrpcWebKind::from_content_type("application/"),
            GrpcWebKind::None,
            "bare application/ is not gRPC-Web"
        );
        assert_eq!(
            GrpcWebKind::from_content_type("application"),
            GrpcWebKind::None,
            "bare application is not gRPC-Web"
        );
    }
}
