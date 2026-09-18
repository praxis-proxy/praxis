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

    /// Some other `+codec`, which Praxis forwards without interpreting.
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
// Helpers
// -----------------------------------------------------------------------------

/// Strip an ASCII-case-insensitive prefix.
fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
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
}
