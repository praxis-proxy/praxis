// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! gRPC content-type classification for HTTP filter context.

// -----------------------------------------------------------------------------
// GrpcKind
// -----------------------------------------------------------------------------

/// Classifies the gRPC variant from the request `content-type` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum GrpcKind {
    /// Not a gRPC request.
    #[default]
    None,

    /// `application/grpc` (implicit protobuf codec).
    Grpc,

    /// `application/grpc+proto` (explicit protobuf codec).
    GrpcProto,

    /// `application/grpc+json` (JSON codec).
    GrpcJson,

    /// `application/grpc+{codec}` (unrecognized codec).
    GrpcOther,
}

impl GrpcKind {
    /// Detect the gRPC variant from a request header map.
    pub(crate) fn from_headers(headers: &http::HeaderMap) -> Self {
        headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(Self::from_content_type)
            .unwrap_or_default()
    }

    /// Classify a `content-type` header value as a gRPC variant.
    pub(crate) fn from_content_type(value: &str) -> Self {
        let mime = value.split_once(';').map_or(value, |(before, _)| before).trim();
        if !mime
            .get(..16)
            .is_some_and(|p| p.as_bytes().eq_ignore_ascii_case(b"application/grpc"))
        {
            return Self::None;
        }
        let suffix = mime.get(16..).unwrap_or_default();
        if suffix.is_empty() {
            Self::Grpc
        } else if suffix.eq_ignore_ascii_case("+proto") {
            Self::GrpcProto
        } else if suffix.eq_ignore_ascii_case("+json") {
            Self::GrpcJson
        } else if suffix.starts_with('+') {
            Self::GrpcOther
        } else {
            Self::None
        }
    }

    /// Return the content-type sub-type as a static string.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Grpc => "grpc",
            Self::GrpcProto => "grpc+proto",
            Self::GrpcJson => "grpc+json",
            Self::GrpcOther => "grpc+other",
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
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
    fn default_is_none() {
        assert_eq!(GrpcKind::default(), GrpcKind::None, "default GrpcKind should be None");
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(GrpcKind::None, GrpcKind::Grpc, "None and Grpc should differ");
        assert_ne!(GrpcKind::Grpc, GrpcKind::GrpcProto, "Grpc and GrpcProto should differ");
        assert_ne!(GrpcKind::Grpc, GrpcKind::GrpcJson, "Grpc and GrpcJson should differ");
        assert_ne!(
            GrpcKind::GrpcProto,
            GrpcKind::GrpcJson,
            "GrpcProto and GrpcJson should differ"
        );
    }

    #[test]
    fn from_content_type_bare_grpc() {
        assert_eq!(
            GrpcKind::from_content_type("application/grpc"),
            GrpcKind::Grpc,
            "bare application/grpc should map to Grpc"
        );
    }

    #[test]
    fn from_content_type_proto() {
        assert_eq!(
            GrpcKind::from_content_type("application/grpc+proto"),
            GrpcKind::GrpcProto,
            "application/grpc+proto should map to GrpcProto"
        );
    }

    #[test]
    fn from_content_type_json() {
        assert_eq!(
            GrpcKind::from_content_type("application/grpc+json"),
            GrpcKind::GrpcJson,
            "application/grpc+json should map to GrpcJson"
        );
    }

    #[test]
    fn from_content_type_unknown_codec() {
        assert_eq!(
            GrpcKind::from_content_type("application/grpc+flatbuffers"),
            GrpcKind::GrpcOther,
            "unknown gRPC codec should map to GrpcOther"
        );
    }

    #[test]
    fn from_content_type_with_params() {
        assert_eq!(
            GrpcKind::from_content_type("application/grpc+proto; charset=utf-8"),
            GrpcKind::GrpcProto,
            "should ignore parameters after semicolon"
        );
    }

    #[test]
    fn from_content_type_case_insensitive() {
        assert_eq!(
            GrpcKind::from_content_type("Application/GRPC+Proto"),
            GrpcKind::GrpcProto,
            "matching should be case-insensitive"
        );
    }

    #[test]
    fn from_content_type_non_grpc() {
        assert_eq!(
            GrpcKind::from_content_type("application/json"),
            GrpcKind::None,
            "non-gRPC content type should map to None"
        );
    }

    #[test]
    fn from_content_type_empty() {
        assert_eq!(
            GrpcKind::from_content_type(""),
            GrpcKind::None,
            "empty content type should map to None"
        );
    }

    #[test]
    fn from_content_type_grpc_prefix_without_plus() {
        assert_eq!(
            GrpcKind::from_content_type("application/grpcx"),
            GrpcKind::None,
            "application/grpcx without + should map to None"
        );
    }

    #[test]
    fn from_content_type_grpc_web_is_not_grpc() {
        assert_eq!(
            GrpcKind::from_content_type("application/grpc-web"),
            GrpcKind::None,
            "gRPC-Web is a separate protocol and should not match"
        );
    }

    #[test]
    fn from_headers_with_grpc_content_type() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "application/grpc".parse().unwrap());
        assert_eq!(
            GrpcKind::from_headers(&headers),
            GrpcKind::Grpc,
            "should detect gRPC from header map"
        );
    }

    #[test]
    fn from_headers_without_content_type() {
        let headers = http::HeaderMap::new();
        assert_eq!(
            GrpcKind::from_headers(&headers),
            GrpcKind::None,
            "missing content-type should default to None"
        );
    }

    #[test]
    fn from_headers_non_grpc_content_type() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "text/html".parse().unwrap());
        assert_eq!(
            GrpcKind::from_headers(&headers),
            GrpcKind::None,
            "non-gRPC content-type should map to None"
        );
    }

    #[test]
    fn from_headers_non_utf8_content_type() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_bytes(b"application/grpc\xff").unwrap(),
        );
        assert_eq!(
            GrpcKind::from_headers(&headers),
            GrpcKind::None,
            "non-UTF-8 content-type should default to None"
        );
    }

    #[test]
    fn as_str_returns_expected_values() {
        assert_eq!(GrpcKind::None.as_str(), "none", "None should map to 'none'");
        assert_eq!(GrpcKind::Grpc.as_str(), "grpc", "Grpc should map to 'grpc'");
        assert_eq!(
            GrpcKind::GrpcProto.as_str(),
            "grpc+proto",
            "GrpcProto should map to 'grpc+proto'"
        );
        assert_eq!(
            GrpcKind::GrpcJson.as_str(),
            "grpc+json",
            "GrpcJson should map to 'grpc+json'"
        );
        assert_eq!(
            GrpcKind::GrpcOther.as_str(),
            "grpc+other",
            "GrpcOther should map to 'grpc+other'"
        );
    }
}
