// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! gRPC content-type classification for HTTP filter context.

// -----------------------------------------------------------------------------
// GrpcKind
// -----------------------------------------------------------------------------

/// Classifies the gRPC variant from the request `content-type` header.
///
/// ```
/// use praxis_filter::GrpcKind;
///
/// let kind = GrpcKind::default();
/// assert_eq!(kind, GrpcKind::None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GrpcKind {
    /// Not a gRPC request.
    #[default]
    None,

    /// `application/grpc` (implicit protobuf codec).
    Grpc,

    /// `application/grpc+proto` (explicit protobuf codec).
    GrpcProto,

    /// `application/grpc+json` (JSON codec).
    GrpcJson,
}

impl GrpcKind {
    /// Detect the gRPC variant from a request header map.
    pub fn from_headers(headers: &http::HeaderMap) -> Self {
        headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(Self::from_content_type)
            .unwrap_or_default()
    }

    /// Classify a `content-type` header value as a gRPC variant.
    pub fn from_content_type(value: &str) -> Self {
        let mime = value.split(';').next().unwrap_or("").trim();
        if mime.eq_ignore_ascii_case("application/grpc") {
            Self::Grpc
        } else if mime.eq_ignore_ascii_case("application/grpc+proto") {
            Self::GrpcProto
        } else if mime.eq_ignore_ascii_case("application/grpc+json") {
            Self::GrpcJson
        } else {
            Self::None
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
}
