// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Request-scoped instruction to answer proxy errors in gRPC's shape.

use praxis_core::grpc::GrpcKind;

// -----------------------------------------------------------------------------
// GrpcErrorMapping
// -----------------------------------------------------------------------------

/// Render proxy-generated errors for this request as gRPC Trailers-Only
/// responses.
///
/// A gRPC client reading an HTTP `403` sees a transport failure, not a
/// `PERMISSION_DENIED`: the status it needs lives in a `grpc-status`
/// header, and the response must be a single header block with no body.
/// A request-phase filter installs this marker in
/// [`HttpFilterContext::extensions`], and the protocol layer consults it
/// wherever it synthesises an error. Absent, Praxis emits its ordinary
/// HTTP error responses.
///
/// ```
/// use praxis_core::grpc::GrpcKind;
/// use praxis_filter::GrpcErrorMapping;
///
/// let mapping = GrpcErrorMapping::new(GrpcKind::GrpcJson, true);
/// assert_eq!(mapping.content_type(), "application/grpc+json");
/// assert!(mapping.include_message());
/// ```
///
/// [`HttpFilterContext::extensions`]: crate::HttpFilterContext::extensions
#[derive(Clone, Debug)]
pub struct GrpcErrorMapping {
    /// `content-type` to write on the error response.
    content_type: http::HeaderValue,

    /// Whether to include `grpc-message` alongside `grpc-status`.
    include_message: bool,
}

impl GrpcErrorMapping {
    /// Build a mapping that echoes the request's gRPC codec.
    pub fn new(kind: GrpcKind, include_message: bool) -> Self {
        Self {
            content_type: content_type_for(kind),
            include_message,
        }
    }

    /// Build a mapping with an explicit response `content-type`.
    pub fn with_content_type(content_type: http::HeaderValue, include_message: bool) -> Self {
        Self {
            content_type,
            include_message,
        }
    }

    /// The `content-type` to write on the error response.
    pub fn content_type(&self) -> &http::HeaderValue {
        &self.content_type
    }

    /// Whether `grpc-message` should carry the proxy's error text.
    pub fn include_message(&self) -> bool {
        self.include_message
    }
}

/// The response `content-type` echoing a request's gRPC codec.
///
/// An unrecognised or absent codec answers bare `application/grpc`,
/// which every gRPC client accepts.
fn content_type_for(kind: GrpcKind) -> http::HeaderValue {
    http::HeaderValue::from_static(match kind {
        GrpcKind::GrpcProto => "application/grpc+proto",
        GrpcKind::GrpcJson => "application/grpc+json",
        GrpcKind::Grpc | GrpcKind::GrpcOther | GrpcKind::None => "application/grpc",
    })
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
    fn content_type_echoes_the_request_codec() {
        for (kind, expected) in [
            (GrpcKind::Grpc, "application/grpc"),
            (GrpcKind::GrpcProto, "application/grpc+proto"),
            (GrpcKind::GrpcJson, "application/grpc+json"),
            (GrpcKind::GrpcOther, "application/grpc"),
            (GrpcKind::None, "application/grpc"),
        ] {
            let mapping = GrpcErrorMapping::new(kind, true);
            assert_eq!(mapping.content_type(), expected, "{kind:?} should answer {expected}");
        }
    }

    #[test]
    fn explicit_content_type_overrides_the_codec() {
        let mapping = GrpcErrorMapping::with_content_type(http::HeaderValue::from_static("application/grpc"), false);
        assert_eq!(mapping.content_type(), "application/grpc", "explicit value should win");
        assert!(!mapping.include_message(), "include_message should be preserved");
    }
}
