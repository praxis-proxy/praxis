// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! gRPC error-envelope filter: answer proxy errors with a `grpc-status`.

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;

use async_trait::async_trait;
use praxis_core::grpc::GrpcKind;
use serde::Deserialize;
use tracing::trace;

use crate::{
    FilterAction, FilterError, GrpcErrorMapping,
    filter::{HttpFilter, HttpFilterContext},
    parse_filter_config,
};

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// How the filter decides a request is gRPC.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum DetectMode {
    /// Classify the request `content-type`.
    #[default]
    ContentType,

    /// Treat every request on this chain as gRPC.
    Always,
}

/// The `content-type` written on a Trailers-Only error response.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ResponseContentType {
    /// Echo the request's gRPC codec (`application/grpc+json`, ...).
    #[default]
    Echo,

    /// Always bare `application/grpc`.
    Grpc,
}

/// Configuration for the `grpc_status` filter.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GrpcStatusConfig {
    /// `content-type` written on the error response.
    content_type: ResponseContentType,

    /// Which requests get gRPC error responses.
    detect: DetectMode,

    /// Whether to include the proxy's error text as `grpc-message`.
    include_message: bool,
}

impl Default for GrpcStatusConfig {
    fn default() -> Self {
        Self {
            content_type: ResponseContentType::default(),
            detect: DetectMode::default(),
            // The message is what tells an operator which proxy rule
            // rejected the call, so it is on unless turned off.
            include_message: true,
        }
    }
}

// -----------------------------------------------------------------------------
// Filter
// -----------------------------------------------------------------------------

/// Answers proxy-generated errors in the shape gRPC clients expect.
///
/// gRPC carries a call's outcome in a `grpc-status` header on an HTTP
/// `200`, not in the HTTP status. When Praxis rejects a call itself —
/// an ACL denial, a missing route, an unreachable upstream — it writes
/// an ordinary HTTP error, which a gRPC client reports as a transport
/// failure with no usable status. This filter marks the request so
/// those errors are emitted as Trailers-Only responses instead: a
/// single header block, no body, with `grpc-status` mapped from the
/// HTTP status Praxis chose.
///
/// Successful short-circuits (a CORS preflight, a `static_response`)
/// are left as real HTTP responses: only error statuses become gRPC
/// statuses.
///
/// Non-gRPC requests are untouched, so a listener can carry mixed
/// traffic.
///
/// # YAML
///
/// ```yaml
/// filter: grpc_status
/// detect: content_type    # content_type | always
/// content_type: echo      # echo | grpc
/// include_message: true
/// ```
pub struct GrpcStatusFilter {
    /// `content-type` written on the error response.
    content_type: ResponseContentType,

    /// Which requests get gRPC error responses.
    detect: DetectMode,

    /// Whether to include `grpc-message`.
    include_message: bool,
}

impl GrpcStatusFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: GrpcStatusConfig = parse_filter_config("grpc_status", config)?;
        Ok(Box::new(Self {
            content_type: cfg.content_type,
            detect: cfg.detect,
            include_message: cfg.include_message,
        }))
    }

    /// The mapping to install for a request of this gRPC kind.
    fn mapping_for(&self, kind: GrpcKind) -> GrpcErrorMapping {
        match self.content_type {
            ResponseContentType::Echo => GrpcErrorMapping::new(kind, self.include_message),
            ResponseContentType::Grpc => GrpcErrorMapping::with_content_type(
                http::HeaderValue::from_static("application/grpc"),
                self.include_message,
            ),
        }
    }
}

#[async_trait]
impl HttpFilter for GrpcStatusFilter {
    fn name(&self) -> &'static str {
        "grpc_status"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let kind = GrpcKind::from_headers(&ctx.request.headers);
        if self.detect == DetectMode::ContentType && !kind.is_grpc() {
            return Ok(FilterAction::Continue);
        }

        trace!(grpc_kind = kind.as_str(), "arming gRPC error responses");
        ctx.extensions.insert(self.mapping_for(kind));
        Ok(FilterAction::Continue)
    }
}
