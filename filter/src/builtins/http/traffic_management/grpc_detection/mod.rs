// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! gRPC content-type detection filter.

pub(crate) mod content_type;

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
use tracing::trace;

use self::content_type::GrpcKind;
use crate::{
    EmptyFilterConfig, FilterAction, FilterError,
    filter::{HttpFilter, HttpFilterContext},
    parse_filter_config,
};

/// Detects gRPC requests from the `content-type` header and promotes the
/// variant to filter metadata and results for downstream routing.
///
/// Detection values: `grpc` (bare `application/grpc`), `grpc+proto`,
/// `grpc+json`, `grpc+other` (unrecognized sub-protocol).
///
/// Writes `grpc.kind` to filter metadata and `kind` to the
/// `grpc_detection` filter results for branch chain conditions.
///
/// A non-gRPC request writes neither, so a branch condition cannot
/// match on the absence of gRPC. Branch on a gRPC value and use the
/// fall-through path for everything else.
///
/// # YAML
///
/// ```yaml
/// filter: grpc_detection
/// ```
pub struct GrpcDetectionFilter;

impl GrpcDetectionFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let _: EmptyFilterConfig = parse_filter_config("grpc_detection", config)?;
        Ok(Box::new(Self))
    }
}

#[async_trait]
impl HttpFilter for GrpcDetectionFilter {
    fn name(&self) -> &'static str {
        "grpc_detection"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let kind = GrpcKind::from_headers(&ctx.request.headers);
        if kind == GrpcKind::None {
            return Ok(FilterAction::Continue);
        }

        let kind_str = kind.as_str();
        ctx.set_metadata("grpc.kind", kind_str);

        let results = ctx.filter_results.entry("grpc_detection").or_default();
        results.set("kind", kind_str.to_owned())?;

        trace!(grpc_kind = kind_str, "detected gRPC content-type");

        Ok(FilterAction::Continue)
    }
}
