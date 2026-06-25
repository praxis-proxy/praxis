// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Token usage response header filter: injects `X-Token-Input`,
//! `X-Token-Output`, and `X-Token-Total` into downstream responses.
//!
//! Reads token counts written by the `token_count` filter from
//! `FilterContext` metadata (`token.input`, `token.output`, `token.total`)
//! and injects them as HTTP response headers. Headers are only injected
//! when all three metadata keys are present.

use async_trait::async_trait;
use http::header::HeaderValue;

use crate::{
    FilterAction, FilterError,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// XTokenHeadersFilter
// -----------------------------------------------------------------------------

/// Injects token usage counts as HTTP response headers.
///
/// Reads `token.input`, `token.output`, and `token.total` from
/// `FilterContext` metadata and injects them as `X-Token-Input`,
/// `X-Token-Output`, and `X-Token-Total` response headers.
///
/// # YAML configuration
///
/// ```yaml
/// filter: x_token_headers
/// ```
///
/// No configuration fields. Place after `token_count` in the pipeline.
pub struct XTokenHeadersFilter;

impl XTokenHeadersFilter {
    /// Create from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is malformed.
    #[expect(clippy::unnecessary_wraps, reason = "signature required by registry")]
    pub fn from_config(_config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        Ok(Box::new(Self))
    }
}

#[async_trait]
impl HttpFilter for XTokenHeadersFilter {
    fn name(&self) -> &'static str {
        "x_token_headers"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let input = ctx.get_metadata("token.input").and_then(|s| s.parse::<u64>().ok());
        let output = ctx.get_metadata("token.output").and_then(|s| s.parse::<u64>().ok());
        let total = ctx.get_metadata("token.total").and_then(|s| s.parse::<u64>().ok());

        let mut modified = false;

        if let (Some(i), Some(o), Some(t)) = (input, output, total)
            && let Some(resp) = ctx.response_header.as_mut()
        {
            resp.headers.insert("x-token-input", HeaderValue::from(i));
            resp.headers.insert("x-token-output", HeaderValue::from(o));
            resp.headers.insert("x-token-total", HeaderValue::from(t));
            modified = true;
        }

        if modified {
            ctx.response_headers_modified = true;
        }

        Ok(FilterAction::Continue)
    }
}
