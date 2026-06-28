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
/// No configuration fields. Place *before* `token_count` in the
/// filter list so that the reverse response-phase execution order
/// runs `token_count` first.
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

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::test_utils::{make_filter_context, make_request, make_response};

    fn meta(ctx: &mut HttpFilterContext<'_>, i: &str, o: &str, t: &str) {
        ctx.set_metadata("token.input", i.to_owned());
        ctx.set_metadata("token.output", o.to_owned());
        ctx.set_metadata("token.total", t.to_owned());
    }

    #[test]
    fn from_config_accepted() {
        let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        assert_eq!(XTokenHeadersFilter::from_config(&yaml).unwrap().name(), "x_token_headers");
    }

    #[tokio::test]
    async fn injects_all_three_headers_when_metadata_present() {
        let filter = XTokenHeadersFilter;
        let req = make_request(http::Method::POST, "/");
        let mut ctx = make_filter_context(&req);
        meta(&mut ctx, "10", "20", "30");
        let mut resp = make_response();
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;
        assert!(ctx.response_headers_modified);
        assert_eq!(resp.headers["x-token-input"], "10");
        assert_eq!(resp.headers["x-token-output"], "20");
        assert_eq!(resp.headers["x-token-total"], "30");
    }

    #[tokio::test]
    async fn noop_when_metadata_absent_or_partial() {
        let filter = XTokenHeadersFilter;
        let req = make_request(http::Method::POST, "/");

        // No metadata at all.
        let mut ctx = make_filter_context(&req);
        let mut resp = make_response();
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;
        assert!(!ctx.response_headers_modified);

        // Only two of three keys present.
        let mut ctx = make_filter_context(&req);
        ctx.set_metadata("token.input", "10".to_owned());
        ctx.set_metadata("token.total", "10".to_owned());
        let mut resp = make_response();
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;
        assert!(!ctx.response_headers_modified);
    }

    #[tokio::test]
    async fn noop_without_response_header() {
        let filter = XTokenHeadersFilter;
        let req = make_request(http::Method::POST, "/");
        let mut ctx = make_filter_context(&req);
        meta(&mut ctx, "10", "20", "30");
        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert!(!ctx.response_headers_modified);
    }

    #[tokio::test]
    async fn noop_when_metadata_is_non_numeric() {
        let filter = XTokenHeadersFilter;
        let req = make_request(http::Method::POST, "/");
        let mut ctx = make_filter_context(&req);
        meta(&mut ctx, "not-a-number", "20", "20");
        let mut resp = make_response();
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;
        assert!(!ctx.response_headers_modified);
    }
}
