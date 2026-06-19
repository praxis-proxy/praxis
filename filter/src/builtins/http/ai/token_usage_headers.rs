// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Token usage response header injection filter.

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use tracing::trace;

use crate::{
    FilterAction, FilterError,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Response header carrying the input (prompt) token count.
const HEADER_TOKEN_INPUT: HeaderName = HeaderName::from_static("praxis-token-input");

/// Response header carrying the output (completion) token count.
const HEADER_TOKEN_OUTPUT: HeaderName = HeaderName::from_static("praxis-token-output");

/// Response header carrying the total token count.
const HEADER_TOKEN_TOTAL: HeaderName = HeaderName::from_static("praxis-token-total");

/// Metadata key for the input token count.
const META_TOKEN_INPUT: &str = "token.input";

/// Metadata key for the output token count.
const META_TOKEN_OUTPUT: &str = "token.output";

/// Metadata key for the total token count.
const META_TOKEN_TOTAL: &str = "token.total";

// -----------------------------------------------------------------------------
// TokenUsageHeadersFilter
// -----------------------------------------------------------------------------

/// Injects `Praxis-Token-Input`, `Praxis-Token-Output`, and
/// `Praxis-Token-Total` headers into downstream responses when
/// token usage data is present in [`filter_metadata`].
///
/// Reads token counts written by upstream filters and exposes them
/// as HTTP response headers for infrastructure-level consumption
/// (billing, monitoring, logging).
///
/// When no token metadata is present the filter is a no-op.
///
/// # YAML configuration
///
/// ```yaml
/// filter: token_usage_headers
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::TokenUsageHeadersFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
/// let filter = TokenUsageHeadersFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "token_usage_headers");
/// ```
///
/// [`filter_metadata`]: HttpFilterContext::filter_metadata
pub struct TokenUsageHeadersFilter;

impl TokenUsageHeadersFilter {
    /// Create a token usage headers filter from parsed YAML config.
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
impl HttpFilter for TokenUsageHeadersFilter {
    fn name(&self) -> &'static str {
        "token_usage_headers"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        inject_usage_headers(ctx);
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Header Injection
// -----------------------------------------------------------------------------

/// Read token counts from `filter_metadata` and inject them as
/// response headers. No-op when response headers are absent or
/// no token data has been written by upstream filters.
fn inject_usage_headers(ctx: &mut HttpFilterContext<'_>) {
    let (Some(input), Some(output), Some(total)) = (
        ctx.get_metadata(META_TOKEN_INPUT).map(str::to_owned),
        ctx.get_metadata(META_TOKEN_OUTPUT).map(str::to_owned),
        ctx.get_metadata(META_TOKEN_TOTAL).map(str::to_owned),
    ) else {
        trace!("no token usage metadata found, skipping header injection");
        return;
    };

    let Some(resp) = ctx.response_header.as_mut() else {
        return;
    };

    ctx.response_headers_modified = true;

    let headers = &mut resp.headers;
    insert_token_header(headers, HEADER_TOKEN_INPUT.clone(), &input);
    insert_token_header(headers, HEADER_TOKEN_OUTPUT.clone(), &output);
    insert_token_header(headers, HEADER_TOKEN_TOTAL.clone(), &total);

    trace!("injected token usage response headers");
}

/// Insert a token count as a response header, logging on failure.
fn insert_token_header(headers: &mut http::HeaderMap, name: HeaderName, value: &str) {
    match HeaderValue::from_str(value) {
        Ok(hv) => {
            headers.insert(name, hv);
        },
        Err(err) => {
            tracing::debug!(
                header = %name,
                %err,
                "failed to convert token value to header"
            );
        },
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    fn set_token_metadata(ctx: &mut HttpFilterContext<'_>, input: &str, output: &str, total: &str) {
        ctx.set_metadata(META_TOKEN_INPUT, input.to_owned());
        ctx.set_metadata(META_TOKEN_OUTPUT, output.to_owned());
        ctx.set_metadata(META_TOKEN_TOTAL, total.to_owned());
    }

    #[tokio::test]
    async fn injects_all_three_headers() {
        let filter = TokenUsageHeadersFilter;
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        set_token_metadata(&mut ctx, "150", "350", "500");

        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());

        assert!(
            ctx.response_headers_modified,
            "should mark response headers as modified"
        );
        ctx.response_header = None;

        assert_eq!(resp.headers["praxis-token-input"], "150", "input token header mismatch");
        assert_eq!(
            resp.headers["praxis-token-output"], "350",
            "output token header mismatch"
        );
        assert_eq!(resp.headers["praxis-token-total"], "500", "total token header mismatch");
    }

    #[tokio::test]
    async fn skips_when_no_metadata() {
        let filter = TokenUsageHeadersFilter;
        let req = crate::test_utils::make_request(http::Method::GET, "/health");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());

        assert!(!ctx.response_headers_modified, "headers should not be marked modified");
        ctx.response_header = None;

        assert!(
            resp.headers.is_empty(),
            "no headers should be injected without metadata"
        );
    }

    #[tokio::test]
    async fn skips_when_partial_metadata() {
        let filter = TokenUsageHeadersFilter;
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        ctx.set_metadata(META_TOKEN_INPUT, "200".to_owned());

        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());

        assert!(
            !ctx.response_headers_modified,
            "should not inject when only partial data is present"
        );
        ctx.response_header = None;

        assert!(
            resp.headers.is_empty(),
            "no headers should be injected with incomplete token data"
        );
    }

    #[tokio::test]
    async fn noop_without_response_header() {
        let filter = TokenUsageHeadersFilter;
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_response(&mut ctx).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "should return Continue without response header"
        );
        assert!(
            !ctx.response_headers_modified,
            "headers should not be marked modified without response header"
        );
    }

    #[tokio::test]
    async fn handles_large_token_values() {
        let filter = TokenUsageHeadersFilter;
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let large = u64::MAX.to_string();
        set_token_metadata(&mut ctx, &large, &large, &large);

        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());

        ctx.response_header = None;

        assert_eq!(resp.headers["praxis-token-input"], large, "should handle max u64 input");
        assert_eq!(
            resp.headers["praxis-token-output"], large,
            "should handle max u64 output"
        );
        assert_eq!(resp.headers["praxis-token-total"], large, "should handle max u64 total");
    }

    #[tokio::test]
    async fn skips_header_with_invalid_value() {
        let filter = TokenUsageHeadersFilter;
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata(META_TOKEN_INPUT, "100".to_owned());
        ctx.set_metadata(META_TOKEN_OUTPUT, "bad\nvalue".to_owned());
        ctx.set_metadata(META_TOKEN_TOTAL, "200".to_owned());

        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;

        assert_eq!(
            resp.headers.get("praxis-token-input").map(|v| v.to_str().unwrap()),
            Some("100")
        );
        assert!(
            resp.headers.get("praxis-token-output").is_none(),
            "invalid value should be skipped"
        );
        assert_eq!(
            resp.headers.get("praxis-token-total").map(|v| v.to_str().unwrap()),
            Some("200")
        );
    }

    #[test]
    fn from_config_succeeds_with_empty_config() {
        let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let filter = TokenUsageHeadersFilter::from_config(&config).unwrap();
        assert_eq!(filter.name(), "token_usage_headers", "filter name should match");
    }
}
