//! Model-to-header filter: promotes the "model" JSON body field to a
//! request header for AI inference routing.
//!
//! Wraps [`JsonBodyFieldFilter`] with a preset field name of "model".
//! Registered as `"model_to_header"` in the filter registry.
//!
//! [`JsonBodyFieldFilter`]: crate::JsonBodyFieldFilter

use async_trait::async_trait;
use bytes::Bytes;

use crate::{
    FilterAction, FilterError, JsonBodyFieldFilter,
    body::{BodyAccess, BodyMode},
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default header name for the promoted model value.
const DEFAULT_HEADER: &str = "X-Model";

// -----------------------------------------------------------------------------
// ModelToHeaderFilter
// -----------------------------------------------------------------------------

/// Promotes the JSON `"model"` field from the request body to a
/// request header for downstream routing.
///
/// This is a convenience filter for AI inference proxying. It
/// wraps [`JsonBodyFieldFilter`] with a fixed field name of
/// `"model"` and a configurable header (default: `X-Model`).
///
/// # YAML configuration
///
/// ```yaml
/// filter: model_to_header
/// header: X-Model   # optional, defaults to X-Model
/// ```
///
/// # Example
///
/// ```
/// use praxis_filter::ModelToHeaderFilter;
///
/// let yaml = serde_yaml::Value::Null;
/// let filter = ModelToHeaderFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "model_to_header");
/// ```
///
/// [`JsonBodyFieldFilter`]: crate::JsonBodyFieldFilter
pub struct ModelToHeaderFilter {
    /// The inner [`JsonBodyFieldFilter`] doing the actual work.
    ///
    /// [`JsonBodyFieldFilter`]: crate::JsonBodyFieldFilter
    inner: Box<dyn HttpFilter>,
}

// -----------------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------------

impl ModelToHeaderFilter {
    /// Create from parsed YAML config.
    ///
    /// Accepts an optional `header` field (defaults to `X-Model`).
    ///
    /// ```
    /// use praxis_filter::ModelToHeaderFilter;
    ///
    /// let yaml: serde_yaml::Value =
    ///     serde_yaml::from_str("header: X-AI-Model").unwrap();
    /// let filter = ModelToHeaderFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "model_to_header");
    /// ```
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let header = config.get("header").and_then(|v| v.as_str()).unwrap_or(DEFAULT_HEADER);

        let mut inner_config = serde_yaml::Mapping::new();
        inner_config.insert(
            serde_yaml::Value::String("field".into()),
            serde_yaml::Value::String("model".into()),
        );
        inner_config.insert(
            serde_yaml::Value::String("header".into()),
            serde_yaml::Value::String(header.to_owned()),
        );

        let inner = JsonBodyFieldFilter::from_config(&serde_yaml::Value::Mapping(inner_config))?;

        Ok(Box::new(Self { inner }))
    }
}

// -----------------------------------------------------------------------------
// Filter Impl
// -----------------------------------------------------------------------------

#[async_trait]
impl HttpFilter for ModelToHeaderFilter {
    fn name(&self) -> &'static str {
        "model_to_header"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.inner.on_request(ctx).await
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.inner.on_response(ctx).await
    }

    fn request_body_access(&self) -> BodyAccess {
        self.inner.request_body_access()
    }

    fn response_body_access(&self) -> BodyAccess {
        self.inner.response_body_access()
    }

    fn request_body_mode(&self) -> BodyMode {
        self.inner.request_body_mode()
    }

    fn response_body_mode(&self) -> BodyMode {
        self.inner.response_body_mode()
    }

    fn needs_request_context(&self) -> bool {
        self.inner.needs_request_context()
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.inner.on_request_body(ctx, body, end_of_stream).await
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.inner.on_response_body(ctx, body, end_of_stream)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_default_header() {
        let filter = ModelToHeaderFilter::from_config(&serde_yaml::Value::Null).unwrap();
        assert_eq!(filter.name(), "model_to_header");
    }

    #[test]
    fn from_config_custom_header() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("header: X-AI-Model").unwrap();
        let filter = ModelToHeaderFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "model_to_header");
    }

    #[test]
    fn body_access_delegates_to_inner() {
        let filter = ModelToHeaderFilter::from_config(&serde_yaml::Value::Null).unwrap();
        assert_eq!(filter.request_body_access(), BodyAccess::ReadOnly);
        assert_eq!(filter.request_body_mode(), BodyMode::StreamBuffer { max_bytes: None });
    }

    #[tokio::test]
    async fn extracts_model_field() {
        let filter = ModelToHeaderFilter::from_config(&serde_yaml::Value::Null).unwrap();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"model":"gpt-4","prompt":"hello"}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(matches!(action, FilterAction::Release));
        assert_eq!(ctx.extra_request_headers.len(), 1);
        assert_eq!(
            ctx.extra_request_headers[0],
            ("X-Model".to_string(), "gpt-4".to_string())
        );
    }

    #[tokio::test]
    async fn custom_header_name_used() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("header: X-AI-Model").unwrap();
        let filter = ModelToHeaderFilter::from_config(&yaml).unwrap();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"model":"claude-3","messages":[]}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(matches!(action, FilterAction::Release));
        assert_eq!(
            ctx.extra_request_headers[0],
            ("X-AI-Model".to_string(), "claude-3".to_string())
        );
    }

    #[tokio::test]
    async fn continues_when_model_absent() {
        let filter = ModelToHeaderFilter::from_config(&serde_yaml::Value::Null).unwrap();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"prompt":"hello"}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
        assert!(ctx.extra_request_headers.is_empty());
    }

    #[tokio::test]
    async fn on_request_is_noop() {
        let filter = ModelToHeaderFilter::from_config(&serde_yaml::Value::Null).unwrap();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
    }
}
