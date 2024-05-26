//! Model-to-header filter: promotes the "model" JSON body field to a request header for AI inference routing.

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

/// Promotes the JSON `"model"` field from the request body to a request header for downstream routing.
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
    /// Delegated body-field extraction filter (type-erased
    /// [`JsonBodyFieldFilter`]).
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
        assert_eq!(
            filter.name(),
            "model_to_header",
            "default config should produce model_to_header"
        );
    }

    #[test]
    fn from_config_custom_header() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("header: X-AI-Model").unwrap();
        let filter = ModelToHeaderFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "model_to_header", "custom header config should parse");
    }

    #[test]
    fn body_access_delegates_to_inner() {
        let filter = ModelToHeaderFilter::from_config(&serde_yaml::Value::Null).unwrap();
        assert_eq!(
            filter.request_body_access(),
            BodyAccess::ReadOnly,
            "body access should delegate to inner"
        );
        assert!(
            matches!(
                filter.request_body_mode(),
                BodyMode::StreamBuffer {
                    max_bytes: Some(limit)
                } if limit > 0
            ),
            "body mode should be StreamBuffer with a default size limit"
        );
    }

    #[tokio::test]
    async fn extracts_model_field() {
        let filter = ModelToHeaderFilter::from_config(&serde_yaml::Value::Null).unwrap();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"model":"mistral-large-latest","prompt":"hello"}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(
            matches!(action, FilterAction::Release),
            "should release after extracting model"
        );
        assert_eq!(ctx.extra_request_headers.len(), 1, "should add exactly one header");
        let (ref name, ref value) = ctx.extra_request_headers[0];
        assert_eq!(name, "X-Model", "header name should be X-Model");
        assert_eq!(
            value, "mistral-large-latest",
            "model value should be promoted to X-Model header"
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

        assert!(
            matches!(action, FilterAction::Release),
            "should release after extracting model"
        );
        let (ref name, ref value) = ctx.extra_request_headers[0];
        assert_eq!(name, "X-AI-Model", "header name should be X-AI-Model");
        assert_eq!(value, "claude-3", "model should be promoted to custom header name");
    }

    #[tokio::test]
    async fn continues_when_model_absent() {
        let filter = ModelToHeaderFilter::from_config(&serde_yaml::Value::Null).unwrap();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"prompt":"hello"}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "absent model field should continue"
        );
        assert!(
            ctx.extra_request_headers.is_empty(),
            "no headers when model field absent"
        );
    }

    #[tokio::test]
    async fn on_request_is_noop() {
        let filter = ModelToHeaderFilter::from_config(&serde_yaml::Value::Null).unwrap();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue), "on_request should be a no-op");
    }
}
