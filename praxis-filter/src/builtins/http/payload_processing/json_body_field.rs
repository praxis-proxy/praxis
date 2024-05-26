//! Extracts a top-level JSON field from the request body and promotes
//! it to a request header.
//!
//! Registered as `"json_body_field"` in the filter registry.

use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use tracing::trace;

use crate::{
    FilterAction, FilterError,
    body::{BodyAccess, BodyMode},
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// JsonBodyFieldConfig
// -----------------------------------------------------------------------------

/// YAML configuration for [`JsonBodyFieldFilter`].
#[derive(Debug, Deserialize)]
struct JsonBodyFieldConfig {
    /// Top-level JSON field name to extract.
    field: String,

    /// Request header name to promote the extracted value into.
    header: String,
}

// -----------------------------------------------------------------------------
// JsonBodyFieldFilter
// -----------------------------------------------------------------------------

/// Extracts a top-level field from a JSON request body and promotes
/// its value to a request header using [`StreamBuffer`] mode.
///
/// # YAML configuration
///
/// ```yaml
/// filter: json_body_field
/// field: model
/// header: X-Model
/// ```
///
/// # Example
///
/// ```
/// use praxis_filter::JsonBodyFieldFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(r#"
/// field: model
/// header: X-Model
/// "#).unwrap();
/// let filter = JsonBodyFieldFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "json_body_field");
/// ```
///
/// [`StreamBuffer`]: crate::BodyMode::StreamBuffer
pub struct JsonBodyFieldFilter {
    /// Top-level JSON field name to extract.
    field: String,

    /// Request header name to promote the extracted value into.
    header_name: String,
}

impl JsonBodyFieldFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// ```
    /// use praxis_filter::JsonBodyFieldFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(r#"
    /// field: user_id
    /// header: X-User-Id
    /// "#).unwrap();
    /// let filter = JsonBodyFieldFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "json_body_field");
    /// ```
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: JsonBodyFieldConfig = serde_yaml::from_value(config.clone())?;
        if cfg.field.is_empty() {
            return Err("json_body_field: 'field' must not be empty".into());
        }
        if cfg.header.is_empty() {
            return Err("json_body_field: 'header' must not be empty".into());
        }
        Ok(Box::new(Self {
            field: cfg.field,
            header_name: cfg.header,
        }))
    }
}

#[async_trait]
impl HttpFilter for JsonBodyFieldFilter {
    fn name(&self) -> &'static str {
        "json_body_field"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: None }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let Some(chunk) = body.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        let Ok(value) = serde_json::from_slice::<serde_json::Value>(chunk) else {
            trace!(field = %self.field, "JSON parsing failed; skipping field extraction");
            return Ok(FilterAction::Continue);
        };

        if let Some(field_val) = value.get(&self.field) {
            let text = match field_val {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            trace!(
                field = %self.field,
                header = %self.header_name,
                value = %text,
                "promoting JSON field to header"
            );
            ctx.extra_request_headers.push((self.header_name.clone(), text));
            return Ok(FilterAction::Release);
        }

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_filter(field: &str, header: &str) -> JsonBodyFieldFilter {
        JsonBodyFieldFilter {
            field: field.to_string(),
            header_name: header.to_string(),
        }
    }

    #[test]
    fn parse_config() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            field: model
            header: X-Model
            "#,
        )
        .unwrap();
        let filter = JsonBodyFieldFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "json_body_field");
    }

    #[test]
    fn reject_empty_field() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("field: ''\nheader: X-Model").unwrap();
        let err = JsonBodyFieldFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("'field' must not be empty"), "got: {err}");
    }

    #[test]
    fn reject_empty_header() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("field: model\nheader: ''").unwrap();
        let err = JsonBodyFieldFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("'header' must not be empty"), "got: {err}");
    }

    #[tokio::test]
    async fn extracts_field_from_complete_json() {
        let filter = make_filter("model", "X-Model");
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"model":"gpt-4","prompt":"hi"}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(matches!(action, FilterAction::Release));
    }

    #[tokio::test]
    async fn returns_continue_on_incomplete_json() {
        let filter = make_filter("model", "X-Model");
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let partial = br#"{"model":"gpt-4","pro"#;
        let mut body = Some(Bytes::from_static(partial));

        let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
        assert!(ctx.extra_request_headers.is_empty());
    }

    #[tokio::test]
    async fn returns_continue_when_field_missing() {
        let filter = make_filter("model", "X-Model");
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"prompt":"hello","temperature":0.7}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
        assert!(ctx.extra_request_headers.is_empty());
    }

    #[tokio::test]
    async fn promotes_to_configured_header() {
        let filter = make_filter("user_id", "X-User-Id");
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"user_id":"abc-123","data":"payload"}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(matches!(action, FilterAction::Release));
        assert_eq!(ctx.extra_request_headers.len(), 1);
        assert_eq!(
            ctx.extra_request_headers[0],
            ("X-User-Id".to_string(), "abc-123".to_string())
        );
    }

    #[tokio::test]
    async fn on_request_is_noop() {
        let filter = make_filter("model", "X-Model");
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
    }

    #[tokio::test]
    async fn returns_continue_on_none_body() {
        let filter = make_filter("model", "X-Model");
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut body: Option<Bytes> = None;

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
    }

    #[tokio::test]
    async fn numeric_field_promoted_as_string() {
        let filter = make_filter("count", "X-Count");
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"count":42}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(matches!(action, FilterAction::Release));
        assert_eq!(ctx.extra_request_headers.len(), 1);
        assert_eq!(ctx.extra_request_headers[0], ("X-Count".to_string(), "42".to_string()));
    }

    #[test]
    fn body_access_is_read_only() {
        let filter = make_filter("f", "H");
        assert_eq!(filter.request_body_access(), BodyAccess::ReadOnly);
    }

    #[test]
    fn body_mode_is_stream_buffer() {
        let filter = make_filter("f", "H");
        assert_eq!(filter.request_body_mode(), BodyMode::StreamBuffer { max_bytes: None });
    }
}
