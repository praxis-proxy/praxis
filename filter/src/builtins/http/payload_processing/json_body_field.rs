//! Extracts top-level JSON fields from the request body and promotes them to request headers.

use std::borrow::Cow;

use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use tracing::trace;

use crate::{
    FilterAction, FilterError,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum request body size for `StreamBuffer` mode (10 MiB).
const DEFAULT_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

// -----------------------------------------------------------------------------
// JsonBodyFieldConfig
// -----------------------------------------------------------------------------

/// A single field-to-header mapping used in the `fields` list.
#[derive(Debug, Deserialize)]
struct JsonBodyFieldMapping {
    /// Top-level JSON field name to extract.
    field: String,

    /// Request header name to promote the extracted value into.
    header: String,
}

/// YAML configuration for [`JsonBodyFieldFilter`].
///
/// Accepts either single-field syntax (`field` + `header`) or
/// multi-field syntax (`fields` list), but not both.
#[derive(Debug, Deserialize)]
struct JsonBodyFieldConfig {
    /// Single-field: top-level JSON field name to extract.
    field: Option<String>,

    /// Single-field: request header name to promote into.
    header: Option<String>,

    /// Multi-field: list of field-to-header mappings.
    fields: Option<Vec<JsonBodyFieldMapping>>,
}

// -----------------------------------------------------------------------------
// JsonBodyFieldFilter
// -----------------------------------------------------------------------------

/// Extracts top-level fields from a JSON request body and promotes
/// their values to request headers using [`StreamBuffer`] mode.
///
/// # Single-field YAML
///
/// ```yaml
/// filter: json_body_field
/// field: model
/// header: X-Model
/// ```
///
/// # Multi-field YAML
///
/// ```yaml
/// filter: json_body_field
/// fields:
///   - field: model
///     header: X-Model
///   - field: user_id
///     header: X-User-Id
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
    /// Field-to-header mappings: `(json_field_name, header_name)`.
    mappings: Vec<(String, String)>,
}

impl JsonBodyFieldFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// Accepts either single-field (`field`/`header`) or multi-field
    /// (`fields` list) syntax.
    ///
    /// ```
    /// use praxis_filter::JsonBodyFieldFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(r#"
    /// fields:
    ///   - field: model
    ///     header: X-Model
    ///   - field: user_id
    ///     header: X-User-Id
    /// "#).unwrap();
    /// let filter = JsonBodyFieldFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "json_body_field");
    /// ```
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: JsonBodyFieldConfig = parse_filter_config("json_body_field", config)?;
        let mappings = build_mappings(cfg)?;
        Ok(Box::new(Self { mappings }))
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
        BodyMode::StreamBuffer {
            max_bytes: Some(DEFAULT_MAX_BODY_BYTES),
        }
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
            trace!("JSON parsing failed; skipping field extraction");
            return Ok(FilterAction::Continue);
        };

        let mut found_any = false;
        for (field, header) in &self.mappings {
            if let Some(field_val) = value.get(field.as_str()) {
                let text = match field_val {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                trace!(
                    field = %field,
                    header = %header,
                    value = %text,
                    "promoting JSON field to header"
                );
                ctx.extra_request_headers.push((Cow::Owned(header.clone()), text));
                found_any = true;
            }
        }

        if found_any {
            Ok(FilterAction::Release)
        } else {
            Ok(FilterAction::Continue)
        }
    }
}

// -----------------------------------------------------------------------------
// Config Parsing
// -----------------------------------------------------------------------------

/// Validate a single field-to-header mapping.
fn validate_mapping(field: &str, header: &str) -> Result<(), FilterError> {
    if field.is_empty() {
        return Err("json_body_field: 'field' must not be empty".into());
    }
    if header.is_empty() {
        return Err("json_body_field: 'header' must not be empty".into());
    }
    Ok(())
}

/// Build the mappings vec from either single-field or multi-field
/// config syntax.
fn build_mappings(cfg: JsonBodyFieldConfig) -> Result<Vec<(String, String)>, FilterError> {
    let has_single = cfg.field.is_some() || cfg.header.is_some();
    let has_multi = cfg.fields.is_some();

    if has_single && has_multi {
        return Err("json_body_field: use 'field'/'header' or 'fields', not both".into());
    }

    if let Some(fields) = cfg.fields {
        if fields.is_empty() {
            return Err("json_body_field: 'fields' must not be empty".into());
        }
        let mut mappings = Vec::with_capacity(fields.len());
        for m in fields {
            validate_mapping(&m.field, &m.header)?;
            mappings.push((m.field, m.header));
        }
        return Ok(mappings);
    }

    let field = cfg.field.ok_or("json_body_field: 'field' is required")?;
    let header = cfg.header.ok_or("json_body_field: 'header' is required")?;
    validate_mapping(&field, &header)?;
    Ok(vec![(field, header)])
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a single-mapping filter for testing.
    fn make_filter(field: &str, header: &str) -> JsonBodyFieldFilter {
        JsonBodyFieldFilter {
            mappings: vec![(field.to_string(), header.to_string())],
        }
    }

    /// Build a multi-mapping filter for testing.
    fn make_multi_filter(mappings: &[(&str, &str)]) -> JsonBodyFieldFilter {
        JsonBodyFieldFilter {
            mappings: mappings.iter().map(|(f, h)| (f.to_string(), h.to_string())).collect(),
        }
    }

    #[test]
    fn parse_single_field_config() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            field: model
            header: X-Model
            "#,
        )
        .unwrap();
        let filter = JsonBodyFieldFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "json_body_field", "single-field config should parse");
    }

    #[test]
    fn parse_multi_field_config() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            fields:
              - field: model
                header: X-Model
              - field: user_id
                header: X-User-Id
            "#,
        )
        .unwrap();
        let filter = JsonBodyFieldFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "json_body_field", "multi-field config should parse");
    }

    #[test]
    fn reject_both_syntaxes() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            field: model
            header: X-Model
            fields:
              - field: user_id
                header: X-User-Id
            "#,
        )
        .unwrap();
        let err = JsonBodyFieldFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("not both"),
            "should reject mixed syntax, got: {err}"
        );
    }

    #[test]
    fn reject_empty_fields_list() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("fields: []").unwrap();
        let err = JsonBodyFieldFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("must not be empty"),
            "should reject empty fields list, got: {err}"
        );
    }

    #[test]
    fn reject_empty_field_in_list() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
            fields:
              - field: ""
                header: X-Model
            "#,
        )
        .unwrap();
        let err = JsonBodyFieldFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("'field' must not be empty"), "got: {err}");
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

    #[test]
    fn reject_missing_both() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let err = JsonBodyFieldFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("'field' is required"),
            "should require field, got: {err}"
        );
    }

    #[tokio::test]
    async fn extracts_field_from_complete_json() {
        let filter = make_filter("model", "X-Model");
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"model":"claude-sonnet-4-5","prompt":"hi"}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(
            matches!(action, FilterAction::Release),
            "should release after extracting field"
        );
    }

    #[tokio::test]
    async fn extracts_multiple_fields_in_single_parse() {
        let filter = make_multi_filter(&[("model", "X-Model"), ("user_id", "X-User-Id")]);
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"model":"claude-sonnet-4-5","user_id":"u-42","prompt":"hi"}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(
            matches!(action, FilterAction::Release),
            "should release after extracting fields"
        );
        assert_eq!(ctx.extra_request_headers.len(), 2, "should add two headers");
        let (ref n0, ref v0) = ctx.extra_request_headers[0];
        assert_eq!(n0, "X-Model", "first mapping should extract model name");
        assert_eq!(v0, "claude-sonnet-4-5", "first mapping should extract model value");
        let (ref n1, ref v1) = ctx.extra_request_headers[1];
        assert_eq!(n1, "X-User-Id", "second mapping should extract user_id name");
        assert_eq!(v1, "u-42", "second mapping should extract user_id value");
    }

    #[tokio::test]
    async fn partial_multi_field_match_still_releases() {
        let filter = make_multi_filter(&[("model", "X-Model"), ("user_id", "X-User-Id")]);
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"model":"claude-sonnet-4-5","prompt":"hi"}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(
            matches!(action, FilterAction::Release),
            "should release when at least one field matches"
        );
        assert_eq!(ctx.extra_request_headers.len(), 1, "should add only matched header");
        let (ref name, ref value) = ctx.extra_request_headers[0];
        assert_eq!(name, "X-Model", "only model name should be extracted");
        assert_eq!(value, "claude-sonnet-4-5", "only model value should be extracted");
    }

    #[tokio::test]
    async fn no_multi_field_match_continues() {
        let filter = make_multi_filter(&[("model", "X-Model"), ("user_id", "X-User-Id")]);
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"prompt":"hi","temperature":0.7}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "should continue when no fields match"
        );
        assert!(
            ctx.extra_request_headers.is_empty(),
            "no headers should be added when no fields match"
        );
    }

    #[tokio::test]
    async fn returns_continue_on_incomplete_json() {
        let filter = make_filter("model", "X-Model");
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let partial = br#"{"model":"claude-sonnet-4-5","pro"#;
        let mut body = Some(Bytes::from_static(partial));

        let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "incomplete JSON should continue"
        );
        assert!(
            ctx.extra_request_headers.is_empty(),
            "no headers should be added for incomplete JSON"
        );
    }

    #[tokio::test]
    async fn returns_continue_when_field_missing() {
        let filter = make_filter("model", "X-Model");
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"prompt":"hello","temperature":0.7}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "missing field should continue"
        );
        assert!(
            ctx.extra_request_headers.is_empty(),
            "no headers should be added when field missing"
        );
    }

    #[tokio::test]
    async fn promotes_to_configured_header() {
        let filter = make_filter("user_id", "X-User-Id");
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"user_id":"abc-123","data":"payload"}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(
            matches!(action, FilterAction::Release),
            "should release after promoting field"
        );
        assert_eq!(ctx.extra_request_headers.len(), 1, "should add exactly one header");
        let (ref name, ref value) = ctx.extra_request_headers[0];
        assert_eq!(name, "X-User-Id", "promoted header name should match");
        assert_eq!(value, "abc-123", "promoted header value should match field value");
    }

    #[tokio::test]
    async fn on_request_is_noop() {
        let filter = make_filter("model", "X-Model");
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue), "on_request should be a no-op");
    }

    #[tokio::test]
    async fn returns_continue_on_none_body() {
        let filter = make_filter("model", "X-Model");
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut body: Option<Bytes> = None;

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(matches!(action, FilterAction::Continue), "None body should continue");
    }

    #[tokio::test]
    async fn numeric_field_promoted_as_string() {
        let filter = make_filter("count", "X-Count");
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let json = br#"{"count":42}"#;
        let mut body = Some(Bytes::from_static(json));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

        assert!(
            matches!(action, FilterAction::Release),
            "numeric field should trigger release"
        );
        assert_eq!(ctx.extra_request_headers.len(), 1, "should add exactly one header");
        let (ref name, ref value) = ctx.extra_request_headers[0];
        assert_eq!(name, "X-Count", "header name should match");
        assert_eq!(value, "42", "numeric value should be stringified");
    }

    #[test]
    fn body_access_is_read_only() {
        let filter = make_filter("f", "H");
        assert_eq!(
            filter.request_body_access(),
            BodyAccess::ReadOnly,
            "body access should be read-only"
        );
    }

    #[test]
    fn body_mode_is_stream_buffer_with_default_limit() {
        let filter = make_filter("f", "H");
        assert_eq!(
            filter.request_body_mode(),
            BodyMode::StreamBuffer {
                max_bytes: Some(DEFAULT_MAX_BODY_BYTES)
            },
            "body mode should be StreamBuffer with 10 MiB default limit"
        );
    }
}
