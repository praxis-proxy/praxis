//! Header manipulation filter: add request headers; add, set, or remove response headers.

use std::borrow::Cow;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::{trace, warn};

use crate::{
    FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// HeaderFilterConfig
// -----------------------------------------------------------------------------

/// Configuration for the header manipulation filter.
#[derive(Debug, Default, Deserialize)]
struct HeaderFilterConfig {
    /// Headers to append to the upstream request.
    #[serde(default)]
    request_add: Vec<HeaderPair>,

    /// Headers to append to the downstream response.
    #[serde(default)]
    response_add: Vec<HeaderPair>,

    /// Header names to remove from the downstream response.
    #[serde(default)]
    response_remove: Vec<String>,

    /// Headers to set on the downstream response (overwrites existing values).
    #[serde(default)]
    response_set: Vec<HeaderPair>,
}

/// A name/value pair used in header add/set/remove config.
#[derive(Debug, Deserialize)]
struct HeaderPair {
    /// Header field name.
    name: String,

    /// Header field value.
    value: String,
}

// -----------------------------------------------------------------------------
// HeaderFilter
// -----------------------------------------------------------------------------

/// Adds headers to upstream requests; adds, sets, or removes headers
/// on downstream responses.
///
/// # YAML configuration
///
/// ```yaml
/// filter: headers
/// request_add:
///   - name: X-Forwarded-By
///     value: praxis
/// response_add:
///   - name: X-Frame-Options
///     value: DENY
/// response_remove:
///   - X-Backend-Server
/// response_set:
///   - name: Server
///     value: praxis
/// ```
///
/// # Example
///
/// ```
/// use praxis_filter::HeaderFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(r#"
/// response_set:
///   - name: Server
///     value: praxis
/// "#).unwrap();
/// let filter = HeaderFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "headers");
/// ```
pub struct HeaderFilter {
    /// Headers to append to the upstream request.
    request_add: Vec<(String, String)>,

    /// Headers to append to the downstream response.
    response_add: Vec<(String, String)>,

    /// Header names to strip from the downstream response.
    response_remove: Vec<String>,

    /// Headers to overwrite on the downstream response.
    response_set: Vec<(String, String)>,
}

impl HeaderFilter {
    /// Create a header filter from parsed YAML config.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: HeaderFilterConfig = parse_filter_config("headers", config)?;
        Ok(Box::new(Self {
            request_add: cfg.request_add.into_iter().map(|p| (p.name, p.value)).collect(),
            response_add: cfg.response_add.into_iter().map(|p| (p.name, p.value)).collect(),
            response_remove: cfg.response_remove,
            response_set: cfg.response_set.into_iter().map(|p| (p.name, p.value)).collect(),
        }))
    }
}

#[async_trait]
impl HttpFilter for HeaderFilter {
    fn name(&self) -> &'static str {
        "headers"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        for (name, value) in &self.request_add {
            trace!(header = %name, "adding request header");
            ctx.extra_request_headers
                .push((Cow::Owned(name.clone()), value.clone()));
        }
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(resp) = ctx.response_header.as_mut() else {
            return Ok(FilterAction::Continue);
        };

        if !self.response_remove.is_empty() || !self.response_add.is_empty() || !self.response_set.is_empty() {
            ctx.response_headers_modified = true;
        }

        for name in &self.response_remove {
            trace!(header = %name, "removing response header");
            resp.headers.remove(name.as_str());
        }

        for (name, value) in &self.response_add {
            trace!(header = %name, "adding response header");
            let Ok(header_name) = http::header::HeaderName::from_bytes(name.as_bytes()) else {
                warn!(header = %name, "invalid header name; skipping");
                continue;
            };
            let Ok(header_value) = http::header::HeaderValue::from_str(value) else {
                warn!(header = %name, "invalid header value; skipping");
                continue;
            };
            resp.headers.append(header_name, header_value);
        }

        for (name, value) in &self.response_set {
            trace!(header = %name, "setting response header");
            let Ok(header_name) = http::header::HeaderName::from_bytes(name.as_bytes()) else {
                warn!(header = %name, "invalid header name; skipping");
                continue;
            };
            let Ok(header_value) = http::header::HeaderValue::from_str(value) else {
                warn!(header = %name, "invalid header value; skipping");
                continue;
            };
            resp.headers.insert(header_name, header_value);
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

    fn make_header_filter(yaml: &str) -> HeaderFilter {
        let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let _ = HeaderFilter::from_config(&config).unwrap();
        let cfg: HeaderFilterConfig = serde_yaml::from_value(config).unwrap();
        HeaderFilter {
            request_add: cfg.request_add.into_iter().map(|p| (p.name, p.value)).collect(),
            response_add: cfg.response_add.into_iter().map(|p| (p.name, p.value)).collect(),
            response_remove: cfg.response_remove,
            response_set: cfg.response_set.into_iter().map(|p| (p.name, p.value)).collect(),
        }
    }

    #[tokio::test]
    async fn request_add_populates_extra_headers() {
        let filter = make_header_filter(
            r#"request_add:
  - name: X-Forwarded-By
    value: praxis"#,
        );
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        filter.on_request(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.extra_request_headers.len(),
            1,
            "should add exactly one request header"
        );
        let (ref name, ref value) = ctx.extra_request_headers[0];
        assert_eq!(name, "X-Forwarded-By", "header name should match");
        assert_eq!(value, "praxis", "header value should match");
    }

    #[tokio::test]
    async fn response_set_overwrites_header() {
        let filter = make_header_filter(
            r#"response_set:
  - name: server
    value: praxis"#,
        );
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut resp = crate::test_utils::make_response();
        resp.headers.insert("server", "nginx".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);
        filter.on_response(&mut ctx).await.unwrap();
        assert_eq!(
            resp.headers["server"], "praxis",
            "response_set should overwrite existing header"
        );
    }

    #[tokio::test]
    async fn response_remove_deletes_header() {
        let filter = make_header_filter(
            r#"response_remove:
  - x-backend-server"#,
        );
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut resp = crate::test_utils::make_response();
        resp.headers.insert("x-backend-server", "internal".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);
        filter.on_response(&mut ctx).await.unwrap();
        assert!(
            !resp.headers.contains_key("x-backend-server"),
            "response_remove should delete header"
        );
    }

    #[tokio::test]
    async fn response_add_appends_without_overwriting() {
        let filter = make_header_filter(
            r#"response_add:
  - name: x-custom
    value: second"#,
        );
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut resp = crate::test_utils::make_response();
        resp.headers.insert("x-custom", "first".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);
        filter.on_response(&mut ctx).await.unwrap();
        let values: Vec<&str> = resp
            .headers
            .get_all("x-custom")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            values,
            vec!["first", "second"],
            "response_add should append without overwriting"
        );
    }

    #[tokio::test]
    async fn from_config_empty_is_noop() {
        let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let filter = HeaderFilter::from_config(&config).unwrap();
        assert_eq!(filter.name(), "headers", "empty config should produce valid filter");
    }

    #[tokio::test]
    async fn invalid_header_name_skipped_gracefully() {
        let filter = HeaderFilter {
            request_add: vec![],
            response_add: vec![("invalid header".to_string(), "value".to_string())],
            response_remove: vec![],
            response_set: vec![],
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut resp = crate::test_utils::make_response();
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);
        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "invalid header name should still continue"
        );
        assert!(resp.headers.is_empty(), "invalid header name should not be added");
    }

    #[tokio::test]
    async fn invalid_header_value_skipped_gracefully() {
        let filter = HeaderFilter {
            request_add: vec![],
            response_add: vec![("x-good-name".to_string(), "bad\x00value".to_string())],
            response_remove: vec![],
            response_set: vec![],
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut resp = crate::test_utils::make_response();
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);
        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "invalid header value should still continue"
        );
        assert!(resp.headers.is_empty(), "invalid header value should not be added");
    }

    #[tokio::test]
    async fn invalid_set_header_name_skipped_gracefully() {
        let filter = HeaderFilter {
            request_add: vec![],
            response_add: vec![],
            response_remove: vec![],
            response_set: vec![("bad name!".to_string(), "value".to_string())],
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut resp = crate::test_utils::make_response();
        resp.headers.insert("existing", "keep".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);
        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "invalid set header name should still continue"
        );
        assert_eq!(resp.headers.len(), 1, "existing headers should be preserved");
        assert_eq!(
            resp.headers["existing"], "keep",
            "existing header should not be removed when set header has invalid name"
        );
    }
}
