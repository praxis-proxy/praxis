//! Header manipulation filter: add request headers; add, set, or remove response headers.
//!
//! Registered as `"headers"` in the filter registry.

use async_trait::async_trait;
use serde::Deserialize;
use tracing::{trace, warn};

use crate::{
    FilterAction, FilterError,
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
        let cfg: HeaderFilterConfig =
            serde_yaml::from_value(config.clone()).map_err(|e| -> FilterError { format!("headers: {e}").into() })?;
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
            ctx.extra_request_headers.push((name.clone(), value.clone()));
        }
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(resp) = ctx.response_header.as_mut() else {
            return Ok(FilterAction::Continue);
        };

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
    use crate::context::Response as FilterResponse;

    fn make_response() -> FilterResponse {
        FilterResponse {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::OK,
        }
    }

    fn make_header_filter(yaml: &str) -> HeaderFilter {
        let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        // Downcast is not possible for Box<dyn Filter>, so rebuild directly.
        // Verify from_config succeeds before reconstructing for field access.
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
            ctx.extra_request_headers,
            vec![("X-Forwarded-By".to_string(), "praxis".to_string())]
        );
    }

    #[tokio::test]
    async fn response_set_overwrites_header() {
        let filter = make_header_filter(
            r#"response_set:
  - name: server
    value: praxis"#,
        );
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut resp = make_response();
        resp.headers.insert("server", "nginx".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);
        filter.on_response(&mut ctx).await.unwrap();
        assert_eq!(resp.headers["server"], "praxis");
    }

    #[tokio::test]
    async fn response_remove_deletes_header() {
        let filter = make_header_filter(
            r#"response_remove:
  - x-backend-server"#,
        );
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut resp = make_response();
        resp.headers.insert("x-backend-server", "internal".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);
        filter.on_response(&mut ctx).await.unwrap();
        assert!(!resp.headers.contains_key("x-backend-server"));
    }

    #[tokio::test]
    async fn response_add_appends_without_overwriting() {
        let filter = make_header_filter(
            r#"response_add:
  - name: x-custom
    value: second"#,
        );
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut resp = make_response();
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
        assert_eq!(values, vec!["first", "second"]);
    }

    #[tokio::test]
    async fn from_config_empty_is_noop() {
        let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let filter = HeaderFilter::from_config(&config).unwrap();
        assert_eq!(filter.name(), "headers");
    }
}
