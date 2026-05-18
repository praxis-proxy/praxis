// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Redirect filter: returns a 3xx redirect without contacting an upstream.

use async_trait::async_trait;
use serde::Deserialize;

use crate::{
    actions::{FilterAction, Rejection},
    factory::parse_filter_config,
    filter::{FilterError, HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// RedirectStatus
// -----------------------------------------------------------------------------

/// Allowed HTTP redirect status codes.
///
/// Deserialized from a `u16` via `TryFrom`.
///
/// ```
/// use praxis_filter::RedirectStatus;
///
/// let status = RedirectStatus::try_from(301u16).unwrap();
/// assert_eq!(status.as_u16(), 301);
///
/// assert!(RedirectStatus::try_from(200u16).is_err());
/// ```
#[derive(Debug, Clone, Copy)]
pub enum RedirectStatus {
    /// 301 Moved Permanently.
    MovedPermanently,

    /// 302 Found.
    Found,

    /// 307 Temporary Redirect.
    TemporaryRedirect,

    /// 308 Permanent Redirect.
    PermanentRedirect,
}

impl RedirectStatus {
    /// Return the numeric HTTP status code.
    pub fn as_u16(self) -> u16 {
        match self {
            Self::MovedPermanently => 301,
            Self::Found => 302,
            Self::TemporaryRedirect => 307,
            Self::PermanentRedirect => 308,
        }
    }
}

impl TryFrom<u16> for RedirectStatus {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            301 => Ok(Self::MovedPermanently),
            302 => Ok(Self::Found),
            307 => Ok(Self::TemporaryRedirect),
            308 => Ok(Self::PermanentRedirect),
            other => Err(format!(
                "redirect: invalid status {other}, must be one of [301, 302, 307, 308]"
            )),
        }
    }
}

// -----------------------------------------------------------------------------
// RedirectConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the redirect filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RedirectConfig {
    /// HTTP redirect status code (301, 302, 307, or 308).
    #[serde(default = "default_status", deserialize_with = "deserialize_redirect_status")]
    status: RedirectStatus,

    /// Location URL template. Supports `${path}`, `${query}`, `${host}`, and `${scheme}` placeholders.
    ///
    /// `${query}` expands to `?key=val` (with leading `?`) when a query string
    /// is present, or to an empty string when absent. `${host}` expands to the
    /// request `Host` header value (port stripped). `${scheme}` expands to the
    /// inferred scheme (`http` or `https`). Templates should use
    /// `${path}${query}` without a literal `?` separator.
    location: String,
}

/// Default redirect status: 301 Moved Permanently.
fn default_status() -> RedirectStatus {
    RedirectStatus::MovedPermanently
}

/// Deserialize a `u16` into [`RedirectStatus`] with validation.
fn deserialize_redirect_status<'de, D>(deserializer: D) -> Result<RedirectStatus, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let code = u16::deserialize(deserializer)?;
    RedirectStatus::try_from(code).map_err(serde::de::Error::custom)
}

// -----------------------------------------------------------------------------
// RedirectFilter
// -----------------------------------------------------------------------------

/// Returns a redirect response without contacting any upstream.
///
/// The `location` template supports `${path}`, `${query}`, `${host}`, and
/// `${scheme}` substitution from the original request. `${query}` includes
/// the leading `?` when a query string is present, and expands to nothing
/// when absent. `${host}` is the `Host` header with port stripped. `${scheme}`
/// is inferred from `X-Forwarded-Proto`, downstream TLS state, or the URI.
///
/// # YAML configuration
///
/// ```yaml
/// filter: redirect
/// status: 301
/// location: "https://example.com${path}${query}"
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::RedirectFilter;
///
/// let yaml: serde_yaml::Value =
///     serde_yaml::from_str(r#"location: "https://example.com${path}""#).unwrap();
/// let filter = RedirectFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "redirect");
/// ```
///
/// ```ignore
/// use praxis_filter::RedirectFilter;
///
/// let yaml: serde_yaml::Value =
///     serde_yaml::from_str("status: 302\nlocation: \"https://new.example.com${path}${query}\"")
///         .unwrap();
/// let filter = RedirectFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "redirect");
/// ```
///
/// ```ignore
/// use praxis_filter::RedirectFilter;
///
/// // Invalid status code
/// let yaml: serde_yaml::Value =
///     serde_yaml::from_str("status: 200\nlocation: \"https://example.com\"").unwrap();
/// let result = RedirectFilter::from_config(&yaml);
/// assert!(result.is_err());
/// ```
pub struct RedirectFilter {
    /// HTTP redirect status code.
    status: RedirectStatus,
    /// Location URL template with `${path}`, `${query}`, `${host}`, and `${scheme}` placeholders.
    location: String,
}

impl RedirectFilter {
    /// Create from YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is malformed or the
    /// status code is not a valid redirect (301, 302, 307, 308).
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: RedirectConfig = parse_filter_config("redirect", config)?;

        Ok(Box::new(Self {
            status: cfg.status,
            location: cfg.location,
        }))
    }
}

#[async_trait]
impl HttpFilter for RedirectFilter {
    fn name(&self) -> &'static str {
        "redirect"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let uri = &ctx.request.uri;
        let host = ctx
            .request
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(strip_port);
        let scheme = infer_scheme(ctx);
        let location = expand_location(&self.location, uri.path(), uri.query(), host, scheme);
        let rejection = Rejection::status(self.status.as_u16()).with_header("Location", &location);
        Ok(FilterAction::Reject(rejection))
    }
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Expand template placeholders in the location string.
///
/// Supported placeholders: `${path}`, `${query}`, `${host}`, `${scheme}`.
///
/// The path is normalized before substitution to prevent open
/// redirects via crafted paths like `//evil.com`. Normalization
/// collapses double slashes and resolves `.`/`..` segments.
///
/// `${query}` includes the `?` prefix when a query string is present,
/// and expands to an empty string when absent.
fn expand_location(template: &str, path: &str, query: Option<&str>, host: Option<&str>, scheme: &str) -> String {
    let safe_path = crate::builtins::http::transformation::path_sanitize::normalize_rewritten_path(path);
    let mut result = template.replace("${path}", &safe_path);
    let query_with_prefix = query.map_or(String::new(), |q| format!("?{q}"));
    result = result.replace("${query}", &query_with_prefix);
    if let Some(h) = host {
        result = result.replace("${host}", h);
    }
    result.replace("${scheme}", scheme)
}

/// Strip port from a `Host` header value (e.g. `example.com:8080` -> `example.com`).
fn strip_port(host: &str) -> &str {
    host.split(':').next().unwrap_or(host)
}

/// Infer the request scheme from headers and connection state.
///
/// Checks `X-Forwarded-Proto` first, then `downstream_tls`, then
/// falls back to the URI scheme. Defaults to `"http"`.
fn infer_scheme(ctx: &HttpFilterContext<'_>) -> &'static str {
    if ctx
        .request
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.eq_ignore_ascii_case("https"))
    {
        return "https";
    }
    if ctx.downstream_tls {
        return "https";
    }
    if ctx
        .request
        .uri
        .scheme_str()
        .is_some_and(|s| s.eq_ignore_ascii_case("https"))
    {
        return "https";
    }
    "http"
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn from_config_minimal() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(r#"location: "https://example.com""#).unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "redirect", "minimal config should parse");
    }

    #[test]
    fn from_config_default_status_is_301() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(r#"location: "https://example.com""#).unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let action = rt.block_on(filter.on_request(&mut ctx)).unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(r.status, 301, "default status should be 301");
            },
            _ => panic!("expected Reject"),
        }
    }

    #[test]
    fn from_config_with_explicit_status() {
        for status in [301u16, 302, 307, 308] {
            let yaml = serde_yaml::from_str::<serde_yaml::Value>(&format!(
                "status: {status}\nlocation: \"https://example.com\""
            ))
            .unwrap();
            let filter = RedirectFilter::from_config(&yaml).unwrap();
            assert_eq!(filter.name(), "redirect", "status {status} should parse");
        }
    }

    #[test]
    fn from_config_invalid_status_fails() {
        for status in [200u16, 404, 500] {
            let yaml =
                serde_yaml::from_str::<serde_yaml::Value>(&format!("status: {status}\nlocation: \"https://x.com\""))
                    .unwrap();
            let result = RedirectFilter::from_config(&yaml);
            assert!(result.is_err(), "status {status} should be rejected");
        }
    }

    #[test]
    fn from_config_missing_location_fails() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>("status: 301").unwrap();
        let result = RedirectFilter::from_config(&yaml);
        assert!(result.is_err(), "missing location should fail");
    }

    #[test]
    fn expand_location_substitutes_path() {
        let result = expand_location("https://example.com${path}", "/api/users", None, None, "http");
        assert_eq!(result, "https://example.com/api/users", "path should be substituted");
    }

    #[test]
    fn expand_location_substitutes_query_with_prefix() {
        let result = expand_location(
            "https://example.com${path}${query}",
            "/search",
            Some("q=rust"),
            None,
            "http",
        );
        assert_eq!(
            result, "https://example.com/search?q=rust",
            "query should include leading ? and value"
        );
    }

    #[test]
    fn expand_location_absent_query_expands_to_nothing() {
        let result = expand_location("https://example.com${path}${query}", "/page", None, None, "http");
        assert_eq!(
            result, "https://example.com/page",
            "missing query should expand to empty string with no trailing ?"
        );
    }

    #[test]
    fn expand_location_double_slash_path_normalized() {
        let result = expand_location("https://example.com${path}", "//evil.com/foo", None, None, "http");
        assert_eq!(
            result, "https://example.com/evil.com/foo",
            "double-slash path should be collapsed to prevent open redirect"
        );
    }

    #[test]
    fn expand_location_triple_slash_path_normalized() {
        let result = expand_location("https://example.com${path}", "///evil.com", None, None, "http");
        assert_eq!(
            result, "https://example.com/evil.com",
            "triple-slash path should be collapsed"
        );
    }

    #[test]
    fn expand_location_traversal_in_path_normalized() {
        let result = expand_location("https://example.com${path}", "/a/../b", None, None, "http");
        assert_eq!(result, "https://example.com/b", "path traversal should be resolved");
    }

    #[test]
    fn expand_location_no_placeholders() {
        let result = expand_location(
            "https://other.com/fixed",
            "/ignored",
            Some("ignored=true"),
            None,
            "http",
        );
        assert_eq!(result, "https://other.com/fixed", "no placeholders should pass through");
    }

    #[test]
    fn expand_location_root_path() {
        let result = expand_location("https://example.com${path}", "/", None, None, "http");
        assert_eq!(result, "https://example.com/", "root path should expand to /");
    }

    #[test]
    fn expand_location_empty_path_normalizes_to_slash() {
        let result = expand_location("https://example.com${path}", "", None, None, "http");
        assert_eq!(
            result, "https://example.com/",
            "empty path should normalize to / for safety"
        );
    }

    #[test]
    fn expand_location_query_with_special_characters() {
        let result = expand_location(
            "https://example.com${path}${query}",
            "/search",
            Some("q=hello+world&page=1&filter=%E2%9C%93"),
            None,
            "http",
        );
        assert_eq!(
            result, "https://example.com/search?q=hello+world&page=1&filter=%E2%9C%93",
            "special characters in query should be preserved verbatim"
        );
    }

    #[tokio::test]
    async fn on_request_always_rejects() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(r#"location: "https://example.com""#).unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(_)),
            "redirect must always short-circuit with Reject"
        );
    }

    #[tokio::test]
    async fn returns_redirect_with_location_header() {
        let yaml =
            serde_yaml::from_str::<serde_yaml::Value>("status: 307\nlocation: \"https://example.com${path}\"").unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let req = crate::test_utils::make_request(http::Method::GET, "/api/data?limit=10");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(r.status, 307, "status should be 307");
                assert_eq!(r.headers.len(), 1, "should have exactly one header");
                assert_eq!(r.headers[0].0, "Location", "header name should be Location");
                assert_eq!(
                    r.headers[0].1, "https://example.com/api/data",
                    "location should substitute path"
                );
            },
            _ => panic!("expected Reject"),
        }
    }

    #[tokio::test]
    async fn returns_redirect_with_path_and_query() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            "status: 308\nlocation: \"https://new.example.com${path}${query}\"",
        )
        .unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let req = crate::test_utils::make_request(http::Method::POST, "/submit?token=abc");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(r.status, 308, "status should be 308");
                assert_eq!(
                    r.headers[0].1, "https://new.example.com/submit?token=abc",
                    "location should substitute both path and query"
                );
            },
            _ => panic!("expected Reject"),
        }
    }

    #[tokio::test]
    async fn returns_302_found() {
        let yaml =
            serde_yaml::from_str::<serde_yaml::Value>("status: 302\nlocation: \"https://temp.example.com${path}\"")
                .unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let req = crate::test_utils::make_request(http::Method::GET, "/old-page");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(r.status, 302, "status should be 302");
                assert_eq!(
                    r.headers[0].1, "https://temp.example.com/old-page",
                    "location should substitute path for 302"
                );
            },
            _ => panic!("expected Reject"),
        }
    }

    #[tokio::test]
    async fn redirects_post_request() {
        let yaml =
            serde_yaml::from_str::<serde_yaml::Value>("status: 308\nlocation: \"https://example.com${path}${query}\"")
                .unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let req = crate::test_utils::make_request(http::Method::POST, "/api/submit?v=1");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(r.status, 308, "POST should get redirected with 308");
                assert_eq!(
                    r.headers[0].1, "https://example.com/api/submit?v=1",
                    "POST location should preserve path and query"
                );
            },
            _ => panic!("expected Reject for POST"),
        }
    }

    #[tokio::test]
    async fn redirects_put_request() {
        let yaml =
            serde_yaml::from_str::<serde_yaml::Value>("status: 307\nlocation: \"https://example.com${path}\"").unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let req = crate::test_utils::make_request(http::Method::PUT, "/resource/42");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(r.status, 307, "PUT should get redirected with 307");
                assert_eq!(
                    r.headers[0].1, "https://example.com/resource/42",
                    "PUT location should preserve path"
                );
            },
            _ => panic!("expected Reject for PUT"),
        }
    }

    #[tokio::test]
    async fn redirects_delete_request() {
        let yaml =
            serde_yaml::from_str::<serde_yaml::Value>("status: 301\nlocation: \"https://example.com${path}\"").unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let req = crate::test_utils::make_request(http::Method::DELETE, "/items/99");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(r.status, 301, "DELETE should get redirected with 301");
                assert_eq!(
                    r.headers[0].1, "https://example.com/items/99",
                    "DELETE location should preserve path"
                );
            },
            _ => panic!("expected Reject for DELETE"),
        }
    }

    #[test]
    fn expand_location_preserves_percent_encoded_path() {
        let result = expand_location(
            "https://example.com${path}${query}",
            "/path%20with%20spaces",
            None,
            None,
            "http",
        );
        assert_eq!(
            result, "https://example.com/path%20with%20spaces",
            "percent-encoded spaces should be preserved verbatim"
        );
    }

    #[test]
    fn expand_location_preserves_utf8_encoded_path() {
        let result = expand_location("https://example.com${path}${query}", "/caf%C3%A9", None, None, "http");
        assert_eq!(
            result, "https://example.com/caf%C3%A9",
            "percent-encoded UTF-8 characters should be preserved"
        );
    }

    #[test]
    fn expand_location_very_long_path() {
        let long_segment = "a".repeat(10_000);
        let path = format!("/{long_segment}");
        let result = expand_location("https://example.com${path}", &path, None, None, "http");
        assert_eq!(
            result.len(),
            "https://example.com/".len() + 10_000,
            "very long path should be preserved in full"
        );
        assert!(result.ends_with(&long_segment), "long path content should match");
    }

    #[test]
    fn expand_location_very_long_query() {
        let long_value = "x".repeat(10_000);
        let query = format!("key={long_value}");
        let result = expand_location("https://example.com${path}${query}", "/p", Some(&query), None, "http");
        assert_eq!(
            result.len(),
            "https://example.com/p?key=".len() + 10_000,
            "very long query should be preserved in full"
        );
        assert!(result.contains(&long_value), "long query value should appear in result");
    }

    #[test]
    fn expand_location_substitutes_host() {
        let result = expand_location("https://${host}${path}", "/page", None, Some("example.com"), "https");
        assert_eq!(
            result, "https://example.com/page",
            "host should be substituted into template"
        );
    }

    #[test]
    fn expand_location_substitutes_scheme() {
        let result = expand_location("${scheme}://new.example.com${path}", "/page", None, None, "https");
        assert_eq!(
            result, "https://new.example.com/page",
            "scheme should be substituted into template"
        );
    }

    #[test]
    fn expand_location_host_and_scheme_combined() {
        let result = expand_location(
            "${scheme}://${host}/new${path}${query}",
            "/page",
            Some("v=1"),
            Some("example.com"),
            "https",
        );
        assert_eq!(
            result, "https://example.com/new/page?v=1",
            "both host and scheme should be substituted"
        );
    }

    #[test]
    fn expand_location_missing_host_preserves_placeholder() {
        let result = expand_location("https://${host}/page", "/", None, None, "http");
        assert_eq!(
            result, "https://${host}/page",
            "missing host should leave placeholder intact"
        );
    }

    #[test]
    fn expand_location_http_scheme() {
        let result = expand_location("${scheme}://example.com${path}", "/page", None, None, "http");
        assert_eq!(result, "http://example.com/page", "http scheme should be substituted");
    }

    #[test]
    fn strip_port_removes_port() {
        assert_eq!(strip_port("example.com:8080"), "example.com", "port should be stripped");
    }

    #[test]
    fn strip_port_no_port_passthrough() {
        assert_eq!(
            strip_port("example.com"),
            "example.com",
            "host without port should pass through"
        );
    }

    #[test]
    fn strip_port_empty_string() {
        assert_eq!(strip_port(""), "", "empty string should return empty");
    }

    #[test]
    fn strip_port_ipv4_with_port() {
        assert_eq!(strip_port("10.0.0.1:443"), "10.0.0.1", "IPv4 port should be stripped");
    }

    #[tokio::test]
    async fn on_request_infers_http_scheme_by_default() {
        let yaml =
            serde_yaml::from_str::<serde_yaml::Value>(r#"location: "${scheme}://new.example.com${path}""#).unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let mut req = crate::test_utils::make_request(http::Method::GET, "/page");
        req.headers.insert("host", "old.example.com".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(
                    r.headers[0].1, "http://new.example.com/page",
                    "default scheme should be http"
                );
            },
            _ => panic!("expected Reject"),
        }
    }

    #[tokio::test]
    async fn on_request_infers_https_from_x_forwarded_proto() {
        let yaml =
            serde_yaml::from_str::<serde_yaml::Value>(r#"location: "${scheme}://new.example.com${path}""#).unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let mut req = crate::test_utils::make_request(http::Method::GET, "/page");
        req.headers.insert("x-forwarded-proto", "https".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(
                    r.headers[0].1, "https://new.example.com/page",
                    "x-forwarded-proto: https should yield https scheme"
                );
            },
            _ => panic!("expected Reject"),
        }
    }

    #[tokio::test]
    async fn on_request_infers_https_from_downstream_tls() {
        let yaml =
            serde_yaml::from_str::<serde_yaml::Value>(r#"location: "${scheme}://new.example.com${path}""#).unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let req = crate::test_utils::make_request(http::Method::GET, "/page");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.downstream_tls = true;

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(
                    r.headers[0].1, "https://new.example.com/page",
                    "downstream TLS should yield https scheme"
                );
            },
            _ => panic!("expected Reject"),
        }
    }

    #[tokio::test]
    async fn on_request_host_substitution() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"status: 302
location: "https://new.example.com${path}""#,
        )
        .unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let mut req = crate::test_utils::make_request(http::Method::GET, "/page");
        req.headers.insert("host", "old.example.com:8080".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(r.status, 302, "status should be 302");
                assert_eq!(
                    r.headers[0].1, "https://new.example.com/page",
                    "location should use new host"
                );
            },
            _ => panic!("expected Reject"),
        }
    }

    #[tokio::test]
    async fn on_request_host_template_with_port_stripping() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(r#"location: "https://${host}/new${path}""#).unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let mut req = crate::test_utils::make_request(http::Method::GET, "/old");
        req.headers.insert("host", "example.com:9090".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(
                    r.headers[0].1, "https://example.com/new/old",
                    "host port should be stripped in template"
                );
            },
            _ => panic!("expected Reject"),
        }
    }

    #[tokio::test]
    async fn on_request_x_forwarded_proto_case_insensitive() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(r#"location: "${scheme}://example.com${path}""#).unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("x-forwarded-proto", "HTTPS".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(
                    r.headers[0].1, "https://example.com/",
                    "HTTPS (uppercase) should be recognized"
                );
            },
            _ => panic!("expected Reject"),
        }
    }

    #[tokio::test]
    async fn on_request_x_forwarded_proto_http_stays_http() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(r#"location: "${scheme}://example.com${path}""#).unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("x-forwarded-proto", "http".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(
                    r.headers[0].1, "http://example.com/",
                    "x-forwarded-proto: http should yield http"
                );
            },
            _ => panic!("expected Reject"),
        }
    }

    #[tokio::test]
    async fn on_request_full_template_with_all_variables() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"status: 307
location: "${scheme}://${host}/redirected${path}${query}""#,
        )
        .unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let mut req = crate::test_utils::make_request(http::Method::GET, "/api/v1?key=abc");
        req.headers.insert("host", "api.example.com".parse().unwrap());
        req.headers.insert("x-forwarded-proto", "https".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(r.status, 307, "status should be 307");
                assert_eq!(
                    r.headers[0].1, "https://api.example.com/redirected/api/v1?key=abc",
                    "all template variables should be expanded"
                );
            },
            _ => panic!("expected Reject"),
        }
    }

    #[tokio::test]
    async fn on_request_no_host_header_leaves_host_placeholder() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(r#"location: "https://${host}/page""#).unwrap();
        let filter = RedirectFilter::from_config(&yaml).unwrap();

        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(
                    r.headers[0].1, "https://${host}/page",
                    "missing host header should leave placeholder"
                );
            },
            _ => panic!("expected Reject"),
        }
    }
}
