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
// Redirect Constants
// -----------------------------------------------------------------------------

/// Allowed redirect status codes.
const VALID_STATUSES: [u16; 4] = [301, 302, 307, 308];

// -----------------------------------------------------------------------------
// RedirectConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the redirect filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RedirectConfig {
    /// HTTP redirect status code (301, 302, 307, or 308).
    #[serde(default = "default_status")]
    status: u16,

    /// Location URL template. Supports `${path}` and `${query}` placeholders.
    ///
    /// `${query}` expands to `?key=val` (with leading `?`) when a query string
    /// is present, or to an empty string when absent. Templates should use
    /// `${path}${query}` without a literal `?` separator.
    location: String,
}

/// Default redirect status: 301 Moved Permanently.
const fn default_status() -> u16 {
    301
}

// -----------------------------------------------------------------------------
// RedirectFilter
// -----------------------------------------------------------------------------

/// Returns a redirect response without contacting any upstream.
///
/// The `location` template supports `${path}` and `${query}` substitution
/// from the original request URI. `${query}` includes the leading `?` when
/// a query string is present, and expands to nothing when absent.
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
    status: u16,
    /// Location URL template with `${path}` / `${query}` placeholders.
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

        if !VALID_STATUSES.contains(&cfg.status) {
            return Err(format!(
                "redirect: invalid redirect status {}, must be one of {VALID_STATUSES:?}",
                cfg.status,
            )
            .into());
        }

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
        let location = expand_location(&self.location, uri.path(), uri.query());
        let rejection = Rejection::status(self.status).with_header("Location", &location);
        Ok(FilterAction::Reject(rejection))
    }
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Expand `${path}` and `${query}` placeholders in the location template.
///
/// `${query}` includes the `?` prefix when a query string is present,
/// and expands to an empty string when absent.
fn expand_location(template: &str, path: &str, query: Option<&str>) -> String {
    let result = template.replace("${path}", path);
    let query_with_prefix = query.map_or(String::new(), |q| format!("?{q}"));
    result.replace("${query}", &query_with_prefix)
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
        for status in [200u16, 301 + 1000, 0, 404, 500] {
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
        let result = expand_location("https://example.com${path}", "/api/users", None);
        assert_eq!(result, "https://example.com/api/users", "path should be substituted");
    }

    #[test]
    fn expand_location_substitutes_query_with_prefix() {
        let result = expand_location("https://example.com${path}${query}", "/search", Some("q=rust"));
        assert_eq!(
            result, "https://example.com/search?q=rust",
            "query should include leading ? and value"
        );
    }

    #[test]
    fn expand_location_absent_query_expands_to_nothing() {
        let result = expand_location("https://example.com${path}${query}", "/page", None);
        assert_eq!(
            result, "https://example.com/page",
            "missing query should expand to empty string with no trailing ?"
        );
    }

    #[test]
    fn expand_location_no_placeholders() {
        let result = expand_location("https://other.com/fixed", "/ignored", Some("ignored=true"));
        assert_eq!(result, "https://other.com/fixed", "no placeholders should pass through");
    }

    #[test]
    fn expand_location_root_path() {
        let result = expand_location("https://example.com${path}", "/", None);
        assert_eq!(result, "https://example.com/", "root path should expand to /");
    }

    #[test]
    fn expand_location_empty_path() {
        let result = expand_location("https://example.com${path}", "", None);
        assert_eq!(result, "https://example.com", "empty path should expand to nothing");
    }

    #[test]
    fn expand_location_query_with_special_characters() {
        let result = expand_location(
            "https://example.com${path}${query}",
            "/search",
            Some("q=hello+world&page=1&filter=%E2%9C%93"),
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
        let result = expand_location("https://example.com${path}${query}", "/path%20with%20spaces", None);
        assert_eq!(
            result, "https://example.com/path%20with%20spaces",
            "percent-encoded spaces should be preserved verbatim"
        );
    }

    #[test]
    fn expand_location_preserves_utf8_encoded_path() {
        let result = expand_location("https://example.com${path}${query}", "/caf%C3%A9", None);
        assert_eq!(
            result, "https://example.com/caf%C3%A9",
            "percent-encoded UTF-8 characters should be preserved"
        );
    }

    #[test]
    fn expand_location_very_long_path() {
        let long_segment = "a".repeat(10_000);
        let path = format!("/{long_segment}");
        let result = expand_location("https://example.com${path}", &path, None);
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
        let result = expand_location("https://example.com${path}${query}", "/p", Some(&query));
        assert_eq!(
            result.len(),
            "https://example.com/p?key=".len() + 10_000,
            "very long query should be preserved in full"
        );
        assert!(result.contains(&long_value), "long query value should appear in result");
    }
}
