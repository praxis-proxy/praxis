//! `X-Forwarded-For/Proto/Host` injection filter with trusted-proxy support.
//!
//! Registered as `"forwarded_headers"` in the filter registry.

use std::net::IpAddr;

use async_trait::async_trait;
use praxis_core::connectivity::CidrRange;
use serde::Deserialize;

use crate::{
    FilterAction, FilterError,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// ForwardedHeadersConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the forwarded headers filter.
#[derive(Debug, Deserialize)]
struct ForwardedHeadersConfig {
    /// CIDR ranges of trusted proxies whose existing
    /// X-Forwarded-For values are preserved (appended to).
    /// Untrusted sources have the header overwritten.
    #[serde(default)]
    trusted_proxies: Vec<String>,
}

// -----------------------------------------------------------------------------
// ForwardedHeadersFilter
// -----------------------------------------------------------------------------

/// Injects `X-Forwarded-For`, `X-Forwarded-Proto`, and
/// `X-Forwarded-Host` headers into upstream requests.
///
/// When the client IP is from a trusted proxy, existing
/// `X-Forwarded-For` values are preserved and the client
/// IP is appended. Otherwise, the header is overwritten
/// with the client IP to prevent spoofing.
///
/// # YAML configuration
///
/// ```yaml
/// filter: forwarded_headers
/// trusted_proxies: ["10.0.0.0/8"]
/// ```
///
/// # Example
///
/// ```
/// use praxis_filter::ForwardedHeadersFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(r#"
/// trusted_proxies: ["10.0.0.0/8"]
/// "#).unwrap();
/// let filter = ForwardedHeadersFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "forwarded_headers");
/// ```
pub struct ForwardedHeadersFilter {
    /// CIDR ranges considered trusted proxies.
    trusted_proxies: Vec<CidrRange>,
}

impl ForwardedHeadersFilter {
    /// Create from YAML config.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: ForwardedHeadersConfig = serde_yaml::from_value(config.clone())
            .map_err(|e| -> FilterError { format!("forwarded_headers: {e}").into() })?;

        let trusted_proxies = cfg
            .trusted_proxies
            .iter()
            .map(|s| CidrRange::parse(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| -> FilterError { format!("forwarded_headers: {e}").into() })?;

        Ok(Box::new(Self { trusted_proxies }))
    }

    /// Returns `true` if `ip` matches any trusted proxy CIDR.
    fn is_trusted(&self, ip: &IpAddr) -> bool {
        self.trusted_proxies.iter().any(|r| r.contains(ip))
    }
}

#[async_trait]
impl HttpFilter for ForwardedHeadersFilter {
    fn name(&self) -> &'static str {
        "forwarded_headers"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(client_ip) = ctx.client_addr else {
            return Ok(FilterAction::Continue);
        };

        let client_str = client_ip.to_string();

        // X-Forwarded-For: append if trusted, overwrite if not
        let xff = if self.is_trusted(&client_ip) {
            if let Some(existing) = ctx.request.headers.get("x-forwarded-for") {
                let existing = existing.to_str().unwrap_or("");
                format!("{existing}, {client_str}")
            } else {
                client_str.clone()
            }
        } else {
            client_str.clone()
        };
        ctx.extra_request_headers.push(("X-Forwarded-For".into(), xff));

        // X-Forwarded-Proto: based on request URI scheme
        let proto = ctx.request.uri.scheme_str().unwrap_or("http");
        ctx.extra_request_headers
            .push(("X-Forwarded-Proto".into(), proto.into()));

        // X-Forwarded-Host: from Host header
        if let Some(host) = ctx.request.headers.get("host")
            && let Ok(host) = host.to_str()
        {
            ctx.extra_request_headers.push(("X-Forwarded-Host".into(), host.into()));
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

    fn make_filter(trusted: &[&str]) -> ForwardedHeadersFilter {
        ForwardedHeadersFilter {
            trusted_proxies: trusted.iter().map(|s| CidrRange::parse(s).unwrap()).collect(),
        }
    }

    #[tokio::test]
    async fn sets_xff_from_client_ip() {
        let f = make_filter(&[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        f.on_request(&mut ctx).await.unwrap();

        let xff = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-For")
            .map(|(_, v)| v.as_str());
        assert_eq!(xff, Some("203.0.113.50"));
    }

    #[tokio::test]
    async fn untrusted_client_overwrites_existing_xff() {
        let f = make_filter(&[]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("x-forwarded-for"),
            "1.2.3.4".parse().unwrap(),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        f.on_request(&mut ctx).await.unwrap();

        let xff = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-For")
            .map(|(_, v)| v.as_str());
        // Overwrites, does NOT append to the spoofed value
        assert_eq!(xff, Some("203.0.113.50"));
    }

    #[tokio::test]
    async fn trusted_proxy_appends_to_existing_xff() {
        let f = make_filter(&["10.0.0.0/8"]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("x-forwarded-for"),
            "203.0.113.50".parse().unwrap(),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.1.2.3".parse().unwrap());

        f.on_request(&mut ctx).await.unwrap();

        let xff = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-For")
            .map(|(_, v)| v.as_str());
        assert_eq!(xff, Some("203.0.113.50, 10.1.2.3"));
    }

    #[tokio::test]
    async fn sets_x_forwarded_proto() {
        let f = make_filter(&[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        f.on_request(&mut ctx).await.unwrap();

        let proto = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-Proto")
            .map(|(_, v)| v.as_str());
        assert_eq!(proto, Some("http"));
    }

    #[tokio::test]
    async fn sets_x_forwarded_host_from_host_header() {
        let f = make_filter(&[]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(http::header::HOST, "example.com".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        f.on_request(&mut ctx).await.unwrap();

        let host = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-Host")
            .map(|(_, v)| v.as_str());
        assert_eq!(host, Some("example.com"));
    }

    #[tokio::test]
    async fn no_host_header_skips_x_forwarded_host() {
        let f = make_filter(&[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        f.on_request(&mut ctx).await.unwrap();

        let host = ctx.extra_request_headers.iter().find(|(k, _)| k == "X-Forwarded-Host");
        assert!(host.is_none());
    }

    #[tokio::test]
    async fn no_client_addr_is_noop() {
        let f = make_filter(&[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        f.on_request(&mut ctx).await.unwrap();

        assert!(ctx.extra_request_headers.is_empty());
    }

    #[tokio::test]
    async fn trusted_proxy_no_existing_xff_just_sets_client() {
        let f = make_filter(&["10.0.0.0/8"]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.1.2.3".parse().unwrap());

        f.on_request(&mut ctx).await.unwrap();

        let xff = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-For")
            .map(|(_, v)| v.as_str());
        assert_eq!(xff, Some("10.1.2.3"));
    }

    #[test]
    fn from_config_parses() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
trusted_proxies:
  - "10.0.0.0/8"
  - "172.16.0.0/12"
"#,
        )
        .unwrap();
        let filter = ForwardedHeadersFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "forwarded_headers");
    }

    #[test]
    fn from_config_empty_is_valid() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let filter = ForwardedHeadersFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "forwarded_headers");
    }

    #[test]
    fn from_config_invalid_cidr_fails() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(r#"trusted_proxies: ["not-a-cidr"]"#).unwrap();
        assert!(ForwardedHeadersFilter::from_config(&yaml).is_err());
    }
}
