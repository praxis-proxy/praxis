// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! `X-Forwarded-For/Proto/Host` injection filter with trusted-proxy support.

use std::{borrow::Cow, net::IpAddr};

use async_trait::async_trait;
use praxis_core::connectivity::CidrRange;
use serde::Deserialize;

use crate::{
    FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// ForwardedHeadersConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the forwarded headers filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardedHeadersConfig {
    /// CIDR ranges of trusted proxies whose existing
    /// X-Forwarded-For values are preserved (appended to).
    /// Untrusted sources have the header overwritten.
    #[serde(default)]
    trusted_proxies: Vec<String>,

    /// When `true`, also inject the standard [RFC 7239]
    /// `Forwarded` header in addition to X-Forwarded-* headers.
    ///
    /// [RFC 7239]: https://datatracker.ietf.org/doc/html/rfc7239
    #[serde(default)]
    use_standard_header: bool,
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
/// When `use_standard_header` is `true`, also injects the
/// [RFC 7239] `Forwarded` header with `for`, `proto`, and
/// `host` parameters.
///
/// # YAML configuration
///
/// ```yaml
/// filter: forwarded_headers
/// trusted_proxies: ["10.0.0.0/8"]
/// use_standard_header: true
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::ForwardedHeadersFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// trusted_proxies: ["10.0.0.0/8"]
/// use_standard_header: true
/// "#,
/// )
/// .unwrap();
/// let filter = ForwardedHeadersFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "forwarded_headers");
/// ```
///
/// [RFC 7239]: https://datatracker.ietf.org/doc/html/rfc7239
pub struct ForwardedHeadersFilter {
    /// CIDR ranges considered trusted proxies.
    trusted_proxies: Vec<CidrRange>,

    /// Whether to inject the standard `Forwarded` header.
    use_standard_header: bool,
}

impl ForwardedHeadersFilter {
    /// Create from YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if a trusted proxy CIDR is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: ForwardedHeadersConfig = parse_filter_config("forwarded_headers", config)?;

        let trusted_proxies = cfg
            .trusted_proxies
            .iter()
            .map(|s| CidrRange::parse(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| -> FilterError { format!("forwarded_headers: {e}").into() })?;

        Ok(Box::new(Self {
            trusted_proxies,
            use_standard_header: cfg.use_standard_header,
        }))
    }

    /// Returns `true` if `ip` matches any trusted proxy CIDR.
    fn is_trusted(&self, ip: &IpAddr) -> bool {
        self.trusted_proxies.iter().any(|r| r.contains(ip))
    }

    /// Inject or append the standard [RFC 7239] `Forwarded` header.
    ///
    /// Format: `Forwarded: for=<ip>;proto=<proto>;host=<host>`
    ///
    /// IPv6 addresses are quoted per [RFC 7239 Section 6]:
    /// `for="[::1]"`.
    ///
    /// The `host` parameter is unconditionally quoted as a
    /// `quoted-string` to prevent injection via `;`, `,`, or
    /// `"` in untrusted Host values. Embedded `"` and `\` are
    /// backslash-escaped. RFC 7239 allows bare `token` values
    /// too, but quoting is correct for all inputs.
    ///
    /// When the client is trusted and a `Forwarded` header already
    /// exists, the new entry is appended comma-separated.
    ///
    /// [RFC 7239]: https://datatracker.ietf.org/doc/html/rfc7239
    /// [RFC 7239 Section 4]: https://datatracker.ietf.org/doc/html/rfc7239#section-4
    /// [RFC 7239 Section 6]: https://datatracker.ietf.org/doc/html/rfc7239#section-6
    fn inject_standard_forwarded(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        client_ip: &IpAddr,
        proto: &str,
        host: Option<&str>,
    ) {
        use std::fmt::Write as _;

        tracing::debug!(client_ip = %client_ip, "setting standard Forwarded header");
        let for_param = format_for_param(client_ip);
        let mut entry = format!("for={for_param};proto={proto}");
        if let Some(h) = host {
            let escaped = quote_forwarded_value(h);
            let _ok = write!(entry, ";host={escaped}");
        }

        let value = if self.is_trusted(client_ip)
            && let Some(existing) = ctx.request.headers.get("forwarded")
            && let Ok(existing) = existing.to_str()
        {
            format!("{existing}, {entry}")
        } else {
            entry
        };

        ctx.extra_request_headers.push((Cow::Borrowed("Forwarded"), value));
    }
}

// -----------------------------------------------------------------------------
// Forwarded Header Formatting
// -----------------------------------------------------------------------------

/// Format the `for` parameter value per [RFC 7239 Section 6].
///
/// IPv6 addresses require quoting because `:` and `[]` are
/// not valid `token` characters. IPv4 addresses are bare tokens.
///
/// [RFC 7239 Section 6]: https://datatracker.ietf.org/doc/html/rfc7239#section-6
fn format_for_param(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}"),
        IpAddr::V6(v6) => format!("\"[{v6}]\""),
    }
}

/// Wrap a value as a `quoted-string` for the `Forwarded` header.
///
/// RFC 7239 allows both `token` and `quoted-string`; we
/// unconditionally quote because it is correct for all inputs.
/// Embedded `\` and `"` are backslash-escaped.
///
/// [RFC 7239 Section 4]: https://datatracker.ietf.org/doc/html/rfc7239#section-4
fn quote_forwarded_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        if ch == '"' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

#[async_trait]
impl HttpFilter for ForwardedHeadersFilter {
    fn name(&self) -> &'static str {
        "forwarded_headers"
    }

    #[expect(clippy::too_many_lines, reason = "header construction")]
    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        use std::fmt::Write as _;

        let Some(client_ip) = ctx.client_addr else {
            return Ok(FilterAction::Continue);
        };

        tracing::debug!(trusted = self.is_trusted(&client_ip), "setting X-Forwarded-For");
        let xff = if self.is_trusted(&client_ip)
            && let Some(existing) = ctx.request.headers.get("x-forwarded-for")
        {
            if let Ok(existing) = existing.to_str() {
                let mut val = String::with_capacity(existing.len() + 2 + 45);
                val.push_str(existing);
                val.push_str(", ");
                let _ok = write!(val, "{client_ip}");
                val
            } else {
                tracing::warn!(client_ip = %client_ip, "existing X-Forwarded-For contains non-UTF-8 bytes; overwriting");
                let mut val = String::with_capacity(45);
                let _ok = write!(val, "{client_ip}");
                val
            }
        } else {
            let mut val = String::with_capacity(45);
            let _ok = write!(val, "{client_ip}");
            val
        };
        ctx.extra_request_headers.push((Cow::Borrowed("X-Forwarded-For"), xff));

        let proto = if ctx.downstream_tls { "https" } else { "http" };
        tracing::debug!(proto, "setting X-Forwarded-Proto from connection state");
        ctx.extra_request_headers
            .push((Cow::Borrowed("X-Forwarded-Proto"), proto.into()));

        let host_value = ctx
            .request
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);
        if let Some(host) = &host_value {
            tracing::debug!(host = %host, "setting X-Forwarded-Host from Host header");
            ctx.extra_request_headers
                .push((Cow::Borrowed("X-Forwarded-Host"), host.clone()));
        }

        if self.use_standard_header {
            self.inject_standard_forwarded(ctx, &client_ip, proto, host_value.as_deref());
        }

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sets_xff_from_client_ip() {
        let f = make_filter(&[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let xff = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-For")
            .map(|(_, v)| v.as_str());
        assert_eq!(xff, Some("203.0.113.50"), "XFF should contain client IP");
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

        drop(f.on_request(&mut ctx).await.unwrap());

        let xff = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-For")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            xff,
            Some("203.0.113.50"),
            "untrusted client XFF should overwrite spoofed value"
        );
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

        drop(f.on_request(&mut ctx).await.unwrap());

        let xff = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-For")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            xff,
            Some("203.0.113.50, 10.1.2.3"),
            "trusted proxy should append to existing XFF"
        );
    }

    #[tokio::test]
    async fn sets_x_forwarded_proto() {
        let f = make_filter(&[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let proto = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-Proto")
            .map(|(_, v)| v.as_str());
        assert_eq!(proto, Some("http"), "X-Forwarded-Proto should default to http");
    }

    #[tokio::test]
    async fn sets_x_forwarded_host_from_host_header() {
        let f = make_filter(&[]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(http::header::HOST, "example.com".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let host = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-Host")
            .map(|(_, v)| v.as_str());
        assert_eq!(host, Some("example.com"), "X-Forwarded-Host should match Host header");
    }

    #[tokio::test]
    async fn no_host_header_skips_x_forwarded_host() {
        let f = make_filter(&[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let host = ctx.extra_request_headers.iter().find(|(k, _)| k == "X-Forwarded-Host");
        assert!(host.is_none(), "X-Forwarded-Host should be absent when no Host header");
    }

    #[tokio::test]
    async fn no_client_addr_is_noop() {
        let f = make_filter(&[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(f.on_request(&mut ctx).await.unwrap());

        assert!(
            ctx.extra_request_headers.is_empty(),
            "no headers should be added without client addr"
        );
    }

    #[tokio::test]
    async fn trusted_proxy_no_existing_xff_just_sets_client() {
        let f = make_filter(&["10.0.0.0/8"]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.1.2.3".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let xff = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-For")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            xff,
            Some("10.1.2.3"),
            "trusted proxy with no existing XFF should set client IP"
        );
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
        assert_eq!(
            filter.name(),
            "forwarded_headers",
            "filter name should be forwarded_headers"
        );
    }

    #[test]
    fn from_config_empty_is_valid() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let filter = ForwardedHeadersFilter::from_config(&yaml).unwrap();
        assert_eq!(
            filter.name(),
            "forwarded_headers",
            "empty config should produce valid filter"
        );
    }

    #[tokio::test]
    async fn standard_forwarded_header_injected() {
        let f = make_standard_filter(&[]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(http::header::HOST, "example.com".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let fwd = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "Forwarded")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            fwd,
            Some("for=203.0.113.50;proto=http;host=\"example.com\""),
            "standard Forwarded header should match RFC 7239 format"
        );
    }

    #[tokio::test]
    async fn standard_forwarded_ipv6_quoted() {
        let f = make_standard_filter(&[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("2001:db8::1".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let fwd = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "Forwarded")
            .map(|(_, v)| v.as_str());
        assert!(
            fwd.is_some_and(|v| v.contains("for=\"[2001:db8::1]\"")),
            "IPv6 address must be quoted in Forwarded header: {fwd:?}"
        );
    }

    #[tokio::test]
    async fn standard_forwarded_appended_when_trusted() {
        let f = make_standard_filter(&["10.0.0.0/8"]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("forwarded"),
            "for=203.0.113.50;proto=https".parse().unwrap(),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.1.2.3".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let fwd = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "Forwarded")
            .map(|(_, v)| v.as_str());
        assert!(
            fwd.is_some_and(|v| v.starts_with("for=203.0.113.50;proto=https, for=10.1.2.3")),
            "trusted proxy should append to existing Forwarded: {fwd:?}"
        );
    }

    #[tokio::test]
    async fn standard_forwarded_ipv6_host_quoted() {
        let f = make_standard_filter(&[]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(http::header::HOST, "[::1]:8080".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let fwd = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "Forwarded")
            .map(|(_, v)| v.as_str());
        assert!(
            fwd.is_some_and(|v| v.contains(";host=\"[::1]:8080\"")),
            "IPv6 host must be quoted in Forwarded header: {fwd:?}"
        );
    }

    #[tokio::test]
    async fn standard_forwarded_not_injected_when_disabled() {
        let f = make_filter(&[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let fwd = ctx.extra_request_headers.iter().find(|(k, _)| k == "Forwarded");
        assert!(
            fwd.is_none(),
            "Forwarded header should not be injected when use_standard_header is false"
        );
    }

    #[test]
    fn format_for_param_ipv4() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(
            format_for_param(&ip),
            "192.168.1.1",
            "IPv4 for-param should be bare address"
        );
    }

    #[test]
    fn format_for_param_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            format_for_param(&ip),
            "\"[2001:db8::1]\"",
            "IPv6 for-param must be quoted with brackets"
        );
    }

    #[tokio::test]
    async fn tls_connection_sets_proto_https() {
        let f = make_filter(&[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());
        ctx.downstream_tls = true;

        drop(f.on_request(&mut ctx).await.unwrap());

        let proto = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-Proto")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            proto,
            Some("https"),
            "TLS connection should set X-Forwarded-Proto to https"
        );
    }

    #[tokio::test]
    async fn non_utf8_xff_overwrites_with_warning() {
        let f = make_filter(&["10.0.0.0/8"]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("x-forwarded-for"),
            http::HeaderValue::from_bytes(b"\xff\xfe").unwrap(),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.1.2.3".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let xff = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-For")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            xff,
            Some("10.1.2.3"),
            "non-UTF-8 XFF should be overwritten with just client IP"
        );
    }

    #[test]
    fn from_config_with_standard_header() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
trusted_proxies: ["10.0.0.0/8"]
use_standard_header: true
"#,
        )
        .unwrap();
        let filter = ForwardedHeadersFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "forwarded_headers");
    }

    #[tokio::test]
    async fn standard_forwarded_host_semicolon_escaped() {
        let f = make_standard_filter(&[]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers
            .insert(http::header::HOST, "evil;host=injected".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let fwd = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "Forwarded")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            fwd,
            Some("for=203.0.113.50;proto=http;host=\"evil;host=injected\""),
            "semicolons in host must be safely quoted"
        );
    }

    #[tokio::test]
    async fn standard_forwarded_host_quotes_escaped() {
        let f = make_standard_filter(&[]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers
            .insert(http::header::HOST, "evil\",host=injected".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let fwd = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "Forwarded")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            fwd,
            Some("for=203.0.113.50;proto=http;host=\"evil\\\",host=injected\""),
            "embedded quotes in host must be backslash-escaped"
        );
    }

    #[tokio::test]
    async fn standard_forwarded_host_comma_escaped() {
        let f = make_standard_filter(&[]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers
            .insert(http::header::HOST, "evil,for=spoofed".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let fwd = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "Forwarded")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            fwd,
            Some("for=203.0.113.50;proto=http;host=\"evil,for=spoofed\""),
            "commas in host must be safely quoted"
        );
    }

    #[tokio::test]
    async fn standard_forwarded_host_backslash_escaped() {
        let f = make_standard_filter(&[]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(http::header::HOST, "evil\\host".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let fwd = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "Forwarded")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            fwd,
            Some("for=203.0.113.50;proto=http;host=\"evil\\\\host\""),
            "backslashes in host must be double-escaped"
        );
    }

    #[test]
    fn quote_forwarded_value_simple() {
        assert_eq!(
            quote_forwarded_value("example.com"),
            "\"example.com\"",
            "simple value should be wrapped in quotes"
        );
    }

    #[test]
    fn quote_forwarded_value_with_embedded_quote() {
        assert_eq!(
            quote_forwarded_value("a\"b"),
            "\"a\\\"b\"",
            "embedded quote must be escaped"
        );
    }

    #[test]
    fn quote_forwarded_value_with_backslash() {
        assert_eq!(
            quote_forwarded_value("a\\b"),
            "\"a\\\\b\"",
            "embedded backslash must be escaped"
        );
    }

    #[test]
    fn from_config_invalid_cidr_fails() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(r#"trusted_proxies: ["not-a-cidr"]"#).unwrap();
        assert!(
            ForwardedHeadersFilter::from_config(&yaml).is_err(),
            "invalid CIDR should fail"
        );
    }

    #[tokio::test]
    async fn untrusted_client_xff_overwritten() {
        let f = make_filter(&[]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("x-forwarded-for"),
            "10.0.0.1, 172.16.0.5".parse().unwrap(),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("198.51.100.7".parse().unwrap());

        drop(f.on_request(&mut ctx).await.unwrap());

        let xff = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-For")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            xff,
            Some("198.51.100.7"),
            "untrusted client should overwrite spoofed XFF chain with actual client IP"
        );
    }

    #[tokio::test]
    async fn x_forwarded_proto_set_for_non_tls() {
        let f = make_filter(&[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("203.0.113.50".parse().unwrap());
        ctx.downstream_tls = false;

        drop(f.on_request(&mut ctx).await.unwrap());

        let proto = ctx
            .extra_request_headers
            .iter()
            .find(|(k, _)| k == "X-Forwarded-Proto")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            proto,
            Some("http"),
            "non-TLS connection should set X-Forwarded-Proto to http"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`ForwardedHeadersFilter`] with the given trusted proxy CIDRs.
    fn make_filter(trusted: &[&str]) -> ForwardedHeadersFilter {
        ForwardedHeadersFilter {
            trusted_proxies: trusted.iter().map(|s| CidrRange::parse(s).unwrap()).collect(),
            use_standard_header: false,
        }
    }

    /// Build a filter with the standard `Forwarded` header enabled.
    fn make_standard_filter(trusted: &[&str]) -> ForwardedHeadersFilter {
        ForwardedHeadersFilter {
            trusted_proxies: trusted.iter().map(|s| CidrRange::parse(s).unwrap()).collect(),
            use_standard_header: true,
        }
    }
}
