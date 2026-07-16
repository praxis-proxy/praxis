// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Endpoint selector filter: selects an upstream endpoint from a request header.

use std::sync::Arc;

use async_trait::async_trait;
use praxis_core::{
    config::{CachedClusterTls, ClusterTls},
    connectivity::{ConnectionOptions, Upstream},
};
use serde::Deserialize;

use crate::{
    FilterAction, FilterError, Rejection,
    context::PendingHeaderResult,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum supported endpoint-selector connection timeout in milliseconds.
///
/// Matches the limit used for configured upstream clusters.
const MAX_CONNECTION_TIMEOUT_MS: u64 = 3_600_000;

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Connection tuning for dynamically selected upstream endpoints.
///
/// Uses the same timeout fields as a configured upstream cluster. All
/// fields are optional; omitted fields retain Pingora defaults.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointConnectionConfig {
    /// TCP connection timeout in milliseconds.
    #[serde(default)]
    connection_timeout_ms: Option<u64>,

    /// Idle connection timeout in milliseconds.
    #[serde(default)]
    idle_timeout_ms: Option<u64>,

    /// Per-read timeout in milliseconds.
    #[serde(default)]
    read_timeout_ms: Option<u64>,

    /// Total TCP and TLS connection timeout in milliseconds.
    #[serde(default)]
    total_connection_timeout_ms: Option<u64>,

    /// Per-write timeout in milliseconds.
    #[serde(default)]
    write_timeout_ms: Option<u64>,
}

impl EndpointConnectionConfig {
    /// Validate configuration and construct reusable upstream options.
    fn build(&self) -> Result<ConnectionOptions, FilterError> {
        for (field, value) in [
            ("connection_timeout_ms", self.connection_timeout_ms),
            ("idle_timeout_ms", self.idle_timeout_ms),
            ("read_timeout_ms", self.read_timeout_ms),
            ("total_connection_timeout_ms", self.total_connection_timeout_ms),
            ("write_timeout_ms", self.write_timeout_ms),
        ] {
            validate_connection_timeout(field, value)?;
        }

        if let (Some(connection), Some(total)) = (self.connection_timeout_ms, self.total_connection_timeout_ms)
            && connection > total
        {
            return Err(format!(
                "endpoint_selector: connection_timeout_ms ({connection}) exceeds total_connection_timeout_ms ({total})"
            )
            .into());
        }

        Ok(ConnectionOptions {
            connection_timeout: self.connection_timeout_ms.map(std::time::Duration::from_millis),
            idle_timeout: self.idle_timeout_ms.map(std::time::Duration::from_millis),
            read_timeout: self.read_timeout_ms.map(std::time::Duration::from_millis),
            total_connection_timeout: self.total_connection_timeout_ms.map(std::time::Duration::from_millis),
            write_timeout: self.write_timeout_ms.map(std::time::Duration::from_millis),
        })
    }
}

/// Validate one optional upstream timeout using cluster-compatible bounds.
fn validate_connection_timeout(field: &str, value: Option<u64>) -> Result<(), FilterError> {
    if let Some(0) = value {
        return Err(format!("endpoint_selector: {field} must be greater than zero").into());
    }
    if let Some(value) = value
        && value > MAX_CONNECTION_TIMEOUT_MS
    {
        return Err(format!(
            "endpoint_selector: {field} ({value} ms) exceeds maximum ({MAX_CONNECTION_TIMEOUT_MS} ms)"
        )
        .into());
    }
    Ok(())
}

/// Cache configured TLS material and reject unusable verified TLS settings.
fn cache_tls(tls: Option<&ClusterTls>) -> Result<Option<CachedClusterTls>, FilterError> {
    let Some(tls) = tls else {
        return Ok(None);
    };
    if let Some(sni) = tls.sni.as_deref() {
        validate_sni(sni)?;
    } else if tls.verify {
        return Err("endpoint_selector: tls.sni is required when tls.verify is true".into());
    }

    CachedClusterTls::try_from_config(tls)
        .map(Some)
        .map_err(|e| format!("endpoint_selector: invalid TLS configuration: {e}").into())
}

/// Validate SNI with the same DNS and wildcard rules as cluster TLS.
///
/// Endpoint-selector TLS is parsed as filter configuration rather than
/// cluster configuration, so it does not pass through the cluster
/// validator.
fn validate_sni(sni: &str) -> Result<(), FilterError> {
    if sni.is_empty() {
        return Err("endpoint_selector: tls.sni must not be empty".into());
    }
    if sni.len() > 253 {
        return Err("endpoint_selector: tls.sni exceeds 253 characters".into());
    }

    for (index, label) in sni.split('.').enumerate() {
        if label.is_empty() || label.len() > 63 {
            return Err("endpoint_selector: tls.sni has an invalid label length".into());
        }
        if label.contains('*') {
            if label != "*" || index != 0 {
                return Err("endpoint_selector: tls.sni wildcard is only valid as the complete leftmost label".into());
            }
            continue;
        }
        if !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
            return Err("endpoint_selector: tls.sni contains invalid characters".into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("endpoint_selector: tls.sni label must not start or end with a hyphen".into());
        }
    }
    Ok(())
}

/// Configuration for the endpoint selector filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointSelectorConfig {
    /// Optional connection tuning for selected upstreams.
    #[serde(default)]
    connection: EndpointConnectionConfig,

    /// Whether the destination header is required (fail-closed).
    ///
    /// When `true`, requests without a trusted destination header
    /// are rejected. Use for compositions where an external
    /// processor is expected to always supply a destination.
    #[serde(default)]
    required: bool,

    /// The request header to read the upstream endpoint address from.
    source_header: String,

    /// HTTP status code for required-mode routing failures.
    ///
    /// Only used when `required: true`. Defaults to 500.
    /// Compositions with required external processing typically set 503.
    #[serde(default = "default_status_on_required_failure")]
    status_on_required_failure: u16,

    /// Whether to remove the source header after reading it.
    #[serde(default = "default_strip_header")]
    strip_header: bool,

    /// Optional TLS settings for selected upstreams.
    ///
    /// Certificates and keys are loaded and parsed once when the
    /// filter is constructed, never on a request path.
    #[serde(default)]
    tls: Option<ClusterTls>,
}

/// Default value for `status_on_required_failure`.
fn default_status_on_required_failure() -> u16 {
    500
}

/// Default value for `strip_header`.
fn default_strip_header() -> bool {
    true
}

// -----------------------------------------------------------------------------
// EndpointSelectorFilter
// -----------------------------------------------------------------------------

/// Selects an upstream endpoint from a trusted mutation source.
///
/// Only values set by trusted pre-read mutations (e.g. from an
/// `ext_proc` filter) are considered. Original client-supplied
/// header values are deliberately ignored to prevent SSRF.
///
/// The resolved value must be a single `host:port` authority. If no
/// trusted value is found and `required` is false, the filter does
/// nothing and returns [`FilterAction::Continue`]. Empty values are
/// rejected as an error.
///
/// # YAML configuration
///
/// ```yaml
/// filter: endpoint_selector
/// source_header: x-gateway-destination-endpoint
/// strip_header: true  # default true
/// connection:
///   connection_timeout_ms: 1000
///   total_connection_timeout_ms: 2000
/// tls:
///   sni: inference.example.internal
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::EndpointSelectorFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     "source_header: x-destination\nstrip_header: false"
/// ).unwrap();
/// let filter = EndpointSelectorFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "endpoint_selector");
/// ```
pub struct EndpointSelectorFilter {
    /// Connection options for constructed upstreams.
    connection: Arc<ConnectionOptions>,

    /// Whether the destination header is required (fail-closed).
    required: bool,

    /// The request header to read.
    source_header: http::HeaderName,

    /// HTTP status code for required-mode routing failures.
    status_on_required_failure: u16,

    /// Whether to strip the source header after reading.
    strip_header: bool,

    /// Pre-parsed TLS material for selected upstreams.
    ///
    /// `None` selects plaintext. Configured certificates and keys are
    /// cached at filter construction, so request handling only clones
    /// this already parsed state.
    tls: Option<CachedClusterTls>,
}

impl std::fmt::Debug for EndpointSelectorFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointSelectorFilter")
            .field("source_header", &self.source_header)
            .field("required", &self.required)
            .field("status_on_required_failure", &self.status_on_required_failure)
            .field("strip_header", &self.strip_header)
            .finish_non_exhaustive()
    }
}

impl EndpointSelectorFilter {
    /// Create an endpoint selector filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if `source_header` is missing or not a
    /// valid HTTP header name.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: EndpointSelectorConfig = parse_filter_config("endpoint_selector", config)?;

        let source_header: http::HeaderName = cfg
            .source_header
            .parse()
            .map_err(|e| format!("endpoint_selector: invalid source_header: {e}"))?;

        if !(100..=599).contains(&cfg.status_on_required_failure) {
            let code = cfg.status_on_required_failure;
            return Err(format!(
                "endpoint_selector: status_on_required_failure {code} is not a valid HTTP status code (must be 100..=599)"
            )
            .into());
        }

        let connection = Arc::new(cfg.connection.build()?);
        let tls = cache_tls(cfg.tls.as_ref())?;

        Ok(Box::new(Self {
            connection,
            required: cfg.required,
            source_header,
            status_on_required_failure: cfg.status_on_required_failure,
            strip_header: cfg.strip_header,
            tls,
        }))
    }

    /// Resolve the destination endpoint from trusted mutations.
    fn resolve_endpoint(&self, ctx: &HttpFilterContext<'_>) -> Result<Option<String>, FilterError> {
        let pending = ctx
            .pending_header_value(&self.source_header)
            .map_err(|e| -> FilterError { format!("endpoint_selector: {e}").into() })?;

        let value = match pending {
            PendingHeaderResult::Value(v) => v,
            PendingHeaderResult::Removed => return self.absent_result("explicitly removed"),
            PendingHeaderResult::Absent => match self.resolve_from_trusted(ctx)? {
                Some(v) => v,
                None => return self.absent_result("absent"),
            },
        };

        self.validate_endpoint(&value)?;
        Ok(Some(value))
    }

    /// Resolve from the pre-read trusted mutation log.
    fn resolve_from_trusted(&self, ctx: &HttpFilterContext<'_>) -> Result<Option<String>, FilterError> {
        ctx.resolve_trusted_header(&self.source_header)
            .map_err(|e| -> FilterError { format!("endpoint_selector: {e}").into() })
    }

    /// Return `Ok(None)` for optional mode, or an error for required mode.
    fn absent_result(&self, reason: &str) -> Result<Option<String>, FilterError> {
        if self.required {
            Err(format!(
                "endpoint_selector: required destination header '{header}' {reason}",
                header = self.source_header
            )
            .into())
        } else {
            Ok(None)
        }
    }

    /// Validate an endpoint value is a well-formed address.
    fn validate_endpoint(&self, value: &str) -> Result<(), FilterError> {
        if value.is_empty() {
            return Err(format!(
                "endpoint_selector: header '{header}' has an empty trusted value",
                header = self.source_header
            )
            .into());
        }
        if value.contains(',') {
            return Err(format!(
                "endpoint_selector: header '{header}' contains multiple values",
                header = self.source_header
            )
            .into());
        }
        validate_host_port(value)
    }

    /// Return a routing failure as either a rejection or an error.
    ///
    /// Required-mode failures return [`Reject`] so they cannot be
    /// bypassed by `failure_mode: open`. Optional-mode failures
    /// return [`FilterError`] for conventional failure-mode handling.
    ///
    /// [`Reject`]: FilterAction::Reject
    fn routing_failure(&self, reason: String) -> Result<FilterAction, FilterError> {
        if self.required {
            tracing::warn!(%reason, "required endpoint_selector rejecting request");
            Ok(FilterAction::Reject(Rejection::status(self.status_on_required_failure)))
        } else {
            Err(reason.into())
        }
    }

    /// Queue removal of the internal source header from forwarded requests.
    fn strip_source_header(&self, ctx: &mut HttpFilterContext<'_>) {
        ctx.request_headers_to_remove.push(self.source_header.clone());
        let name_str = self.source_header.as_str();
        ctx.extra_request_headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case(name_str));
        ctx.request_headers_to_set.retain(|(n, _)| *n != self.source_header);
        ctx.pre_read_mutations
            .retain(|m| !m.matches_header(&self.source_header));
    }
}

#[async_trait]
impl HttpFilter for EndpointSelectorFilter {
    fn name(&self) -> &'static str {
        "endpoint_selector"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let resolved = self.resolve_endpoint(ctx);

        if self.strip_header {
            self.strip_source_header(ctx);
        }

        let value = match resolved {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(FilterAction::Continue),
            Err(e) => return self.routing_failure(e.to_string()),
        };

        let upstream = Upstream {
            address: Arc::from(value.as_str()),
            connection: Arc::clone(&self.connection),
            tls: self.tls.clone(),
        };

        ctx.upstream = Some(upstream);

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Validate that `addr` is a well-formed `host:port` authority.
///
/// Accepts DNS names, IPv4 addresses, and bracketed IPv6 addresses
/// (e.g. `[::1]:8080`). The port must be a valid `u16`. Rejects URIs
/// (scheme prefixes), paths, query strings, and malformed hosts.
fn validate_host_port(addr: &str) -> Result<(), FilterError> {
    if addr.contains("://") {
        return Err(format!("endpoint_selector: value looks like a URI, expected host:port: '{addr}'").into());
    }
    if addr.contains('/') || addr.contains('?') || addr.contains('#') {
        return Err(
            format!("endpoint_selector: value contains path/query/fragment, expected host:port: '{addr}'").into(),
        );
    }
    if addr.contains('@') {
        return Err(format!("endpoint_selector: value contains userinfo, expected host:port: '{addr}'").into());
    }

    // Handle bracketed IPv6: [host]:port
    if let Some(rest) = addr.strip_prefix('[') {
        let (ipv6_host, port_str) = rest
            .split_once("]:")
            .ok_or_else(|| format!("endpoint_selector: invalid IPv6 address format: '{addr}'"))?;
        if ipv6_host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(format!("endpoint_selector: invalid IPv6 address in brackets: '{addr}'").into());
        }
        parse_port(port_str, addr)?;
        return Ok(());
    }

    // For non-IPv6, split on the last colon.
    let (host, port_str) = addr
        .rsplit_once(':')
        .ok_or_else(|| format!("endpoint_selector: missing port in address: '{addr}'"))?;

    if host.is_empty() {
        return Err(format!("endpoint_selector: empty host in address: '{addr}'").into());
    }

    validate_host_label(host, addr)?;
    parse_port(port_str, addr)?;

    Ok(())
}

/// Validate a non-IPv6 host label (DNS name or IPv4 address).
fn validate_host_label(host: &str, addr: &str) -> Result<(), FilterError> {
    for ch in host.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' {
            return Err(format!("endpoint_selector: invalid character '{ch}' in host: '{addr}'").into());
        }
    }
    if host.starts_with('.') || host.ends_with('.') || host.starts_with('-') {
        return Err(format!("endpoint_selector: malformed host in address: '{addr}'").into());
    }
    if host.contains("..") {
        return Err(format!("endpoint_selector: consecutive dots in host: '{addr}'").into());
    }
    for label in host.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(format!("endpoint_selector: DNS label exceeds 63 characters in: '{addr}'").into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("endpoint_selector: DNS label starts or ends with hyphen in: '{addr}'").into());
        }
    }
    Ok(())
}

/// Parse and validate a port string as a nonzero `u16`.
fn parse_port(port_str: &str, addr: &str) -> Result<u16, FilterError> {
    let port: u16 = port_str.parse().map_err(|_parse_err| -> FilterError {
        format!("endpoint_selector: invalid port in address: '{addr}'").into()
    })?;
    if port == 0 {
        return Err(format!("endpoint_selector: port 0 is not valid in address: '{addr}'").into());
    }
    Ok(port)
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
    use crate::context::TrustedHeaderMutation;

    #[test]
    fn parse_valid_config() {
        let config: serde_yaml::Value =
            serde_yaml::from_str("source_header: x-destination\nstrip_header: false").unwrap();
        let filter = EndpointSelectorFilter::from_config(&config).unwrap();
        assert_eq!(filter.name(), "endpoint_selector", "filter name should match");
    }

    #[test]
    fn parse_missing_source_header_errors() {
        let config: serde_yaml::Value = serde_yaml::from_str("strip_header: true").unwrap();
        assert!(
            EndpointSelectorFilter::from_config(&config).is_err(),
            "missing source_header should error"
        );
    }

    #[tokio::test]
    async fn selects_upstream_from_header() {
        let filter = make_filter("x-dest", true);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "backend.local:8080".to_owned(),
        ));

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue), "should return Continue");
        assert_eq!(
            ctx.upstream_addr(),
            Some("backend.local:8080"),
            "upstream should be set from header"
        );
    }

    #[tokio::test]
    async fn strips_header_by_default() {
        let filter = make_filter("x-dest", true);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "backend.local:8080".to_owned(),
        ));

        let _action = filter.on_request(&mut ctx).await.unwrap();

        let header_name: http::HeaderName = "x-dest".parse().unwrap();
        assert!(
            ctx.request_headers_to_remove.contains(&header_name),
            "source header should be in remove list when strip_header is true"
        );
    }

    #[tokio::test]
    async fn ignores_absent_header() {
        let filter = make_filter("x-dest", true);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "should return Continue when header absent"
        );
        assert!(ctx.upstream.is_none(), "upstream should remain None when header absent");
    }

    #[tokio::test]
    async fn required_mode_rejects_when_absent() {
        let filter = make_required_filter("x-dest", true);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 503),
            "required mode should reject with configured 503 when header absent"
        );
    }

    #[tokio::test]
    async fn client_supplied_header_not_selected() {
        let filter = make_filter("x-dest", true);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("x-dest", "evil.attacker:9999".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "should continue without selecting upstream"
        );
        assert!(
            ctx.upstream.is_none(),
            "client-supplied destination must not select upstream"
        );
        assert!(
            ctx.request_headers_to_remove.contains(&"x-dest".parse().unwrap()),
            "client-supplied source header should still be stripped"
        );
    }

    #[tokio::test]
    async fn strips_header_when_optional_selection_errors() {
        let filter = make_filter("x-dest", true);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "http://backend.local:8080".to_owned(),
        ));

        let err = filter.on_request(&mut ctx).await.unwrap_err();

        assert!(err.to_string().contains("URI"), "unexpected error: {err}");
        assert!(
            ctx.request_headers_to_remove.contains(&"x-dest".parse().unwrap()),
            "source header should be stripped even if optional routing errors and failure_mode opens"
        );
    }

    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "asserts all configured connection option fields")]
    async fn configured_connection_options_are_applied_to_upstream() {
        let config: serde_yaml::Value = serde_yaml::from_str(
            "\nsource_header: x-dest\nconnection:\n  connection_timeout_ms: 100\n  idle_timeout_ms: 200\n  read_timeout_ms: 300\n  write_timeout_ms: 400\n  total_connection_timeout_ms: 500\n",
        )
        .unwrap();
        let filter = EndpointSelectorFilter::from_config(&config).unwrap();
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "backend.local:8443".to_owned(),
        ));

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
        let upstream = ctx.upstream.as_ref().expect("selector should set upstream");
        assert_eq!(
            upstream.connection.connection_timeout,
            Some(std::time::Duration::from_millis(100))
        );
        assert_eq!(
            upstream.connection.idle_timeout,
            Some(std::time::Duration::from_millis(200))
        );
        assert_eq!(
            upstream.connection.read_timeout,
            Some(std::time::Duration::from_millis(300))
        );
        assert_eq!(
            upstream.connection.write_timeout,
            Some(std::time::Duration::from_millis(400))
        );
        assert_eq!(
            upstream.connection.total_connection_timeout,
            Some(std::time::Duration::from_millis(500))
        );
        assert!(upstream.tls.is_none(), "TLS should remain disabled when omitted");
    }

    #[tokio::test]
    async fn configured_tls_is_cached_and_applied_to_upstream() {
        let config: serde_yaml::Value =
            serde_yaml::from_str("source_header: x-dest\ntls:\n  sni: inference.example.internal\n  verify: false\n")
                .unwrap();
        let filter = EndpointSelectorFilter::from_config(&config).unwrap();
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "backend.local:443".to_owned(),
        ));

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
        let tls = ctx
            .upstream
            .as_ref()
            .and_then(|upstream| upstream.tls.as_ref())
            .expect("configured TLS should be applied to selected upstream");
        assert_eq!(tls.sni(), Some("inference.example.internal"));
        assert!(!tls.verify(), "configured TLS verify flag should be preserved");
    }

    #[test]
    fn configured_tls_load_failure_rejects_config() {
        let config: serde_yaml::Value =
            serde_yaml::from_str(
                "source_header: x-dest\ntls:\n  sni: inference.example.internal\n  ca:\n    ca_path: /definitely/not/a/real/ca.pem\n",
            )
                .unwrap();

        let Err(err) = EndpointSelectorFilter::from_config(&config) else {
            panic!("TLS file-load failure should reject filter construction");
        };
        assert!(
            err.to_string().contains("invalid TLS configuration"),
            "TLS file-load failure should reject filter construction: {err}"
        );
    }

    #[test]
    fn verified_tls_without_sni_rejects_config() {
        let config: serde_yaml::Value = serde_yaml::from_str("source_header: x-dest\ntls: {}\n").unwrap();

        let Err(err) = EndpointSelectorFilter::from_config(&config) else {
            panic!("verified TLS without SNI should reject filter construction");
        };
        assert!(err.to_string().contains("tls.sni"), "unexpected error: {err}");
    }

    #[test]
    fn invalid_tls_sni_rejects_config() {
        let config: serde_yaml::Value =
            serde_yaml::from_str("source_header: x-dest\ntls:\n  sni: invalid host\n  verify: false\n").unwrap();

        let Err(err) = EndpointSelectorFilter::from_config(&config) else {
            panic!("invalid TLS SNI should reject filter construction");
        };
        assert!(
            err.to_string().contains("invalid") || err.to_string().contains("sni"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wildcard_tls_sni_is_rejected() {
        let config: serde_yaml::Value =
            serde_yaml::from_str("source_header: x-dest\ntls:\n  sni: '*.example.internal'\n  verify: false\n")
                .unwrap();

        assert!(
            EndpointSelectorFilter::from_config(&config).is_err(),
            "wildcard SNI is invalid for outbound ClientHello per RFC 6066"
        );
    }

    #[test]
    fn invalid_failure_status_rejected() {
        let config: serde_yaml::Value =
            serde_yaml::from_str("source_header: x-dest\nstatus_on_required_failure: 0").unwrap();
        assert!(
            EndpointSelectorFilter::from_config(&config).is_err(),
            "status 0 should be rejected"
        );
    }

    #[test]
    fn out_of_range_failure_status_rejected() {
        let config: serde_yaml::Value =
            serde_yaml::from_str("source_header: x-dest\nstatus_on_required_failure: 600").unwrap();
        assert!(
            EndpointSelectorFilter::from_config(&config).is_err(),
            "status 600 should be rejected"
        );
    }

    #[test]
    fn connection_timeout_zero_is_rejected() {
        let config: serde_yaml::Value =
            serde_yaml::from_str("source_header: x-dest\nconnection:\n  connection_timeout_ms: 0\n").unwrap();

        let Err(err) = EndpointSelectorFilter::from_config(&config) else {
            panic!("zero connection timeout should reject filter construction");
        };
        assert!(err.to_string().contains("greater than zero"), "unexpected error: {err}");
    }

    #[test]
    fn connection_timeout_over_maximum_is_rejected() {
        let config: serde_yaml::Value =
            serde_yaml::from_str("source_header: x-dest\nconnection:\n  read_timeout_ms: 3600001\n").unwrap();

        let Err(err) = EndpointSelectorFilter::from_config(&config) else {
            panic!("excessive connection timeout should reject filter construction");
        };
        assert!(err.to_string().contains("exceeds maximum"), "unexpected error: {err}");
    }

    #[test]
    fn connection_timeout_cannot_exceed_total_timeout() {
        let config: serde_yaml::Value = serde_yaml::from_str(
            "source_header: x-dest\nconnection:\n  connection_timeout_ms: 200\n  total_connection_timeout_ms: 100\n",
        )
        .unwrap();

        let Err(err) = EndpointSelectorFilter::from_config(&config) else {
            panic!("inconsistent connection timeouts should reject filter construction");
        };
        assert!(err.to_string().contains("exceeds total"), "unexpected error: {err}");
    }

    // -------------------------------------------------------------------------
    // Endpoint Validation Tests
    // -------------------------------------------------------------------------

    #[test]
    fn validates_valid_dns_host_port() {
        assert!(validate_host_port("backend.local:8080").is_ok());
    }

    #[test]
    fn validates_valid_ipv4_host_port() {
        assert!(validate_host_port("10.0.0.1:9090").is_ok());
    }

    #[test]
    fn validates_valid_ipv6_host_port() {
        assert!(validate_host_port("[::1]:8080").is_ok());
    }

    #[test]
    fn rejects_uri_with_scheme() {
        let err = validate_host_port("http://host:80").unwrap_err();
        assert!(err.to_string().contains("URI"), "should reject URI scheme: {err}");
    }

    #[test]
    fn rejects_address_with_path() {
        let err = validate_host_port("host:80/path").unwrap_err();
        assert!(err.to_string().contains("path"), "should reject path component: {err}");
    }

    #[test]
    fn rejects_address_with_userinfo() {
        let err = validate_host_port("user@host:80").unwrap_err();
        assert!(err.to_string().contains("userinfo"), "should reject userinfo: {err}");
    }

    #[test]
    fn rejects_invalid_bracketed_ipv6() {
        let err = validate_host_port("[not-ipv6]:8080").unwrap_err();
        assert!(err.to_string().contains("IPv6"), "should reject invalid IPv6: {err}");
    }

    #[test]
    fn rejects_malformed_dns_host() {
        let err = validate_host_port(".leading-dot:80").unwrap_err();
        assert!(
            err.to_string().contains("malformed"),
            "should reject leading dot: {err}"
        );
    }

    #[test]
    fn rejects_host_with_invalid_chars() {
        let err = validate_host_port("host name:80").unwrap_err();
        assert!(
            err.to_string().contains("invalid character"),
            "should reject spaces in host: {err}"
        );
    }

    #[test]
    fn rejects_missing_port() {
        let err = validate_host_port("hostname").unwrap_err();
        assert!(
            err.to_string().contains("missing port"),
            "should reject missing port: {err}"
        );
    }

    #[test]
    fn rejects_port_zero() {
        let err = validate_host_port("host:0").unwrap_err();
        assert!(err.to_string().contains("port 0"), "should reject port 0: {err}");
    }

    #[test]
    fn rejects_consecutive_dots_in_host() {
        let err = validate_host_port("host..internal:80").unwrap_err();
        assert!(
            err.to_string().contains("consecutive dots"),
            "should reject consecutive dots: {err}"
        );
    }

    #[test]
    fn rejects_underscore_in_hostname() {
        let err = validate_host_port("my_host:80").unwrap_err();
        assert!(
            err.to_string().contains("invalid character"),
            "should reject underscore: {err}"
        );
    }

    #[test]
    fn rejects_label_ending_with_hyphen() {
        let err = validate_host_port("a.-b:80").unwrap_err();
        assert!(
            err.to_string().contains("hyphen"),
            "should reject label starting with hyphen: {err}"
        );
    }

    #[test]
    fn rejects_dns_label_longer_than_63_chars() {
        let host = format!("{}.example:80", "a".repeat(64));
        let err = validate_host_port(&host).unwrap_err();
        assert!(
            err.to_string().contains("63 characters"),
            "should reject overlong DNS label: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build an [`EndpointSelectorFilter`] with the given header name and strip flag.
    fn make_filter(header: &str, strip: bool) -> EndpointSelectorFilter {
        EndpointSelectorFilter {
            connection: Arc::new(ConnectionOptions::default()),
            required: false,
            source_header: header.parse().expect("valid header name"),
            status_on_required_failure: 500,
            strip_header: strip,
            tls: None,
        }
    }

    /// Build a required [`EndpointSelectorFilter`] (fail-closed, 503).
    fn make_required_filter(header: &str, strip: bool) -> EndpointSelectorFilter {
        EndpointSelectorFilter {
            connection: Arc::new(ConnectionOptions::default()),
            required: true,
            source_header: header.parse().expect("valid header name"),
            status_on_required_failure: 503,
            strip_header: strip,
            tls: None,
        }
    }
}
