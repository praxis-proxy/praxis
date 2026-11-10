// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! SNI-based TCP routing filter.
//!
//! Routes TLS connections to upstream addresses based on the
//! Server Name Indication (SNI) hostname extracted from the
//! `ClientHello`. Supports exact matches and wildcard patterns
//! (e.g. `*.example.com`).
//!
//! # YAML configuration
//!
//! ```yaml
//! filter: sni_router
//! routes:
//!   - server_names: ["api.example.com"]
//!     upstream: "10.0.0.1:443"
//!   - server_names: ["*.example.com"]
//!     upstream: "10.0.0.2:443"
//! default_upstream: "10.0.0.3:443"
//! ```

use std::borrow::Cow;

use async_trait::async_trait;
use praxis_tls::{SniMatcher, SniMatcherError, SniNameError, WildcardMatch};
use serde::Deserialize;
use tracing::{debug, trace};

use crate::{
    Rejection,
    actions::FilterAction,
    factory::parse_filter_config,
    filter::FilterError,
    tcp_filter::{TcpFilter, TcpFilterContext},
};

// -----------------------------------------------------------------------------
// SniRouterFilter
// -----------------------------------------------------------------------------

/// Routes TCP connections by SNI hostname.
///
/// Performs exact-match lookup first, then longest-suffix
/// wildcard match. Case-insensitive per [RFC 4343].
///
/// Connections without SNI or with no matching route use
/// `default_upstream` if configured, otherwise receive a
/// TLS alert rejection.
///
/// Bare wildcards (`*`), IP addresses as server names, and
/// duplicate server names across routes are rejected at
/// config validation.
///
/// [RFC 4343]: https://datatracker.ietf.org/doc/html/rfc4343
///
/// # Example
///
/// ```ignore
/// use praxis_filter::builtins::SniRouterFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// routes:
///   - server_names: ["api.example.com"]
///     upstream: "10.0.0.1:443"
/// default_upstream: "10.0.0.3:443"
/// "#,
/// )
/// .unwrap();
/// let filter = SniRouterFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "sni_router");
/// ```
pub struct SniRouterFilter {
    /// Fallback upstream when no route matches.
    default_upstream: Option<String>,

    /// SNI-to-upstream matcher, using suffix wildcard semantics.
    matcher: SniMatcher<String>,
}

impl SniRouterFilter {
    /// Create from YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid or
    /// contains duplicate server names, bare wildcards, or IP
    /// literals.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError> {
        let cfg: SniRouterConfig = parse_filter_config("sni_router", config)?;
        build_filter(cfg)
    }

    /// Resolve a hostname to an upstream address.
    ///
    /// Delegates exact and suffix wildcard matching to the shared
    /// [`SniMatcher`]; falls back to `default_upstream` when no route matches.
    fn resolve(&self, hostname: &str) -> Option<&str> {
        self.matcher
            .lookup(hostname)
            .map(String::as_str)
            .or(self.default_upstream.as_deref())
    }
}

#[async_trait]
impl TcpFilter for SniRouterFilter {
    fn name(&self) -> &'static str {
        "sni_router"
    }

    async fn on_connect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(sni) = ctx.sni else {
            debug!(remote = %ctx.remote_addr, "no SNI in ClientHello, trying default upstream");
            return if let Some(upstream) = &self.default_upstream {
                trace!(upstream = %upstream, "using default upstream (no SNI)");
                ctx.upstream_addr = Some(Cow::Owned(upstream.clone()));
                Ok(FilterAction::Continue)
            } else {
                debug!(remote = %ctx.remote_addr, "no SNI and no default upstream, rejecting");
                Ok(FilterAction::Reject(Rejection::status(421)))
            };
        };

        if let Some(upstream) = self.resolve(sni) {
            trace!(sni = %sni, upstream = %upstream, "SNI route matched");
            ctx.upstream_addr = Some(Cow::Owned(upstream.to_owned()));
            Ok(FilterAction::Continue)
        } else {
            debug!(sni = %sni, "no SNI route matched and no default, rejecting");
            Ok(FilterAction::Reject(Rejection::status(421)))
        }
    }
}

// -----------------------------------------------------------------------------
// Config Types
// -----------------------------------------------------------------------------

/// YAML configuration for the SNI router filter.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SniRouterConfig {
    /// Fallback upstream when no route matches.
    #[serde(default)]
    default_upstream: Option<String>,

    /// Route entries mapping server names to upstreams.
    routes: Vec<SniRouteEntry>,
}

/// A single SNI route entry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SniRouteEntry {
    /// Server name patterns (exact or wildcard like `*.example.com`).
    server_names: Vec<String>,

    /// Upstream address for matching connections.
    upstream: String,
}

// -----------------------------------------------------------------------------
// Filter Construction
// -----------------------------------------------------------------------------

/// Build the filter from validated config.
///
/// Flattens every `(server_name, upstream)` pair into a suffix-matching
/// [`SniMatcher`], which validates patterns and rejects duplicates. Routing
/// uses [`WildcardMatch::Suffix`], so `*.example.com` matches multiple label
/// depths and `*.com` is permitted.
fn build_filter(cfg: SniRouterConfig) -> Result<Box<dyn TcpFilter>, FilterError> {
    if cfg.routes.is_empty() && cfg.default_upstream.is_none() {
        return Err("sni_router: at least one route or a default_upstream is required".into());
    }

    let mut entries: Vec<(String, String)> = Vec::new();
    for entry in &cfg.routes {
        if entry.server_names.is_empty() {
            return Err("sni_router: route entry has empty server_names list".into());
        }
        for name in &entry.server_names {
            entries.push((name.clone(), entry.upstream.clone()));
        }
    }

    let matcher = SniMatcher::build(entries, WildcardMatch::Suffix).map_err(map_build_error)?;

    Ok(Box::new(SniRouterFilter {
        default_upstream: cfg.default_upstream,
        matcher,
    }))
}

/// Translate a matcher build failure into an `sni_router`-prefixed error,
/// preserving the filter's original messages for bare wildcards and duplicates.
fn map_build_error(err: SniMatcherError) -> FilterError {
    match err {
        SniMatcherError::DuplicatePattern { pattern } => {
            let lower = pattern.to_ascii_lowercase();
            if let Some(suffix) = lower.strip_prefix('*') {
                format!("sni_router: duplicate wildcard pattern '*{suffix}'").into()
            } else {
                format!("sni_router: duplicate server name '{lower}'").into()
            }
        },
        SniMatcherError::InvalidPattern { pattern, source } => match source {
            SniNameError::BareWildcard => {
                "sni_router: bare wildcard '*' is not allowed; use default_upstream instead".into()
            },
            _ => format!("sni_router: server name '{pattern}' {source}").into(),
        },
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
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::redundant_closure_for_method_calls,
    clippy::stable_sort_primitive,
    reason = "tests"
)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[tokio::test]
    async fn exact_match_routes() {
        let filter = make_filter(&[("api.example.com", "10.0.0.1:443")], &[], None);
        let mut ctx = make_ctx(Some("api.example.com"));

        let action = filter.on_connect(&mut ctx).await.expect("on_connect should succeed");
        assert!(matches!(action, FilterAction::Continue), "exact match should continue");
        assert_eq!(
            ctx.upstream_addr.as_deref(),
            Some("10.0.0.1:443"),
            "upstream should be set"
        );
    }

    #[tokio::test]
    async fn wildcard_match_routes() {
        let filter = make_filter(&[], &[("*.example.com", "10.0.0.2:443")], None);
        let mut ctx = make_ctx(Some("www.example.com"));

        let action = filter.on_connect(&mut ctx).await.expect("on_connect should succeed");
        assert!(matches!(action, FilterAction::Continue), "wildcard should match");
        assert_eq!(
            ctx.upstream_addr.as_deref(),
            Some("10.0.0.2:443"),
            "upstream should be set by wildcard"
        );
    }

    #[tokio::test]
    async fn exact_takes_precedence_over_wildcard() {
        let filter = make_filter(
            &[("api.example.com", "10.0.0.1:443")],
            &[("*.example.com", "10.0.0.2:443")],
            None,
        );
        let mut ctx = make_ctx(Some("api.example.com"));

        drop(filter.on_connect(&mut ctx).await.expect("on_connect should succeed"));
        assert_eq!(
            ctx.upstream_addr.as_deref(),
            Some("10.0.0.1:443"),
            "exact match should take precedence"
        );
    }

    #[tokio::test]
    async fn longest_wildcard_wins() {
        let filter = make_filter(
            &[],
            &[("*.example.com", "10.0.0.1:443"), ("*.sub.example.com", "10.0.0.2:443")],
            None,
        );
        let mut ctx = make_ctx(Some("app.sub.example.com"));

        drop(filter.on_connect(&mut ctx).await.expect("on_connect should succeed"));
        assert_eq!(
            ctx.upstream_addr.as_deref(),
            Some("10.0.0.2:443"),
            "longest wildcard suffix should win"
        );
    }

    #[tokio::test]
    async fn default_upstream_used_on_no_match() {
        let filter = make_filter(&[("api.example.com", "10.0.0.1:443")], &[], Some("10.0.0.9:443"));
        let mut ctx = make_ctx(Some("unknown.example.com"));

        let action = filter.on_connect(&mut ctx).await.expect("on_connect should succeed");
        assert!(matches!(action, FilterAction::Continue), "default should continue");
        assert_eq!(
            ctx.upstream_addr.as_deref(),
            Some("10.0.0.9:443"),
            "default upstream should be used"
        );
    }

    #[tokio::test]
    async fn no_match_no_default_rejects() {
        let filter = make_filter(&[("api.example.com", "10.0.0.1:443")], &[], None);
        let mut ctx = make_ctx(Some("unknown.example.com"));

        let action = filter.on_connect(&mut ctx).await.expect("on_connect should succeed");
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 421),
            "no match without default should reject with 421"
        );
    }

    #[tokio::test]
    async fn no_sni_with_default() {
        let filter = make_filter(&[], &[], Some("10.0.0.9:443"));
        let mut ctx = make_ctx(None);

        let action = filter.on_connect(&mut ctx).await.expect("on_connect should succeed");
        assert!(
            matches!(action, FilterAction::Continue),
            "no SNI with default should continue"
        );
        assert_eq!(
            ctx.upstream_addr.as_deref(),
            Some("10.0.0.9:443"),
            "default upstream used when no SNI"
        );
    }

    #[tokio::test]
    async fn no_sni_no_default_rejects() {
        let filter = make_filter(&[("api.example.com", "10.0.0.1:443")], &[], None);
        let mut ctx = make_ctx(None);

        let action = filter.on_connect(&mut ctx).await.expect("on_connect should succeed");
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 421),
            "no SNI without default should reject with 421"
        );
    }

    #[tokio::test]
    async fn case_insensitive_matching() {
        let filter = make_filter(&[("API.Example.COM", "10.0.0.1:443")], &[], None);
        let mut ctx = make_ctx(Some("api.example.com"));

        drop(filter.on_connect(&mut ctx).await.expect("on_connect should succeed"));
        assert_eq!(
            ctx.upstream_addr.as_deref(),
            Some("10.0.0.1:443"),
            "matching should be case-insensitive"
        );
    }

    #[tokio::test]
    async fn case_insensitive_sni_input() {
        let filter = make_filter(&[("api.example.com", "10.0.0.1:443")], &[], None);
        let mut ctx = make_ctx(Some("API.EXAMPLE.COM"));

        drop(filter.on_connect(&mut ctx).await.expect("on_connect should succeed"));
        assert_eq!(
            ctx.upstream_addr.as_deref(),
            Some("10.0.0.1:443"),
            "SNI input should be lowercased for comparison"
        );
    }

    #[tokio::test]
    async fn unicode_lookalike_sni_does_not_match_ascii_route() {
        // U+212A KELVIN SIGN folds to ASCII 'k' under Unicode lowercasing but is
        // left untouched by ASCII folding. SNI case-insensitivity is ASCII-only
        // (RFC 4343), so a Kelvin-sign SNI must NOT match a route configured for
        // 'k'. Unicode lowercasing (the pre-fix behavior) would spuriously match.
        let filter = make_filter(&[("k.example.com", "10.0.0.1:443")], &[], None);
        let mut ctx = make_ctx(Some("\u{212A}.example.com"));

        let action = filter.on_connect(&mut ctx).await.expect("on_connect should succeed");
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 421),
            "a Unicode-lookalike SNI must not spuriously match an ASCII route"
        );
        assert_eq!(
            ctx.upstream_addr.as_deref(),
            None,
            "no upstream should be selected for a non-matching Unicode-lookalike SNI"
        );
    }

    #[test]
    fn reject_bare_wildcard() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
routes:
  - server_names: ["*"]
    upstream: "10.0.0.1:443"
"#,
        )
        .expect("valid YAML");
        let err = expect_config_error(&yaml);
        assert!(
            err.to_string().contains("wildcard"),
            "bare wildcard should be rejected: {err}"
        );
    }

    #[test]
    fn reject_invalid_wildcard_pattern() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
routes:
  - server_names: ["*example.com"]
    upstream: "10.0.0.1:443"
"#,
        )
        .expect("valid YAML");
        let err = expect_config_error(&yaml);
        assert!(
            err.to_string().contains("wildcard"),
            "invalid wildcard should be rejected: {err}"
        );
    }

    #[test]
    fn reject_ip_address_server_name() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
routes:
  - server_names: ["192.168.1.1"]
    upstream: "10.0.0.1:443"
"#,
        )
        .expect("valid YAML");
        let err = expect_config_error(&yaml);
        assert!(
            err.to_string().contains("IP address"),
            "IP address should be rejected: {err}"
        );
    }

    #[test]
    fn reject_duplicate_server_names() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
routes:
  - server_names: ["api.example.com"]
    upstream: "10.0.0.1:443"
  - server_names: ["api.example.com"]
    upstream: "10.0.0.2:443"
"#,
        )
        .expect("valid YAML");
        let err = expect_config_error(&yaml);
        assert!(
            err.to_string().contains("duplicate server name"),
            "duplicate names should be rejected: {err}"
        );
    }

    #[test]
    fn from_config_valid() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
routes:
  - server_names: ["api.example.com"]
    upstream: "10.0.0.1:443"
  - server_names: ["*.example.com"]
    upstream: "10.0.0.2:443"
default_upstream: "10.0.0.3:443"
"#,
        )
        .expect("valid YAML");
        let filter = SniRouterFilter::from_config(&yaml).expect("valid config should succeed");
        assert_eq!(filter.name(), "sni_router");
    }

    #[tokio::test]
    async fn wildcard_does_not_match_exact_suffix() {
        let filter = make_filter(&[], &[("*.example.com", "10.0.0.1:443")], None);
        let mut ctx = make_ctx(Some("example.com"));

        let action = filter.on_connect(&mut ctx).await.expect("on_connect should succeed");
        assert!(
            matches!(action, FilterAction::Reject(_)),
            "wildcard should not match the bare suffix 'example.com'"
        );
    }

    #[test]
    fn reject_duplicate_wildcard_patterns() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
routes:
  - server_names: ["*.example.com"]
    upstream: "10.0.0.1:443"
  - server_names: ["*.example.com"]
    upstream: "10.0.0.2:443"
"#,
        )
        .expect("valid YAML");
        let err = expect_config_error(&yaml);
        assert!(
            err.to_string().contains("duplicate wildcard"),
            "duplicate wildcard patterns should be rejected: {err}"
        );
    }

    #[test]
    fn reject_empty_server_names() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
routes:
  - server_names: []
    upstream: "10.0.0.1:443"
"#,
        )
        .expect("valid YAML");
        let err = expect_config_error(&yaml);
        assert!(
            err.to_string().contains("empty server_names"),
            "empty server_names should be rejected: {err}"
        );
    }

    #[test]
    fn reject_leading_hyphen_in_label() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
routes:
  - server_names: ["-example.com"]
    upstream: "10.0.0.1:443"
"#,
        )
        .expect("valid YAML");
        let err = expect_config_error(&yaml);
        assert!(
            err.to_string().contains("hyphen"),
            "leading hyphen should be rejected: {err}"
        );
    }

    #[test]
    fn reject_invalid_characters_in_label() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
routes:
  - server_names: ["invalid_host.com"]
    upstream: "10.0.0.1:443"
"#,
        )
        .expect("valid YAML");
        let err = expect_config_error(&yaml);
        assert!(
            err.to_string().contains("invalid characters"),
            "underscore should be rejected: {err}"
        );
    }

    #[test]
    fn reject_overlong_label() {
        let long = "a".repeat(64);
        let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
            r#"
routes:
  - server_names: ["{long}.example.com"]
    upstream: "10.0.0.1:443"
"#,
        ))
        .expect("valid YAML");
        let err = expect_config_error(&yaml);
        assert!(
            err.to_string().contains("exceeds 63 characters"),
            "label >63 chars should be rejected: {err}"
        );
    }

    #[test]
    fn reject_empty_routes_no_default() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
routes: []
"#,
        )
        .expect("valid YAML");
        let err = expect_config_error(&yaml);
        assert!(
            err.to_string().contains("at least one route"),
            "empty routes without default should be rejected: {err}"
        );
    }

    #[test]
    fn accept_empty_routes_with_default() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
routes: []
default_upstream: "10.0.0.1:443"
"#,
        )
        .expect("valid YAML");
        let filter = SniRouterFilter::from_config(&yaml).expect("empty routes with default should succeed");
        assert_eq!(filter.name(), "sni_router");
    }

    #[tokio::test]
    async fn trailing_dot_in_sni_matches() {
        let filter = make_filter(&[("api.example.com", "10.0.0.1:443")], &[], None);
        let mut ctx = make_ctx(Some("api.example.com."));

        let action = filter.on_connect(&mut ctx).await.expect("on_connect should succeed");
        assert!(
            matches!(action, FilterAction::Continue),
            "trailing dot in SNI should still match after trim"
        );
        assert_eq!(
            ctx.upstream_addr.as_deref(),
            Some("10.0.0.1:443"),
            "upstream should resolve despite trailing dot in SNI"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Call `from_config` and assert it returns an error.
    fn expect_config_error(yaml: &serde_yaml::Value) -> FilterError {
        match SniRouterFilter::from_config(yaml) {
            Err(e) => e,
            Ok(_) => panic!("expected config error but got Ok"),
        }
    }

    /// Build an [`SniRouterFilter`] from exact entries, wildcard entries, and optional default.
    ///
    /// Goes through the real suffix-matching [`SniMatcher`], so tests exercise
    /// the same build path as production (including policy wiring).
    fn make_filter(
        exact_entries: &[(&str, &str)],
        wildcard_entries: &[(&str, &str)],
        default: Option<&str>,
    ) -> SniRouterFilter {
        let entries: Vec<(String, String)> = exact_entries
            .iter()
            .chain(wildcard_entries)
            .map(|(pattern, upstream)| ((*pattern).to_owned(), (*upstream).to_owned()))
            .collect();
        let matcher = SniMatcher::build(entries, WildcardMatch::Suffix).expect("test routes should build");

        SniRouterFilter {
            default_upstream: default.map(|s| s.to_owned()),
            matcher,
        }
    }

    /// Build a [`TcpFilterContext`] with the given SNI.
    fn make_ctx(sni: Option<&str>) -> TcpFilterContext<'_> {
        TcpFilterContext {
            remote_addr: "127.0.0.1:12345",
            local_addr: "0.0.0.0:443",
            sni,
            upstream_addr: None,
            cluster: None,
            health_registry: None,
            kv_stores: None,
            connect_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        }
    }
}
