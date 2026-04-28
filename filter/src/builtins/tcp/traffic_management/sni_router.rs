// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

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

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

use async_trait::async_trait;
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

    /// Exact hostname to upstream mapping (lowercased keys).
    exact: HashMap<String, String>,

    /// Wildcard suffix patterns sorted by length (longest first).
    wildcards: Vec<WildcardRoute>,
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
    fn resolve(&self, hostname: &str) -> Option<&str> {
        let lower = hostname.to_lowercase();

        if let Some(upstream) = self.exact.get(&lower) {
            return Some(upstream.as_str());
        }

        for wc in &self.wildcards {
            if lower.len() > wc.suffix.len() && lower.ends_with(wc.suffix.as_str()) {
                return Some(wc.upstream.as_str());
            }
        }

        self.default_upstream.as_deref()
    }
}

#[async_trait]
impl TcpFilter for SniRouterFilter {
    fn name(&self) -> &'static str {
        "sni_router"
    }

    async fn on_connect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(sni) = ctx.sni else {
            debug!("no SNI in ClientHello, trying default upstream");
            return if let Some(upstream) = &self.default_upstream {
                trace!(upstream = %upstream, "using default upstream (no SNI)");
                ctx.upstream_addr = Some(Cow::Owned(upstream.clone()));
                Ok(FilterAction::Continue)
            } else {
                debug!("no SNI and no default upstream, rejecting");
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
// WildcardRoute
// -----------------------------------------------------------------------------

/// A wildcard SNI route (e.g. `*.example.com`).
struct WildcardRoute {
    /// The suffix to match against (e.g. `.example.com`), lowercased.
    suffix: String,

    /// Upstream address for matching connections.
    upstream: String,
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
fn build_filter(cfg: SniRouterConfig) -> Result<Box<dyn TcpFilter>, FilterError> {
    if cfg.routes.is_empty() && cfg.default_upstream.is_none() {
        return Err("sni_router: at least one route or a default_upstream is required".into());
    }

    let mut tables = RouteTables::default();
    for entry in &cfg.routes {
        validate_route_entry(entry, &mut tables)?;
    }
    tables.wildcards.sort_by_key(|b| std::cmp::Reverse(b.suffix.len()));

    Ok(Box::new(SniRouterFilter {
        default_upstream: cfg.default_upstream,
        exact: tables.exact,
        wildcards: tables.wildcards,
    }))
}

/// Accumulated routes identified during construction.
#[derive(Default)]
struct RouteTables {
    /// Exact hostname to upstream mapping.
    exact: HashMap<String, String>,

    /// Wildcard suffix patterns.
    wildcards: Vec<WildcardRoute>,

    /// Seen wildcard suffixes for duplicate detection.
    seen_wildcards: HashSet<String>,
}

/// Validate a single route entry and insert into the tables.
fn validate_route_entry(entry: &SniRouteEntry, tables: &mut RouteTables) -> Result<(), FilterError> {
    if entry.server_names.is_empty() {
        return Err("sni_router: route entry has empty server_names list".into());
    }

    for name in &entry.server_names {
        validate_server_name(name)?;

        if let Some(suffix) = name.strip_prefix('*') {
            let lower = suffix.to_lowercase();
            if !tables.seen_wildcards.insert(lower.clone()) {
                return Err(format!("sni_router: duplicate wildcard pattern '*{lower}'").into());
            }
            tables.wildcards.push(WildcardRoute {
                suffix: lower,
                upstream: entry.upstream.clone(),
            });
        } else {
            let lower = name.to_lowercase();
            if tables.exact.contains_key(&lower) {
                return Err(format!("sni_router: duplicate server name '{lower}'").into());
            }
            tables.exact.insert(lower, entry.upstream.clone());
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Validate a server name pattern.
fn validate_server_name(name: &str) -> Result<(), FilterError> {
    if name == "*" {
        return Err("sni_router: bare wildcard '*' is not allowed; use default_upstream instead".into());
    }

    if name.starts_with('*') && !name.starts_with("*.") {
        return Err(format!("sni_router: invalid wildcard pattern '{name}'; wildcards must start with '*.'").into());
    }

    let check = if let Some(suffix) = name.strip_prefix("*.") {
        suffix
    } else {
        name
    };

    if check.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!("sni_router: IP address '{name}' is not allowed as a server name").into());
    }

    if check.is_empty() {
        return Err(format!("sni_router: empty server name in pattern '{name}'").into());
    }

    Ok(())
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
            err.to_string().contains("bare wildcard"),
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
            err.to_string().contains("must start with '*.'"),
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
    fn make_filter(
        exact_entries: &[(&str, &str)],
        wildcard_entries: &[(&str, &str)],
        default: Option<&str>,
    ) -> SniRouterFilter {
        let mut exact = HashMap::new();
        let mut wildcards = Vec::new();

        for (name, upstream) in exact_entries {
            exact.insert(name.to_lowercase(), (*upstream).to_owned());
        }

        for (pattern, upstream) in wildcard_entries {
            let suffix = pattern
                .strip_prefix('*')
                .expect("wildcard should start with *")
                .to_lowercase();
            wildcards.push(WildcardRoute {
                suffix,
                upstream: (*upstream).to_owned(),
            });
        }

        wildcards.sort_by_key(|b| std::cmp::Reverse(b.suffix.len()));

        SniRouterFilter {
            default_upstream: default.map(|s| s.to_owned()),
            exact,
            wildcards,
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
            connect_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        }
    }
}
