// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! IP-based access control filter (allow/deny by address or CIDR range).

use std::net::IpAddr;

use async_trait::async_trait;
use praxis_core::connectivity::CidrRange;
use serde::Deserialize;

use crate::{
    FilterAction, FilterError, Rejection,
    builtins::http::net::normalize_mapped_ipv4,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// Deserialized YAML config for the IP ACL filter.
struct IpAclConfig {
    /// IPs/CIDRs to allow. If non-empty, only these are permitted.
    #[serde(default)]
    allow: Vec<String>,

    /// IPs/CIDRs to deny.
    #[serde(default)]
    deny: Vec<String>,
}

// -----------------------------------------------------------------------------
// IpAclFilter
// -----------------------------------------------------------------------------

/// IP-based access control filter.
///
/// When `allow` is configured, only matching clients are permitted.
/// When `deny` is configured, matching clients are rejected.
/// When both are set, `allow` takes precedence: a client matching
/// an allow entry is never denied.
///
/// # YAML configuration
///
/// ```yaml
/// filter: ip_acl
/// allow:
///   - "10.0.0.0/8"
///   - "192.168.0.0/16"
/// deny:
///   - "0.0.0.0/0"
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::IpAclFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// allow: ["10.0.0.0/8"]
/// deny: ["0.0.0.0/0"]
/// "#,
/// )
/// .unwrap();
/// let filter = IpAclFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "ip_acl");
/// ```
pub struct IpAclFilter {
    /// Parsed allow-list CIDR ranges.
    allow: Vec<CidrRange>,

    /// Parsed deny-list CIDR ranges.
    deny: Vec<CidrRange>,
}

impl IpAclFilter {
    /// Create an IP ACL filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if a CIDR range is invalid or both lists are empty.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: IpAclConfig = parse_filter_config("ip_acl", config)?;

        let allow = cfg
            .allow
            .iter()
            .map(|s| CidrRange::parse(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| -> FilterError { format!("ip_acl: {e}").into() })?;

        let deny = cfg
            .deny
            .iter()
            .map(|s| CidrRange::parse(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| -> FilterError { format!("ip_acl: {e}").into() })?;

        Ok(Box::new(Self { allow, deny }))
    }

    /// Check `ip` against allow/deny lists. Allow takes precedence.
    fn is_allowed(&self, ip: &IpAddr) -> bool {
        if !self.allow.is_empty() {
            if self.allow.iter().any(|r| r.contains(ip)) {
                return true;
            }
            return false;
        }

        if self.deny.iter().any(|r| r.contains(ip)) {
            return false;
        }

        true
    }
}

#[async_trait]
impl HttpFilter for IpAclFilter {
    fn name(&self) -> &'static str {
        "ip_acl"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(raw_ip) = ctx.client_addr else {
            tracing::info!("denying request: client address unavailable");
            return Ok(FilterAction::Reject(Rejection::status(403)));
        };

        let ip = normalize_mapped_ipv4(raw_ip);
        if self.is_allowed(&ip) {
            Ok(FilterAction::Continue)
        } else {
            Ok(FilterAction::Reject(Rejection::status(403)))
        }
    }
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
    fn allow_only_permits_matching() {
        let f = make_filter(&["10.0.0.0/8"], &[]);
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(f.is_allowed(&ip), "IP in allow range should be permitted");
    }

    #[test]
    fn allow_only_rejects_non_matching() {
        let f = make_filter(&["10.0.0.0/8"], &[]);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!f.is_allowed(&ip), "IP outside allow range should be rejected");
    }

    #[test]
    fn deny_only_blocks_matching() {
        let f = make_filter(&[], &["192.168.0.0/16"]);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!f.is_allowed(&ip), "IP in deny range should be blocked");
    }

    #[test]
    fn deny_only_permits_non_matching() {
        let f = make_filter(&[], &["192.168.0.0/16"]);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(f.is_allowed(&ip), "IP outside deny range should be permitted");
    }

    #[test]
    fn allow_overrides_deny() {
        let f = make_filter(&["10.0.0.0/8"], &["0.0.0.0/0"]);
        let allowed: IpAddr = "10.1.2.3".parse().unwrap();
        let denied: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(f.is_allowed(&allowed), "allow list should take precedence over deny");
        assert!(!f.is_allowed(&denied), "IP not in allow list should be denied");
    }

    #[test]
    fn empty_lists_allow_all() {
        let f = make_filter(&[], &[]);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(f.is_allowed(&ip), "empty lists should allow all IPs");
    }

    #[test]
    fn from_config_parses() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
allow: ["10.0.0.0/8"]
deny: ["0.0.0.0/0"]
"#,
        )
        .unwrap();
        let filter = IpAclFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "ip_acl", "filter name should be ip_acl");
    }

    #[tokio::test]
    async fn no_client_addr_rejects() {
        let f = make_filter(&["10.0.0.0/8"], &[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 403),
            "missing client addr should reject with 403"
        );
    }

    #[tokio::test]
    async fn allowed_client_continues() {
        let f = make_filter(&["10.0.0.0/8"], &[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.1.2.3".parse().unwrap());
        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "allowed client should continue"
        );
    }

    #[tokio::test]
    async fn ipv4_mapped_ipv6_normalized_for_allow() {
        let f = make_filter(&["10.0.0.0/8"], &[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("::ffff:10.1.2.3".parse().unwrap());
        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "IPv4-mapped IPv6 matching allow range should continue"
        );
    }

    #[tokio::test]
    async fn ipv4_mapped_ipv6_normalized_for_deny() {
        let f = make_filter(&[], &["192.168.0.0/16"]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("::ffff:192.168.1.1".parse().unwrap());
        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 403),
            "IPv4-mapped IPv6 matching deny range should be rejected"
        );
    }

    #[tokio::test]
    async fn denied_client_rejected() {
        let f = make_filter(&["10.0.0.0/8"], &[]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("192.168.1.1".parse().unwrap());
        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 403),
            "denied client should be rejected with 403"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build an [`IpAclFilter`] with the given allow and deny lists.
    fn make_filter(allow: &[&str], deny: &[&str]) -> IpAclFilter {
        IpAclFilter {
            allow: allow.iter().map(|s| CidrRange::parse(s).unwrap()).collect(),
            deny: deny.iter().map(|s| CidrRange::parse(s).unwrap()).collect(),
        }
    }
}
