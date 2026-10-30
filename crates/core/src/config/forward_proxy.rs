// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Forward-proxy (HTTP CONNECT) configuration for HTTP listeners.
//!
//! A listener with a [`ForwardProxyConfig`] block accepts `CONNECT host:port`
//! requests and tunnels bytes to the destination after the filter pipeline
//! and the destination rules approve it. This turns Praxis into an egress
//! gateway for clients configured with `HTTP_PROXY`/`HTTPS_PROXY`.
//!
//! The tunnel is opaque: TLS inside it is end-to-end between client and
//! destination, so payload-inspecting filters (`guardrails`,
//! `credential_injection`) cannot see tunneled traffic. Egress control is
//! L4 — destination host/port, client identity, timing.
//!
//! Destinations are matched with [`SniMatcher`] semantics: exact hostnames
//! win over wildcards, `*.example.com` matches any number of leading labels
//! (longest suffix first), and matching is case-insensitive. IP-literal
//! destinations cannot be allowlisted (host patterns must be DNS names);
//! they are denied whenever a destination rule list is configured. Private
//! destination IPs are denied at connect time unless
//! `insecure_options.allow_private_upstreams` is set.

use std::collections::BTreeMap;

use praxis_tls::{SniMatcher, WildcardMatch};
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::errors::ProxyError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default tunnel idle timeout (5 minutes).
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 300_000; // 5 minutes

/// Maximum tunnel idle timeout (1 hour), matching listener timeout bounds.
const MAX_IDLE_TIMEOUT_MS: u64 = 3_600_000; // 1 hour

/// Maximum total tunnel duration (24 hours), matching TCP session bounds.
const MAX_DURATION_SECS: u64 = 86_400; // 24 hours

// -----------------------------------------------------------------------------
// DestinationRule
// -----------------------------------------------------------------------------

/// One `allow_destinations` entry: a host pattern plus an optional port.
///
/// ```
/// use praxis_core::config::DestinationRule;
///
/// let rule: DestinationRule = serde_yaml::from_str("host: api.example.com\nport: 443\n").unwrap();
/// assert_eq!(rule.host, "api.example.com");
/// assert_eq!(rule.port, Some(443));
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationRule {
    /// Destination host pattern.
    ///
    /// A DNS name or a `*.`-prefixed wildcard; IP literals are rejected
    /// (they cannot be expressed as patterns and are always denied when
    /// any destination rule list is configured).
    pub host: String,

    /// Destination port this rule covers.
    ///
    /// `None` (the default) matches any port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

// -----------------------------------------------------------------------------
// ForwardProxyConfig
// -----------------------------------------------------------------------------

/// Forward-proxy settings for an `protocol: http` listener.
///
/// Deserialization validates timeout bounds, ports, and destination host
/// patterns, so a malformed block fails at config load rather than at the
/// first CONNECT request.
///
/// ```
/// use praxis_core::config::ForwardProxyConfig;
///
/// let config: ForwardProxyConfig = serde_yaml::from_str(
///     r#"
/// enabled: true
/// allow_destinations:
///   - host: api.example.com
///     port: 443
///   - host: "*.internal.example.com"
/// "#,
/// )
/// .unwrap();
/// assert!(config.enabled);
/// assert_eq!(
///     config.idle_timeout_ms, 300_000,
///     "idle timeout defaults to 5 minutes"
/// );
/// assert_eq!(config.allow_destinations.len(), 2);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ForwardProxyConfig {
    /// Whether the listener accepts CONNECT requests.
    ///
    /// Defaults to `false`: the block's presence alone is inert until
    /// enabled, so a staged rollout can ship the rest of the settings
    /// first.
    pub enabled: bool,

    /// How long the tunnel may stay idle before it is closed, in
    /// milliseconds.
    ///
    /// Progress in either direction resets the deadline. Defaults to
    /// 300,000 (5 minutes); bounded to 1 hour.
    pub idle_timeout_ms: u64,

    /// Maximum total tunnel duration in seconds, regardless of activity.
    ///
    /// `None` (the default) means no hard cap. Tunnels do not observe
    /// graceful proxy shutdown, so setting a cap is recommended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_secs: Option<u64>,

    /// Destination host/port patterns a CONNECT may target.
    ///
    /// Entries sharing a host (case-insensitively) merge their ports. An
    /// empty list allows every destination and relies on filters
    /// (`ip_acl`, `policy`) for egress control; listener validation
    /// requires one or the other so the listener is never an open relay.
    pub allow_destinations: Vec<DestinationRule>,
}

/// Raw deserialization shape for [`ForwardProxyConfig`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardProxyConfigRaw {
    /// Whether CONNECT is accepted.
    #[serde(default)]
    enabled: bool,

    /// Tunnel idle timeout in milliseconds.
    #[serde(default = "default_idle_timeout_ms")]
    idle_timeout_ms: u64,

    /// Maximum total tunnel duration in seconds.
    #[serde(default)]
    max_duration_secs: Option<u64>,

    /// Destination patterns.
    #[serde(default)]
    allow_destinations: Vec<DestinationRule>,
}

/// Default [`ForwardProxyConfigRaw::idle_timeout_ms`].
const fn default_idle_timeout_ms() -> u64 {
    DEFAULT_IDLE_TIMEOUT_MS
}

impl<'de> Deserialize<'de> for ForwardProxyConfig {
    /// Deserialize and validate forward-proxy settings.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = ForwardProxyConfigRaw::deserialize(deserializer)?;
        let config = Self {
            enabled: raw.enabled,
            idle_timeout_ms: raw.idle_timeout_ms,
            max_duration_secs: raw.max_duration_secs,
            allow_destinations: raw.allow_destinations,
        };
        config.validate().map_err(de::Error::custom)?;
        Ok(config)
    }
}

impl ForwardProxyConfig {
    /// Validate timeout bounds, ports, and destination patterns.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] when a bound is exceeded, a port is
    /// zero, or a destination host pattern is malformed.
    pub fn validate(&self) -> Result<(), ProxyError> {
        if self.idle_timeout_ms == 0 || self.idle_timeout_ms > MAX_IDLE_TIMEOUT_MS {
            return Err(ProxyError::Config(format!(
                "forward_proxy: idle_timeout_ms must be between 1 and {MAX_IDLE_TIMEOUT_MS}"
            )));
        }
        if let Some(secs) = self.max_duration_secs
            && (secs == 0 || secs > MAX_DURATION_SECS)
        {
            return Err(ProxyError::Config(format!(
                "forward_proxy: max_duration_secs must be between 1 and {MAX_DURATION_SECS}"
            )));
        }
        for rule in &self.allow_destinations {
            if rule.port == Some(0) {
                return Err(ProxyError::Config(format!(
                    "forward_proxy: destination '{}' has port 0",
                    rule.host
                )));
            }
        }
        self.destination_matcher()?;
        Ok(())
    }

    /// Build the host-to-ports matcher used at tunnel setup time.
    ///
    /// Entries sharing a host merge their ports; pattern validity and
    /// duplicates are delegated to [`SniMatcher::build`] under
    /// [`WildcardMatch::Suffix`] semantics (same policy as `sni_router`).
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] when a destination host pattern is
    /// malformed for suffix-wildcard matching.
    pub fn destination_matcher(&self) -> Result<SniMatcher<Vec<u16>>, ProxyError> {
        SniMatcher::build(merge_destination_ports(&self.allow_destinations), WildcardMatch::Suffix)
            .map_err(|err| ProxyError::Config(format!("forward_proxy: {err}")))
    }

    /// Whether a CONNECT to `host`:`port` matches the destination rules.
    ///
    /// A host matches when a configured pattern matches it (exact wins over
    /// wildcard) and the pattern's port set is empty (any port) or contains
    /// `port`. With no rules configured every destination matches; egress
    /// control then rests on the listener's filters.
    pub fn destination_allowed(&self, host: &str, port: u16) -> bool {
        if self.allow_destinations.is_empty() {
            return true;
        }
        let Ok(matcher) = self.destination_matcher() else {
            return false;
        };
        matcher
            .lookup(host)
            .is_some_and(|ports| ports.is_empty() || ports.contains(&port))
    }
}

/// Merge destination rules into one host-to-ports map.
///
/// Hosts are lowercased so case variants merge; duplicate ports collapse.
/// A [`BTreeMap`] keeps the resulting entry order deterministic for
/// matcher construction.
fn merge_destination_ports(rules: &[DestinationRule]) -> BTreeMap<String, Vec<u16>> {
    let mut merged: BTreeMap<String, Vec<u16>> = BTreeMap::new();
    for rule in rules {
        let ports = merged.entry(rule.host.to_ascii_lowercase()).or_default();
        if let Some(port) = rule.port
            && !ports.contains(&port)
        {
            ports.push(port);
        }
    }
    merged
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
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config_with_defaults() {
        let config: ForwardProxyConfig = serde_yaml::from_str("enabled: true\n").unwrap();
        assert!(config.enabled, "enabled should parse");
        assert_eq!(
            config.idle_timeout_ms, 300_000,
            "idle timeout should default to 5 minutes"
        );
        assert_eq!(config.max_duration_secs, None, "max duration should default to None");
        assert!(config.allow_destinations.is_empty(), "no destinations by default");
    }

    #[test]
    fn block_defaults_to_disabled() {
        let config: ForwardProxyConfig = serde_yaml::from_str("idle_timeout_ms: 1000\n").unwrap();
        assert!(!config.enabled, "enabled should default to false");
    }

    #[test]
    fn parse_full_config() {
        let config: ForwardProxyConfig = serde_yaml::from_str(
            r#"
enabled: true
idle_timeout_ms: 60000
max_duration_secs: 3600
allow_destinations:
  - host: api.example.com
    port: 443
  - host: "*.internal.example.com"
"#,
        )
        .unwrap();
        assert_eq!(config.idle_timeout_ms, 60_000);
        assert_eq!(config.max_duration_secs, Some(3_600));
        assert_eq!(config.allow_destinations.len(), 2);
    }

    #[test]
    fn reject_unknown_field() {
        let err = serde_yaml::from_str::<ForwardProxyConfig>("enabled: true\nbogus: 1\n").unwrap_err();
        assert!(err.to_string().contains("bogus"), "unknown fields rejected: {err}");
    }

    #[test]
    fn reject_zero_idle_timeout() {
        let err = serde_yaml::from_str::<ForwardProxyConfig>("enabled: true\nidle_timeout_ms: 0\n").unwrap_err();
        assert!(
            err.to_string().contains("idle_timeout_ms"),
            "zero idle timeout rejected: {err}"
        );
    }

    #[test]
    fn reject_idle_timeout_above_maximum() {
        let err = serde_yaml::from_str::<ForwardProxyConfig>("enabled: true\nidle_timeout_ms: 3600001\n").unwrap_err();
        assert!(
            err.to_string().contains("idle_timeout_ms"),
            "over-max idle timeout rejected: {err}"
        );
    }

    #[test]
    fn reject_zero_max_duration() {
        let err = serde_yaml::from_str::<ForwardProxyConfig>("enabled: true\nmax_duration_secs: 0\n").unwrap_err();
        assert!(
            err.to_string().contains("max_duration_secs"),
            "zero max duration rejected: {err}"
        );
    }

    #[test]
    fn reject_max_duration_above_maximum() {
        let err = serde_yaml::from_str::<ForwardProxyConfig>("enabled: true\nmax_duration_secs: 86401\n").unwrap_err();
        assert!(
            err.to_string().contains("max_duration_secs"),
            "over-max duration rejected: {err}"
        );
    }

    #[test]
    fn reject_port_zero_destination() {
        let err = serde_yaml::from_str::<ForwardProxyConfig>(
            "enabled: true\nallow_destinations:\n  - host: api.example.com\n    port: 0\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("port 0"), "port 0 rejected: {err}");
    }

    #[test]
    fn reject_ip_literal_destination_pattern() {
        let err =
            serde_yaml::from_str::<ForwardProxyConfig>("enabled: true\nallow_destinations:\n  - host: 10.0.0.1\n")
                .unwrap_err();
        assert!(
            err.to_string().contains("10.0.0.1"),
            "IP-literal pattern rejected: {err}"
        );
    }

    #[test]
    fn reject_malformed_destination_pattern() {
        let err =
            serde_yaml::from_str::<ForwardProxyConfig>("enabled: true\nallow_destinations:\n  - host: \"bad..name\"\n")
                .unwrap_err();
        assert!(
            err.to_string().contains("bad..name"),
            "malformed pattern rejected: {err}"
        );
    }

    #[test]
    fn merge_same_host_rules_case_insensitively() {
        let config: ForwardProxyConfig = serde_yaml::from_str(
            r#"
enabled: true
allow_destinations:
  - host: api.example.com
    port: 443
  - host: API.example.com
    port: 8443
  - host: api.example.com
    port: 443
"#,
        )
        .unwrap();
        let matcher = config.destination_matcher().unwrap();
        let ports = matcher.lookup("api.example.com").unwrap();
        assert_eq!(
            *ports,
            vec![443, 8443],
            "case variants merge and duplicate ports collapse"
        );
    }

    #[test]
    fn destination_allowed_matches_exact_host_and_port() {
        let config: ForwardProxyConfig = serde_yaml::from_str(
            r#"
enabled: true
allow_destinations:
  - host: api.example.com
    port: 443
"#,
        )
        .unwrap();
        assert!(config.destination_allowed("api.example.com", 443));
        assert!(
            !config.destination_allowed("api.example.com", 8443),
            "other port denied"
        );
        assert!(
            !config.destination_allowed("other.example.com", 443),
            "other host denied"
        );
    }

    #[test]
    fn destination_allowed_portless_rule_matches_any_port() {
        let config: ForwardProxyConfig =
            serde_yaml::from_str("enabled: true\nallow_destinations:\n  - host: api.example.com\n").unwrap();
        assert!(config.destination_allowed("api.example.com", 443));
        assert!(config.destination_allowed("api.example.com", 8443));
    }

    #[test]
    fn destination_allowed_wildcard_matches_subdomains() {
        let config: ForwardProxyConfig =
            serde_yaml::from_str("enabled: true\nallow_destinations:\n  - host: \"*.example.com\"\n").unwrap();
        assert!(config.destination_allowed("api.example.com", 443));
        assert!(
            config.destination_allowed("a.b.example.com", 443),
            "suffix policy matches multi-label"
        );
        assert!(!config.destination_allowed("example.com", 443), "bare apex not covered");
    }

    #[test]
    fn destination_allowed_empty_rules_allow_everything() {
        let config: ForwardProxyConfig = serde_yaml::from_str("enabled: true\n").unwrap();
        assert!(config.destination_allowed("anything.example.com", 443));
    }

    #[test]
    fn destination_allowed_ip_literal_denied_when_rules_exist() {
        let config: ForwardProxyConfig =
            serde_yaml::from_str("enabled: true\nallow_destinations:\n  - host: api.example.com\n").unwrap();
        assert!(
            !config.destination_allowed("127.0.0.1", 443),
            "IP literals never match patterns"
        );
    }

    #[test]
    fn serializes_and_round_trips() {
        let config: ForwardProxyConfig = serde_yaml::from_str(
            "enabled: true\nidle_timeout_ms: 60000\nmax_duration_secs: 3600\nallow_destinations:\n  - host: a.com\n    port: 443\n",
        )
        .unwrap();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: ForwardProxyConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, config, "round trip should be lossless");
    }
}
