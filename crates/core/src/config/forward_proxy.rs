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
//! (longest suffix first), and matching is case-insensitive. Host patterns
//! must be DNS names, so no pattern matches an IP literal. An IP-literal
//! rule instead lists one exact address and port (`host: 127.0.0.1`,
//! `port: 11434`); any other IP literal is denied whenever a destination
//! rule list is configured.
//!
//! Private destination IPs are denied at connect time unless
//! `insecure_options.allow_private_upstreams` is set, except an address a
//! rule lists: the operator chose it, as with a cluster endpoint, so it is
//! gated at config load instead. A listed loopback, link-local, or
//! cloud-metadata address needs `insecure_options.allow_private_endpoints`,
//! and the runtime guard keeps applying to every destination a client
//! chooses, names included.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};

use praxis_tls::{SniMatcher, WildcardMatch};
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{connectivity::normalize_mapped_ipv4, errors::ProxyError};

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

/// One `allow_destinations` entry: a host pattern or IP address, plus an
/// optional port.
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
    /// Destination host pattern or IP address.
    ///
    /// A DNS name, a `*.`-prefixed wildcard, or an IP literal (IPv6
    /// without brackets). An IP literal matches only that address, on the
    /// rule's port; numeric patterns such as `*.0.1` are rejected, so no
    /// wildcard can match an address.
    pub host: String,

    /// Destination port this rule covers.
    ///
    /// `None` (the default) matches any port. An IP-literal rule must set
    /// one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

// -----------------------------------------------------------------------------
// ForwardProxyConfig
// -----------------------------------------------------------------------------

/// Forward-proxy settings for a `protocol: http` listener.
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
    /// Entries sharing a host (case-insensitively) merge their ports; a
    /// portless entry makes that host any-port. An empty list allows
    /// every destination and relies on filters (`ip_acl`, `policy`) for
    /// egress control; listener validation requires one or the other.
    /// That check is structural — it verifies a control is configured,
    /// not that it restricts egress, so what the control actually permits
    /// remains the operator's responsibility.
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
    /// zero, an IP-literal destination has no port, or a destination host
    /// pattern is malformed.
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
        self.allow_destinations.iter().try_for_each(validate_destination_rule)?;
        self.destination_matcher()?;
        Ok(())
    }

    /// Build the host-to-ports matcher used at tunnel setup time.
    ///
    /// Entries sharing a host merge their ports; pattern validity and
    /// duplicates are delegated to [`SniMatcher::build`] under
    /// [`WildcardMatch::Suffix`] semantics (same policy as `sni_router`).
    /// IP-literal rules are left out; [`destination_addresses`] holds them.
    ///
    /// Building allocates and sorts, so hot paths (the per-CONNECT
    /// destination check) must build the matcher once — at service or
    /// runtime construction — and reuse it, not call this per request.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] when a destination host pattern is
    /// malformed for suffix-wildcard matching.
    ///
    /// [`destination_addresses`]: Self::destination_addresses
    pub fn destination_matcher(&self) -> Result<SniMatcher<Vec<u16>>, ProxyError> {
        SniMatcher::build(merge_destination_ports(&self.allow_destinations), WildcardMatch::Suffix)
            .map_err(|err| ProxyError::Config(format!("forward_proxy: {err}")))
    }

    /// The IP-literal destinations the rules list, each with its port.
    ///
    /// An IPv4-mapped IPv6 rule is listed as plain IPv4, the canonical form
    /// destinations are matched in, so either spelling of a rule matches
    /// the same requests. As with [`destination_matcher`], build the set
    /// once and reuse it.
    ///
    /// ```
    /// use praxis_core::config::ForwardProxyConfig;
    ///
    /// let config: ForwardProxyConfig = serde_yaml::from_str(
    ///     "enabled: true\nallow_destinations:\n  - host: 127.0.0.1\n    port: 11434\n",
    /// )
    /// .unwrap();
    /// let addresses = config.destination_addresses();
    /// assert!(addresses.contains(&"127.0.0.1:11434".parse().unwrap()));
    /// assert_eq!(addresses.len(), 1, "one address, on one port");
    /// ```
    ///
    /// [`destination_matcher`]: Self::destination_matcher
    pub fn destination_addresses(&self) -> BTreeSet<SocketAddr> {
        self.allow_destinations
            .iter()
            .filter_map(|rule| {
                Some(SocketAddr::new(
                    normalize_mapped_ipv4(ip_literal(&rule.host)?),
                    rule.port?,
                ))
            })
            .collect()
    }
}

/// The address `host` names, when it is an IP literal.
fn ip_literal(host: &str) -> Option<IpAddr> {
    host.parse().ok()
}

/// Reject a destination rule with port 0, an IP literal without a port, or
/// a host whose last label starts with a digit.
///
/// An IP literal names one address, so it is allowlisted one port at a
/// time, and only by its own rule. The [`SniMatcher`] pattern check only
/// refuses a pattern that parses as an IP address, so `*.0.1` would pass
/// and then suffix-match `10.0.0.1` (or `::ffff:10.0.0.1`). Every IPv4
/// literal, including the `inet_aton` short and hex forms a resolver may
/// accept (`10.1`, `10.0x1`), ends in a label that starts with a digit,
/// while top-level domains are alphabetic (RFC 3696 §2 forbids all-numeric
/// ones; none starts with a digit). Refusing such hosts keeps IP literals
/// out of reach of every pattern.
fn validate_destination_rule(rule: &DestinationRule) -> Result<(), ProxyError> {
    let host = &rule.host;
    if rule.port == Some(0) {
        return Err(ProxyError::Config(format!(
            "forward_proxy: destination '{host}' has port 0"
        )));
    }
    if ip_literal(host).is_some() {
        if rule.port.is_none() {
            return Err(ProxyError::Config(format!(
                "forward_proxy: IP destination '{host}' needs a port; \
                 an address is allowlisted one port at a time"
            )));
        }
        return Ok(());
    }
    let last_label = host.rsplit('.').next().unwrap_or_default();
    if last_label.starts_with(|first: char| first.is_ascii_digit()) {
        return Err(ProxyError::Config(format!(
            "forward_proxy: destination '{host}' ends in a numeric label; \
             host patterns must be DNS names, not IP addresses"
        )));
    }
    Ok(())
}

/// Merge the host-pattern rules into one host-to-ports map.
///
/// IP-literal rules are not patterns and are left out. Hosts are lowercased
/// so case variants merge; duplicate ports collapse. A portless rule grants
/// every port, so a host with both portless and ported rules merges to
/// any-port (an empty port set), regardless of rule order. A [`BTreeMap`]
/// keeps the resulting entry order deterministic for matcher construction.
fn merge_destination_ports(rules: &[DestinationRule]) -> BTreeMap<String, Vec<u16>> {
    // (any-port seen, explicit ports)
    let mut merged: BTreeMap<String, (bool, Vec<u16>)> = BTreeMap::new();
    for rule in rules.iter().filter(|rule| ip_literal(&rule.host).is_none()) {
        let entry = merged.entry(rule.host.to_ascii_lowercase()).or_default();
        match rule.port {
            None => entry.0 = true,
            Some(port) => {
                if !entry.1.contains(&port) {
                    entry.1.push(port);
                }
            },
        }
    }
    merged
        .into_iter()
        .map(|(host, (any_port, ports))| (host, if any_port { Vec::new() } else { ports }))
        .collect()
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

    /// Whether `host`:`port` matches the config's destination rules,
    /// building the matcher once per call the way the runtime does.
    ///
    /// A host matches when a configured pattern matches it (exact wins
    /// over wildcard) and the pattern's port set is empty (any port) or
    /// contains `port`. An IP-literal host matches only a rule listing that
    /// address and port. With no rules configured every destination
    /// matches; egress control then rests on the listener's filters.
    fn destination_allowed(config: &ForwardProxyConfig, host: &str, port: u16) -> bool {
        if config.allow_destinations.is_empty() {
            return true;
        }
        host.parse::<IpAddr>()
            .is_ok_and(|ip| config.destination_addresses().contains(&SocketAddr::new(ip, port)))
            || config
                .destination_matcher()
                .unwrap()
                .lookup(host)
                .is_some_and(|ports| ports.is_empty() || ports.contains(&port))
    }

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
    fn reject_ip_literal_destination_without_port() {
        for host in ["10.0.0.1", "::1"] {
            let yaml = format!("enabled: true\nallow_destinations:\n  - host: \"{host}\"\n");
            let err = serde_yaml::from_str::<ForwardProxyConfig>(&yaml).unwrap_err();
            assert!(
                err.to_string().contains("needs a port"),
                "'{host}' without a port must be rejected: {err}"
            );
        }
    }

    #[test]
    fn reject_bracketed_ipv6_destination() {
        let err = serde_yaml::from_str::<ForwardProxyConfig>(
            "enabled: true\nallow_destinations:\n  - host: \"[::1]\"\n    port: 11434\n",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("[::1]"),
            "an IPv6 rule is written without brackets: {err}"
        );
    }

    #[test]
    fn ip_literal_destination_matches_only_its_address_and_port() {
        let config: ForwardProxyConfig = serde_yaml::from_str(
            r#"
enabled: true
allow_destinations:
  - host: 127.0.0.1
    port: 11434
  - host: "2001:db8::1"
    port: 443
"#,
        )
        .unwrap();
        assert!(destination_allowed(&config, "127.0.0.1", 11434));
        assert!(destination_allowed(&config, "2001:db8::1", 443));
        assert!(
            !destination_allowed(&config, "127.0.0.1", 11435),
            "another port of a listed address is denied"
        );
        assert!(
            !destination_allowed(&config, "127.0.0.2", 11434),
            "an unlisted address is denied"
        );
        assert!(
            !destination_allowed(&config, "localhost", 11434),
            "a name for a listed address is not the address"
        );
    }

    #[test]
    fn ipv4_mapped_rule_is_listed_as_ipv4() {
        let config: ForwardProxyConfig = serde_yaml::from_str(
            "enabled: true\nallow_destinations:\n  - host: \"::ffff:127.0.0.1\"\n    port: 11434\n",
        )
        .unwrap();
        assert_eq!(
            config.destination_addresses().into_iter().collect::<Vec<_>>(),
            vec!["127.0.0.1:11434".parse::<SocketAddr>().unwrap()],
            "destinations are matched in canonical form, so the rule is too"
        );
    }

    #[test]
    fn ip_literal_rules_stay_out_of_the_host_matcher() {
        // SniMatcher refuses IP patterns, so building it with an IP rule in
        // the list must skip that rule rather than fail.
        let config: ForwardProxyConfig = serde_yaml::from_str(
            "enabled: true\nallow_destinations:\n  - host: api.example.com\n  - host: 127.0.0.1\n    port: 11434\n",
        )
        .unwrap();
        let matcher = config.destination_matcher().unwrap();
        assert!(matcher.lookup("api.example.com").is_some());
        assert!(matcher.lookup("127.0.0.1").is_none(), "addresses are not patterns");
        assert_eq!(config.destination_addresses().len(), 1);
    }

    #[test]
    fn reject_numeric_suffix_destination_patterns() {
        // Each would pass the SniMatcher check (the part after `*.` is not
        // itself an IP) and then suffix-match an IPv4 literal.
        for host in ["*.0.1", "*.1", "*.8", "*.0x1", "10.1", "10.0x1"] {
            let yaml = format!("enabled: true\nallow_destinations:\n  - host: \"{host}\"\n");
            let err = serde_yaml::from_str::<ForwardProxyConfig>(&yaml).unwrap_err();
            assert!(
                err.to_string().contains("numeric label"),
                "'{host}' must be rejected: {err}"
            );
        }
    }

    #[test]
    fn digits_outside_last_label_are_accepted() {
        let config: ForwardProxyConfig = serde_yaml::from_str(
            "enabled: true\nallow_destinations:\n  - host: 1password.com\n  - host: \"*.10.example.com\"\n",
        )
        .unwrap();
        assert!(
            destination_allowed(&config, "1password.com", 443),
            "a leading digit in a non-final label is a DNS name"
        );
        assert!(
            destination_allowed(&config, "a.10.example.com", 443),
            "a numeric middle label is a DNS name"
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
    fn portless_rule_subsumes_ported_rule_for_same_host() {
        // {host: a.com, port: 443} + {host: a.com} must mean any port,
        // not [443]: the portless grant cannot be narrowed by a sibling
        // rule, regardless of order.
        let ported_first: ForwardProxyConfig = serde_yaml::from_str(
            "enabled: true\nallow_destinations:\n  - host: a.com\n    port: 443\n  - host: a.com\n",
        )
        .unwrap();
        assert!(destination_allowed(&ported_first, "a.com", 443));
        assert!(
            destination_allowed(&ported_first, "a.com", 8443),
            "a portless rule for the same host grants any port"
        );

        let portless_first: ForwardProxyConfig = serde_yaml::from_str(
            "enabled: true\nallow_destinations:\n  - host: a.com\n  - host: a.com\n    port: 443\n",
        )
        .unwrap();
        assert!(
            destination_allowed(&portless_first, "a.com", 8443),
            "rule order must not change the any-port grant"
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
        assert!(destination_allowed(&config, "api.example.com", 443));
        assert!(
            !destination_allowed(&config, "api.example.com", 8443),
            "other port denied"
        );
        assert!(
            !destination_allowed(&config, "other.example.com", 443),
            "other host denied"
        );
    }

    #[test]
    fn destination_allowed_portless_rule_matches_any_port() {
        let config: ForwardProxyConfig =
            serde_yaml::from_str("enabled: true\nallow_destinations:\n  - host: api.example.com\n").unwrap();
        assert!(destination_allowed(&config, "api.example.com", 443));
        assert!(destination_allowed(&config, "api.example.com", 8443));
    }

    #[test]
    fn destination_allowed_wildcard_matches_subdomains() {
        let config: ForwardProxyConfig =
            serde_yaml::from_str("enabled: true\nallow_destinations:\n  - host: \"*.example.com\"\n").unwrap();
        assert!(destination_allowed(&config, "api.example.com", 443));
        assert!(
            destination_allowed(&config, "a.b.example.com", 443),
            "suffix policy matches multi-label"
        );
        assert!(
            !destination_allowed(&config, "example.com", 443),
            "bare apex not covered"
        );
    }

    #[test]
    fn destination_allowed_empty_rules_allow_everything() {
        let config: ForwardProxyConfig = serde_yaml::from_str("enabled: true\n").unwrap();
        assert!(destination_allowed(&config, "anything.example.com", 443));
    }

    #[test]
    fn destination_allowed_ip_literal_denied_when_rules_exist() {
        let config: ForwardProxyConfig =
            serde_yaml::from_str("enabled: true\nallow_destinations:\n  - host: api.example.com\n").unwrap();
        assert!(
            !destination_allowed(&config, "127.0.0.1", 443),
            "IP literals never match patterns"
        );
    }

    #[test]
    fn serializes_and_round_trips() {
        let config: ForwardProxyConfig = serde_yaml::from_str(
            "enabled: true\nidle_timeout_ms: 60000\nmax_duration_secs: 3600\nallow_destinations:\n  - host: a.com\n    port: 443\n  - host: \"::1\"\n    port: 11434\n",
        )
        .unwrap();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: ForwardProxyConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, config, "round trip should be lossless");
    }
}
