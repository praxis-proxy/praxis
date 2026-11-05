// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Forward-proxy listener validation: the egress-control requirement.
//!
//! An enabled `forward_proxy` listener that accepts CONNECT to anywhere,
//! gated by nothing, is an open relay. Validation therefore requires at
//! least one egress control: a non-empty `allow_destinations` list, or an
//! `ip_acl`/`policy` filter in the listener's chains that runs for every
//! request (no `conditions` on the filter or its chain).
//!
//! The check is structural: it verifies that a control is *configured*,
//! not that it restricts egress — an `ip_acl` that allows every source or
//! a `policy` that permits every request still passes. What the configured
//! control actually permits is the operator's responsibility.

use crate::{
    config::{Config, Listener},
    errors::ProxyError,
};

/// Filter types that count as egress control on a forward-proxy listener.
///
/// `ip_acl` gates by client source; `policy` makes per-request decisions.
/// Both run in the request phase on the CONNECT request before any tunnel
/// byte is forwarded.
const EGRESS_CONTROL_FILTERS: [&str; 2] = ["ip_acl", "policy"];

/// Validate the egress-control requirement for enabled forward-proxy
/// listeners.
///
/// Inert (`enabled: false`) blocks are exempt: they accept no CONNECT
/// requests, so there is nothing to gate. Filters nested inside branch
/// chains do not count — the main pipeline path is what runs for a CONNECT
/// request — and neither do filters gated by request `conditions`, on the
/// filter or its chain, which may not run for CONNECT.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] when an enabled forward-proxy listener
/// has neither `allow_destinations` nor an `ip_acl`/`policy` filter in its
/// chains.
pub(in crate::config::validate) fn validate_forward_proxy_listeners(config: &Config) -> Result<(), ProxyError> {
    for listener in &config.listeners {
        if !listener
            .forward_proxy
            .as_ref()
            .is_some_and(|forward_proxy| forward_proxy.enabled)
        {
            continue;
        }
        if !egress_controlled(config, listener) {
            return Err(ProxyError::Config(format!(
                "listener '{}': forward_proxy requires 'allow_destinations' or an ip_acl/policy \
                 filter without conditions in its filter chains, otherwise it is an open relay",
                listener.name
            )));
        }
    }
    Ok(())
}

/// Whether the listener has at least one egress control configured.
fn egress_controlled(config: &Config, listener: &Listener) -> bool {
    let has_destinations = listener
        .forward_proxy
        .as_ref()
        .is_some_and(|forward_proxy| !forward_proxy.allow_destinations.is_empty());
    has_destinations || chains_have_egress_control_filter(config, listener)
}

/// Whether any chain the listener references contains an egress-control
/// filter in its main pipeline path that runs for every request.
///
/// A chain or filter with request `conditions` can skip the CONNECT request
/// (for example `methods: [GET]`), so it does not count. The pipeline build
/// also rejects conditional security filters, but that check can be opted
/// out of (`skip_pipeline_checks.conditional_security`); this rule must hold
/// on its own.
fn chains_have_egress_control_filter(config: &Config, listener: &Listener) -> bool {
    listener.filter_chains.iter().any(|chain_name| {
        config
            .filter_chains
            .iter()
            .find(|chain| chain.name == *chain_name && chain.conditions.is_empty())
            .is_some_and(|chain| {
                chain.filters.iter().any(|filter| {
                    filter.conditions.is_empty() && EGRESS_CONTROL_FILTERS.contains(&filter.filter_type.as_str())
                })
            })
    })
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
    use crate::config::Config;

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn enabled_forward_proxy_without_egress_control_is_rejected() {
        let yaml = r#"
listeners:
  - name: egress
    address: "127.0.0.1:32123"
    forward_proxy:
      enabled: true
    filter_chains: [egress]
filter_chains:
  - name: egress
    filters:
      - filter: access_log
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("open relay"),
            "error should mention the open-relay risk: {err}"
        );
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn enabled_forward_proxy_with_allow_destinations_is_accepted() {
        let yaml = r#"
listeners:
  - name: egress
    address: "127.0.0.1:32123"
    forward_proxy:
      enabled: true
      allow_destinations:
        - host: api.example.com
          port: 443
    filter_chains: [egress]
filter_chains:
  - name: egress
    filters:
      - filter: access_log
"#;
        Config::from_yaml(yaml).expect("allow_destinations satisfies the egress-control requirement");
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn enabled_forward_proxy_with_ip_acl_chain_is_accepted() {
        let yaml = r#"
listeners:
  - name: egress
    address: "127.0.0.1:32123"
    forward_proxy:
      enabled: true
    filter_chains: [egress]
filter_chains:
  - name: egress
    filters:
      - filter: ip_acl
        allow:
          - "127.0.0.0/8"
"#;
        Config::from_yaml(yaml).expect("ip_acl in chains satisfies the egress-control requirement");
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn enabled_forward_proxy_with_policy_chain_is_accepted() {
        let yaml = r#"
listeners:
  - name: egress
    address: "127.0.0.1:32123"
    forward_proxy:
      enabled: true
    filter_chains: [egress]
filter_chains:
  - name: egress
    filters:
      - filter: access_log
      - filter: policy
        rules:
          - name: allow-local
            effect: allow
            match:
              path_prefix: "/"
"#;
        Config::from_yaml(yaml).expect("policy in chains satisfies the egress-control requirement");
    }

    /// An enabled forward-proxy listener whose only egress control is an
    /// `ip_acl` placed under the given chain-level and filter-level YAML.
    #[cfg(feature = "forward-proxy")]
    fn ip_acl_only_config(chain_conditions: &str, filter_conditions: &str) -> String {
        format!(
            r#"
listeners:
  - name: egress
    address: "127.0.0.1:32123"
    forward_proxy:
      enabled: true
    filter_chains: [egress]
filter_chains:
  - name: egress
{chain_conditions}    filters:
      - filter: ip_acl
{filter_conditions}        allow:
          - "127.0.0.0/8"
insecure_options:
  skip_pipeline_checks:
    conditional_security: true
"#
        )
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn conditional_ip_acl_is_not_egress_control() {
        // Gated to GET, the ip_acl does not run for CONNECT. The pipeline's
        // conditional-security check is opted out here, so this rule alone
        // must keep the listener from being an open relay.
        let yaml = ip_acl_only_config("", "        conditions:\n          - when: {methods: [GET]}\n");
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("open relay"), "{err}");
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn ip_acl_in_conditional_chain_is_not_egress_control() {
        let yaml = ip_acl_only_config("    conditions:\n      - when: {methods: [GET]}\n", "");
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("open relay"), "{err}");
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn unconditional_ip_acl_is_egress_control_with_the_opt_out_set() {
        Config::from_yaml(&ip_acl_only_config("", ""))
            .expect("an ip_acl that runs for every request still satisfies the rule");
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn egress_control_filter_in_unreferenced_chain_does_not_count() {
        let yaml = r#"
listeners:
  - name: egress
    address: "127.0.0.1:32123"
    forward_proxy:
      enabled: true
    filter_chains: [egress]
filter_chains:
  - name: egress
    filters:
      - filter: access_log
  - name: unused
    filters:
      - filter: ip_acl
        allow:
          - "127.0.0.0/8"
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("open relay"),
            "only chains the listener references count: {err}"
        );
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn disabled_forward_proxy_without_egress_control_is_accepted() {
        let yaml = r#"
listeners:
  - name: egress
    address: "127.0.0.1:32123"
    forward_proxy:
      enabled: false
    filter_chains: [egress]
filter_chains:
  - name: egress
    filters:
      - filter: access_log
"#;
        Config::from_yaml(yaml).expect("inert forward_proxy blocks are exempt");
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn forward_proxy_on_tcp_listener_is_rejected() {
        let yaml = r#"
listeners:
  - name: db
    address: "127.0.0.1:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
    forward_proxy:
      enabled: false
insecure_options:
  allow_private_upstreams: true
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("'forward_proxy' only applies to protocol: http"),
            "TCP listeners have no request phase for CONNECT: {err}"
        );
    }

    #[cfg(not(feature = "forward-proxy"))]
    #[test]
    fn forward_proxy_is_unknown_without_the_feature() {
        let yaml = r#"
listeners:
  - name: egress
    address: "127.0.0.1:32123"
    forward_proxy:
      enabled: true
      allow_destinations:
        - host: api.example.com
    filter_chains: [egress]
filter_chains:
  - name: egress
    filters:
      - filter: access_log
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("forward_proxy"),
            "forward_proxy must be rejected when the feature is off: {err}"
        );
    }

    #[test]
    fn listener_without_forward_proxy_is_untouched() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: access_log
"#;
        Config::from_yaml(yaml).expect("listeners without forward_proxy need no egress control");
    }

    /// Parse a valid forward-proxy config, apply `edit` to its block in code,
    /// and return the error `Config::validate()` reports.
    ///
    /// Parsing checks the block's bounds; a config built or changed in code
    /// must meet the same bounds when it is validated.
    #[cfg(feature = "forward-proxy")]
    fn validate_after_edit(edit: impl FnOnce(&mut crate::config::ForwardProxyConfig)) -> String {
        let yaml = r#"
listeners:
  - name: egress
    address: "127.0.0.1:32123"
    forward_proxy:
      enabled: true
      allow_destinations:
        - host: api.example.com
    filter_chains: [egress]
filter_chains:
  - name: egress
    filters:
      - filter: access_log
"#;
        let mut config = Config::from_yaml(yaml).unwrap();
        edit(config.listeners[0].forward_proxy.as_mut().unwrap());
        let err = config.validate().expect_err("out-of-bounds block must fail validation");
        let err = err.to_string();
        assert!(err.contains("listener 'egress'"), "{err}");
        err
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn validate_rejects_programmatic_idle_timeout_out_of_bounds() {
        assert!(validate_after_edit(|fp| fp.idle_timeout_ms = 0).contains("idle_timeout_ms"));
        assert!(validate_after_edit(|fp| fp.idle_timeout_ms = 3_600_001).contains("idle_timeout_ms"));
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn validate_rejects_programmatic_zero_max_duration() {
        assert!(validate_after_edit(|fp| fp.max_duration_secs = Some(0)).contains("max_duration_secs"));
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn validate_rejects_programmatic_port_zero_destination() {
        assert!(validate_after_edit(|fp| fp.allow_destinations[0].port = Some(0)).contains("port 0"));
    }

    #[cfg(feature = "forward-proxy")]
    #[test]
    fn validate_rejects_programmatic_numeric_destination_pattern() {
        let err = validate_after_edit(|fp| {
            fp.allow_destinations.push(crate::config::DestinationRule {
                host: "*.0.1".to_owned(),
                port: None,
            });
        });
        assert!(err.contains("numeric label"), "{err}");
    }
}
