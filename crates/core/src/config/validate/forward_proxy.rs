// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Forward-proxy listener validation: the egress-control requirement.
//!
//! An enabled `forward_proxy` listener that accepts CONNECT to anywhere,
//! gated by nothing, is an open relay. Validation therefore requires at
//! least one egress control: a non-empty `allow_destinations` list, or an
//! `ip_acl`/`policy` filter in the listener's chains.

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
/// request.
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
                 filter in its filter chains, otherwise it is an open relay",
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
/// filter in its main pipeline path.
fn chains_have_egress_control_filter(config: &Config, listener: &Listener) -> bool {
    listener.filter_chains.iter().any(|chain_name| {
        config
            .filter_chains
            .iter()
            .find(|chain| chain.name == *chain_name)
            .is_some_and(|chain| {
                chain
                    .filters
                    .iter()
                    .any(|filter| EGRESS_CONTROL_FILTERS.contains(&filter.filter_type.as_str()))
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
}
