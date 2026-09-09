// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The bind identity the running listener sockets were created with.
//!
//! Hot reload can replace a listener's filter pipeline, but it cannot
//! rebind its socket or move it to the other protocol handler. This module
//! records what each socket was actually bound with at startup so reload
//! can tell an applicable change from one that only a restart can apply.

use std::collections::{HashMap, HashSet};

use praxis_core::config::{Config, ProtocolKind};

// -----------------------------------------------------------------------------
// BoundListener
// -----------------------------------------------------------------------------

/// The restart-only bind settings of one live listener.
///
/// These are exactly the listener properties [`crate::reload_diagnostics`]
/// reports as requiring a restart: the socket is bound, and its protocol
/// handler created, once at startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundListener {
    /// Address the socket is bound to.
    pub(crate) address: String,
    /// Protocol handler that owns this listener's pipeline slot.
    pub(crate) protocol: ProtocolKind,
    /// Whether the bound socket terminates TLS.
    pub(crate) tls: bool,
    /// Named filter chains this listener served at startup.
    ///
    /// A removed or protocol-blocked listener keeps serving that original
    /// pipeline, so its admin metadata must report these chains rather than a
    /// rejected config's, even after the listener's live metadata entry is
    /// gone (removed in an earlier reload, then reintroduced).
    pub(crate) chain_names: Vec<String>,
}

// -----------------------------------------------------------------------------
// BoundListeners
// -----------------------------------------------------------------------------

/// Every listener's bind identity, captured once from the startup config.
///
/// `register_protocols` creates the HTTP and TCP handlers and their sockets
/// exactly once, and `ListenerPipelines` never gains or loses a key
/// afterwards, so this snapshot describes what is actually listening for
/// the whole life of the process.
///
/// Reload must compare against this snapshot rather than against the
/// previous reload's config. The watcher adopts every config that reloads
/// without error as the baseline for the next comparison, and a reload that
/// declines to apply a restart-only change still succeeds, so an
/// old-versus-new diff forgets which generation the handlers were bound for
/// as soon as one such config is adopted, and would wave the very same
/// change through on the next reload.
#[derive(Clone, Debug, Default)]
pub(crate) struct BoundListeners {
    /// Bind identity by listener name.
    listeners: HashMap<String, BoundListener>,
}

impl BoundListeners {
    /// Capture the bind identity of every listener in the startup config.
    pub(crate) fn from_config(config: &Config) -> Self {
        Self {
            listeners: config
                .listeners
                .iter()
                .map(|listener| {
                    (
                        listener.name.clone(),
                        BoundListener {
                            address: listener.address.clone(),
                            protocol: listener.protocol,
                            tls: listener.tls.is_some(),
                            chain_names: listener.filter_chains.clone(),
                        },
                    )
                })
                .collect(),
        }
    }

    /// The bind identity a listener's socket was created with, or `None`
    /// for a name that was never bound (a listener a later reload added,
    /// which has no socket and no pipeline slot until a restart).
    pub(crate) fn get(&self, name: &str) -> Option<&BoundListener> {
        self.listeners.get(name)
    }

    /// Names of `config`'s listeners whose protocol differs from the one
    /// their handler was bound for.
    ///
    /// Pipelines are validated against the protocol the *config* asks for,
    /// so a listener switched between HTTP and TCP in place builds a
    /// pipeline whose every filter the bound handler skips as a protocol
    /// mismatch. Such a pipeline must never be swapped in, and the
    /// listener's live metadata must keep describing the bound generation.
    ///
    /// Listeners that were never bound are not reported: they have no slot
    /// to swap and no socket to misdescribe.
    pub(crate) fn protocol_mismatches<'cfg>(&self, config: &'cfg Config) -> HashSet<&'cfg str> {
        config
            .listeners
            .iter()
            .filter(|listener| {
                self.get(listener.name.as_str())
                    .is_some_and(|bound| bound.protocol != listener.protocol)
            })
            .map(|listener| listener.name.as_str())
            .collect()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    /// Config with `web` on HTTP and `edge` on TCP.
    fn mixed_config() -> Config {
        Config::from_yaml(
            r#"
insecure_options:
  allow_private_upstreams: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: edge
    address: "127.0.0.1:9000"
    protocol: tcp
    upstream: "127.0.0.1:15432"
    filter_chains: [tcp_main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
  - name: tcp_main
    filters:
      - filter: tcp_access_log
"#,
        )
        .unwrap()
    }

    #[test]
    fn from_config_records_every_listener() {
        let bound = BoundListeners::from_config(&mixed_config());

        let web = bound.get("web").unwrap();
        assert_eq!(web.address, "127.0.0.1:8080", "web address should come from config");
        assert_eq!(web.protocol, ProtocolKind::Http, "web should be bound as HTTP");
        assert!(!web.tls, "web has no tls block");

        let edge = bound.get("edge").unwrap();
        assert_eq!(edge.protocol, ProtocolKind::Tcp, "edge should be bound as TCP");
        assert!(bound.get("absent").is_none(), "unknown listener has no bind identity");
    }

    #[test]
    fn unchanged_config_has_no_protocol_mismatch() {
        let config = mixed_config();
        let bound = BoundListeners::from_config(&config);
        assert!(
            bound.protocol_mismatches(&config).is_empty(),
            "a config identical to the bound one mismatches nothing"
        );
    }

    /// [`mixed_config`] with both listeners' protocols swapped in place.
    const SWAPPED_PROTOCOLS: &str = r#"
insecure_options:
  allow_private_upstreams: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    protocol: tcp
    upstream: "127.0.0.1:15432"
    filter_chains: [tcp_main]
  - name: edge
    address: "127.0.0.1:9000"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
  - name: tcp_main
    filters:
      - filter: tcp_access_log
"#;

    #[test]
    fn protocol_mismatches_report_both_directions() {
        let bound = BoundListeners::from_config(&mixed_config());
        let swapped = Config::from_yaml(SWAPPED_PROTOCOLS).unwrap();

        let mismatched = bound.protocol_mismatches(&swapped);
        assert_eq!(
            mismatched,
            ["web", "edge"].into_iter().collect::<HashSet<&str>>(),
            "both directions of an in-place protocol change are mismatches"
        );
    }

    #[test]
    fn never_bound_listener_is_not_a_mismatch() {
        let bound = BoundListeners::default();
        let config = mixed_config();
        let mismatched = bound.protocol_mismatches(&config);
        assert!(
            mismatched.is_empty(),
            "a listener with no bound socket cannot mismatch one"
        );
    }
}
