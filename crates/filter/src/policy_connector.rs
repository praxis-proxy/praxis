// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Process-wide handoff of the proxy sub-request connector to policy filters.
//!
//! This is needed because filter factories cannot receive a sub-request
//! client directly.
//!
//! Compiled unconditionally so a host can register the connector without
//! knowing whether `policy-engine` ended up enabled: a dependency feature
//! turned on elsewhere through Cargo feature unification is invisible to the
//! host's own `cfg`. Only the reader is gated, so with `policy-engine` off the
//! registration is accepted and nothing ever reads it.

use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwapOption;
use praxis_core::subrequest::SubRequestConnector;

/// Last-wins connector storage.
#[derive(Debug, Default)]
struct ConnectorHolder(ArcSwapOption<SubRequestConnector>);

impl ConnectorHolder {
    /// Store `connector`, replacing whatever was held.
    fn set(&self, connector: &SubRequestConnector) {
        self.0.store(Some(Arc::new(connector.clone())));
    }

    /// The held connector, if one was stored.
    #[cfg(any(feature = "policy-engine", test))]
    fn get(&self) -> Option<SubRequestConnector> {
        self.0.load_full().map(|held| held.as_ref().clone())
    }
}

/// The registered connector, or none when the host never registered one.
fn policy_connector() -> &'static ConnectorHolder {
    static POLICY_CONNECTOR: OnceLock<ConnectorHolder> = OnceLock::new();
    POLICY_CONNECTOR.get_or_init(ConnectorHolder::default)
}

/// Register the connector captured by subsequently constructed policy transports.
///
/// Registration is process-wide and last-wins. Call immediately before
/// building pipelines.
///
/// Always available. Without the `policy-engine` feature nothing reads the
/// registration, so the call is accepted and has no effect.
///
/// Because it is process-wide, two runtimes building pipelines *concurrently*
/// in one process can cross-wire their pools: each registers, and whichever
/// registered last is what the other's filters capture. Build them one at a
/// time. A single server, including across hot reloads, is unaffected.
pub fn set_policy_subrequest_connector(connector: &SubRequestConnector) {
    policy_connector().set(connector);
}

/// Clone the registered connector handle, if any.
#[cfg(feature = "policy-engine")]
pub(crate) fn shared_policy_connector() -> Option<SubRequestConnector> {
    policy_connector().get()
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn a_holder_hands_back_the_connector_it_was_given() {
        let holder = ConnectorHolder::default();
        assert!(holder.get().is_none(), "an empty holder holds nothing");

        let first = SubRequestConnector::new(8, None);
        holder.set(&first);
        assert!(
            std::ptr::eq(holder.get().expect("registered").connector(), first.connector()),
            "readers see the registered pool, not a fresh one"
        );
    }

    #[test]
    fn storing_the_held_connector_again_keeps_the_same_pool() {
        let holder = ConnectorHolder::default();
        let held = SubRequestConnector::new(8, None);
        holder.set(&held);
        holder.set(&held);
        assert!(std::ptr::eq(
            holder.get().expect("registered").connector(),
            held.connector()
        ));
    }

    #[test]
    fn a_second_runtimes_connector_replaces_the_first() {
        let holder = ConnectorHolder::default();
        let first = SubRequestConnector::new(8, None);
        let second = SubRequestConnector::new(1, None);

        holder.set(&first);
        holder.set(&second);

        let held = holder.get().expect("registered");
        assert!(
            std::ptr::eq(held.connector(), second.connector()),
            "the later registration is what readers see"
        );
        assert!(
            !std::ptr::eq(held.connector(), first.connector()),
            "and it is not the earlier pool"
        );
    }
}
