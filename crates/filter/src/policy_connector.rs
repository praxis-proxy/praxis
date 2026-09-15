// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Process-wide handoff of the proxy sub-request connector to policy filters.
//!
//! This is needed because filter factories cannot receive a sub-request
//! client directly.
//!
//! The setter is compiled unconditionally so a host can register the connector
//! without knowing whether `policy-engine` ended up enabled: a dependency
//! feature turned on elsewhere through Cargo feature unification is invisible
//! to the host's own `cfg`. The storage behind it is feature-gated, so a build
//! without the policy engine holds onto nothing.

use praxis_core::subrequest::SubRequestConnector;
#[cfg(feature = "policy-engine")]
pub(crate) use storage::shared_policy_connector;

/// Serializes tests that register a connector and then read it back. The
/// registration is a process-wide last-wins slot, so a test that asserts on
/// what it registered must hold this across both halves, and every other test
/// that registers must hold it while it does.
#[cfg(all(test, feature = "policy-engine"))]
pub(crate) static REGISTRATION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Register the connector captured by subsequently constructed policy transports.
///
/// Registration is process-wide and last-wins. Call immediately before
/// building pipelines.
///
/// Always available. Without the `policy-engine` feature there is nothing to
/// read the registration, so the connector is dropped rather than retained and
/// the call has no effect.
///
/// Because it is process-wide, two runtimes building pipelines *concurrently*
/// in one process can cross-wire their pools: each registers, and whichever
/// registered last is what the other's filters capture. Build them one at a
/// time. A single server, including across hot reloads, is unaffected.
pub fn set_policy_subrequest_connector(connector: &SubRequestConnector) {
    #[cfg(feature = "policy-engine")]
    storage::policy_connector().set(connector);
    #[cfg(not(feature = "policy-engine"))]
    let _ = connector;
}

/// The connector a host registered, if this build can hold one.
///
/// Exists so a host can verify its registration was retained. Not part of the
/// stable API.
#[cfg(feature = "policy-engine")]
#[doc(hidden)]
#[must_use]
pub fn registered_policy_subrequest_connector() -> Option<SubRequestConnector> {
    shared_policy_connector()
}

/// The registered connector and the slot holding it.
///
/// Gated so a policy-free build never stores a connector: a stored clone owns
/// the keepalive pool, the admission semaphore, and the circuit-breaker
/// registry, and a `'static` slot would keep all three alive for the life of
/// the process even though nothing can read them.
#[cfg(feature = "policy-engine")]
mod storage {
    use std::sync::{Arc, OnceLock};

    use arc_swap::ArcSwapOption;
    use praxis_core::subrequest::SubRequestConnector;

    /// Last-wins connector storage.
    #[derive(Debug, Default)]
    pub(super) struct ConnectorHolder(ArcSwapOption<SubRequestConnector>);

    impl ConnectorHolder {
        /// Store `connector`, replacing whatever was held.
        pub(super) fn set(&self, connector: &SubRequestConnector) {
            self.0.store(Some(Arc::new(connector.clone())));
        }

        /// The held connector, if one was stored.
        pub(super) fn get(&self) -> Option<SubRequestConnector> {
            self.0.load_full().map(|held| held.as_ref().clone())
        }
    }

    /// The registered connector, or none when the host never registered one.
    pub(super) fn policy_connector() -> &'static ConnectorHolder {
        static POLICY_CONNECTOR: OnceLock<ConnectorHolder> = OnceLock::new();
        POLICY_CONNECTOR.get_or_init(ConnectorHolder::default)
    }

    /// Clone the registered connector handle, if any.
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
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]
mod tests {
    #[cfg(not(feature = "policy-engine"))]
    #[test]
    fn registering_without_the_policy_engine_is_accepted_and_stores_nothing() {
        use praxis_core::subrequest::SubRequestConnector;

        super::set_policy_subrequest_connector(&SubRequestConnector::new(8, None));
        super::set_policy_subrequest_connector(&SubRequestConnector::new(1, None));
    }
}
