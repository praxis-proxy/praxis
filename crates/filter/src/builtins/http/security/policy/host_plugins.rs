// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Plugin factories the embedding host supplies, for `kind:` values the engine
//! does not bundle.
//!
//! The engine's bundled extensions are compiled in and registered by
//! `ppe::install_builtins`. Anything else — an organisation's own PII detector,
//! an audit sink that writes to their SIEM, a validator for a house-specific
//! identifier — has to come from the process embedding the filter, because
//! `PolicyFilter` builds its own [`ppe::PolicyEngine`] and nothing else can reach it.
//!
//! A host registers before starting the server:
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use praxis_filter::register_policy_plugin_factory;
//!
//! register_policy_plugin_factory("validator/pii-scan", Arc::new(|| {
//!     Box::new(my_plugins::PiiScannerFactory)
//! }));
//! ```
//!
//! and then names that `kind:` in the policy document like any other plugin.
//! An unrecognised `kind:` fails the load, so a forgotten registration shows up
//! as a startup error naming the kind rather than as a plugin that silently
//! never runs.

use std::{
    collections::BTreeMap,
    sync::{Arc, LazyLock, RwLock},
};

/// Builds a fresh factory each time it is called.
///
/// A closure rather than a stored factory because
/// `PolicyEngine::register_factory` takes its factory by value, and one
/// registration has to serve more than one manager: `PolicyFilter::new` runs
/// once per filter instance and again on every hot reload.
pub type PolicyPluginFactoryFn = Arc<dyn Fn() -> Box<dyn ppe::PluginFactory> + Send + Sync>;

/// Host registrations, keyed by the `kind:` they serve.
///
/// Read on every filter construction and never emptied. Draining it would make
/// the first `PolicyFilter` work and every later one fail, which in practice
/// means a gateway that starts cleanly and then fails its first config reload
/// with "no factory registered" for a config that had just been working.
static HOST_FACTORIES: LazyLock<RwLock<BTreeMap<String, PolicyPluginFactoryFn>>> =
    LazyLock::new(|| RwLock::new(BTreeMap::new()));

/// Register a plugin factory for a policy-document `kind:`.
///
/// Call before the server starts. Registrations are applied *after* the engine's
/// bundled factories, so registering a `kind` the engine also provides replaces
/// it — that is the useful direction, letting a deployment swap a bundled
/// implementation for its own without forking. Registering the same `kind` twice
/// here keeps the later call.
///
/// The factory is built fresh for each `PolicyFilter`, so it need not be `Clone`
/// and may capture host state in the closure.
pub fn register_policy_plugin_factory(kind: impl Into<String>, make: PolicyPluginFactoryFn) {
    HOST_FACTORIES
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(kind.into(), make);
}

/// Every host registration, as `(kind, fresh factory)` pairs.
///
/// Called by `PolicyFilter::new`. The registry is snapshotted first and the
/// read guard dropped before any `make` closure runs: the closures are
/// host-supplied and may do anything, including registering another `kind`.
/// Running them under the guard would make such a call block forever, the
/// write it wants can never be granted while this thread still holds the read
/// lock it is waiting inside of. Cloning the `Arc`s is cheap; building the
/// factories under the lock is not worth a deadlock.
pub(super) fn host_plugin_factories() -> Vec<(String, Box<dyn ppe::PluginFactory>)> {
    let registered: Vec<(String, PolicyPluginFactoryFn)> = HOST_FACTORIES
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .map(|(kind, make)| (kind.clone(), Arc::clone(make)))
        .collect();

    registered.into_iter().map(|(kind, make)| (kind, make())).collect()
}

/// How many kinds a host has registered. For diagnostics at startup.
pub(super) fn host_plugin_count() -> usize {
    HOST_FACTORIES
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        time::Duration,
    };

    use super::*;

    /// Stands in for a host's factory. The probe never asks it to build.
    struct ProbeFactory;

    impl ppe::PluginFactory for ProbeFactory {
        fn create(
            &self,
            _config: &ppe::prelude::PluginConfig,
        ) -> Result<ppe::prelude::PluginInstance, Box<ppe::prelude::PluginError>> {
            panic!("the registry-lock probe never builds a plugin instance")
        }
    }

    /// Can another thread take the registry write lock right now?
    ///
    /// Models the re-entrant registration a host `make` closure may perform:
    /// [`register_policy_plugin_factory`] needs the write lock, so a closure
    /// running under a read guard could never be granted it. The wait is
    /// bounded so the regression surfaces as a failed assertion instead of a
    /// hung test binary, the queued writer is granted the lock as soon as
    /// [`host_plugin_factories`] returns.
    fn write_lock_reachable() -> bool {
        let (tx, rx) = mpsc::channel();
        drop(std::thread::spawn(move || {
            drop(
                HOST_FACTORIES
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            let _sent = tx.send(());
        }));
        rx.recv_timeout(Duration::from_secs(5)).is_ok()
    }

    /// Host factories are built with no registry lock held, so a factory that
    /// registers another `kind` cannot deadlock against its own caller.
    #[test]
    fn factories_are_built_with_no_registry_lock_held() {
        let reachable = Arc::new(AtomicBool::new(false));
        let probing = Arc::new(AtomicBool::new(true));
        let reachable_in_factory = Arc::clone(&reachable);
        let probing_in_factory = Arc::clone(&probing);

        register_policy_plugin_factory(
            "test/registry-lock-probe",
            Arc::new(move || {
                // Disarmed once this test is done, so later `PolicyFilter`
                // constructions in this binary stay cheap.
                if probing_in_factory.load(Ordering::SeqCst) {
                    reachable_in_factory.store(write_lock_reachable(), Ordering::SeqCst);
                }
                Box::new(ProbeFactory)
            }),
        );

        let built = host_plugin_factories();
        probing.store(false, Ordering::SeqCst);

        assert!(
            built.iter().any(|(kind, _)| kind == "test/registry-lock-probe"),
            "the probe kind must be among the returned factories"
        );
        assert!(
            reachable.load(Ordering::SeqCst),
            "a host factory ran while the registry lock was held; a re-entrant \
             registration from inside it would deadlock"
        );
    }
}
