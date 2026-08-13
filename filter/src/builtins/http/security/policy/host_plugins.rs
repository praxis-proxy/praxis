// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Plugin factories the embedding host supplies, for `kind:` values the engine
//! does not bundle.
//!
//! The engine's bundled extensions are compiled in and registered by
//! `ppe::install_builtins`. Anything else — an organisation's own PII detector,
//! an audit sink that writes to their SIEM, a validator for a house-specific
//! identifier — has to come from the process embedding the filter, because
//! `PolicyFilter` builds its own [`PluginManager`] and nothing else can reach it.
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
/// `PluginManager::register_factory` takes its factory by value, and one
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
/// Called by `PolicyFilter::new`. Factories are constructed here rather than
/// handed out as closures so the lock is released before any of them runs.
pub(super) fn host_plugin_factories() -> Vec<(String, Box<dyn ppe::PluginFactory>)> {
    HOST_FACTORIES
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .map(|(kind, make)| (kind.clone(), make()))
        .collect()
}

/// How many kinds a host has registered. For diagnostics at startup.
pub(super) fn host_plugin_count() -> usize {
    HOST_FACTORIES
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len()
}
