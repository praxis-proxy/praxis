// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Server bootstrap for the Praxis proxy.

pub(crate) mod pipelines;
pub(crate) mod reload;
mod server;
pub(crate) mod watcher;
pub use pipelines::resolve_pipelines;
pub use praxis_core::{config::load_config, logging::init_tracing};
pub use server::{check_root_privilege, fatal, resolve_config_path, run_server, run_server_with_registry};

// -----------------------------------------------------------------------------
// External Filter Discovery
// -----------------------------------------------------------------------------

// Provides: fn register_external_filters(&mut FilterRegistry)
include!(concat!(env!("OUT_DIR"), "/external_filters.rs"));

/// Build a [`FilterRegistry`] with built-in and auto-discovered external
/// filters.
///
/// External filter crates are discovered at build time via
/// `[package.metadata.praxis-filters]` markers in their `Cargo.toml`.
/// This is the standard registry used by the `praxis` binary; callers
/// that need a custom registry should use [`run_server_with_registry`]
/// instead.
///
/// [`FilterRegistry`]: praxis_filter::FilterRegistry
#[must_use]
pub fn build_full_registry() -> praxis_filter::FilterRegistry {
    let mut registry = praxis_filter::FilterRegistry::with_builtins();
    register_external_filters(&mut registry);
    registry
}
