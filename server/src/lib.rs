// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

#![expect(
    clippy::arithmetic_side_effects,
    clippy::min_ident_chars,
    reason = "TODO(conventions-sync): fix violations and remove"
)]

//! Server bootstrap for the Praxis proxy.
//!
//! `praxis` is the top of the crate dependency flow
//! `server -> protocol -> filter -> core -> tls` and the library behind
//! the `praxis-proxy` binary. It wires the other crates together into a
//! running proxy: loading configuration, building the filter registry,
//! resolving named filter chains into concrete pipelines, and starting
//! the Pingora runtime.
//!
//! Responsibilities:
//! - Configuration loading and config-path resolution ([`load_config`], [`resolve_config_path`]).
//! - Registry assembly with built-in and auto-discovered external filters ([`build_full_registry`]); external filter
//!   crates are discovered at build time via `[package.metadata.praxis-filters]`.
//! - Pipeline resolution: named chains are concatenated into per-listener [`FilterPipeline`]s at startup
//!   ([`resolve_pipelines`]).
//! - Running the server ([`run_server`], [`run_server_with_registry`]) and the file-watching hot-reload path that
//!   rebuilds and atomically swaps pipelines when the config file changes.
//!
//! [`FilterPipeline`]: praxis_filter::FilterPipeline

pub(crate) mod pipelines;
pub(crate) mod reload;
pub(crate) mod reload_diagnostics;
mod server;
pub(crate) mod startup_checks;
pub(crate) mod watcher;
pub use pipelines::resolve_pipelines;
pub use praxis_core::{
    config::load_config,
    logging::{TracingGuard, init_tracing},
};
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
