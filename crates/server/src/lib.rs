// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

#![forbid(unsafe_code)]

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
//! - Running the server ([`try_run_server`], [`try_run_server_with_registry`], or the never-returning [`run_server`]
//!   and [`run_server_with_registry`]) and the file-watching hot-reload path that rebuilds and atomically swaps
//!   pipelines when the config file changes.
//!
//! [`FilterPipeline`]: praxis_filter::FilterPipeline

mod composition;
pub(crate) mod pipelines;
#[cfg(feature = "config-reload")]
pub(crate) mod reload;
#[cfg(feature = "config-reload")]
pub(crate) mod reload_diagnostics;
mod server;
pub(crate) mod startup_checks;
#[cfg(feature = "admin-api")]
mod version;
#[cfg(feature = "config-reload")]
pub(crate) mod watcher;
pub use composition::{CompositionError, ExtensionContext, RegistryContext, ServerComposition, ValidatorContext};
pub use pipelines::{build_full_registry, build_subrequest_client, resolve_pipelines};
pub use praxis_core::{
    config::load_config,
    logging::{TracingGuard, init_tracing, with_bootstrap_logging},
};
pub use praxis_filter::{PipelineExtension, RequestExtensions};
pub use server::{
    StartupError, check_root_privilege, fatal, install_crypto_provider, report_fatal, resolve_config_path, run_server,
    run_server_with_composition, run_server_with_registry, try_run_server, try_run_server_with_composition,
    try_run_server_with_registry,
};
#[cfg(feature = "admin-api")]
pub use version::process_version_info;

/// Test-only helpers.
#[cfg(test)]
pub(crate) mod test_support {
    use praxis_core::subrequest::SubRequestConnector;

    /// Build a `SubRequestConnector`, installing the crypto provider first.
    ///
    /// Unit tests construct connectors directly, bypassing the server
    /// bootstrap that normally installs the provider. Pingora builds a TLS
    /// client config while the connector is created, and rustls has no
    /// implicit fallback — the Pingora fork enables `custom-provider` — so
    /// without this the constructor panics.
    ///
    /// Production is unaffected: `run_server_*` installs during bootstrap,
    /// well before any connector exists.
    pub(crate) fn connector(peers: usize) -> SubRequestConnector {
        praxis_tls::provider::install();
        SubRequestConnector::new(peers, None)
    }
}
