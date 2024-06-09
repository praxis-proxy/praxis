#![deny(unsafe_code)]

//! Shared server bootstrap for the Praxis proxy.
//!
//! [`run_server`] builds filter pipelines, registers protocol
//! handlers, and starts the server. [`load_config`] resolves
//! a configuration from an explicit path, `praxis.yaml` in the
//! current directory, or the built-in default.
//!
//! [`init_tracing`] sets up the global tracing subscriber with
//! optional JSON output and per-module log level overrides.

mod config;
mod server;
mod tracing;

pub use config::{DEFAULT_CONFIG, load_config};
pub use server::{run_server, run_server_with_registry};
pub use tracing::init_tracing;
