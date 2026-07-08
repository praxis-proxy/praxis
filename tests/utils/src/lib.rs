// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

#![allow(
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::let_underscore_must_use,
    clippy::missing_assert_message,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test utility code"
)]
#![allow(let_underscore_drop, reason = "test utility code")]

//! Shared test utilities for the Praxis workspace.

pub mod example_config;
pub mod filters;
pub mod net;
pub mod proxy;

pub use example_config::{example_config_path, load_example_config, patch_yaml};
pub use net::*;
pub use proxy::{
    ProxyGuard, ReloadableProxyGuard, build_pipeline, custom_filter_yaml, registry_with, simple_proxy_yaml,
    start_full_proxy, start_proxy, start_proxy_with_registry, start_reloadable_proxy, start_tls_proxy,
    start_tls_proxy_no_wait,
};
