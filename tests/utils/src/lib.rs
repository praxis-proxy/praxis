// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

#![forbid(unsafe_code)]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::let_underscore_must_use,
    clippy::min_ident_chars,
    clippy::missing_assert_message,
    clippy::panic,
    clippy::partial_pub_fields,
    clippy::shadow_unrelated,
    clippy::unwrap_used,
    clippy::wildcard_enum_match_arm,
    reason = "test utility code"
)]
#![allow(let_underscore_drop, reason = "test utility code")]

//! Shared test utilities for the Praxis workspace.

pub mod example_config;
pub mod filters;
pub mod fips;
pub mod load;
pub mod net;
pub mod process;
pub mod proxy;
pub mod tls_probe;

pub use example_config::{allow_loopback_endpoints, example_config_path, load_example_config, patch_yaml};
pub use fips::{FIPS_HOST_ENV, approved_mode, assert_fips_host_if_declared, expect_approved_mode, fips_host};
pub use load::{LoadReport, collect_responses, concurrent_gets, open_requests, read_raw_responses};
pub use net::*;
#[cfg(target_os = "linux")]
pub use process::own_open_file_limits;
pub use process::{PraxisProcess, READY_TIMEOUT};
pub use proxy::{
    PRAXIS_BIN_ENV, ProxyGuard, ReloadableProxyGuard, build_pipeline, custom_filter_yaml, praxis_bin, registry_with,
    simple_proxy_yaml, start_full_proxy, start_full_proxy_with_registry, start_proxy, start_proxy_with_registry,
    start_reloadable_proxy, start_tls_proxy, start_tls_proxy_no_wait, start_tls_proxy_no_wait_with_registry,
};
