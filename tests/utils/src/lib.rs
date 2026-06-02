// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    reason = "test utility code"
)]
#![allow(let_underscore_drop, reason = "test utility code")]

//! Shared test utilities for the Praxis workspace.

pub mod agentic;
pub mod example_config;
pub mod filters;
pub mod net;
pub mod proxy;

pub use agentic::{
    A2aMockConfig, A2aMockServerGuard, A2aRecordedRequest, McpMockConfig, McpMockServerGuard, McpRecordedRequest,
    McpToolFixture, start_a2a_mock_server, start_a2a_mock_server_with_config, start_mcp_mock_server,
    start_mcp_mock_server_with_config,
};
pub use example_config::{example_config_path, load_example_config, patch_yaml};
pub use net::*;
pub use proxy::{
    ProxyGuard, ReloadableProxyGuard, build_pipeline, custom_filter_yaml, registry_with, simple_proxy_yaml,
    start_full_proxy, start_proxy, start_proxy_with_registry, start_reloadable_proxy, start_tls_proxy,
    start_tls_proxy_no_wait,
};
