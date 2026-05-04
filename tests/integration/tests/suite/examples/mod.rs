// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Integration tests for example configurations.

mod test_utils;
#[allow(unreachable_pub)]
pub use test_utils::load_example_config;

mod access_logging;
mod api_key_filter;
mod basic_reverse_proxy;
mod canary_routing;
mod circuit_breaker;
mod conditional_filters;
mod credential_injection;
mod default_config;
mod header_manipulation;
mod health_checks;
mod hostname_upstream;
mod least_connections;
mod logging;
mod max_body_guard;
mod max_connections;
#[cfg(feature = "ai-inference")]
mod model_to_header;
mod multi_listener;
mod path_based_routing;
mod path_rewriting;
mod payload_processing;
mod protocols;
mod redirect;
mod round_robin;
mod session_affinity;
mod static_response;
mod stream_buffer;
mod timeout;
mod virtual_hosts;
mod websocket;
mod weighted_load_balancing;
