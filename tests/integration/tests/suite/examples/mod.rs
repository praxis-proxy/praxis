// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for example configurations.

mod test_utils;
#[expect(unreachable_pub)]
pub use test_utils::load_example_config;

mod access_logging;
mod admin_interface;
mod api_key_filter;
mod basic_reverse_proxy;
mod branching;
mod canary_routing;
mod circuit_breaker;
mod conditional_filters;
mod csrf;
mod default_config;
#[cfg(feature = "ext-proc")]
mod ext_proc_endpoint_selector;
mod grpc_detection;
mod guardrails;
mod header_manipulation;
mod health_checks;
mod hostname_upstream;
mod least_connections;
mod logging;
mod max_body_guard;
mod max_connections;
mod multi_listener;
mod operations;
mod p2c;
mod path_based_routing;
mod path_rewriting;
mod payload_examples;
mod payload_processing;
mod pipeline;
#[cfg(feature = "cpex-policy-engine")]
mod policy;
#[cfg(feature = "cpex-policy-engine")]
mod policy_http;
mod protocol_examples;
mod protocols;
mod redirect;
mod round_robin;
mod security_examples;
mod session_affinity;
mod static_response;
mod stream_buffer;
mod timeout;
mod traffic_management_examples;
mod url_rewriting;
mod virtual_hosts;
mod websocket;
mod weighted_load_balancing;
