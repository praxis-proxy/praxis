// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Networking test utilities: port allocation, readiness
//! checks, mock backends, HTTP clients, and TLS utilities.

pub mod backend;
pub mod http_client;
pub mod port;
pub mod tls;
pub mod wait;

pub use backend::{
    Backend, BackendGuard, RoutedBackend, WsBackendGuard, start_backend, start_backend_v6, start_backend_with_shutdown,
    start_echo_backend, start_echo_backend_with_shutdown, start_header_echo_backend,
    start_header_echo_backend_with_shutdown, start_hop_by_hop_response_backend, start_slow_backend,
    start_uri_echo_backend, start_uri_echo_backend_with_shutdown, start_websocket_echo_backend,
};
pub use http_client::{
    http_get, http_get_retry, http_get_v6, http_post, http_send, json_post, parse_body, parse_header, parse_header_all,
    parse_status,
};
pub use port::{PortGuard, bind_unique_port, free_port, free_port_guard, free_port_v6, ipv6_available};
pub use tls::{
    ClientCert, TestCertificates, https_get, start_mtls_backend, start_tcp_echo_backend, start_tcp_tagged_backend,
    start_tls_backend, tls_connection_rejected, tls_send_recv, wait_for_https, wait_for_tls,
};
pub use wait::{wait_for_http, wait_for_http2, wait_for_tcp};
