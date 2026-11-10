// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Networking test utilities: port allocation, readiness
//! checks, mock backends, HTTP clients, and TLS utilities.

pub mod backend;
pub mod http1;
pub mod http2;
pub mod http_client;
pub mod port;
pub mod postgres;
pub mod tls;
pub mod wait;

pub use backend::{
    Backend, BackendGuard, BackendReceipt, CountingBackend, GrpcBackend, GrpcBackendGuard, PayloadResponseBackend,
    PayloadResponseFraming, PayloadResponseReceipt, ReusedConnectionLog, RoutedBackend, WsBackendGuard,
    read_http_request, spawn_raw_http_backend, start_backend, start_backend_v6, start_backend_with_shutdown,
    start_counting_backend, start_echo_backend, start_grpc_backend, start_gzip_encoded_backend,
    start_header_echo_backend, start_hop_by_hop_response_backend, start_keepalive_backend,
    start_keepalive_poison_backend, start_malicious_response_header_backend, start_payload_response_backend,
    start_request_counting_backend, start_reserved_header_response_backend, start_response_header_backend,
    start_reused_connection_kill_backend, start_slow_backend, start_stateful_backend, start_tagged_header_echo_backend,
    start_uri_echo_backend, start_websocket_echo_backend,
};
pub(crate) use http_client::try_http_send_on_connection_until;
pub use http_client::{
    GrpcCallResult, h2c_get, h2c_get_absolute, h2c_get_authority_only, h2c_grpc_call, http_delete, http_get,
    http_get_retry, http_get_v6, http_post, http_put_json, http_send, http_send_on_connection, json_post, parse_body,
    parse_header, parse_header_all, parse_status,
};
pub use http1::{H1Completion, H1Response, assert_buffered_response_rejected, read_h1_response};
pub use http2::{
    H2PausedResult, H2PausedUploads, H2Response, H2Upload, read_h2_response, send_h2_payload, start_h2_paused_uploads,
};
pub use port::{
    PortGuard, bind_unique_port, bind_unique_port_on, free_port, free_port_guard, free_port_v6, ipv6_available,
};
pub use postgres::{PostgresGuard, start_postgres};
pub use tls::{
    ClientCert, TestCertificates, ensure_crypto_provider, https_client_config, https_get, https_get_attempt,
    https_get_attempt_on, parse_cert_chain_and_key, start_mtls_backend, start_tcp_echo_backend,
    start_tcp_tagged_backend, start_tls_backend, start_tls_backend_from_pem, tls_connection_rejected, tls_send_recv,
    tls_serial, wait_for_https, wait_for_tls, write_test_certificate,
};
pub use wait::{wait_for_http, wait_for_http2, wait_for_tcp};
