// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! HTTP backends for integration testing.

mod echo;
mod simple;
mod specialized;
mod websocket;

pub use echo::{start_echo_backend, start_header_echo_backend, start_uri_echo_backend};
pub use simple::{Backend, RoutedBackend, start_backend, start_backend_v6, start_backend_with_shutdown};
pub use specialized::{
    BackendGuard, start_hop_by_hop_response_backend, start_reserved_header_response_backend, start_slow_backend,
};
pub use websocket::{WsBackendGuard, start_websocket_echo_backend};
