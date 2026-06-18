// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! HTTP protocol implementation.

/// Pingora-backed HTTP implementation.
pub mod pingora;

pub use pingora::{PingoraHttp, handler::load_http_handler, health::PingoraHealthService};
