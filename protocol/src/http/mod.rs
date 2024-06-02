// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! HTTP protocol implementation.

/// Pingora-backed HTTP implementation.
pub mod pingora;

pub use pingora::{PingoraHttp, handler::load_http_handler, health::PingoraHealthService};
