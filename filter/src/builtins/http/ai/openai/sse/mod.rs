// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! SSE parsing for OpenAI streaming APIs.
//!
//! - [`frame::SseFrameParser`] — byte-level SSE chunk reassembly
//! - [`responses::ResponsesSseParser`] — typed Responses API event parser

#![cfg_attr(not(test), allow(dead_code, reason = "used by filter implementations"))]

mod config;
mod frame;
pub(crate) mod responses;

pub(crate) use config::SseParserConfig;
pub(crate) use frame::{SseFrame, SseFrameParser, SseParseError};
