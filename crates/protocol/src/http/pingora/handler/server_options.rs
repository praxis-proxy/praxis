// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pingora HTTP/2 server option builders.
//!
//! Constructs `HttpServerOptions` and `H2Options` with security
//! hardening (HPACK limits, concurrent stream bounds). Extracted from
//! `mod.rs` to keep the handler module focused on lifecycle hooks.

use pingora_core::{apps::HttpServerOptions, protocols::http::v2::server::H2Options};

/// Build [`HttpServerOptions`] with h2c enabled.
///
/// `allow_connect` turns on CONNECT method proxying for the listener
/// (its `forward_proxy.enabled` flag); without it the proxy layer
/// answers CONNECT with 405 before any handler hook runs.
///
/// [`HttpServerOptions`]: pingora_core::apps::HttpServerOptions
pub(super) fn h2c_server_options(allow_connect: bool) -> HttpServerOptions {
    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    opts.allow_connect_method_proxying = allow_connect;
    opts
}

/// Build [`H2Options`] with limits to mitigate HPACK amplification attacks
/// (CWE-409).
///
/// Without explicit limits the `h2` crate defaults allow unbounded header
/// list sizes and concurrent streams, enabling a small compressed request
/// to allocate hundreds of megabytes on the server.
///
/// [`H2Options`]: pingora_core::protocols::http::v2::server::H2Options
pub(super) fn h2_server_options() -> H2Options {
    let mut opts = H2Options::new();
    opts.max_header_list_size(65_536); // 64 KiB
    opts.max_concurrent_streams(128);
    opts
}
