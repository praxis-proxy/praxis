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
/// [`HttpServerOptions`]: pingora_core::apps::HttpServerOptions
pub(super) fn h2c_server_options() -> HttpServerOptions {
    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    opts
}

/// Build [`H2Options`] bounding the resources one HTTP/2 client can make the
/// server hold, following RFC 9113 §10.5.
///
/// The `h2` builder already enforces most of these through its own defaults;
/// naming them here pins the values Praxis depends on, so a dependency update
/// cannot loosen them unnoticed, and keeps them in one auditable place. The
/// `h2_limits` suite in `tests/security` exercises the behaviour each bound
/// produces.
///
/// These are fixed for now. When operators need to tune them, promote this
/// set to per-listener configuration alongside the existing listener limits in
/// `praxis_core::config::listener` (`downstream_read_timeout_ms`,
/// `max_connections`, and the like), keeping these values as the defaults.
///
/// [`H2Options`]: pingora_core::protocols::http::v2::server::H2Options
pub(super) fn h2_server_options() -> H2Options {
    let mut opts = H2Options::new();
    opts.max_header_list_size(65_536); // 64 KiB decoded header list
    opts.max_concurrent_streams(128); // concurrent streams per connection
    opts.max_frame_size(16_384); // 16 KiB, the largest frame a client may send
    opts.max_send_buffer_size(409_600); // 400 KiB queued per connection
    opts.max_pending_accept_reset_streams(20); // reset streams tolerated before GOAWAY
    opts.max_local_error_reset_streams(Some(1_024)); // server-side resets before GOAWAY
    opts
}
