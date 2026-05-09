// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Envoy-compatible external processing (`ext_proc`) filter.
//!
//! Sends request and response data to an external gRPC server for
//! inspection or mutation via the Envoy [`ext_proc`] protocol.
//!
//! [`ext_proc`]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ext_proc/v3/external_processor.proto

#[cfg(test)]
mod tests;

use std::time::Duration;

use async_trait::async_trait;
use praxis_core::config::FailureMode;
use serde::Deserialize;
use tonic::transport::{Channel, Endpoint};

use crate::{
    FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default per-message timeout in milliseconds.
const DEFAULT_MESSAGE_TIMEOUT_MS: u64 = 200;

// -----------------------------------------------------------------------------
// ExtProcConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the `ext_proc` filter.
///
/// ```yaml
/// filter: ext_proc
/// target: "http://127.0.0.1:50051"
/// failure_mode: open        # optional, default: closed
/// message_timeout_ms: 200   # optional, default: 200
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtProcConfig {
    /// gRPC endpoint URI of the external processing server.
    target: String,

    /// Behaviour when the external processor is unreachable or returns an error.
    #[serde(default)]
    failure_mode: FailureMode,

    /// Per-message timeout in milliseconds.
    #[serde(default = "default_message_timeout_ms")]
    message_timeout_ms: u64,
}

/// Returns the default message timeout in milliseconds.
fn default_message_timeout_ms() -> u64 {
    DEFAULT_MESSAGE_TIMEOUT_MS
}

// -----------------------------------------------------------------------------
// ExtProcFilter
// -----------------------------------------------------------------------------

/// External processing filter using the Envoy `ext_proc` gRPC protocol.
///
/// Establishes a gRPC channel to an external server at construction time.
/// The channel connects lazily on first use, but a malformed endpoint URI
/// is rejected immediately.
///
/// For each request, the filter opens a new bidirectional `Process` stream
/// and sends the request headers as the first message. The server responds
/// with header mutations or an immediate response. The same pattern repeats
/// during the response phase.
///
/// # YAML configuration
///
/// ```yaml
/// filter: ext_proc
/// target: "http://127.0.0.1:50051"
/// failure_mode: open        # optional, default: closed
/// message_timeout_ms: 200   # optional, default: 200
/// ```
pub struct ExtProcFilter {
    /// Lazily-connecting gRPC channel to the external processor.
    #[allow(dead_code, reason = "used by gRPC callout in subsequent commits")]
    channel: Channel,

    /// Behaviour when the external processor is unreachable or errors.
    #[allow(dead_code, reason = "used by gRPC callout in subsequent commits")]
    failure_mode: FailureMode,

    /// Per-message timeout for gRPC calls.
    #[allow(dead_code, reason = "used by gRPC callout in subsequent commits")]
    message_timeout: Duration,

    /// gRPC endpoint URI (retained for diagnostics).
    target: String,
}

impl ExtProcFilter {
    /// Create from parsed YAML config.
    ///
    /// Validates the target URI and builds a lazily-connecting gRPC channel.
    /// A malformed URI is rejected at construction time (fail-fast).
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is malformed or the
    /// target URI is invalid.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: ExtProcConfig = parse_filter_config("ext_proc", config)?;

        let endpoint: Endpoint = cfg
            .target
            .parse()
            .map_err(|e: tonic::transport::Error| -> FilterError {
                format!("ext_proc: invalid target URI '{}': {e}", cfg.target).into()
            })?;

        let channel = endpoint.connect_lazy();

        Ok(Box::new(Self {
            channel,
            failure_mode: cfg.failure_mode,
            message_timeout: Duration::from_millis(cfg.message_timeout_ms),
            target: cfg.target,
        }))
    }
}

#[async_trait]
impl HttpFilter for ExtProcFilter {
    fn name(&self) -> &'static str {
        "ext_proc"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        tracing::trace!(
            target = %self.target,
            "ext_proc on_request (skeleton)"
        );
        Ok(FilterAction::Continue)
    }
}
