// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Anthropic Messages protocol filter for native `/v1/messages` backends.
//!
//! Supplies a gateway-managed `anthropic-version` default for
//! internal or non-SDK callers while preserving caller-provided
//! versions. Does not touch the request or response body.

mod config;

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests;

use std::borrow::Cow;

use async_trait::async_trait;
use tracing::debug;

use self::config::{AnthropicMessagesProtocolConfig, build_config};
use crate::{
    FilterAction, FilterError,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Anthropic API version header name.
const ANTHROPIC_VERSION_HEADER: &str = "anthropic-version";

// -----------------------------------------------------------------------------
// AnthropicMessagesProtocolFilter
// -----------------------------------------------------------------------------

/// Normalizes Anthropic Messages protocol headers for native
/// backends.
///
/// # YAML
///
/// ```yaml
/// filter: anthropic_messages_protocol
/// ```
///
/// # Full YAML
///
/// ```yaml
/// filter: anthropic_messages_protocol
/// default_version: "2023-06-01"
/// ```
pub struct AnthropicMessagesProtocolFilter {
    /// Parsed and validated configuration.
    config: AnthropicMessagesProtocolConfig,
}

impl AnthropicMessagesProtocolFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: AnthropicMessagesProtocolConfig = parse_filter_config("anthropic_messages_protocol", config)?;
        let validated = build_config(cfg)?;
        Ok(Box::new(Self { config: validated }))
    }
}

#[async_trait]
impl HttpFilter for AnthropicMessagesProtocolFilter {
    fn name(&self) -> &'static str {
        "anthropic_messages_protocol"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::None
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::Stream
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let has_version = ctx.request.headers.get(ANTHROPIC_VERSION_HEADER).is_some();

        if !has_version {
            debug!(
                version = self.config.default_version.as_str(),
                "injecting default anthropic-version header"
            );
            ctx.extra_request_headers.push((
                Cow::Borrowed(ANTHROPIC_VERSION_HEADER),
                self.config.default_version.clone(),
            ));
        }

        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}
