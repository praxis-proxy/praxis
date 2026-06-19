// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Anthropic Messages request validation filter.
//!
//! Validates the JSON request envelope before forwarding.
//! Backend-owned Anthropic API semantics remain the
//! inference backend's responsibility.

mod config;

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::needless_raw_strings, reason = "tests")]
mod tests;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::debug;

use self::config::{AnthropicValidateConfig, build_config};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// AnthropicValidateFilter
// -----------------------------------------------------------------------------

/// Validates Anthropic Messages request bodies for proxy-owned
/// JSON envelope requirements.
///
/// # YAML
///
/// ```yaml
/// filter: anthropic_validate
/// ```
pub struct AnthropicValidateFilter {
    /// Parsed and validated configuration.
    config: AnthropicValidateConfig,
}

impl AnthropicValidateFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: AnthropicValidateConfig = parse_filter_config("anthropic_validate", config)?;
        let validated = build_config(cfg)?;
        Ok(Box::new(Self { config: validated }))
    }
}

#[async_trait]
impl HttpFilter for AnthropicValidateFilter {
    fn name(&self) -> &'static str {
        "anthropic_validate"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.config.max_body_bytes),
        }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let Some(bytes) = body.as_deref().filter(|b| !b.is_empty()) else {
            return Ok(FilterAction::Reject(reject("request body is required")));
        };

        if let Some(rejection) = validate_request(bytes) {
            return Ok(FilterAction::Reject(rejection));
        }

        debug!("anthropic request validation passed");
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Validate the JSON envelope in the request body.
fn validate_request(body: &[u8]) -> Option<Rejection> {
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return Some(reject("request body is not valid JSON")),
    };

    if !value.is_object() {
        return Some(reject("request body is not a JSON object"));
    }

    None
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Build a 400 rejection with a JSON error body.
fn reject(message: &str) -> Rejection {
    let body = serde_json::json!({
        "error": {
            "message": message,
            "type": "invalid_request_error"
        }
    })
    .to_string();

    Rejection::status(400)
        .with_header("content-type", "application/json")
        .with_body(Bytes::from(body))
}
