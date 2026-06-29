// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Responses API proxy filter.
//!
//! Body-preparation waypoint in the Responses API filter pipeline.
//! Sits between upstream enrichment filters (`rehydrate`, `tool_parse`)
//! and downstream consumption filters (`stream_events`, `tool_dispatch`).
//! Named `inference` in pipeline configs so branch chains can
//! `rejoin` here for the agentic tool loop.
//!
//! When `ResponsesState` is present in `RequestExtensions`,
//! rebuilds the request body with the full conversation history
//! from `state.messages` and strips `previous_response_id` (already
//! resolved by the rehydrate filter). When no state is present,
//! passes the body through unchanged.

mod config;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests;

use std::borrow::Cow;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, trace};

use self::config::{ResponsesProxyConfig, build_config};
use super::{error::responses_error_rejection, state::ResponsesState};
use crate::{
    FilterAction, FilterError,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// ResponsesProxyFilter
// -----------------------------------------------------------------------------

/// Rebuilds the request body from `ResponsesState` when present.
///
/// Reads the assembled conversation history from
/// `ResponsesState::messages` and replaces the `input` field in
/// the outbound body. Strips `previous_response_id` since Praxis
/// already resolved it locally via the rehydrate filter.
///
/// When no `ResponsesState` exists (non-Responses requests, or
/// requests without `previous_response_id`), passes through
/// unchanged.
///
/// # YAML
///
/// ```yaml
/// filter: responses_proxy
/// ```
///
/// # Full YAML
///
/// ```yaml
/// filter: responses_proxy
/// max_body_bytes: 67108864
/// ```
///
/// # Example
///
/// ```rust
/// use praxis_filter::ai::ResponsesProxyFilter;
///
/// let yaml = serde_yaml::Value::Null;
/// let filter = ResponsesProxyFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "responses_proxy");
/// ```
pub struct ResponsesProxyFilter {
    /// Parsed and validated configuration.
    config: ResponsesProxyConfig,
}

impl ResponsesProxyFilter {
    /// Create from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config contains unknown fields.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: ResponsesProxyConfig = if config.is_null() {
            ResponsesProxyConfig::default()
        } else {
            parse_filter_config("responses_proxy", config)?
        };
        let validated = build_config(cfg)?;
        Ok(Box::new(Self { config: validated }))
    }

    /// Serialize the rebuilt body from conversation state.
    fn serialize_body(
        &self,
        state: &ResponsesState,
        streaming: bool,
    ) -> Result<Result<Vec<u8>, FilterAction>, FilterError> {
        let mut outbound = state.request_body.clone();
        if let Some(obj) = outbound.as_object_mut() {
            obj.insert("input".to_owned(), serde_json::Value::Array(state.messages.clone()));
            if obj.remove("previous_response_id").is_some() {
                debug!("stripped previous_response_id from outbound body");
            }
        }

        let serialized =
            serde_json::to_vec(&outbound).map_err(|e| -> FilterError { format!("responses_proxy: {e}").into() })?;
        if serialized.len() > self.config.max_body_bytes {
            debug!(
                body_bytes = serialized.len(),
                max_bytes = self.config.max_body_bytes,
                "rebuilt request body exceeds maximum size"
            );
            return Ok(Err(FilterAction::Reject(responses_error_rejection(
                413,
                "invalid_request_error",
                "request body exceeds maximum size",
                streaming,
            ))));
        }

        debug!(
            messages = state.messages.len(),
            body_bytes = serialized.len(),
            "rebuilt request body from ResponsesState"
        );

        Ok(Ok(serialized))
    }
}

#[async_trait]
impl HttpFilter for ResponsesProxyFilter {
    fn name(&self) -> &'static str {
        "responses_proxy"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
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
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            trace!("buffering request body chunk");
            return Ok(FilterAction::Continue);
        }

        let Some(state) = ctx.extensions.get::<ResponsesState>() else {
            debug!("no ResponsesState in extensions, passthrough");
            return Ok(FilterAction::Continue);
        };

        let streaming = ctx
            .get_metadata("openai_responses_format.stream")
            .is_some_and(|v| v == "true");

        let serialized = match self.serialize_body(state, streaming)? {
            Ok(bytes) => bytes,
            Err(action) => return Ok(action),
        };

        let len = serialized.len();
        *body = Some(Bytes::from(serialized));
        ctx.extra_request_headers
            .push((Cow::Borrowed("content-length"), len.to_string()));

        Ok(FilterAction::Continue)
    }
}
