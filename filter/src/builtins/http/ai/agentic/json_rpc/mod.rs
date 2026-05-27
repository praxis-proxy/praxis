// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Extracts JSON-RPC 2.0 envelope metadata from request bodies for routing.

pub(crate) mod config;
pub(crate) mod envelope;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::{trace, warn};

use self::{
    config::{JsonRpcConfig, build_config},
    envelope::{JsonRpcEnvelope, parse_json_rpc_envelope},
};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// JsonRpcFilter
// -----------------------------------------------------------------------------

/// Extracts JSON-RPC 2.0 envelope metadata from request bodies and promotes
/// method, id, and kind to request headers and filter results for routing.
///
/// # Basic YAML
///
/// ```yaml
/// filter: json_rpc
/// ```
///
/// # Full YAML
///
/// ```yaml
/// filter: json_rpc
/// max_body_bytes: 1048576
/// batch_policy: reject
/// on_invalid: continue
/// headers:
///   method: X-Json-Rpc-Method
///   id: X-Json-Rpc-Id
///   kind: X-Json-Rpc-Kind
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::JsonRpcFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// max_body_bytes: 1048576
/// batch_policy: reject
/// "#,
/// )
/// .unwrap();
/// let filter = JsonRpcFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "json_rpc");
/// ```
pub struct JsonRpcFilter {
    /// Maximum body bytes for `StreamBuffer`.
    pub(crate) max_body_bytes: usize,
    /// Parsed filter configuration.
    config: JsonRpcConfig,
}

impl JsonRpcFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: JsonRpcConfig = parse_filter_config("json_rpc", config)?;
        let (max_body_bytes, validated_config) = build_config(cfg)?;
        Ok(Box::new(Self {
            max_body_bytes,
            config: validated_config,
        }))
    }
}

#[async_trait]
impl HttpFilter for JsonRpcFilter {
    fn name(&self) -> &'static str {
        "json_rpc"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.max_body_bytes),
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
        let Some(chunk) = body.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        let envelope = match parse_json_rpc_envelope(chunk, &self.config) {
            Ok(Some(envelope)) => envelope,
            Ok(None) => return Ok(FilterAction::Continue),
            Err(_) if !end_of_stream => return Ok(FilterAction::Continue),
            Err(e) => return handle_parse_error(e, &self.config),
        };

        promote_to_headers(&envelope, &self.config, &mut ctx.extra_request_headers);
        promote_to_filter_results(&envelope, ctx)?;

        trace!(
            method_len = envelope.method.as_ref().map(String::len),
            kind = ?envelope.kind,
            "extracted JSON-RPC envelope metadata"
        );

        Ok(FilterAction::Release)
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Handle JSON-RPC parse errors based on error type and `on_invalid` config.
fn handle_parse_error(e: envelope::JsonRpcParseError, config: &JsonRpcConfig) -> Result<FilterAction, FilterError> {
    use self::{config::InvalidJsonRpcBehavior, envelope::JsonRpcParseError};

    match e {
        JsonRpcParseError::UnsupportedBatch | JsonRpcParseError::EmptyBatch => {
            Ok(FilterAction::Reject(Rejection::status(400)))
        },
        _ => match config.on_invalid {
            InvalidJsonRpcBehavior::Continue => Ok(FilterAction::Continue),
            InvalidJsonRpcBehavior::Reject => Ok(FilterAction::Reject(Rejection::status(400))),
            InvalidJsonRpcBehavior::Error => Err(e.into()),
        },
    }
}

/// Promote JSON-RPC envelope metadata to request headers.
fn promote_to_headers(
    envelope: &JsonRpcEnvelope,
    config: &JsonRpcConfig,
    headers: &mut Vec<(std::borrow::Cow<'static, str>, String)>,
) {
    if let (Some(method), Some(header_name)) = (&envelope.method, &config.headers.method) {
        if contains_control_chars(method) {
            warn!(
                header = %header_name,
                method_len = method.len(),
                "skipping header injection: method contains control characters"
            );
        } else {
            headers.push((std::borrow::Cow::Owned(header_name.clone()), method.clone()));
        }
    }

    if let (Some(id), Some(header_name)) = (&envelope.id, &config.headers.id) {
        if contains_control_chars(id) {
            warn!(
                header = %header_name,
                id_len = id.len(),
                "skipping header injection: id contains control characters"
            );
        } else {
            headers.push((std::borrow::Cow::Owned(header_name.clone()), id.clone()));
        }
    }

    promote_kind_header(envelope, config, headers);
}

/// Promote the kind header if configured.
fn promote_kind_header(
    envelope: &JsonRpcEnvelope,
    config: &JsonRpcConfig,
    headers: &mut Vec<(std::borrow::Cow<'static, str>, String)>,
) {
    if let Some(header_name) = &config.headers.kind {
        headers.push((
            std::borrow::Cow::Owned(header_name.clone()),
            envelope.kind.as_str().to_owned(),
        ));
    }
}

/// Promote JSON-RPC envelope metadata to filter results.
fn promote_to_filter_results(envelope: &JsonRpcEnvelope, ctx: &mut HttpFilterContext<'_>) -> Result<(), FilterError> {
    let results = ctx.filter_results.entry("json_rpc").or_default();

    results.set("kind", envelope.kind.as_str())?;

    if let Some(method) = &envelope.method
        && !contains_control_chars(method)
    {
        results.set("method", method.clone())?;
    }

    set_id_results(envelope, results)?;

    if let Some(batch_len) = envelope.batch_len {
        results.set("batch_len", batch_len.to_string())?;
    }

    Ok(())
}

/// Set id and `id_kind` in filter results.
fn set_id_results(
    envelope: &JsonRpcEnvelope,
    results: &mut crate::results::FilterResultSet,
) -> Result<(), FilterError> {
    if let Some(id) = &envelope.id {
        if !contains_control_chars(id) {
            results.set("id", id.clone())?;
        }
        results.set("id_kind", envelope.id_kind.as_str())?;
    } else {
        results.set("id_kind", envelope.id_kind.as_str())?;
    }
    Ok(())
}

/// Check whether a string contains control characters.
pub(crate) fn contains_control_chars(s: &str) -> bool {
    s.bytes().any(|b| (b < 0x20 && b != 0x09) || b == 0x7F)
}
