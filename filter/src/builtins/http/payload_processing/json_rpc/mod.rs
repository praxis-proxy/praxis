// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Extracts JSON-RPC 2.0 envelope metadata from request bodies for routing.

pub mod config;
pub mod envelope;
mod raw_envelope;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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
    config::{BatchPolicy, JsonRpcConfig, build_config},
    envelope::{JsonRpcEnvelope, parse_json_rpc_envelope},
};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    builtins::http::value_safety::contains_control_chars,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// JsonRpcFilter
// -----------------------------------------------------------------------------

/// Extracts JSON-RPC 2.0 envelope metadata from request bodies and promotes
/// method, id, and kind to request headers and filter results for routing.
///
/// Message kinds: `request`, `notification`, `response`, `batch`.
///
/// Writes `json_rpc.*` entries to the filter result set for branch
/// chain conditions.
///
/// # Batch Security
///
/// When [`batch_policy`] is set to [`first`], a single HTTP request
/// can carry many JSON-RPC calls, which may bypass per-request rate
/// limiting. Use [`max_batch_size`] to cap the number of items
/// allowed per batch (default: 100). The default policy is
/// [`reject`], which blocks all batch arrays.
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
/// batch_policy: first
/// max_batch_size: 50
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
///
/// [`batch_policy`]: config::JsonRpcConfig::batch_policy
/// [`first`]: config::BatchPolicy::First
/// [`max_batch_size`]: config::JsonRpcConfig::max_batch_size
/// [`reject`]: config::BatchPolicy::Reject
pub struct JsonRpcFilter {
    /// Parsed filter configuration.
    config: JsonRpcConfig,
    /// Maximum body bytes for `StreamBuffer`.
    pub(crate) max_body_bytes: usize,
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

        if validated_config.batch_policy == BatchPolicy::First {
            warn!(
                max_batch_size = validated_config.max_batch_size,
                "json_rpc batch_policy is 'first': only the first item \
                 in a batch is used for routing; remaining items bypass \
                 per-request policy checks"
            );
        }

        Ok(Box::new(Self {
            config: validated_config,
            max_body_bytes,
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
        // StreamBuffer accumulates the whole body; inspect only the
        // complete request at end-of-stream. Promoting on each chunk (and
        // again on the final EOS pass) pushed duplicate X-Json-Rpc-*
        // headers onto every request with a body, and acting on a partial
        // prefix let a client desync the promoted metadata from the body
        // the upstream receives.
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let Some(chunk) = body.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        let envelope = match parse_json_rpc_envelope(chunk, &self.config) {
            Ok(Some(envelope)) => envelope,
            Ok(None) => return Ok(FilterAction::Continue),
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
// Private Utilities
// -----------------------------------------------------------------------------

/// Handle JSON-RPC parse errors based on error type and `on_invalid` config.
fn handle_parse_error(e: envelope::JsonRpcParseError, config: &JsonRpcConfig) -> Result<FilterAction, FilterError> {
    use self::envelope::JsonRpcParseError;
    use crate::builtins::http::payload_processing::OnInvalidBehavior;

    match e {
        JsonRpcParseError::BatchTooLarge(..) | JsonRpcParseError::EmptyBatch | JsonRpcParseError::UnsupportedBatch => {
            Ok(FilterAction::Reject(Rejection::status(400)))
        },
        _ => match config.on_invalid {
            OnInvalidBehavior::Continue => Ok(FilterAction::Continue),
            OnInvalidBehavior::Reject => Ok(FilterAction::Reject(Rejection::status(400))),
            OnInvalidBehavior::Error => Err(e.into()),
        },
    }
}

/// Promote JSON-RPC envelope metadata to request headers.
fn promote_to_headers(
    envelope: &JsonRpcEnvelope,
    config: &JsonRpcConfig,
    headers: &mut Vec<(std::borrow::Cow<'static, str>, String)>,
) {
    promote_checked(
        headers,
        config.headers.method.as_ref(),
        envelope.method.as_ref(),
        "method",
    );
    promote_checked(headers, config.headers.id.as_ref(), envelope.id.as_ref(), "id");

    if let Some(header_name) = &config.headers.kind {
        headers.push((
            std::borrow::Cow::Owned(header_name.clone()),
            envelope.kind.as_str().to_owned(),
        ));
    }
}

/// Promote one envelope value to a configured header, skipping (with a
/// warning) values containing control characters or exceeding the
/// dynamic-value length limit.
fn promote_checked(
    headers: &mut Vec<(std::borrow::Cow<'static, str>, String)>,
    header_name: Option<&String>,
    value: Option<&String>,
    what: &'static str,
) {
    let (Some(header_name), Some(value)) = (header_name, value) else {
        return;
    };
    if contains_control_chars(value) || value.len() > super::MAX_DYNAMIC_VALUE_LEN {
        warn!(
            header = %header_name,
            value_len = value.len(),
            "skipping {what} header injection: value contains control characters or exceeds length limit"
        );
    } else {
        headers.push((std::borrow::Cow::Owned(header_name.clone()), value.clone()));
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

    if let Some(id) = &envelope.id
        && !contains_control_chars(id)
    {
        results.set("id", id.clone())?;
    }
    results.set("id_kind", envelope.id_kind.as_str())?;

    if let Some(batch_len) = envelope.batch_len {
        results.set("batch_len", batch_len.to_string())?;
    }

    Ok(())
}
