// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! JSON Pointer rewrite/extract filter. Operator semantics: [`JsonBodyFilter`].
//!
//! Walks the document with a path-stack tokenizer (no JSON DOM). Unused
//! subtrees are copied as byte spans. Programmatic construction:
//! [`JsonBodyFilter::from_ops`] and [`crate::json_ops::JsonOps::builder`].

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
    reason = "tests"
)]
mod tests;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::warn;

use self::config::{JsonBodyConfig, build_ops};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode, DEFAULT_JSON_BODY_MAX_BYTES},
    builtins::http::payload_processing::{OnInvalidBehavior, config_validation::validate_max_body_bytes},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
    json_ops::{HttpJsonStore, JsonOps},
};

// -----------------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------------

/// Request and response op sets plus HTTP framing policy.
#[derive(Clone, Debug)]
pub struct JsonBodyOps {
    /// Request-body operations.
    pub request: JsonOps,
    /// Response-body operations.
    pub response: JsonOps,
    /// Maximum request/response body size for `StreamBuffer`.
    pub max_body_bytes: usize,
    /// Behavior when the body is not valid JSON.
    pub on_invalid: OnInvalidBehavior,
    /// Content-Type allowlist. When non-empty, only bodies whose
    /// `Content-Type` starts with one of these values are processed;
    /// others pass through unchanged. Empty means all content types.
    pub content_types: Vec<String>,
}

impl Default for JsonBodyOps {
    fn default() -> Self {
        Self {
            request: JsonOps::empty(),
            response: JsonOps::empty(),
            max_body_bytes: DEFAULT_JSON_BODY_MAX_BYTES,
            on_invalid: OnInvalidBehavior::Continue,
            content_types: Vec::new(),
        }
    }
}

// -----------------------------------------------------------------------------
// JsonBodyFilter
// -----------------------------------------------------------------------------

/// Rewrites JSON request bodies with JSON Pointer add, remove, replace, and extract, and response bodies with remove
/// and extract.
///
/// Applies mutating operations in one pass over a `StreamBuffer`-held body.
/// Extract copies a pointer's JSON into `filter_metadata`, structured
/// metadata, or a request header without changing the body.
/// `filter_metadata` values over 256 bytes are dropped; use structured
/// metadata for nested or larger values. Extract promotion requires a single JSON
/// value with only trailing whitespace after the document; non-whitespace
/// trailing content blocks all extract destinations. Header values over 256 bytes
/// or containing control characters are also skipped.
/// Mutating pointers must not overlap (equal or prefix) within a direction.
/// Duplicate extract pointers are rejected; nested extract pointers are allowed.
/// Unused subtrees are copied as byte spans. Missing parents, missing
/// replace/extract targets, and missing context values skip that operation
/// (the original member is left unchanged). Duplicate object member names
/// are not canonicalized. Remove drops every matching member. Replace and
/// add-over-existing rewrite every matching member; add injects once only
/// when no match exists. Extract keeps the last matching value. Add `/-`
/// appends to arrays only; on an object the operation is skipped (same as a
/// missing parent). Invalid JSON follows `on_invalid` ([`OnInvalidBehavior`]).
///
/// Extract-only directions are `ReadOnly` and defer extract until end of stream
/// so promotion sees the full `StreamBuffer` body. Mixed extract and rewrite uses one
/// walk; metadata-sourced add/replace resolve lazily at each splice site and
/// are skipped when the extract value is not yet available.
///
/// **Body signature preservation**: extract-only directions never modify the
/// body bytes, so upstream HMAC or signature checks remain valid. Directions
/// with any mutating op (add, remove, replace) may alter inter-token whitespace
/// even when the op has no runtime effect (e.g., a replace whose target is
/// missing). Callers that need a stable body signature should not combine
/// extract and mutating ops in the same direction; use a separate extract-only
/// `json_body` filter earlier in the pipeline.
///
/// Response `Content-Length` is already committed when body hooks run.
/// `response_add` and `response_replace` are rejected at config time.
/// `response_remove` shrinks are padded with trailing spaces so the
/// transferred byte count matches the committed `Content-Length`.
/// This achieves redaction, not bandwidth reduction.
///
/// **Content-type gating**: when `content_types` is set, only bodies whose
/// `Content-Type` matches one of the listed prefixes (case-insensitive) are
/// processed; non-matching bodies pass through unchanged. When the list is
/// empty (the default), all content types are processed. The compression
/// filter has an equivalent knob.
///
/// **Memory usage**: peak heap per concurrent request is approximately
/// 2 × `max_body_bytes` per mutating direction (the `StreamBuffer` input
/// and the rewrite output coexist during the walk). Extract-only directions
/// allocate no output buffer, so their peak is 1 × `max_body_bytes`.
/// Size `max_body_bytes` for the workload, not the default.
///
/// # YAML configuration
///
/// ```yaml
/// filter: json_body
/// content_types:
///   - application/json
/// request_extract:
///   - pointer: /model
///     metadata: original.model
///   - pointer: /stream
///     header: X-Stream
/// request_add:
///   - pointer: /tenant
///     value: acme
///   - pointer: /api_key
///     env_var: TENANT_API_KEY
///   - pointer: /original_model
///     metadata: original.model
/// request_remove:
///   - /password
/// request_replace:
///   - pointer: /model
///     value: forced-model
/// response_remove:
///   - /internal
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::JsonBodyFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// request_replace:
///   - pointer: /model
///     value: forced-model
/// "#,
/// )
/// .unwrap();
/// let filter = JsonBodyFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "json_body");
/// ```
pub struct JsonBodyFilter {
    /// Maximum request/response body size for `StreamBuffer`.
    max_body_bytes: usize,
    /// Behavior when the body is not valid JSON.
    on_invalid: OnInvalidBehavior,
    /// Compiled request-body operations.
    request_ops: JsonOps,
    /// Compiled response-body operations.
    response_ops: JsonOps,
    /// Content-Type allowlist (prefix match, case-insensitive).
    /// Empty means all content types are processed.
    content_types: Vec<String>,
}

impl JsonBodyFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML is invalid, no operations are
    /// configured, `response_add` or `response_replace` is set, pointers
    /// overlap, or a value source is missing.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: JsonBodyConfig = parse_filter_config("json_body", config)?;
        let result = build_ops(cfg)?;
        Self::from_ops(JsonBodyOps {
            request: result.request,
            response: result.response,
            max_body_bytes: result.max_body_bytes,
            on_invalid: result.on_invalid,
            content_types: result.content_types,
        })
    }

    /// Create a filter from already compiled [`JsonOps`].
    ///
    /// YAML [`from_config`](Self::from_config) uses this after compiling
    /// through [`JsonOps::builder`].
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if both directions are empty, `max_body_bytes`
    /// is out of range, or response ops can grow the body.
    pub fn from_ops(ops: JsonBodyOps) -> Result<Box<dyn HttpFilter>, FilterError> {
        validate_max_body_bytes("json_body", ops.max_body_bytes)?;
        if ops.request.is_empty() && ops.response.is_empty() {
            return Err("json_body: at least one add, remove, replace, or extract operation is required".into());
        }
        if ops.response.can_grow() {
            return Err("json_body: response_add and response_replace are not supported; \
                 response Content-Length is already committed. Use response_remove or response_extract"
                .into());
        }
        Ok(Box::new(Self {
            max_body_bytes: ops.max_body_bytes,
            on_invalid: ops.on_invalid,
            request_ops: ops.request,
            response_ops: ops.response,
            content_types: ops.content_types,
        }))
    }

    /// Returns `true` when `content_type` matches the configured allowlist.
    ///
    /// An empty allowlist matches everything. Matching uses case-insensitive
    /// prefix comparison, following the same convention as the compression
    /// filter's `content_types` option.
    fn matches_content_type(&self, content_type: &str) -> bool {
        if self.content_types.is_empty() {
            return true;
        }
        self.content_types.iter().any(|pattern| {
            content_type
                .get(..pattern.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(pattern))
        })
    }
}

/// Per-request state stashed in `on_response` for the response body phase.
struct ResponseContentTypeMatch {
    /// `true` when the response `Content-Type` matched the allowlist.
    matches: bool,
}

#[async_trait]
impl HttpFilter for JsonBodyFilter {
    fn name(&self) -> &'static str {
        "json_body"
    }

    fn request_body_access(&self) -> BodyAccess {
        direction_access(&self.request_ops)
    }

    fn response_body_access(&self) -> BodyAccess {
        direction_access(&self.response_ops)
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.max_body_bytes),
        }
    }

    fn response_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.max_body_bytes),
        }
    }

    fn needs_request_context(&self) -> bool {
        !self.content_types.is_empty()
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
            return Ok(FilterAction::Continue);
        }
        if !self.content_types.is_empty() {
            let ct = ctx
                .request
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !self.matches_content_type(ct) {
                return Ok(FilterAction::Continue);
            }
        }
        apply_rewrite(&self.request_ops, self.on_invalid, ctx, body, FitMode::Request)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if !self.content_types.is_empty() && !self.response_ops.is_empty() {
            let matches = ctx
                .response_header
                .as_ref()
                .and_then(|r| r.headers.get(http::header::CONTENT_TYPE))
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ct| self.matches_content_type(ct));
            ctx.insert_filter_state(ResponseContentTypeMatch { matches });
        }
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        if !self.content_types.is_empty() && !self.response_ops.is_empty() {
            let matches = ctx
                .get_filter_state::<ResponseContentTypeMatch>()
                .is_some_and(|s| s.matches);
            if !matches {
                return Ok(FilterAction::Continue);
            }
        }
        apply_rewrite(&self.response_ops, self.on_invalid, ctx, body, FitMode::Response)
    }
}

// -----------------------------------------------------------------------------
// Rewrite application
// -----------------------------------------------------------------------------

/// How to fit a rewritten body to HTTP framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FitMode {
    /// Request: length may change; `StreamBuffer` repairs `Content-Length`.
    Request,
    /// Response: pad with trailing spaces on shrink to match the committed
    /// `Content-Length`. The transferred byte count is unchanged — removal
    /// achieves redaction, not bandwidth savings. Padding is unconditional:
    /// chunked responses where no committed length exists are also padded.
    /// Refuse on grow (config forbids add/replace).
    Response,
}

/// Resolve context values, rewrite, and apply framing policy.
///
/// Callers must invoke this only at end of stream so `StreamBuffer` holds
/// the full body before extract promotion or rewrite.
fn apply_rewrite(
    op_set: &JsonOps,
    on_invalid: OnInvalidBehavior,
    ctx: &mut HttpFilterContext<'_>,
    body: &mut Option<Bytes>,
    fit: FitMode,
) -> Result<FilterAction, FilterError> {
    if op_set.is_empty() {
        return Ok(FilterAction::Continue);
    }

    let Some(original) = body.as_ref() else {
        return Ok(FilterAction::Continue);
    };
    let original_len = original.len();
    let mut store = HttpJsonStore::new(ctx);
    let result = op_set.apply(original, Some(&mut store));

    match result {
        Ok(_outcome) if op_set.is_extract_only() => Ok(FilterAction::BodyDone),
        Ok(outcome) => {
            apply_fitted_body(body, original_len, outcome.output.unwrap_or_default(), fit);
            Ok(FilterAction::BodyDone)
        },
        Err(err) => handle_invalid(on_invalid, err.as_str()),
    }
}

/// Write the rewritten body, padding or refusing according to [`FitMode`].
fn apply_fitted_body(body: &mut Option<Bytes>, original_len: usize, rewritten: Vec<u8>, fit: FitMode) {
    match fit {
        FitMode::Request => *body = Some(Bytes::from(rewritten)),
        FitMode::Response => match fit_response(original_len, rewritten) {
            Some(fitted) => *body = Some(fitted),
            None => {
                warn!(
                    original_len,
                    "json_body: refusing response rewrite that exceeds committed Content-Length"
                );
            },
        },
    }
}

/// Body access for one direction.
fn direction_access(op_set: &JsonOps) -> BodyAccess {
    if op_set.is_empty() {
        BodyAccess::None
    } else if op_set.is_extract_only() {
        BodyAccess::ReadOnly
    } else {
        BodyAccess::ReadWrite
    }
}

/// Map a parse/rewrite failure to `on_invalid`.
fn handle_invalid(on_invalid: OnInvalidBehavior, reason: &str) -> Result<FilterAction, FilterError> {
    match on_invalid {
        OnInvalidBehavior::Continue => {
            warn!(reason, "json_body: leaving body unchanged");
            Ok(FilterAction::Continue)
        },
        OnInvalidBehavior::Reject => Ok(FilterAction::Reject(Rejection::status(400))),
        OnInvalidBehavior::Error => Err(format!("json_body: {reason}").into()),
    }
}

/// Pad a shorter response to `original_len` so the byte count matches the
/// already-committed `Content-Length`; `None` means grow (caller keeps
/// original). Padding is applied unconditionally, including chunked
/// responses where the downstream has no committed length.
fn fit_response(original_len: usize, rewritten: Vec<u8>) -> Option<Bytes> {
    match rewritten.len().cmp(&original_len) {
        std::cmp::Ordering::Greater => None,
        std::cmp::Ordering::Equal => Some(Bytes::from(rewritten)),
        std::cmp::Ordering::Less => {
            let mut padded = rewritten;
            padded.resize(original_len, b' ');
            Some(Bytes::from(padded))
        },
    }
}
