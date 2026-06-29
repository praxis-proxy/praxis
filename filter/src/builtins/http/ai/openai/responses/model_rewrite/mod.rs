// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Model rewrite filter for `OpenAI` Responses API requests.
//!
//! Rewrites the top-level `model` field in `POST /v1/responses`
//! request bodies using a configured alias map. Alias sources may
//! be exact model names or single-wildcard patterns such as
//! `codex-*`; exact aliases win before wildcard aliases, then the
//! wildcard with the most literal characters wins. Equal-specificity
//! wildcard ties use lexical source-pattern ordering so `HashMap`
//! iteration order cannot affect the rewrite. When the `model` field
//! is missing or null and a `default_model` is configured, injects the
//! default. Preserves every other field semantically, including
//! `input`, `instructions`, `tools`, and unknown fields. Rewritten
//! requests are re-serialized as JSON, so original whitespace and
//! byte-level object key order are not preserved.
//!
//! Gates on the request path (`POST /v1/responses` exactly), not
//! on classifier metadata. This ensures `on_invalid: reject` fires
//! for malformed JSON on the create endpoint even when the
//! classifier could not classify the body.

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

use std::{borrow::Cow, collections::HashMap};

use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, trace, warn};

use self::config::{ModelRewriteConfig, OnInvalidBehavior, validate_config};
use super::error::responses_error_rejection;
use crate::{
    FilterAction, FilterError,
    body::{BodyAccess, BodyMode},
    builtins::http::{ai::classifier::is_responses_create, value_safety::is_safe_promoted_value},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum length of a body-derived value promoted to headers or filter results.
const MAX_PROMOTED_VALUE_LEN: usize = 256;

// -----------------------------------------------------------------------------
// ModelRewriteFilter
// -----------------------------------------------------------------------------

/// Rewrites the `model` field in Responses API request bodies.
///
/// # YAML
///
/// ```yaml
/// filter: openai_responses_model_rewrite
/// default_model: "llama-3.3-70b"
/// model_aliases:
///   "codex-mini-latest": "llama-3.3-70b"
///   "gpt-4.1-*": "qwen-2.5-72b"
///   "gpt-4.1-mini": "qwen-2.5-72b"
/// ```
///
/// # Full YAML
///
/// ```yaml
/// filter: openai_responses_model_rewrite
/// default_model: "llama-3.3-70b"
/// model_aliases:
///   "codex-mini-latest": "llama-3.3-70b"
///   "gpt-4.1-*": "qwen-2.5-72b"
/// max_body_bytes: 10485760
/// on_invalid: continue
/// headers:
///   effective_model: x-praxis-ai-effective-model
///   original_model: x-praxis-ai-original-model
/// ```
pub struct ModelRewriteFilter {
    /// Model name to inject when absent or null.
    default_model: Option<String>,

    /// Configurable header names for promoted model values.
    headers: config::ModelRewriteHeaders,

    /// Maximum request body size for `StreamBuffer` mode.
    max_body_bytes: usize,

    /// Map from client-facing model names or single-wildcard patterns
    /// to backend model names. Quote wildcard keys in YAML.
    model_aliases: HashMap<String, String>,

    /// Behavior when the body is not valid JSON.
    on_invalid: OnInvalidBehavior,
}

impl ModelRewriteFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: ModelRewriteConfig = parse_filter_config("openai_responses_model_rewrite", config)?;
        validate_config(&cfg)?;
        Ok(Box::new(Self {
            default_model: cfg.default_model,
            headers: cfg.headers,
            max_body_bytes: cfg.max_body_bytes,
            model_aliases: cfg.model_aliases,
            on_invalid: cfg.on_invalid,
        }))
    }

    /// Parse, rewrite, and re-serialize the request body.
    fn rewrite_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<FilterAction, FilterError> {
        let Some(raw) = body.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        let streaming = ctx
            .get_metadata("openai_responses_format.stream")
            .is_some_and(|v| v == "true");

        let mut value: serde_json::Value = match serde_json::from_slice(raw) {
            Ok(v) => v,
            Err(_) => return Ok(invalid_body_action(self.on_invalid, streaming)),
        };

        let Some(obj) = value.as_object_mut() else {
            return Ok(invalid_body_action(self.on_invalid, streaming));
        };

        let result = apply_rewrite(obj, &self.model_aliases, self.default_model.as_deref());
        promote_facts(ctx, &result, &self.headers);

        if !result.mutated {
            return Ok(FilterAction::Continue);
        }

        serialize_and_update(ctx, body, &value, &result)
    }
}

#[async_trait]
impl HttpFilter for ModelRewriteFilter {
    fn name(&self) -> &'static str {
        "openai_responses_model_rewrite"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.max_body_bytes),
        }
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        // Repopulate filter results from metadata written during body
        // pre-read. Branch chains evaluate after on_request, and a
        // preceding filter's branch evaluation clears filter_results
        // before this filter's branches fire.
        repopulate_filter_results(ctx);
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

        if !is_responses_create(&ctx.request.method, ctx.request.uri.path()) {
            trace!("skipping non-create request");
            return Ok(FilterAction::Continue);
        }

        self.rewrite_body(ctx, body)
    }
}

// -----------------------------------------------------------------------------
// Rewrite Logic
// -----------------------------------------------------------------------------

/// Outcome of a model rewrite attempt.
#[expect(clippy::struct_excessive_bools, reason = "independent decision flags")]
struct RewriteResult {
    /// Whether the default model was injected.
    default_injected: bool,

    /// Effective model value after alias/default resolution.
    effective_model: String,

    /// Whether the model value was changed in the body.
    mutated: bool,

    /// Original model value before rewrite, if present.
    original_model: Option<String>,

    /// Whether an alias changed the model.
    rewritten: bool,
}

/// Apply alias and default model policy to the JSON object.
///
/// Three cases:
/// - Missing or null `model` → inject `default_model` if configured.
/// - String `model` → apply alias mapping or pass through.
/// - Non-string type (number, object, array, bool) → no-op; let the backend validate. The proxy should not silently
///   replace a non-string value with its own default.
fn apply_rewrite(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    aliases: &HashMap<String, String>,
    default_model: Option<&str>,
) -> RewriteResult {
    match obj.get("model") {
        Some(serde_json::Value::String(model)) => apply_alias(obj, aliases, model.clone()),
        Some(serde_json::Value::Null) | None => apply_default(obj, default_model),
        Some(_) => noop_result(),
    }
}

/// Apply alias mapping when a model field is present.
fn apply_alias(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    aliases: &HashMap<String, String>,
    model: String,
) -> RewriteResult {
    if let Some(target) = resolve_alias(aliases, &model) {
        let effective = target.to_owned();
        obj.insert("model".to_owned(), serde_json::Value::String(effective.clone()));
        RewriteResult {
            default_injected: false,
            effective_model: effective,
            mutated: true,
            original_model: Some(model),
            rewritten: true,
        }
    } else {
        RewriteResult {
            default_injected: false,
            effective_model: model.clone(),
            mutated: false,
            original_model: Some(model),
            rewritten: false,
        }
    }
}

/// Resolve exact aliases first, then the most specific single-wildcard alias.
///
/// Equal-specificity wildcard ties use lexical pattern ordering so
/// `HashMap` iteration order cannot affect the result.
fn resolve_alias<'a>(aliases: &'a HashMap<String, String>, model: &str) -> Option<&'a str> {
    if let Some(target) = aliases.get(model) {
        return Some(target);
    }

    let mut best: Option<(&str, &str, u32)> = None;
    for (pattern, target) in aliases {
        if !pattern.contains('*') || !pattern_matches(pattern, model) {
            continue;
        }

        let specificity = pattern_specificity(pattern);
        let should_replace = best.is_none_or(|(best_pattern, _, best_specificity)| {
            specificity > best_specificity || (specificity == best_specificity && pattern.as_str() < best_pattern)
        });
        if should_replace {
            best = Some((pattern, target, specificity));
        }
    }
    best.map(|(_, target, _)| target)
}

/// Match an exact or single-wildcard alias pattern against a model name.
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if let Some(pos) = pattern.find('*') {
        let (prefix, rest) = pattern.split_at(pos);
        let suffix = rest.get(1..).unwrap_or_default();
        value.starts_with(prefix) && value.ends_with(suffix) && value.len() >= prefix.len() + suffix.len()
    } else {
        pattern == value
    }
}

/// Exact patterns sort above wildcards; wildcard specificity is literal length.
fn pattern_specificity(pattern: &str) -> u32 {
    if pattern.contains('*') {
        let literal_len = pattern.len().saturating_sub(1);
        u32::try_from(literal_len).unwrap_or(u32::MAX - 1)
    } else {
        u32::MAX
    }
}

/// Inject default model when the model field is missing or null.
fn apply_default(obj: &mut serde_json::Map<String, serde_json::Value>, default_model: Option<&str>) -> RewriteResult {
    if let Some(dm) = default_model {
        let effective = dm.to_owned();
        obj.insert("model".to_owned(), serde_json::Value::String(effective.clone()));
        RewriteResult {
            default_injected: true,
            effective_model: effective,
            mutated: true,
            original_model: None,
            rewritten: false,
        }
    } else {
        RewriteResult {
            default_injected: false,
            effective_model: String::new(),
            mutated: false,
            original_model: None,
            rewritten: false,
        }
    }
}

/// Build a no-op result for non-string model values.
fn noop_result() -> RewriteResult {
    RewriteResult {
        default_injected: false,
        effective_model: String::new(),
        mutated: false,
        original_model: None,
        rewritten: false,
    }
}

/// Serialize the mutated body, update content-length, and log.
fn serialize_and_update(
    ctx: &mut HttpFilterContext<'_>,
    body: &mut Option<Bytes>,
    value: &serde_json::Value,
    result: &RewriteResult,
) -> Result<FilterAction, FilterError> {
    let serialized = serde_json::to_vec(value).map_err(|e| -> FilterError {
        format!("openai_responses_model_rewrite: failed to re-serialize rewritten request body: {e}").into()
    })?;

    let len = serialized.len();
    *body = Some(Bytes::from(serialized));

    ctx.extra_request_headers
        .push((Cow::Borrowed("content-length"), len.to_string()));

    debug!(
        original = ?result.original_model,
        effective = %result.effective_model,
        "model rewritten"
    );

    Ok(FilterAction::Continue)
}

// -----------------------------------------------------------------------------
// Promotion Helpers
// -----------------------------------------------------------------------------

/// Promote rewrite facts to durable metadata, request headers,
/// and filter results.
///
/// Filter results are also repopulated in `on_request` because
/// a preceding filter's branch evaluation clears them before this
/// filter's branches fire.
fn promote_facts(ctx: &mut HttpFilterContext<'_>, result: &RewriteResult, headers: &config::ModelRewriteHeaders) {
    write_metadata(ctx, result);
    promote_headers(ctx, result, headers);
    set_filter_results_from_result(ctx, result);
}

/// Write durable metadata for downstream filters.
///
/// Applies the same safety and length policy used for header
/// promotion so request-controlled model values containing
/// control characters are not written to metadata.
fn write_metadata(ctx: &mut HttpFilterContext<'_>, result: &RewriteResult) {
    if let Some(orig) = &result.original_model
        && is_safe_promoted_value(orig)
        && orig.len() <= MAX_PROMOTED_VALUE_LEN
    {
        ctx.set_metadata("openai_responses_model_rewrite.original_model", orig.clone());
    }
    if !result.effective_model.is_empty()
        && is_safe_promoted_value(&result.effective_model)
        && result.effective_model.len() <= MAX_PROMOTED_VALUE_LEN
    {
        ctx.set_metadata(
            "openai_responses_model_rewrite.effective_model",
            result.effective_model.clone(),
        );
    }
    if result.rewritten {
        ctx.set_metadata("openai_responses_model_rewrite.rewritten", "true");
    }
    if result.default_injected {
        ctx.set_metadata("openai_responses_model_rewrite.default_injected", "true");
    }
}

/// Promote model values to configurable request headers.
fn promote_headers(ctx: &mut HttpFilterContext<'_>, result: &RewriteResult, headers: &config::ModelRewriteHeaders) {
    if let Some(header) = &headers.effective_model
        && !result.effective_model.is_empty()
        && is_safe_promoted_value(&result.effective_model)
        && result.effective_model.len() <= MAX_PROMOTED_VALUE_LEN
    {
        ctx.extra_request_headers
            .push((Cow::Owned(header.clone()), result.effective_model.clone()));
    }

    if let Some(header) = &headers.original_model
        && let Some(orig) = &result.original_model
        && is_safe_promoted_value(orig)
        && orig.len() <= MAX_PROMOTED_VALUE_LEN
    {
        ctx.extra_request_headers
            .push((Cow::Owned(header.clone()), orig.clone()));
    }
}

/// Set filter results from a [`RewriteResult`] (body pre-read phase).
fn set_filter_results_from_result(ctx: &mut HttpFilterContext<'_>, result: &RewriteResult) {
    let results = ctx.filter_results.entry("openai_responses_model_rewrite").or_default();

    if !result.effective_model.is_empty()
        && is_safe_promoted_value(&result.effective_model)
        && result.effective_model.len() <= MAX_PROMOTED_VALUE_LEN
    {
        set_filter_result(results, "effective_model", result.effective_model.clone());
    }
    if result.rewritten {
        set_filter_result(results, "rewritten", "true");
    }
    if result.default_injected {
        set_filter_result(results, "default_injected", "true");
    }
}

/// Repopulate filter results from durable metadata.
///
/// Branch chains evaluate after `on_request`, not after body
/// pre-read. A preceding filter's branch evaluation clears
/// `filter_results` before this filter's branches fire. This
/// function rebuilds results from the metadata written during
/// body pre-read so branches on this filter work correctly.
fn repopulate_filter_results(ctx: &mut HttpFilterContext<'_>) {
    let effective = ctx
        .get_metadata("openai_responses_model_rewrite.effective_model")
        .map(str::to_owned);
    let rewritten = ctx.get_metadata("openai_responses_model_rewrite.rewritten") == Some("true");
    let default_injected = ctx.get_metadata("openai_responses_model_rewrite.default_injected") == Some("true");

    if effective.is_none() && !rewritten && !default_injected {
        return;
    }

    let results = ctx.filter_results.entry("openai_responses_model_rewrite").or_default();
    if let Some(eff) = effective {
        set_filter_result(results, "effective_model", eff);
    }
    if rewritten {
        set_filter_result(results, "rewritten", "true");
    }
    if default_injected {
        set_filter_result(results, "default_injected", "true");
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Set a filter result and log validation failures.
fn set_filter_result(
    results: &mut crate::results::FilterResultSet,
    key: &'static str,
    value: impl Into<Cow<'static, str>>,
) {
    if let Err(err) = results.set(key, value) {
        warn!(error = %err, key, "failed to set model rewrite filter result");
    }
}

/// Map [`OnInvalidBehavior`] to the appropriate [`FilterAction`].
fn invalid_body_action(behavior: OnInvalidBehavior, streaming: bool) -> FilterAction {
    match behavior {
        OnInvalidBehavior::Continue => FilterAction::Continue,
        OnInvalidBehavior::Reject => FilterAction::Reject(responses_error_rejection(
            400,
            "invalid_request_error",
            "invalid JSON body",
            streaming,
        )),
    }
}
