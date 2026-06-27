// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

#![deny(unreachable_pub)]

//! HTTP callout filter for Praxis.
//!
//! Provides an [`HttpFilter`] that makes outbound HTTP requests during
//! request processing, extracts results from the response via `JSONPath`,
//! and feeds them into [`FilterResultSet`] for branch-chain evaluation.
//!
//! [`HttpFilter`]: praxis_filter::HttpFilter
//! [`FilterResultSet`]: praxis_filter::FilterResultSet

mod config;
mod extract;

use std::borrow::Cow;

use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::callout::{
    CalloutClient, CalloutConfig, CalloutRequest, CalloutResponse, CalloutResult,
    CircuitBreakerConfig as CoreCircuitBreakerConfig, DEPTH_HEADER, FailureMode,
};
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext, Rejection, parse_filter_config,
};
use tracing::debug;

use crate::{
    config::{FailureModeConfig, HttpCalloutConfig, Phase, expand_env_vars, validate_callout_url},
    extract::CompiledExtraction,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Filter type name.
const FILTER_NAME: &str = "http_callout";

// -----------------------------------------------------------------------------
// HttpCalloutFilter
// -----------------------------------------------------------------------------

/// HTTP callout filter.
///
/// Makes an outbound HTTP request during request processing,
/// optionally forwarding the request body and downstream headers.
/// Extracts values from the callout response via `JSONPath` and
/// writes them to [`FilterResultSet`] for branch-chain evaluation.
///
/// [`FilterResultSet`]: praxis_filter::FilterResultSet
struct HttpCalloutFilter {
    /// Reusable HTTP callout client.
    client: CalloutClient,

    /// Pre-compiled `JSONPath` extraction rules.
    extractions: Vec<CompiledExtraction>,

    /// Downstream headers to copy into the callout request.
    forward_headers: Vec<http::HeaderName>,

    /// Static headers to send with every callout.
    headers: Vec<(http::HeaderName, http::HeaderValue)>,

    /// Callout response headers to inject into the upstream
    /// request on success.
    inject_headers: Vec<http::HeaderName>,

    /// Maximum request body bytes to buffer.
    max_body_bytes: usize,

    /// Callout response headers to include in the rejection
    /// response when the callout returns non-2xx.
    on_denied_headers: Vec<http::HeaderName>,

    /// When the callout fires.
    phase: Phase,

    /// Target URL for the callout.
    url: String,
}

impl HttpCalloutFilter {
    /// Construct the filter from a YAML config value.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if config parsing, SSRF validation,
    /// env-var expansion, `JSONPath` compilation, or client
    /// construction fails.
    fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: HttpCalloutConfig = parse_filter_config(FILTER_NAME, config)?;

        validate_callout_url(&cfg.target.url)?;

        let headers = parse_static_headers(&cfg)?;
        let forward_headers = parse_header_names(&cfg.target.forward_headers, "forward_header")?;
        let extractions = compile_extractions(&cfg)?;
        let inject_headers = parse_header_names(&cfg.response.inject_headers, "inject_header")?;
        let on_denied_headers = parse_header_names(&cfg.response.on_denied_headers, "on_denied_header")?;

        let client = build_callout_client(&cfg)?;

        Ok(Box::new(Self {
            client,
            extractions,
            forward_headers,
            headers,
            inject_headers,
            max_body_bytes: cfg.request.max_body_bytes,
            on_denied_headers,
            phase: cfg.request.phase,
            url: cfg.target.url,
        }))
    }

    /// Build a [`CalloutRequest`] from the current filter context.
    fn build_request(&self, ctx: &HttpFilterContext<'_>, body: Option<Vec<u8>>) -> CalloutRequest {
        let depth = ctx
            .request
            .headers
            .get(DEPTH_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let mut headers = self.headers.clone();

        for name in &self.forward_headers {
            if let Some(value) = ctx.request.headers.get(name) {
                headers.push((name.clone(), value.clone()));
            }
        }

        CalloutRequest {
            body,
            depth,
            headers,
            method: http::Method::POST,
            url: self.url.clone(),
        }
    }

    /// Process a successful callout response: extract results and
    /// inject headers.
    fn handle_success(
        &self,
        response: &CalloutResponse,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        if !self.extractions.is_empty() {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&response.body) {
                let results = ctx.filter_results.entry(self.name()).or_default();
                for extraction in &self.extractions {
                    extraction.evaluate(&json, results)?;
                }
            } else {
                debug!("callout response body is not valid JSON; skipping extraction");
            }
        }

        for name in &self.inject_headers {
            if let Some((_, value)) = response.headers.iter().find(|(n, _)| n == name)
                && let Ok(value_str) = value.to_str()
            {
                ctx.extra_request_headers
                    .push((Cow::Owned(name.to_string()), value_str.to_owned()));
            }
        }

        Ok(FilterAction::Continue)
    }

    /// Build a rejection with on-denied headers from the callout
    /// response, if available.
    fn build_rejection(&self, response: Option<&CalloutResponse>, status: u16) -> FilterAction {
        let mut rejection = Rejection::status(status);

        if let Some(resp) = response {
            for name in &self.on_denied_headers {
                if let Some((_, value)) = resp.headers.iter().find(|(n, _)| n == name)
                    && let Ok(value_str) = value.to_str()
                {
                    rejection = rejection.with_header(name.to_string(), value_str.to_owned());
                }
            }
        }

        FilterAction::Reject(rejection)
    }

    /// Execute the callout and process the result.
    async fn execute_callout(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: Option<Vec<u8>>,
    ) -> Result<FilterAction, FilterError> {
        let request = self.build_request(ctx, body);
        let result = self.client.execute(request).await;

        match result {
            CalloutResult::Success(response) => self.handle_success(&response, ctx),
            CalloutResult::Failed => {
                debug!("callout failed (open mode); continuing");
                Ok(FilterAction::Continue)
            },
            CalloutResult::Rejected(rejection) => Ok(self.build_rejection(None, rejection.status)),
        }
    }
}

// -----------------------------------------------------------------------------
// Config Parsing Helpers
// -----------------------------------------------------------------------------

/// Parse static header entries with env-var expansion.
fn parse_static_headers(cfg: &HttpCalloutConfig) -> Result<Vec<(http::HeaderName, http::HeaderValue)>, FilterError> {
    cfg.target
        .headers
        .iter()
        .map(|h| {
            let expanded = expand_env_vars(&h.value)?;
            let name: http::HeaderName = h.name.parse().map_err(|e| -> FilterError {
                format!("http_callout: invalid header name '{}': {e}", h.name).into()
            })?;
            let value: http::HeaderValue = expanded.parse().map_err(|e| -> FilterError {
                format!("http_callout: invalid header value for '{}': {e}", h.name).into()
            })?;
            Ok((name, value))
        })
        .collect()
}

/// Parse a list of header name strings.
fn parse_header_names(names: &[String], context: &str) -> Result<Vec<http::HeaderName>, FilterError> {
    names
        .iter()
        .map(|h| {
            h.parse::<http::HeaderName>()
                .map_err(|e| -> FilterError { format!("http_callout: invalid {context} '{h}': {e}").into() })
        })
        .collect()
}

/// Compile `JSONPath` extraction rules from config.
fn compile_extractions(cfg: &HttpCalloutConfig) -> Result<Vec<CompiledExtraction>, FilterError> {
    cfg.response
        .extract
        .iter()
        .map(|e| CompiledExtraction::compile(&e.json_path, e.result_key.clone()))
        .collect()
}

/// Build the [`CalloutClient`] from parsed config.
#[expect(
    clippy::cast_possible_truncation,
    reason = "durations are bounded by config validation"
)]
fn build_callout_client(cfg: &HttpCalloutConfig) -> Result<CalloutClient, FilterError> {
    let failure_mode = match cfg.on_failure {
        FailureModeConfig::Closed => FailureMode::Closed,
        FailureModeConfig::Open => FailureMode::Open,
    };

    let circuit_breaker = cfg.circuit_breaker.as_ref().map(|cb| CoreCircuitBreakerConfig {
        consecutive_failures: cb.failure_threshold,
        recovery_window_ms: cb.recovery_timeout.as_millis() as u64,
    });

    let callout_config = CalloutConfig {
        circuit_breaker,
        failure_mode,
        max_depth: cfg.max_depth.unwrap_or(1),
        status_on_error: cfg.status_on_error.unwrap_or(403),
        timeout_ms: cfg.target.timeout.as_millis() as u64,
        ..CalloutConfig::default()
    };

    CalloutClient::new(callout_config).map_err(|e| -> FilterError { format!("http_callout: {e}").into() })
}

// -----------------------------------------------------------------------------
// HttpFilter Implementation
// -----------------------------------------------------------------------------

#[async_trait]
impl HttpFilter for HttpCalloutFilter {
    fn name(&self) -> &'static str {
        FILTER_NAME
    }

    fn request_body_access(&self) -> BodyAccess {
        match self.phase {
            Phase::RequestBody => BodyAccess::ReadOnly,
            Phase::RequestHeaders => BodyAccess::None,
        }
    }

    fn request_body_mode(&self) -> BodyMode {
        match self.phase {
            Phase::RequestBody => BodyMode::StreamBuffer {
                max_bytes: Some(self.max_body_bytes),
            },
            Phase::RequestHeaders => BodyMode::Stream,
        }
    }

    fn needs_request_context(&self) -> bool {
        true
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if self.phase != Phase::RequestHeaders {
            return Ok(FilterAction::Continue);
        }

        self.execute_callout(ctx, None).await
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if self.phase != Phase::RequestBody || !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let body_bytes = body.as_ref().map(|b| b.to_vec());
        self.execute_callout(ctx, body_bytes).await
    }
}

// -----------------------------------------------------------------------------
// Filter Registration
// -----------------------------------------------------------------------------

praxis_filter::export_filters! {
    http "http_callout" => HttpCalloutFilter::from_config,
}
