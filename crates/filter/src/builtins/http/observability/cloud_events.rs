// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `CloudEvents` structured-JSON publisher.

use std::{
    collections::BTreeMap,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, SecondsFormat, Utc};
use http::{
    HeaderMap, HeaderValue, Method, StatusCode, Uri,
    header::{CONTENT_TYPE, HeaderName},
};
use serde::Deserialize;
use serde_json::{Map, Value};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::{
    BodyAccess, FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// CloudEventsFilter
// -----------------------------------------------------------------------------

/// Generate structured `CloudEvents` and ship them to a configured HTTP endpoint.
///
/// Experimental: requires the off-by-default `cloud-events-filter` feature.
/// Review its best-effort delivery limitations before using it in production.
///
/// # YAML configuration
///
/// ```yaml
/// filter: cloud_events
/// on: response_complete
/// destination: https://events.example.net/v1/events
/// authorization:
///   env_var: METERING_AUTH_TOKEN
/// delivery: best_effort
/// format: structured_json
/// source: urn:praxis:gateway
/// type: inference.tokens.used
/// size_limit_bytes: 65536
/// delivery_timeout_ms: 3000
/// include_provenance: false
/// context_fields:
///   - identity.subject_id
///   - identity.claim.group
///   - identity.claim.subscription
///   - identity.claim.model
///   - cluster
/// request_headers: [user-agent]
/// metadata_fields:
///   - token.input
///   - token.output
///   - token.total
///   - token.cache_read
///   - token.cache_write
///   - token.reasoning
/// subject: { value: context.identity.subject_id, type: string, required: true }
/// data:
///   user: { value: context.identity.subject_id, type: string, required: true }
///   provider: { value: context.cluster, type: string }
///   user_agent: { value: request_header.user-agent, type: string }
///   total_tokens: { value: metadata.token.total, type: integer, required: true }
/// ```
///
/// Mapped values are resolved only from explicitly allowlisted context fields,
/// metadata fields, request or response headers, and response status.
/// `authorization.env_var` sends the resolved value as a bearer token without
/// exposing it in logs.
///
/// # Example
///
/// ```ignore
/// use praxis_filter::CloudEventsFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     "on: response_complete\nsource: urn:praxis:gateway\ntype: inference.tokens.used\ndestination: https://events.example.net/events",
/// )
/// .unwrap();
/// let filter = CloudEventsFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "cloud_events");
/// ```
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent config flags cache distinct source requirements"
)]
pub struct CloudEventsFilter {
    /// Selected lifecycle phase.
    on: CloudEventsPhase,
    /// Configured event destination.
    destination: String,
    /// Static `CloudEvents` source.
    source: String,
    /// Static `CloudEvents` type.
    event_type: String,
    /// Optional subject mapping.
    subject: Option<CloudEventsMapping>,
    /// Optional data-schema identifier.
    schema: Option<String>,
    /// Include source-derived provenance for mapped data fields.
    include_provenance: bool,
    /// Allowlisted context fields.
    context_fields: Vec<String>,
    /// Allowlisted request headers.
    request_headers: Vec<String>,
    /// Allowlisted response headers.
    response_headers: Vec<String>,
    /// Whether any mapping reads response headers.
    needs_response_headers: bool,
    /// Whether any mapping reads the response status.
    needs_response_status: bool,
    /// Allowlisted filter metadata fields.
    metadata_fields: Vec<String>,
    /// `CloudEvent` data mappings.
    data: BTreeMap<String, CloudEventsMapping>,
    /// `CloudEvent` extension mappings.
    extensions: BTreeMap<String, CloudEventsMapping>,
    /// Maximum serialized event size.
    size_limit_bytes: usize,
    /// Largest raw mapped value accepted while constructing an event.
    max_mapping_value_bytes: usize,
    /// Maximum outbound delivery time.
    delivery_timeout: Duration,
    /// Optional bearer token for the event receiver.
    authorization_token: Option<Zeroizing<String>>,
}

/// Deserialized configuration for one `CloudEvents` publisher.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudEventsFilterConfig {
    /// Lifecycle phase for this publisher.
    on: CloudEventsPhase,
    /// HTTP endpoint receiving the structured `CloudEvent`.
    destination: String,
    /// Optional environment-backed bearer authorization for the receiver.
    authorization: Option<CloudEventsAuthorizationConfig>,
    /// Delivery guarantee supported by this version.
    #[serde(default)]
    delivery: CloudEventsDelivery,
    /// HTTP `CloudEvents` binding used by this publisher.
    #[serde(default)]
    format: CloudEventsFormat,
    /// Static `CloudEvents` source attribute.
    source: String,
    /// Static `CloudEvents` type attribute.
    #[serde(rename = "type")]
    event_type: String,
    /// Optional `CloudEvents` subject attribute.
    subject: Option<CloudEventsMapping>,
    /// Optional `CloudEvents` data-schema identifier.
    schema: Option<String>,
    /// Include source-derived provenance in reserved `data._praxis_provenance`.
    #[serde(default)]
    include_provenance: bool,
    /// Explicitly allowlisted context references.
    #[serde(default)]
    context_fields: Vec<String>,
    /// Explicitly allowlisted request header names.
    #[serde(default)]
    request_headers: Vec<String>,
    /// Explicitly allowlisted response header names.
    #[serde(default)]
    response_headers: Vec<String>,
    /// Explicitly allowlisted filter metadata references.
    #[serde(default)]
    metadata_fields: Vec<String>,
    /// Mapped `CloudEvent` data fields.
    #[serde(default)]
    data: BTreeMap<String, CloudEventsMapping>,
    /// Mapped `CloudEvent` extension attributes.
    #[serde(default)]
    extensions: BTreeMap<String, CloudEventsMapping>,
    /// Maximum serialized event size in bytes (1 through 65536).
    #[serde(default = "default_size_limit_bytes")]
    size_limit_bytes: usize,
    /// Maximum outbound delivery time in milliseconds.
    #[serde(default = "default_delivery_timeout_ms")]
    delivery_timeout_ms: u64,
}

/// Environment-backed authorization for the `CloudEvents` receiver.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CloudEventsAuthorizationConfig {
    /// Environment variable containing the bearer token.
    env_var: String,
}

/// Maximum receiver response body retained by a best-effort publication.
const MAX_DELIVERY_RESPONSE_BYTES: usize = 4_096;

/// Maximum serialized `CloudEvent` size accepted.
const MAX_EVENT_SIZE_BYTES: usize = 65_536; // 64 KiB

/// Maximum `CloudEvents` delivery tasks across all publishers.
const MAX_PENDING_DELIVERIES: usize = 64;

/// Maximum explicitly configured mapped values in one event.
const MAX_EVENT_MAPPINGS: usize = 64;

/// Process-wide bound for active `CloudEvents` deliveries.
static DELIVERY_PERMITS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(MAX_PENDING_DELIVERIES)));

// -----------------------------------------------------------------------------
// Configuration types
// -----------------------------------------------------------------------------

/// Lifecycle phase at which a `CloudEvent` is published.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum CloudEventsPhase {
    /// Publish during request processing.
    Request,
    /// Publish after response headers are available.
    ResponseHeaders,
    /// Publish after the response has completed.
    ResponseComplete,
}

/// Delivery behavior for a `CloudEvents` publisher.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum CloudEventsDelivery {
    /// Attempt delivery without changing the proxied request outcome.
    #[default]
    BestEffort,
}

/// Wire format for a `CloudEvents` publisher.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum CloudEventsFormat {
    /// `CloudEvents` structured-mode JSON over HTTP.
    #[default]
    StructuredJson,
}

/// Type conversion requested for a mapped value.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum CloudEventsValueType {
    /// Serialize the value as a JSON string.
    String,
    /// Convert the value to a JSON integer.
    Integer,
    /// Convert the value to a JSON boolean.
    Boolean,
    /// Parse the value as JSON.
    Json,
}

/// One explicitly configured value exported into a `CloudEvent`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CloudEventsMapping {
    /// Source reference: `context.*`, `metadata.*`, `request_header.*`, `response_header.*`, or `response.status`.
    value: String,
    /// Output conversion to apply.
    #[serde(rename = "type")]
    value_type: CloudEventsValueType,
    /// Whether failure to resolve this value suppresses the event.
    #[serde(default)]
    required: bool,
}

/// Cached response metadata for emission on the body phase.
#[derive(Clone, Debug)]
struct CloudEventsState {
    /// Response status captured during the response-header phase.
    status: Option<u16>,
    /// Response headers captured during the response-header phase.
    response_headers: Option<HeaderMap>,
    /// Whether this configured publisher already emitted its event.
    emitted: bool,
}

/// Supported mapping source families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloudEventsSource<'a> {
    /// A trusted Praxis context field.
    Context(&'a str),
    /// A value published by an earlier filter.
    Metadata(&'a str),
    /// An explicitly allowlisted request header.
    RequestHeader(&'a str),
    /// An explicitly allowlisted response header.
    ResponseHeader(&'a str),
    /// The upstream response status code.
    ResponseStatus,
}

/// Default maximum serialized event size: 64 KiB.
fn default_size_limit_bytes() -> usize {
    65_536 // 64 KiB
}

/// Default outbound delivery timeout: 3 seconds.
fn default_delivery_timeout_ms() -> u64 {
    3_000
}

// -----------------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------------

impl CloudEventsFilter {
    /// Create a `CloudEvents` filter from parsed YAML configuration.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: CloudEventsFilterConfig = parse_filter_config("cloud_events", config)?;
        Ok(Box::new(Self::build(cfg)?))
    }

    /// Build validated runtime state from one configuration.
    #[expect(
        clippy::too_many_lines,
        reason = "construction derives bounded runtime state from one config"
    )]
    fn build(cfg: CloudEventsFilterConfig) -> Result<Self, FilterError> {
        validate_config(&cfg)?;

        let mapping_count = cfg
            .data
            .len()
            .saturating_add(cfg.extensions.len())
            .saturating_add(usize::from(cfg.subject.is_some()));

        let needs_response_headers = cfg
            .subject
            .iter()
            .chain(cfg.data.values())
            .chain(cfg.extensions.values())
            .any(|mapping| matches!(parse_source(&mapping.value), Some(CloudEventsSource::ResponseHeader(_))));
        let needs_response_status = cfg
            .subject
            .iter()
            .chain(cfg.data.values())
            .chain(cfg.extensions.values())
            .any(|mapping| matches!(parse_source(&mapping.value), Some(CloudEventsSource::ResponseStatus)));
        let _ = (cfg.delivery, cfg.format);
        let authorization_token = cfg.authorization.as_ref().map(resolve_authorization).transpose()?;

        Ok(Self {
            on: cfg.on,
            destination: cfg.destination,
            source: cfg.source,
            event_type: cfg.event_type,
            subject: cfg.subject,
            schema: cfg.schema,
            include_provenance: cfg.include_provenance,
            context_fields: cfg.context_fields,
            request_headers: cfg.request_headers,
            response_headers: cfg.response_headers,
            needs_response_headers,
            needs_response_status,
            metadata_fields: cfg.metadata_fields,
            data: cfg.data,
            extensions: cfg.extensions,
            size_limit_bytes: cfg.size_limit_bytes,
            max_mapping_value_bytes: cfg.size_limit_bytes / mapping_count.max(1),
            delivery_timeout: Duration::from_millis(cfg.delivery_timeout_ms),
            authorization_token,
        })
    }

    /// Build and enqueue one event without affecting the client response.
    fn maybe_emit(&self, ctx: &mut HttpFilterContext<'_>) {
        if ctx
            .get_filter_state::<CloudEventsState>()
            .is_some_and(|state| state.emitted)
        {
            return;
        }

        let Some(event) = self.build_event(ctx) else {
            crate::metrics::record_cloud_events_skipped("missing_required");
            Self::mark_emitted(ctx);
            return;
        };
        self.enqueue_event(ctx, &event);
        Self::mark_emitted(ctx);
    }

    /// Enqueue one bounded best-effort delivery without changing filter state.
    #[expect(
        clippy::large_futures,
        clippy::large_stack_frames,
        clippy::too_many_lines,
        reason = "delivery preparation and bounded failure telemetry stay together"
    )]
    fn enqueue_event(&self, ctx: &HttpFilterContext<'_>, event: &Value) -> bool {
        let Ok(permit) = Arc::clone(&DELIVERY_PERMITS).try_acquire_owned() else {
            crate::metrics::record_cloud_events_skipped("backpressure");
            return false;
        };
        let Ok(body) = serde_json::to_vec(&event) else {
            crate::metrics::record_cloud_events_skipped("serialization");
            return false;
        };
        if body.len() > self.size_limit_bytes {
            crate::metrics::record_cloud_events_skipped("size_limit");
            return false;
        }
        let Some(client) = ctx.subrequest_client().cloned() else {
            crate::metrics::record_cloud_events_skipped("missing_client");
            return false;
        };

        let destination = self.destination.clone();
        let timeout = self.delivery_timeout;
        let authorization_token = self.authorization_token.as_ref().map(|token| token.to_string());
        let mut headers =
            HeaderMap::from_iter([(CONTENT_TYPE, HeaderValue::from_static("application/cloudevents+json"))]);
        if let Some(token) = authorization_token {
            let value = format!("Bearer {token}");
            if let Ok(value) = HeaderValue::from_str(&value) {
                headers.insert(http::header::AUTHORIZATION, value);
            } else {
                crate::metrics::record_cloud_events_skipped("invalid_authorization");
                return false;
            }
        }
        let request = praxis_core::subrequest::SubRequest {
            method: Method::POST,
            // `PreparedTarget::bind` replaces this with the destination path.
            uri: Uri::from_static("/"),
            headers,
            body: Bytes::from(body),
        };

        // share the runtime subrequest pool;
        // TODO(#1203): add a dedicated background/event pool if event bursts
        // contend with request-critical callouts.
        crate::metrics::record_cloud_events_attempt();
        tokio::spawn(async move {
            // Hold the permit until delivery completes so the semaphore bounds active
            // deliveries, not only task creation.
            let _permit = permit;
            let started = Instant::now();
            let deadline = Instant::now() + timeout;
            let Ok(target) = praxis_core::connectivity::prepare_url_target(&destination, deadline, |_| Ok(())).await
            else {
                crate::metrics::record_cloud_events_publish(
                    "failure",
                    "destination",
                    None,
                    started.elapsed().as_secs_f64(),
                );
                return;
            };
            let prepared = target.bind(request);
            let Some(peer) = prepared.peer_at(0) else {
                crate::metrics::record_cloud_events_publish(
                    "failure",
                    "destination",
                    None,
                    started.elapsed().as_secs_f64(),
                );
                return;
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                crate::metrics::record_cloud_events_publish(
                    "failure",
                    "timeout",
                    None,
                    started.elapsed().as_secs_f64(),
                );
                return;
            }
            match client
                .execute(&peer, prepared.request(), MAX_DELIVERY_RESPONSE_BYTES, remaining, None)
                .await
            {
                Ok(response) if (200..300).contains(&response.status) => {
                    crate::metrics::record_cloud_events_publish(
                        "success",
                        "none",
                        Some(response.status),
                        started.elapsed().as_secs_f64(),
                    );
                },
                Ok(response) => {
                    if matches!(response.status, 401 | 403) {
                        tracing::warn!(
                            destination = %destination,
                            status = response.status,
                            "cloud_events: receiver rejected event delivery"
                        );
                    }
                    crate::metrics::record_cloud_events_publish(
                        "failure",
                        "http_status",
                        Some(response.status),
                        started.elapsed().as_secs_f64(),
                    );
                },
                Err(error) => {
                    crate::metrics::record_cloud_events_publish(
                        "failure",
                        cloud_events_failure_class(&error),
                        None,
                        started.elapsed().as_secs_f64(),
                    );
                },
            }
        });
        true
    }

    /// Mark this filter invocation as having completed its publication decision.
    fn mark_emitted(ctx: &mut HttpFilterContext<'_>) {
        if let Some(state) = ctx.get_filter_state_mut::<CloudEventsState>() {
            state.emitted = true;
        }
    }

    /// Build one structured `CloudEvent` without performing network delivery.
    fn build_event(&self, ctx: &HttpFilterContext<'_>) -> Option<Value> {
        self.build_event_with_state(ctx, ctx.get_filter_state::<CloudEventsState>())
    }

    /// Build an event using an explicitly supplied response state.
    #[expect(
        clippy::too_many_lines,
        reason = "envelope and payload assembly stay in one bounded operation"
    )]
    fn build_event_with_state(&self, ctx: &HttpFilterContext<'_>, state: Option<&CloudEventsState>) -> Option<Value> {
        let mut event = Map::from_iter([
            ("specversion".to_owned(), Value::String("1.0".to_owned())),
            (
                "id".to_owned(),
                Value::String(ctx.id_generator.generate(ctx.time_source)),
            ),
            ("source".to_owned(), Value::String(self.source.clone())),
            ("type".to_owned(), Value::String(self.event_type.clone())),
            ("time".to_owned(), Value::String(event_time(ctx))),
        ]);

        if let Some(mapping) = &self.subject {
            if let Some(value) = self.resolve_mapping(ctx, state, mapping) {
                event.insert("subject".to_owned(), value);
            } else if mapping.required {
                return None;
            }
        }

        if let Some(schema) = &self.schema {
            event.insert("dataschema".to_owned(), Value::String(schema.clone()));
        }

        let mut data = Map::new();
        let mut provenance = Map::new();
        for (name, mapping) in &self.data {
            let Some(value) = self.resolve_mapping(ctx, state, mapping) else {
                if mapping.required {
                    return None;
                }
                continue;
            };
            data.insert(name.clone(), value);
            if self.include_provenance {
                provenance.insert(name.clone(), Value::String(mapping_provenance(mapping).to_owned()));
            }
        }
        if self.include_provenance {
            data.insert("_praxis_provenance".to_owned(), Value::Object(provenance));
        }
        event.insert("data".to_owned(), Value::Object(data));

        for (name, mapping) in &self.extensions {
            let Some(value) = self.resolve_mapping(ctx, state, mapping) else {
                if mapping.required {
                    return None;
                }
                continue;
            };
            event.insert(name.clone(), value);
        }

        Some(Value::Object(event))
    }

    /// Resolve one configured mapping from an explicitly allowlisted source.
    #[expect(
        clippy::too_many_lines,
        reason = "source-specific allowlist checks stay local to resolution"
    )]
    fn resolve_mapping(
        &self,
        ctx: &HttpFilterContext<'_>,
        state: Option<&CloudEventsState>,
        mapping: &CloudEventsMapping,
    ) -> Option<Value> {
        let source = parse_source(&mapping.value)?;
        let raw = match source {
            CloudEventsSource::Context(name) => {
                if !self.context_fields.iter().any(|field| field == name) {
                    return None;
                }
                resolve_context(ctx, name)
            },
            CloudEventsSource::Metadata(name) => {
                if !self.metadata_fields.iter().any(|field| field == name) {
                    return None;
                }
                ctx.get_metadata(name).map(str::to_owned)
            },
            CloudEventsSource::RequestHeader(name) => {
                if !self
                    .request_headers
                    .iter()
                    .any(|header| header.eq_ignore_ascii_case(name))
                {
                    return None;
                }
                ctx.request
                    .headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            },
            CloudEventsSource::ResponseHeader(name) => {
                if !self
                    .response_headers
                    .iter()
                    .any(|header| header.eq_ignore_ascii_case(name))
                {
                    return None;
                }
                state
                    .and_then(|state| state.response_headers.as_ref())
                    .and_then(|headers| headers.get(name))
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            },
            CloudEventsSource::ResponseStatus => state.and_then(|state| state.status).map(|status| status.to_string()),
        }?;

        if raw.len() > self.max_mapping_value_bytes {
            return None;
        }

        convert_value(raw, mapping.value_type)
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "lifecycle hooks share phase-specific state transitions"
)]
#[async_trait]
impl HttpFilter for CloudEventsFilter {
    fn name(&self) -> &'static str {
        "cloud_events"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if self.on != CloudEventsPhase::Request {
            return Ok(FilterAction::Continue);
        }
        ctx.insert_filter_state(CloudEventsState {
            status: None,
            response_headers: None,
            emitted: false,
        });
        self.maybe_emit(ctx);
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        // Interim responses can invoke this hook before the final response.
        // `101 Switching Protocols` is an upgrade response and is final.
        if ctx.response_header.as_ref().is_some_and(|response| {
            response.status.is_informational() && response.status != StatusCode::SWITCHING_PROTOCOLS
        }) {
            return Ok(FilterAction::Continue);
        }
        if self.on == CloudEventsPhase::ResponseHeaders {
            let Some(response) = ctx.response_header.as_ref() else {
                return Ok(FilterAction::Continue);
            };
            ctx.insert_filter_state(CloudEventsState {
                status: self.needs_response_status.then_some(response.status.as_u16()),
                response_headers: self.needs_response_headers.then(|| response.headers.clone()),
                emitted: false,
            });
            self.maybe_emit(ctx);
            return Ok(FilterAction::Continue);
        }
        if self.on == CloudEventsPhase::ResponseComplete {
            let (status, response_headers, bodyless, has_response) = match ctx.response_header.as_ref() {
                Some(response) => (
                    self.needs_response_status.then_some(response.status.as_u16()),
                    self.needs_response_headers.then(|| response.headers.clone()),
                    super::bodyless_response(response.status, &ctx.request.method),
                    true,
                ),
                None => (None, None, false, false),
            };

            ctx.insert_filter_state(CloudEventsState {
                status,
                response_headers,
                emitted: false,
            });

            if bodyless || !has_response {
                self.maybe_emit(ctx);
            }
        }
        Ok(FilterAction::Continue)
    }

    // TODO(#1228): generalize deferred-record dispatch so incomplete lifecycle
    // handling is not coupled to the access-log fallback path.
    fn emit_deferred_record(&self, ctx: &HttpFilterContext<'_>, status: u16) -> bool {
        if self.on != CloudEventsPhase::ResponseComplete
            || ctx
                .get_filter_state::<CloudEventsState>()
                .is_some_and(|state| state.emitted)
        {
            return false;
        }

        let fallback_state = CloudEventsState {
            status: (status != 0).then_some(status),
            response_headers: ctx.response_header.as_ref().map(|response| response.headers.clone()),
            emitted: false,
        };
        let state = ctx.get_filter_state::<CloudEventsState>().or(Some(&fallback_state));
        let Some(event) = self.build_event_with_state(ctx, state) else {
            crate::metrics::record_cloud_events_skipped("missing_required");
            return true;
        };
        let _ = self.enqueue_event(ctx, &event);
        true
    }

    fn response_body_access(&self) -> BodyAccess {
        if self.on == CloudEventsPhase::ResponseComplete {
            return BodyAccess::ReadOnly;
        }
        BodyAccess::None
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream && self.on == CloudEventsPhase::ResponseComplete {
            self.maybe_emit(ctx);
        }
        Ok(FilterAction::Continue)
    }
}

/// Map a subrequest failure to a bounded telemetry class.
fn cloud_events_failure_class(error: &praxis_core::subrequest::SubRequestError) -> &'static str {
    use praxis_core::subrequest::SubRequestError;

    match error {
        SubRequestError::AdmissionTimeout { .. } => "admission",
        SubRequestError::DeadlineExceeded | SubRequestError::StreamIdleTimeout { .. } => "timeout",
        SubRequestError::CircuitOpen { .. } => "circuit_open",
        SubRequestError::InvalidRequest(_) => "request",
        SubRequestError::ResponseTooLarge { .. } => "response_too_large",
        _ => "transport",
    }
}

/// Resolve the receiver bearer token once while building the filter.
fn resolve_authorization(config: &CloudEventsAuthorizationConfig) -> Result<Zeroizing<String>, FilterError> {
    if config.env_var.trim().is_empty() {
        return Err("cloud_events: authorization.env_var must not be blank".into());
    }
    let token = std::env::var(&config.env_var).map_err(|error| {
        format!(
            "cloud_events: authorization environment variable {:?} is not set: {error}",
            config.env_var
        )
    })?;
    if token.is_empty() {
        return Err(format!(
            "cloud_events: authorization environment variable {:?} must not be empty",
            config.env_var
        )
        .into());
    }
    authorization_header(&token)?;
    Ok(Zeroizing::new(token))
}

/// Build the receiver's bearer authorization header.
fn authorization_header(token: &str) -> Result<HeaderValue, FilterError> {
    HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_error| "cloud_events: authorization token contains invalid header characters".into())
}

/// Validate configuration that can be checked without a live request.
#[expect(
    clippy::too_many_lines,
    reason = "validation keeps all static safety checks together"
)]
fn validate_config(cfg: &CloudEventsFilterConfig) -> Result<(), FilterError> {
    praxis_core::connectivity::validate_url_target(&cfg.destination)
        .map_err(|error| format!("cloud_events: invalid destination: {error}"))?;
    if !(1..=MAX_EVENT_SIZE_BYTES).contains(&cfg.size_limit_bytes) {
        return Err(format!("cloud_events: size_limit_bytes must be between 1 and {MAX_EVENT_SIZE_BYTES}").into());
    }

    validate_uri_reference("source", &cfg.source)?;
    validate_static_attribute_size("source", &cfg.source, cfg.size_limit_bytes)?;
    if cfg.event_type.trim().is_empty() {
        return Err("cloud_events: type must not be blank".into());
    }
    validate_static_attribute_size("type", &cfg.event_type, cfg.size_limit_bytes)?;
    if cfg
        .subject
        .as_ref()
        .is_some_and(|mapping| mapping.value.trim().is_empty())
    {
        return Err("cloud_events: subject mapping value must not be blank".into());
    }
    if cfg
        .subject
        .as_ref()
        .is_some_and(|mapping| mapping.value_type != CloudEventsValueType::String)
    {
        return Err("cloud_events: subject mapping type must be string".into());
    }
    if let Some(schema) = &cfg.schema {
        validate_uri_reference("schema", schema)?;
        validate_static_attribute_size("schema", schema, cfg.size_limit_bytes)?;
    }
    let mapping_count = cfg
        .data
        .len()
        .saturating_add(cfg.extensions.len())
        .saturating_add(usize::from(cfg.subject.is_some()));
    if mapping_count > MAX_EVENT_MAPPINGS {
        return Err(format!("cloud_events: supports at most {MAX_EVENT_MAPPINGS} mapped values").into());
    }
    if cfg.delivery_timeout_ms == 0 {
        return Err("cloud_events: delivery_timeout_ms must be greater than zero".into());
    }

    validate_context_fields(&cfg.context_fields)?;
    validate_metadata_fields(&cfg.metadata_fields)?;
    validate_headers("request_headers", &cfg.request_headers)?;
    validate_headers("response_headers", &cfg.response_headers)?;
    if let Some(mapping) = &cfg.subject {
        validate_mapping("subject", mapping, cfg)?;
    }
    for (name, mapping) in &cfg.data {
        if name.trim().is_empty() {
            return Err("cloud_events: data field names must not be blank".into());
        }
        if name == "_praxis_provenance" {
            return Err("cloud_events: data field name is reserved: _praxis_provenance".into());
        }
        validate_mapping(&format!("data.{name}"), mapping, cfg)?;
    }
    for (name, mapping) in &cfg.extensions {
        if name.trim().is_empty() {
            return Err("cloud_events: extension names must not be blank".into());
        }
        if is_standard_attribute(name) {
            return Err(format!("cloud_events: extension {name:?} conflicts with a standard attribute").into());
        }
        if !is_valid_extension_attribute_name(name) {
            return Err(format!("cloud_events: extension {name:?} must start with a lowercase letter and contain only lowercase letters or digits").into());
        }
        validate_mapping(&format!("extension.{name}"), mapping, cfg)?;
    }

    Ok(())
}

/// Validate a configured header allowlist.
fn validate_headers(field: &str, headers: &[String]) -> Result<(), FilterError> {
    for header in headers {
        if header.trim() != header || header.is_empty() {
            return Err(format!("cloud_events: {field} contains a blank or padded header name").into());
        }
        HeaderName::from_bytes(header.as_bytes())
            .map_err(|error| format!("cloud_events: {field} contains invalid header {header:?}: {error}"))?;
        if super::is_sensitive_header(header) {
            return Err(format!("cloud_events: header {header:?} is not allowed").into());
        }
    }
    Ok(())
}

/// Validate a URI-valued `CloudEvents` attribute.
fn validate_uri_reference(field: &str, value: &str) -> Result<(), FilterError> {
    if value.trim().is_empty() {
        return Err(format!("cloud_events: {field} must not be blank").into());
    }
    if url::Url::parse(value).is_err() && value.parse::<Uri>().is_err() {
        return Err(format!("cloud_events: invalid {field} URI reference").into());
    }
    Ok(())
}

/// Validate the bounded size of a static attribute.
fn validate_static_attribute_size(field: &str, value: &str, limit: usize) -> Result<(), FilterError> {
    if value.len() > limit {
        return Err(format!("cloud_events: {field} exceeds size_limit_bytes").into());
    }
    Ok(())
}

/// Validate configured context field names.
fn validate_context_fields(fields: &[String]) -> Result<(), FilterError> {
    for field in fields {
        if !is_supported_context_field(field) {
            return Err(format!("cloud_events: unsupported context field {field:?}").into());
        }
    }
    Ok(())
}

/// Validate configured metadata field names.
fn validate_metadata_fields(fields: &[String]) -> Result<(), FilterError> {
    for field in fields {
        if field.trim() != field || field.is_empty() {
            return Err("cloud_events: metadata_fields contains a blank or padded field name".into());
        }
    }
    Ok(())
}

/// Validate one mapping against its configured source allowlists.
#[expect(
    clippy::too_many_lines,
    reason = "mapping validation keeps source-specific safety checks together"
)]
fn validate_mapping(
    field: &str,
    mapping: &CloudEventsMapping,
    cfg: &CloudEventsFilterConfig,
) -> Result<(), FilterError> {
    let source = parse_source(&mapping.value).ok_or_else(|| {
        format!(
            "cloud_events: {field} has an unknown mapping source {:?}",
            mapping.value
        )
    })?;
    match source {
        CloudEventsSource::Context(name) => {
            if name.is_empty() || !cfg.context_fields.iter().any(|allowed| allowed == name) {
                return Err(format!("cloud_events: {field} requires {name:?} in context_fields").into());
            }
            if !is_supported_context_field(name) {
                return Err(format!("cloud_events: {field} references unsupported context field {name:?}").into());
            }
        },
        CloudEventsSource::Metadata(name) => {
            if name.is_empty() || !cfg.metadata_fields.iter().any(|allowed| allowed == name) {
                return Err(format!("cloud_events: {field} requires {name:?} in metadata_fields").into());
            }
        },
        CloudEventsSource::RequestHeader(name) => {
            validate_mapping_header(field, name, &cfg.request_headers)?;
        },
        CloudEventsSource::ResponseHeader(name) => {
            if cfg.on == CloudEventsPhase::Request {
                return Err(format!("cloud_events: {field} cannot use response headers during request phase").into());
            }
            validate_mapping_header(field, name, &cfg.response_headers)?;
        },
        CloudEventsSource::ResponseStatus => {
            if cfg.on == CloudEventsPhase::Request {
                return Err(format!("cloud_events: {field} cannot use response status during request phase").into());
            }
        },
    }
    Ok(())
}

/// Validate one mapped header against an allowlist.
fn validate_mapping_header(field: &str, name: &str, allowlist: &[String]) -> Result<(), FilterError> {
    if name.is_empty() || !allowlist.iter().any(|allowed| allowed.eq_ignore_ascii_case(name)) {
        return Err(format!("cloud_events: {field} requires {name:?} in its header allowlist").into());
    }
    Ok(())
}

/// Return whether an extension name conflicts with a standard attribute.
fn is_standard_attribute(name: &str) -> bool {
    matches!(
        name,
        "specversion"
            | "id"
            | "source"
            | "type"
            | "subject"
            | "time"
            | "dataschema"
            | "data"
            | "data_base64"
            | "datacontenttype"
    )
}

/// Return whether an extension name satisfies the configured naming rule.
fn is_valid_extension_attribute_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

/// Return whether a context field is supported by this filter version.
fn is_supported_context_field(name: &str) -> bool {
    matches!(name, "cluster" | "identity.subject_id")
        || name
            .strip_prefix("identity.claim.")
            .is_some_and(|claim| !claim.is_empty())
}

/// Classify a configured mapping source by its explicit prefix.
fn parse_source(value: &str) -> Option<CloudEventsSource<'_>> {
    value
        .strip_prefix("context.")
        .map(CloudEventsSource::Context)
        .or_else(|| value.strip_prefix("metadata.").map(CloudEventsSource::Metadata))
        .or_else(|| {
            value
                .strip_prefix("request_header.")
                .map(CloudEventsSource::RequestHeader)
        })
        .or_else(|| {
            value
                .strip_prefix("response_header.")
                .map(CloudEventsSource::ResponseHeader)
        })
        .or_else(|| (value == "response.status").then_some(CloudEventsSource::ResponseStatus))
}

/// Classify a mapping's provenance for optional event data.
fn mapping_provenance(mapping: &CloudEventsMapping) -> &'static str {
    match parse_source(&mapping.value) {
        Some(CloudEventsSource::Context(name))
            if name == "identity.subject_id" || name.starts_with("identity.claim.") =>
        {
            "verified"
        },
        Some(CloudEventsSource::RequestHeader(_) | CloudEventsSource::ResponseHeader(_)) => "unverified",
        Some(CloudEventsSource::Context(_) | CloudEventsSource::Metadata(_) | CloudEventsSource::ResponseStatus)
        | None => "filter",
    }
}

/// Resolve the small, stable set of context fields exposed by V1.
fn resolve_context(ctx: &HttpFilterContext<'_>, name: &str) -> Option<String> {
    match name {
        "cluster" => ctx.cluster_name().map(str::to_owned),
        "identity.subject_id" => ctx
            .extensions
            .get::<crate::AuthenticatedIdentity>()
            .map(|identity| identity.subject_id().to_owned()),
        name => name.strip_prefix("identity.claim.").and_then(|claim| {
            ctx.extensions
                .get::<crate::AuthenticatedIdentity>()
                .and_then(|identity| identity.custom_claims().get(claim))
                .cloned()
        }),
    }
}

/// Convert a source string into the configured JSON value type.
/// Convert a resolved source string into the configured JSON type.
fn convert_value(raw: String, value_type: CloudEventsValueType) -> Option<Value> {
    match value_type {
        CloudEventsValueType::String => Some(Value::String(raw)),
        CloudEventsValueType::Integer => raw.parse::<i64>().ok().map(Value::from),
        CloudEventsValueType::Boolean => match raw.to_ascii_lowercase().as_str() {
            "true" => Some(Value::Bool(true)),
            "false" => Some(Value::Bool(false)),
            _ => None,
        },
        CloudEventsValueType::Json => serde_json::from_str(&raw).ok(),
    }
}

/// Generate an RFC 3339 event timestamp from the request's clock abstraction.
fn event_time(ctx: &HttpFilterContext<'_>) -> String {
    let now = ctx.time_source.now();
    DateTime::<Utc>::from_timestamp(i64::try_from(now.as_secs()).unwrap_or(i64::MAX), now.subsec_nanos()).map_or_else(
        || "1970-01-01T00:00:00.000Z".to_owned(),
        |time| time.to_rfc3339_opts(SecondsFormat::Millis, true),
    )
}

#[cfg(test)]
#[expect(
    clippy::assertions_on_result_states,
    clippy::indexing_slicing,
    clippy::single_element_loop,
    clippy::too_many_lines,
    clippy::unwrap_used,
    reason = "tests use direct fixture construction and panic on malformed test setup"
)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use http::{Method, header::USER_AGENT};
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
        sync::oneshot,
    };
    use zeroize::Zeroizing;

    use super::{
        CloudEventsDelivery, CloudEventsFilter, CloudEventsFilterConfig, CloudEventsFormat, CloudEventsMapping,
        CloudEventsPhase, CloudEventsValueType,
    };
    use crate::{FilterAction, filter::HttpFilter as _};

    fn config(extra: &str) -> serde_yaml::Value {
        let mut base: serde_yaml::Value = serde_yaml::from_str(
            "on: response_complete\ndestination: https://events.example.test/events\nsource: urn:praxis:test\ntype: test.event",
        )
        .unwrap();
        let overrides: serde_yaml::Value = serde_yaml::from_str(extra).unwrap();
        for (key, value) in overrides.as_mapping().unwrap() {
            base.as_mapping_mut().unwrap().insert(key.clone(), value.clone());
        }
        base
    }

    fn mapping(value: &str, value_type: CloudEventsValueType) -> CloudEventsMapping {
        CloudEventsMapping {
            value: value.to_owned(),
            value_type,
            required: false,
        }
    }

    fn mapping_filter(value_type: CloudEventsValueType, required: bool) -> CloudEventsFilter {
        let filter = CloudEventsFilterConfig {
            on: CloudEventsPhase::ResponseComplete,
            destination: "https://events.example.test/events".to_owned(),
            authorization: None,
            delivery: CloudEventsDelivery::BestEffort,
            format: CloudEventsFormat::StructuredJson,
            source: "urn:praxis:test".to_owned(),
            event_type: "test.event".to_owned(),
            subject: None,
            schema: None,
            include_provenance: false,
            context_fields: Vec::new(),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            metadata_fields: vec!["token.total".to_owned()],
            data: BTreeMap::from([(
                "total_tokens".to_owned(),
                CloudEventsMapping {
                    value: "metadata.token.total".to_owned(),
                    value_type,
                    required,
                },
            )]),
            extensions: BTreeMap::new(),
            size_limit_bytes: 65_536,
            delivery_timeout_ms: 3_000,
        };
        CloudEventsFilter::build(filter).unwrap()
    }

    fn phase_filter(phase: &str) -> CloudEventsFilter {
        let yaml = config(&format!("on: {phase}"));
        let cfg: CloudEventsFilterConfig = serde_yaml::from_value(yaml).unwrap();
        CloudEventsFilter::build(cfg).unwrap()
    }

    #[test]
    fn rejects_non_http_destination() {
        let yaml = config("destination: events.example.test/events");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());

        let yaml = config("destination: http://events.example.test:0/events");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());

        let yaml = config("destination: http://events.example.test/events#fragment");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());
    }

    #[test]
    fn rejects_blank_required_attributes() {
        for field in ["source", "type"] {
            let yaml = config(&format!("{field}: '  '"));
            assert!(CloudEventsFilter::from_config(&yaml).is_err(), "{field}");
        }

        let yaml = config("source: not a uri");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());
    }

    #[test]
    fn rejects_blank_optional_attributes() {
        for field in ["schema"] {
            let yaml = config(&format!("{field}: '  '"));
            assert!(CloudEventsFilter::from_config(&yaml).is_err(), "{field}");
        }

        let yaml = config("subject: { value: '  ', type: string }");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());
    }

    #[test]
    fn rejects_zero_limits() {
        for field in ["size_limit_bytes", "delivery_timeout_ms"] {
            let yaml = config(&format!("{field}: 0"));
            assert!(CloudEventsFilter::from_config(&yaml).is_err(), "{field}");
        }

        let yaml = config("size_limit_bytes: 65537");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());
    }

    #[test]
    fn rejects_oversized_static_attributes() {
        let yaml = config("size_limit_bytes: 16\nsource: urn:0123456789abcdef");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());

        let yaml = config("size_limit_bytes: 16\ntype: 0123456789abcdefg");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());

        let yaml = config("size_limit_bytes: 16\nschema: urn:0123456789abcdef");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());
    }

    #[test]
    fn rejects_unallowlisted_mapping_sources() {
        let yaml = config("data: {total: { value: metadata.token.total, type: integer }}");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());

        let yaml = config("metadata_fields: [token.total]\ndata: {total: { value: metadata.other, type: integer }}");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());
    }

    #[test]
    fn rejects_invalid_or_sensitive_headers() {
        let yaml = config("request_headers: [not a header]");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());

        let yaml = config("request_headers: [authorization]");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());

        let yaml = config(
            "request_headers: [user-agent]\ndata: {agent: { value: request_header.x-request-id, type: string }}",
        );
        assert!(CloudEventsFilter::from_config(&yaml).is_err());
    }

    #[test]
    fn rejects_missing_authorization_environment_variable() {
        let yaml = config("authorization: { env_var: PRAXIS_CLOUD_EVENTS_TEST_MISSING_TOKEN }");

        assert!(CloudEventsFilter::from_config(&yaml).is_err());
    }

    #[test]
    fn rejects_blank_authorization_environment_variable() {
        let yaml = config("authorization: { env_var: '  ' }");

        assert!(CloudEventsFilter::from_config(&yaml).is_err());
    }

    #[test]
    fn rejects_authorization_tokens_with_invalid_header_values() {
        assert!(super::authorization_header("secret\nforged").is_err());
    }

    #[test]
    fn rejects_unknown_sources_and_standard_extensions() {
        let yaml = config("data: {value: { value: body.raw, type: json }}");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());

        let yaml = config("extensions: {id: { value: context.cluster, type: string }}\ncontext_fields: [cluster]");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());

        let yaml =
            config("extensions: {not_valid: { value: context.cluster, type: string }}\ncontext_fields: [cluster]");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());
    }

    #[test]
    fn rejects_provenance_field_override() {
        let yaml =
            config("data: {_praxis_provenance: { value: context.cluster, type: string }}\ncontext_fields: [cluster]");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());
    }

    #[test]
    fn rejects_response_headers_during_request_phase() {
        let yaml = config(
            "on: request\nresponse_headers: [x-upstream-status]\ndata: {status: { value: response_header.x-upstream-status, type: integer }}",
        );
        assert!(CloudEventsFilter::from_config(&yaml).is_err());
    }

    #[test]
    fn accepts_response_status_only_after_request_phase() {
        let yaml = config("on: response_headers\ndata: {status: { value: response.status, type: integer }}");
        assert!(CloudEventsFilter::from_config(&yaml).is_ok());

        let yaml = config("on: request\ndata: {status: { value: response.status, type: integer }}");
        assert!(CloudEventsFilter::from_config(&yaml).is_err());
    }

    #[test]
    fn builds_structured_event_with_mapped_data_and_extensions() {
        let cfg = CloudEventsFilterConfig {
            on: CloudEventsPhase::ResponseComplete,
            destination: "https://events.example.test/events".to_owned(),
            authorization: None,
            delivery: CloudEventsDelivery::BestEffort,
            format: CloudEventsFormat::StructuredJson,
            source: "urn:praxis:test".to_owned(),
            event_type: "test.event".to_owned(),
            subject: Some(mapping("context.cluster", CloudEventsValueType::String)),
            schema: Some("https://events.example.test/schema".to_owned()),
            include_provenance: true,
            context_fields: vec!["cluster".to_owned()],
            request_headers: vec!["user-agent".to_owned()],
            response_headers: Vec::new(),
            metadata_fields: vec!["token.total".to_owned()],
            data: BTreeMap::from([
                (
                    "provider".to_owned(),
                    mapping("context.cluster", CloudEventsValueType::String),
                ),
                (
                    "total_tokens".to_owned(),
                    mapping("metadata.token.total", CloudEventsValueType::Integer),
                ),
                (
                    "user_agent".to_owned(),
                    mapping("request_header.user-agent", CloudEventsValueType::String),
                ),
            ]),
            extensions: BTreeMap::from([(
                "tenant".to_owned(),
                mapping("context.cluster", CloudEventsValueType::String),
            )]),
            size_limit_bytes: 65_536,
            delivery_timeout_ms: 3_000,
        };
        let filter = CloudEventsFilter::build(cfg).unwrap();
        let mut request = crate::test_utils::make_request(Method::GET, "/");
        request.headers.insert(USER_AGENT, "praxis-test".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&request);
        ctx.cluster = Some("provider-a".into());
        ctx.filter_metadata.insert("token.total".to_owned(), "42".to_owned());

        let event = filter.build_event(&ctx).unwrap();
        let object = event.as_object().unwrap();
        assert!(object["id"].as_str().is_some_and(|id| !id.is_empty()));
        assert!(object["time"].as_str().is_some_and(|time| time.ends_with('Z')));
        assert_eq!(object["specversion"], json!("1.0"));
        assert_eq!(object["source"], json!("urn:praxis:test"));
        assert_eq!(object["type"], json!("test.event"));
        assert_eq!(object["subject"], json!("provider-a"));
        assert_eq!(object["dataschema"], json!("https://events.example.test/schema"));
        assert_eq!(
            object["data"],
            json!({
                "provider": "provider-a",
                "total_tokens": 42,
                "user_agent": "praxis-test",
                "_praxis_provenance": {
                    "provider": "filter",
                    "total_tokens": "filter",
                    "user_agent": "unverified"
                }
            })
        );
        assert_eq!(object["tenant"], json!("provider-a"));
    }

    #[test]
    fn maps_response_status_from_captured_response_metadata() {
        let yaml = config("data: {status: { value: response.status, type: integer, required: true }}");
        let cfg: CloudEventsFilterConfig = serde_yaml::from_value(yaml).unwrap();
        let filter = CloudEventsFilter::build(cfg).unwrap();
        let request = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&request);
        ctx.current_filter_id = Some(0);
        ctx.insert_filter_state(super::CloudEventsState {
            status: Some(201),
            response_headers: None,
            emitted: false,
        });

        let event = filter.build_event(&ctx).unwrap();

        assert_eq!(event["data"]["status"], json!(201));
    }

    #[test]
    fn omits_missing_optional_mapping() {
        let filter = mapping_filter(CloudEventsValueType::Integer, false);
        let request = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&request);

        let event = filter.build_event(&ctx).unwrap();
        assert_eq!(event["data"], json!({}));
    }

    #[test]
    fn suppresses_event_for_missing_required_mapping() {
        let filter = mapping_filter(CloudEventsValueType::Integer, true);
        let request = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&request);

        assert!(filter.build_event(&ctx).is_none());
    }

    #[test]
    fn treats_failed_conversion_as_missing() {
        let request = crate::test_utils::make_request(Method::GET, "/");

        let optional_filter = mapping_filter(CloudEventsValueType::Integer, false);
        let mut optional_ctx = crate::test_utils::make_filter_context(&request);
        optional_ctx
            .filter_metadata
            .insert("token.total".to_owned(), "not-an-integer".to_owned());
        let event = optional_filter.build_event(&optional_ctx).unwrap();
        assert_eq!(event["data"], json!({}));

        let required_filter = mapping_filter(CloudEventsValueType::Integer, true);
        let mut required_ctx = crate::test_utils::make_filter_context(&request);
        required_ctx
            .filter_metadata
            .insert("token.total".to_owned(), "not-an-integer".to_owned());
        assert!(required_filter.build_event(&required_ctx).is_none());
    }

    #[test]
    fn classifies_delivery_failures_without_high_cardinality_values() {
        use praxis_core::subrequest::SubRequestError;

        assert_eq!(
            super::cloud_events_failure_class(&SubRequestError::AdmissionTimeout { max_connections: 1 }),
            "admission"
        );
        assert_eq!(
            super::cloud_events_failure_class(&SubRequestError::DeadlineExceeded),
            "timeout"
        );
        assert_eq!(
            super::cloud_events_failure_class(&SubRequestError::Connect("refused".to_owned())),
            "transport"
        );
    }

    #[tokio::test]
    async fn request_phase_emits_during_request_hook() {
        let filter = phase_filter("request");
        let request = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&request);
        ctx.current_filter_id = Some(0);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert!(
            ctx.get_filter_state::<super::CloudEventsState>()
                .is_some_and(|state| state.emitted)
        );
    }

    #[tokio::test]
    async fn publish_failure_does_not_change_filter_action() {
        let yaml = config("on: request\ndestination: http://127.0.0.1:1/events");
        let cfg: CloudEventsFilterConfig = serde_yaml::from_value(yaml).unwrap();
        let filter = CloudEventsFilter::build(cfg).unwrap();
        let request = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&request);
        ctx.current_filter_id = Some(0);
        let connector = praxis_core::subrequest::SubRequestConnector::new(1, None);
        let client = praxis_core::subrequest::SubRequestClient::new(connector);
        ctx.subrequest_client = Some(&client);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
    }

    #[tokio::test]
    async fn response_headers_phase_emits_when_response_headers_arrive() {
        let filter = phase_filter("response_headers");
        let request = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&request);
        ctx.current_filter_id = Some(0);
        let mut response = crate::test_utils::make_response();
        ctx.response_header = Some(&mut response);

        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;

        let state = ctx.get_filter_state::<super::CloudEventsState>().unwrap();
        assert!(state.emitted);
    }

    #[tokio::test]
    async fn response_complete_waits_for_end_of_stream() {
        let filter = phase_filter("response_complete");
        let request = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&request);
        ctx.current_filter_id = Some(0);
        let mut response = crate::test_utils::make_response();
        ctx.response_header = Some(&mut response);

        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;
        assert!(!ctx.get_filter_state::<super::CloudEventsState>().unwrap().emitted);

        let mut body = None;
        drop(filter.on_response_body(&mut ctx, &mut body, true).unwrap());
        assert!(ctx.get_filter_state::<super::CloudEventsState>().unwrap().emitted);
    }

    #[tokio::test]
    async fn response_complete_ignores_interim_informational_responses() {
        let filter = phase_filter("response_complete");
        let request = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&request);
        ctx.current_filter_id = Some(0);
        let mut interim_response = crate::test_utils::make_response();
        interim_response.status = http::StatusCode::EARLY_HINTS;
        ctx.response_header = Some(&mut interim_response);

        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;
        assert!(ctx.get_filter_state::<super::CloudEventsState>().is_none());

        let mut response = crate::test_utils::make_response();
        response.status = http::StatusCode::OK;
        ctx.response_header = Some(&mut response);
        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;
        assert!(!ctx.get_filter_state::<super::CloudEventsState>().unwrap().emitted);

        let mut body = None;
        drop(filter.on_response_body(&mut ctx, &mut body, true).unwrap());
        assert!(ctx.get_filter_state::<super::CloudEventsState>().unwrap().emitted);
    }

    #[tokio::test]
    async fn response_complete_emits_immediately_for_bodyless_response() {
        let filter = phase_filter("response_complete");
        let request = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&request);
        ctx.current_filter_id = Some(0);
        let mut response = crate::test_utils::make_response();
        response.status = http::StatusCode::NO_CONTENT;
        ctx.response_header = Some(&mut response);

        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;

        assert!(ctx.get_filter_state::<super::CloudEventsState>().unwrap().emitted);
    }

    #[tokio::test]
    async fn response_complete_emits_without_response_metadata() {
        let filter = phase_filter("response_complete");
        let request = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&request);
        ctx.current_filter_id = Some(0);

        drop(filter.on_response(&mut ctx).await.unwrap());

        assert!(ctx.get_filter_state::<super::CloudEventsState>().unwrap().emitted);
    }

    #[tokio::test]
    async fn response_headers_phase_skips_without_response() {
        let filter = phase_filter("response_headers");
        let request = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&request);
        ctx.current_filter_id = Some(0);

        drop(filter.on_response(&mut ctx).await.unwrap());

        assert!(ctx.get_filter_state::<super::CloudEventsState>().is_none());
    }

    /// Publish one authenticated event to a local receiver and return its request.
    async fn publish_authenticated_event(response: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 4096];
            let body_length = loop {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "receiver closed before request completed");
                request.extend_from_slice(&chunk[..read]);
                let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                break headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
            };
            let header_end = request.windows(4).position(|window| window == b"\r\n\r\n").unwrap() + 4;
            while request.len() < header_end + body_length {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "receiver closed before request body completed");
                request.extend_from_slice(&chunk[..read]);
            }
            sender.send(request).unwrap();
            stream.write_all(response).await.unwrap();
        });

        let mut filter = CloudEventsFilter::build(CloudEventsFilterConfig {
            on: CloudEventsPhase::ResponseComplete,
            destination: format!("http://{address}/events"),
            authorization: None,
            delivery: CloudEventsDelivery::BestEffort,
            format: CloudEventsFormat::StructuredJson,
            source: "urn:praxis:test".to_owned(),
            event_type: "test.event".to_owned(),
            subject: None,
            schema: None,
            include_provenance: false,
            context_fields: Vec::new(),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            metadata_fields: Vec::new(),
            data: BTreeMap::new(),
            extensions: BTreeMap::new(),
            size_limit_bytes: 65_536,
            delivery_timeout_ms: 3_000,
        })
        .unwrap();
        filter.authorization_token = Some(Zeroizing::new("metering-secret".to_owned()));
        let connector = praxis_core::subrequest::SubRequestConnector::new(1, None);
        let client = praxis_core::subrequest::SubRequestClient::new(connector);
        let request = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&request);
        ctx.current_filter_id = Some(0);
        ctx.subrequest_client = Some(&client);

        let mut response = crate::test_utils::make_response();
        ctx.response_header = Some(&mut response);
        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;
        assert!(!ctx.get_filter_state::<super::CloudEventsState>().unwrap().emitted);
        assert!(filter.emit_deferred_record(&ctx, 502));
        let request = tokio::time::timeout(Duration::from_secs(2), receiver)
            .await
            .unwrap()
            .unwrap();
        let request_text = String::from_utf8_lossy(&request);
        assert!(request_text.starts_with("POST /events HTTP/1.1\r\n"));
        assert!(
            request_text
                .to_ascii_lowercase()
                .contains("content-type: application/cloudevents+json")
        );
        assert!(request_text.contains("authorization: Bearer metering-secret"));
        assert!(request_text.contains("\"specversion\":\"1.0\""));
        server.await.unwrap();
        request_text.into_owned()
    }

    #[tokio::test]
    async fn publishes_deferred_event_with_authorization() {
        let request_text = publish_authenticated_event(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;

        assert!(request_text.starts_with("POST /events HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn records_authorization_rejection() {
        crate::test_utils::install_metrics_recorder();
        let request_text = publish_authenticated_event(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n").await;

        assert!(request_text.contains("authorization: Bearer metering-secret"));
        let metrics = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let metrics = crate::test_utils::render_metrics();
                if metrics.contains("failure_class=\"http_status\"") {
                    break metrics;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(metrics.contains("failure_class=\"http_status\""));
        assert!(metrics.contains("status_class=\"4xx\""));
    }
}
