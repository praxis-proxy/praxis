// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `PolicyFilter` — embeds the policy engine in-process to resolve and
//! validate identity, evaluate APL routes, optionally mint delegated
//! credentials, scan for PII, emit audit records, and optionally
//! rewrite request/response bodies.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ppe::praxis_policy_core::{
    assertions::Direction,
    cmf::{
        CmfHook, Message, MessagePayload, Role,
        constants::{
            ENTITY_HTTP, ENTITY_NAME_GLOBAL, HOOK_CMF_PROMPT_PRE_INVOKE, HOOK_CMF_RESOURCE_PRE_FETCH,
            HOOK_CMF_TOOL_PRE_INVOKE,
        },
    },
    engine::PolicyEngine,
    error::{PluginError, PluginViolation},
    extensions::MetaExtension,
    hooks::Extensions,
    http_hook::{HOOK_HTTP_REQUEST, HOOK_HTTP_RESPONSE, HttpHook, HttpPayload},
    identity::{HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource},
};

use super::{
    assertions::{
        GovernedNames, apply_request_assertions, apply_response_assertions, snapshot_response_headers,
        unreachable_response_levels,
    },
    common_message_format::{entity_for_protocol_method, entity_for_protocol_method_post},
    config::{BodyAccessMode, PolicyFilterConfig},
    error::{VIOLATION_HEADER, auth_rejection, json_rpc_error_envelope_bytes, json_rpc_error_rejection},
    json_rpc::{
        ParsedEnvelope, build_content_for_method, build_response_content_for_method, reserialize_json_rpc_body,
        reserialize_json_rpc_response_body,
    },
};
use crate::{
    AuthenticatedIdentity, FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// PolicyFilter
// -----------------------------------------------------------------------------

/// Per-filter admission state shared across lifecycle phases. Both fields live
/// here so multiple policy instances cannot overwrite one another's temporary
/// identity projection or completion marker.
#[derive(Default)]
struct AdmissionState {
    /// Whether this instance has already admitted the request.
    complete: bool,
    /// Sanitized result retained from the unscoped early gate.
    gated_identity: GatedIdentity,
}

/// Three-state result for an early identity gate.
#[derive(Default)]
enum GatedIdentity {
    /// The gate has not run for this policy instance.
    #[default]
    NotRun,
    /// Validation succeeded without producing a user subject.
    NoSubject,
    /// Validation succeeded and produced a raw-credential-free subject.
    Subject(AuthenticatedIdentity),
}

/// Embeds the Praxis Policy Engine in-process to enforce multi-source JWT
/// identity, APL route policy, RFC 8693 token exchange, PII
/// scanning, audit emission, and (under `body_access: read_write`)
/// request / response body rewriting.
///
/// Experimental: requires the `policy-engine` cargo feature, which
/// is off by default. Registered under the YAML filter name `policy`.
///
/// A single request can carry multiple identity sources — user JWT in
/// `Authorization`, agent JWT in `X-Agent-Token`, workload JWT in
/// `X-Workload-Token`, etc. Each registered identity plugin reads its
/// own configured header and contributes to a typed `Extensions`
/// context.
///
/// On the body phase, the filter consumes protocol classifier filter metadata
/// (from the `praxis-ai` package) to dispatch the matching CMF
/// hook chain. APL routes
/// (declared in the policy document) gate the tool/prompt/resource call by
/// role, attribute, or Cedar PDP decision. `delegate(...)` steps mint
/// audience-scoped tokens (RFC 8693) that the allow path attaches as
/// upstream headers.
///
/// `body_access: read_write` enables the JSON-RPC re-serialization
/// round-trip so APL field mutators (`redact()`, `assign()`) rewrite
/// the upstream request body and the downstream response.
///
/// # YAML configuration
///
/// Filter fields sit directly under the `- filter:` entry; there is no
/// `config:` wrapper. See `examples/configs/security/policy.yaml` for a
/// runnable example.
///
/// ```yaml
/// filter: policy
/// config_path: /etc/praxis/policy.yaml
/// body_access: read_write       # optional; default read_only
/// require_protocol_metadata: true    # optional; default true
/// init_timeout_secs: 30         # optional; default 30
/// max_buffer_bytes: 10485760    # optional; default 10 MiB (read_write only)
/// ```
pub struct PolicyFilter {
    /// Filter-level configuration parsed from the YAML block. Held so
    /// `request_body_access` / `request_body_mode` / their response
    /// counterparts can branch on `body_access` per request.
    cfg: PolicyFilterConfig,
    /// Policy engine plugin manager — owns the loaded plugin instances and
    /// dispatches hook chains. Wrapped in `Arc` so the response-phase
    /// `spawn_blocking` closure can hold its own handle without
    /// borrowing `&self`.
    mgr: Arc<PolicyEngine>,
    /// Derived from the loaded policy at construction: the `global` policy
    /// wired the entity-less HTTP path (`http.request`). When true and
    /// `entity_routes` is false, the filter is a pure L7 policy evaluated at
    /// `on_request` over `http.*` + identity — no classifier, no body.
    http_global: bool,
    /// Derived from the loaded policy: it declares per-entity routes
    /// (tool/prompt/resource). When true, authorization runs at the body
    /// phase after classification, and a missing `mcp.method` fails
    /// closed (the classifier is required).
    entity_routes: bool,
    /// Header names governed by request assertions.
    request_assertions: GovernedNames,
    /// Header names governed by response assertions.
    response_assertions: GovernedNames,
    /// Response hook to dispatch when the policy has response work.
    response_hook: Option<&'static str>,
}

impl PolicyFilter {
    /// Construct a filter from a parsed config. Loads the policy document
    /// referenced by `cfg.config_path`, registers bundled plugin
    /// factories, wires the APL visitor, and initializes the manager.
    /// Errors abort filter chain construction at server startup —
    /// failing fast is what we want for misconfigured policy.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the referenced YAML cannot be read,
    /// the policy document fails to parse, or plugin initialization
    /// fails (e.g., a JWKS endpoint is unreachable).
    #[expect(
        clippy::too_many_lines,
        reason = "linear construction + init steps; splitting obscures the startup flow"
    )]
    pub(crate) fn new(cfg: PolicyFilterConfig) -> Result<Self, FilterError> {
        // Bound the per-request ReadWrite buffer ceiling: 0 makes every
        // non-empty body fail, and an unbounded value multiplies per-request
        // memory by concurrency. The pipeline's unbounded-buffer startup check
        // never fires here because this filter always passes a concrete
        // Some(max_buffer_bytes), so validate it directly.
        if cfg.max_buffer_bytes == 0 {
            return Err("policy: max_buffer_bytes must be > 0".into());
        }
        if cfg.max_buffer_bytes > praxis_core::config::ABSOLUTE_MAX_BODY_BYTES {
            return Err(format!(
                "policy: max_buffer_bytes ({}) exceeds the maximum ({})",
                cfg.max_buffer_bytes,
                praxis_core::config::ABSOLUTE_MAX_BODY_BYTES
            )
            .into());
        }

        let yaml = std::fs::read_to_string(&cfg.config_path).map_err(|e| -> FilterError {
            format!("policy: failed to read config_path {}: {e}", cfg.config_path).into()
        })?;

        let mgr = Arc::new(PolicyEngine::default());
        ppe::install_builtins(&mgr);

        // The lazy connection pool must not bind to the temporary init runtime.
        if !Self::install_http_transport(&mgr, cfg.allow_private_idp) {
            // Set-once, and this manager was just constructed, so a refusal
            // means the engine changed under us rather than a double install.
            tracing::warn!(
                target: "policy.filter",
                "policy: an HTTP transport was already installed on a fresh engine"
            );
        }

        // Host-supplied factories, for `kind:` values the engine does not
        // bundle. After the builtins on purpose: the factory registry is
        // last-writer-wins, so a host registering a bundled `kind` replaces it,
        // which is how a deployment swaps an implementation without forking.
        //
        // Re-read on every construction, not drained. `PolicyFilter::new` runs
        // again on each hot reload, and a registry emptied by the first read
        // would fail the reload with "no factory registered" for a config that
        // had been serving traffic.
        let host_factories = super::host_plugins::host_plugin_factories();
        if !host_factories.is_empty() {
            tracing::info!(
                count = super::host_plugins::host_plugin_count(),
                "policy: registering host-supplied plugin factories"
            );
        }
        for (kind, factory) in host_factories {
            tracing::debug!(target: "policy.filter", kind = %kind, "registering host plugin factory");
            mgr.register_factory(kind, factory);
        }

        mgr.load_config_yaml(&yaml)
            .map_err(|e: Box<PluginError>| -> FilterError {
                format!("policy: load_config_yaml failed for {}: {e}", cfg.config_path).into()
            })?;

        // `initialize()` is async. The praxis filter-factory signature
        // is sync, so we drive init to completion here. We spawn a
        // dedicated OS thread to build a single-threaded runtime and
        // call `block_on` there — running `block_on` on the current
        // thread would panic if any caller (notably `#[tokio::test]`)
        // already has a runtime attached. Production startup has no
        // caller runtime; tests do; the thread hop is correct in both.
        //
        // The init future is wrapped in `tokio::time::timeout` so a
        // misbehaving plugin's `initialize()` future can't hang startup
        // / hot-reload indefinitely. The bundled identity-jwt plugin
        // already has its own JWKS connect/request timeouts plus
        // soft-fail-at-boot, so this is defense-in-depth for other
        // init paths (custom plugins, future hooks) where a future
        // could legitimately stall.
        let mgr_for_init = Arc::clone(&mgr);
        let init_timeout = std::time::Duration::from_secs(cfg.init_timeout_secs);
        let init: Result<(), String> = std::thread::spawn(move || -> Result<(), String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("policy: failed to build init runtime: {e}"))?;
            rt.block_on(async move {
                match tokio::time::timeout(init_timeout, mgr_for_init.initialize()).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(format!("policy: PolicyEngine::initialize failed: {e}")),
                    Err(_) => Err(format!(
                        "policy: PolicyEngine::initialize timed out after {}s \
                         (init_timeout_secs); likely a JWKS / OAuth endpoint is unreachable",
                        init_timeout.as_secs(),
                    )),
                }
            })
        })
        .join()
        .map_err(|panic| {
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<no panic message>".to_owned());
            format!("policy: PolicyEngine::initialize panicked in init thread: {msg}")
        })?;
        init.map_err(|s: String| -> FilterError { s.into() })?;

        // Derive the evaluation shape from the loaded policy so the filter
        // needs no operator-set mode. `has_hooks_for` reports whether a hook
        // was wired by the policy (registered handler or route annotation).
        let http_global = mgr.has_hooks_for(HOOK_HTTP_REQUEST);
        let entity_routes = mgr.has_hooks_for(HOOK_CMF_TOOL_PRE_INVOKE)
            || mgr.has_hooks_for(HOOK_CMF_PROMPT_PRE_INVOKE)
            || mgr.has_hooks_for(HOOK_CMF_RESOURCE_PRE_FETCH);

        // Fail-silent guard. A policy with both a `global` HTTP policy and
        // entity routes is the normal "global baseline layer + entity routes"
        // pattern: for entity-aware policies the global policy is enforced as
        // the per-entity layer (classified traffic) and non-classified traffic
        // is fail-closed by `require_protocol_metadata`. If the operator
        // disabled that gate, non-classified requests are admitted
        // identity-only and are NOT evaluated against the global HTTP policy —
        // a silent skip. Make that specific misconfiguration loud at startup.
        if http_global && entity_routes && !cfg.require_protocol_metadata {
            tracing::warn!(
                target: "policy.filter",
                "policy declares a `global` HTTP policy AND entity routes with \
                 `require_protocol_metadata: false`: non-classified (non-MCP) requests will be \
                 admitted identity-only and will NOT be evaluated against the global HTTP policy. \
                 Keep `require_protocol_metadata: true` (default) to fail closed, or move the \
                 global HTTP policy to a separate listener/filter that fronts non-MCP traffic.",
            );
        }

        // Re-parse because the engine does not retain the loaded document.
        let policy_config =
            ppe::praxis_policy_core::config::parse_config(&yaml).map_err(|e: Box<PluginError>| -> FilterError {
                format!(
                    "policy: the engine accepted {} but praxis could not re-read it for the \
                     assertions contract: {e}",
                    cfg.config_path
                )
                .into()
            })?;
        let request_assertions = GovernedNames::from_config(&policy_config, Direction::Request);
        let response_assertions = GovernedNames::from_config(&policy_config, Direction::Response);

        // Reject controls that cannot reach the writable response-header phase.
        let unreachable = unreachable_response_levels(&policy_config);
        if !unreachable.is_empty() {
            return Err(format!(
                "policy: {} declares `assertions.response:` that praxis cannot apply. A response \
                 contract is applied at the response header phase, which carries the entity-less \
                 HTTP coordinates, so only `global:`, `global.defaults.http:` and an `http:` route \
                 can reach one. Move the block to one of those, or drop it.",
                unreachable.join(", "),
            )
            .into());
        }

        let response_hook =
            (mgr.has_hooks_for(HOOK_HTTP_RESPONSE) || !response_assertions.is_empty()).then_some(HOOK_HTTP_RESPONSE);

        Ok(Self {
            cfg,
            mgr,
            http_global,
            entity_routes,
            request_assertions,
            response_assertions,
            response_hook,
        })
    }

    /// Test accessor for the hook the response half dispatches, if any.
    #[cfg(test)]
    pub(super) fn response_hook(&self) -> Option<&'static str> {
        self.response_hook
    }

    /// Test accessor for the shape derived from the loaded policy:
    /// `(http_global, entity_routes)`.
    #[cfg(test)]
    pub(super) fn derived_shape(&self) -> (bool, bool) {
        (self.http_global, self.entity_routes)
    }

    /// Praxis-side factory hook, wired via `register_http` in
    /// `filter/src/registry.rs`.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the config block fails to parse
    /// as a `PolicyFilterConfig` or filter construction fails.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: PolicyFilterConfig = parse_filter_config("policy", config)?;
        let filter = Self::new(cfg)?;
        Ok(Box::new(filter))
    }

    /// Snapshot the request's HTTP headers into a case-normalized
    /// map. Each registered identity plugin reads its own configured
    /// header from this map.
    ///
    /// Keys are normalized to ASCII lowercase. HTTP header names are
    /// case-insensitive (RFC 7230 §3.2) but the `HashMap` lookup is
    /// case-sensitive; plugins lowercase their configured header
    /// before lookup to match.
    pub(super) fn snapshot_headers(ctx: &HttpFilterContext<'_>) -> std::collections::HashMap<String, String> {
        ctx.request
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_ascii_lowercase(), v.to_owned()))
            })
            .collect()
    }

    /// Build a fresh `IdentityPayload` from pre-snapshotted headers.
    /// `raw_token` is left empty: each registered identity plugin
    /// reads its own configured header from `headers` instead.
    fn identity_payload(headers: std::collections::HashMap<String, String>) -> IdentityPayload {
        IdentityPayload::new(String::new(), TokenSource::Bearer).with_headers(headers)
    }

    /// Build identity extensions with route coordinates and request attributes.
    ///
    /// Both are required to select route-scoped authentication; omitting the
    /// request line could silently fall back to the global authenticator.
    fn identity_extensions(
        ctx: &HttpFilterContext<'_>,
        headers: std::collections::HashMap<String, String>,
        entity_type: &str,
        entity_name: &str,
    ) -> Extensions {
        let mut ext = Extensions {
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some(entity_type.to_owned()),
                entity_name: Some(entity_name.to_owned()),
                ..Default::default()
            })),
            ..Default::default()
        };
        Self::attach_http_attributes(ctx, &mut ext, headers);
        ext
    }

    /// Resolve identity by invoking the identity hook chain. Returns the
    /// resolved [`IdentityPayload`] (subject / client / workload / raw
    /// credentials / delegation) or a rejection when no identity
    /// continues. Cheap — the JWT verifier hits its in-process key cache.
    #[expect(clippy::large_stack_frames, reason = "async handler over large CMF/pipeline types")]
    async fn resolve_identity(
        &self,
        ctx: &HttpFilterContext<'_>,
        headers: std::collections::HashMap<String, String>,
        entity_type: &str,
        entity_name: &str,
    ) -> Result<IdentityPayload, Rejection> {
        let route_ext = Self::identity_extensions(ctx, headers.clone(), entity_type, entity_name);

        let (id_result, _bg) = self
            .mgr
            .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, Self::identity_payload(headers), route_ext, None)
            .await;
        if !id_result.continue_processing {
            return Err(auth_rejection(id_result.violation.as_ref()));
        }
        IdentityPayload::from_pipeline_result(&id_result).ok_or_else(|| {
            Rejection::status(500).with_body(Bytes::from_static(b"policy: identity result missing modified payload"))
        })
    }

    /// Build the CMF `Extensions` from an already-resolved identity,
    /// stamping `MetaExtension.entity_type` / `entity_name` for route
    /// resolution and threading the `X-Session-Id` header into
    /// `agent.session_id`.
    ///
    /// Pure field-mapping — no token validation, no network — so it is
    /// safe to call in the response phase against the identity resolved
    /// in the request phase. That is exactly why the response phase
    /// reuses the request-phase identity instead of re-running the
    /// identity hook: a token that expires between the request and the
    /// (already-served) response must not turn into a false deny.
    fn extensions_from_identity(
        headers: &std::collections::HashMap<String, String>,
        identity: &IdentityPayload,
        entity_type: &str,
        entity_name: &str,
    ) -> Extensions {
        let mut ext = identity.apply_to_extensions(Extensions::default());

        let mut meta = ext.meta.as_ref().map(|arc| (**arc).clone()).unwrap_or_default();
        meta.entity_type = Some(entity_type.to_owned());
        meta.entity_name = Some(entity_name.to_owned());
        ext.meta = Some(Arc::new(meta));

        if let Some(session_id) = headers.get("x-session-id").filter(|value| !value.is_empty()).cloned() {
            let mut agent = ext.agent.as_ref().map(|arc| (**arc).clone()).unwrap_or_default();
            agent.session_id = Some(session_id);
            ext.agent = Some(Arc::new(agent));
        }

        ext
    }

    /// Publish the raw-credential-free subject projection for downstream filters.
    ///
    /// The Praxis Policy Engine (PPE) may authenticate a client or workload without resolving a user
    /// subject. In that case no `AuthenticatedIdentity` is published; a
    /// consumer that requires a user principal must fail closed when the
    /// extension is absent.
    fn publish_authenticated_identity(ctx: &mut HttpFilterContext<'_>, identity: &IdentityPayload) {
        Self::publish_identity_projection(ctx, Self::authenticated_identity(identity));
    }

    /// Install the bundled transport with the configured destination policy.
    fn install_http_transport(mgr: &Arc<PolicyEngine>, allow_private: bool) -> bool {
        if allow_private {
            tracing::info!(
                target: "policy.filter",
                "policy: allowing the engine to reach private and loopback IdP addresses"
            );
            return mgr.set_http_transport(Arc::new(ppe::HyperTransport::new().with_allow_private_destinations()));
        }
        ppe::install_default_http_transport(mgr)
    }

    /// Build the public string-valued identity projection from a validated payload.
    fn authenticated_identity(identity: &IdentityPayload) -> Option<AuthenticatedIdentity> {
        identity.subject.as_ref().and_then(|subject| {
            AuthenticatedIdentity::new(
                subject.id.clone()?,
                subject.roles.iter().cloned(),
                subject.teams.iter().cloned(),
                subject
                    .claims
                    .iter()
                    .map(|(name, value)| (name.clone(), flatten_claim(value))),
            )
        })
    }

    /// Insert a sanitized projection, or clear a projection left by an earlier
    /// identity attempt when validation produced no subject.
    fn publish_identity_projection(ctx: &mut HttpFilterContext<'_>, authenticated: Option<AuthenticatedIdentity>) {
        if let Some(authenticated) = authenticated {
            ctx.extensions.insert(authenticated);
        } else {
            // Do not let a value from an earlier authentication attempt remain
            // authoritative when the current resolved identity has no subject.
            ctx.extensions.remove::<AuthenticatedIdentity>();
        }
    }

    /// Whether this policy instance already completed admission in an earlier
    /// lifecycle phase.
    fn admission_complete(ctx: &HttpFilterContext<'_>) -> bool {
        ctx.get_filter_state::<AdmissionState>()
            .is_some_and(|state| state.complete)
    }

    /// Record successful admission when executing through a pipeline. Direct
    /// unit-test calls have no current filter ID and intentionally skip the
    /// marker rather than emitting the context helper's warning.
    fn mark_admission_complete(ctx: &mut HttpFilterContext<'_>) {
        if ctx.current_filter_id.is_none() {
            return;
        }
        if let Some(state) = ctx.get_filter_state_mut::<AdmissionState>() {
            state.complete = true;
        } else {
            ctx.insert_filter_state(AdmissionState {
                complete: true,
                ..Default::default()
            });
        }
    }

    /// Preserve an unscoped gate result in state owned by this policy filter
    /// instance until classification proves that no entity route applies.
    fn store_gated_identity(ctx: &mut HttpFilterContext<'_>, authenticated: Option<AuthenticatedIdentity>) {
        if ctx.current_filter_id.is_none() {
            return;
        }
        let gated_identity = authenticated.map_or(GatedIdentity::NoSubject, GatedIdentity::Subject);
        if let Some(state) = ctx.get_filter_state_mut::<AdmissionState>() {
            state.gated_identity = gated_identity;
        } else {
            ctx.insert_filter_state(AdmissionState {
                gated_identity,
                ..Default::default()
            });
        }
    }

    /// Remove and return this policy instance's temporary early-gate result.
    fn take_gated_identity(ctx: &mut HttpFilterContext<'_>) -> GatedIdentity {
        ctx.get_filter_state_mut::<AdmissionState>()
            .map_or(GatedIdentity::NotRun, |state| std::mem::take(&mut state.gated_identity))
    }

    /// Resolve the global identity gate without publishing route-scoped state.
    ///
    /// Reserved entity-less coordinates select global authentication; absent
    /// coordinates would be rejected as an unidentified request.
    #[expect(clippy::large_stack_frames, reason = "async PPE identity payload")]
    async fn resolve_gated_identity(
        &self,
        ctx: &HttpFilterContext<'_>,
    ) -> Result<Option<AuthenticatedIdentity>, Rejection> {
        let headers = Self::snapshot_headers(ctx);
        let gate_ext = Self::identity_extensions(ctx, headers.clone(), ENTITY_HTTP, ENTITY_NAME_GLOBAL);
        let (result, _bg) = self
            .mgr
            .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, Self::identity_payload(headers), gate_ext, None)
            .await;

        if !result.continue_processing {
            return Err(auth_rejection(result.violation.as_ref()));
        }
        let identity = IdentityPayload::from_pipeline_result(&result).ok_or_else(|| {
            Rejection::status(500).with_body(Bytes::from_static(b"policy: identity result missing modified payload"))
        })?;
        Ok(Self::authenticated_identity(&identity))
    }

    /// Finish an identity-only admission after classification establishes that
    /// no entity-specific resolver can apply.
    async fn complete_gated_admission(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let authenticated = match Self::take_gated_identity(ctx) {
            GatedIdentity::Subject(authenticated) => Some(authenticated),
            GatedIdentity::NoSubject => None,
            GatedIdentity::NotRun => match self.resolve_gated_identity(ctx).await {
                Ok(authenticated) => authenticated,
                Err(rejection) => return Ok(FilterAction::Reject(rejection)),
            },
        };
        Self::publish_identity_projection(ctx, authenticated);
        Self::mark_admission_complete(ctx);
        Ok(FilterAction::BodyDone)
    }

    /// Early identity gate: resolve identity in `on_request` so
    /// un-authenticated traffic is rejected before the body-buffer cost is
    /// paid. For entity-aware policies, authorization runs later, in
    /// `on_request_body`, once the request is classified.
    async fn identity_gate(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        // When a downstream body-buffering filter (e.g. the protocol
        // classifier) forces a pre-read, praxis runs `on_request_body` BEFORE
        // this header phase. That body phase already resolved and enforced
        // identity (stashing `ResolvedIdentity`) and may have stripped the
        // inbound identity headers (`X-User-Token`, `Authorization`) for the
        // upstream. Re-resolving here would fail on the now-stripped headers
        // and spuriously reject an already-authorized request. The body phase
        // is authoritative — skip the early gate when it already ran.
        if ctx.extensions.get::<ResolvedIdentity>().is_some() {
            tracing::trace!(target: "policy.filter", "identity already resolved in body phase; skipping early gate");
            return Ok(FilterAction::Continue);
        }

        let authenticated = match self.resolve_gated_identity(ctx).await {
            Ok(authenticated) => authenticated,
            Err(rejection) => {
                tracing::debug!(target: "policy.filter", "identity deny (on_request)");
                return Ok(FilterAction::Reject(rejection));
            },
        };
        // Entity-routed policies resolve again once classifier metadata gives
        // PPE the authoritative route coordinates. Publishing this unscoped
        // gate result could expose a principal from the wrong route resolver.
        if self.entity_routes {
            Self::store_gated_identity(ctx, authenticated);
        } else {
            Self::publish_identity_projection(ctx, authenticated);
        }
        tracing::trace!(target: "policy.filter", "identity allow (on_request)");
        Ok(FilterAction::Continue)
    }

    /// Generic-HTTP (L7) authorization: resolve identity, populate the
    /// HTTP request line + headers into the attribute bag, and evaluate the
    /// `global` policy via the `http.request` hook. A deny maps to a
    /// plain HTTP response ([`super::error::http_authz_rejection`]); an
    /// identity failure is the usual 401. Authorization runs here (not the
    /// body phase) because it needs no request body.
    #[expect(
        clippy::large_stack_frames,
        clippy::too_many_lines,
        reason = "async handler over large CMF types; linear resolve/authz/delegate flow"
    )]
    async fn on_request_http_authz(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let headers = Self::snapshot_headers(ctx);
        let identity = match self
            .resolve_identity(ctx, headers.clone(), ENTITY_HTTP, ENTITY_NAME_GLOBAL)
            .await
        {
            Ok(id) => id,
            Err(rej) => return Ok(FilterAction::Reject(rej)),
        };
        Self::publish_authenticated_identity(ctx, &identity);
        let mut extensions = Self::extensions_from_identity(&headers, &identity, ENTITY_HTTP, ENTITY_NAME_GLOBAL);
        Self::attach_http_attributes(ctx, &mut extensions, headers);

        // Policy evaluation (APL predicates, Cedar/CEL PDP queries, PII
        // scanning) can be CPU-intensive for complex rule sets or large
        // input data. Offload to the blocking thread pool so the async
        // runtime stays responsive to other concurrent requests.
        // Generic HTTP handlers read request data from extensions, not a body payload.
        let payload = HttpPayload;
        let mgr = Arc::clone(&self.mgr);
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::spawn_blocking(move || {
            handle.block_on(async {
                let (r, _bg) = mgr
                    .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, payload, extensions, None)
                    .await;
                r
            })
        })
        .await
        .map_err(|e| -> FilterError { format!("policy: HTTP request-phase hook task failed: {e}").into() })?;

        if !result.continue_processing {
            tracing::debug!(target: "policy.filter", "http authz deny (on_request)");
            return Ok(FilterAction::Reject(super::error::http_authz_rejection(
                result.violation.as_ref(),
            )));
        }
        // Allow path. If the `global` policy ran `delegate(...)` steps, attach
        // the minted tokens to the upstream request (mirrors the entity path in
        // `on_request_body`); a no-op when the policy declares no delegation.
        let attached = attach_delegated_tokens(ctx, result.modified_extensions.as_ref());
        if attached > 0 {
            tracing::debug!(
                target: "policy.filter",
                count = attached,
                "attached delegated tokens to upstream request (L7 authz)",
            );
        }
        // Apply assertions after delegation so strip rules govern delegated headers.
        let (set, removed) =
            apply_request_assertions(ctx, result.modified_extensions.as_ref(), &self.request_assertions);
        if set > 0 || removed > 0 {
            tracing::debug!(
                target: "policy.filter",
                set, removed,
                "applied request assertions to upstream request (L7 authz)",
            );
        }
        // Reuse the admitted identity so mid-exchange token expiry cannot cause a late deny.
        ctx.extensions.insert(ResolvedIdentity(identity));
        tracing::trace!(target: "policy.filter", "http authz allow (on_request)");
        Ok(FilterAction::Continue)
    }

    /// Populate `ext.http` with the request line + headers so CEL/APL
    /// predicates over `http.method` / `http.path` / `http.host` /
    /// `http.request_headers.*` evaluate. `host` is sourced from the parsed
    /// request authority (Praxis validates Host upstream — see the Pingora
    /// boundary docs), never a raw unvalidated header.
    fn attach_http_attributes(
        ctx: &HttpFilterContext<'_>,
        ext: &mut Extensions,
        request_headers: std::collections::HashMap<String, String>,
    ) {
        use ppe::praxis_policy_core::extensions::HttpExtension;

        let req = ctx.request;
        let host = req.uri.authority().map(|a| a.host().to_owned()).or_else(|| {
            req.headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        });
        let http = HttpExtension {
            method: Some(req.method.as_str().to_owned()),
            path: Some(req.uri.path().to_owned()),
            host,
            scheme: req.uri.scheme_str().map(str::to_owned),
            request_headers,
            ..Default::default()
        };
        ext.http = Some(Arc::new(http));
    }
}

/// Render a validated claim into the identity projection's string format.
///
/// Strings remain unquoted; other values use compact JSON.
fn flatten_claim(value: &serde_json::Value) -> String {
    value.as_str().map_or_else(|| value.to_string(), str::to_owned)
}

/// Request-scoped identity reused during response processing.
///
/// Typed storage avoids serializing credentials and revalidating expired tokens.
pub(super) struct ResolvedIdentity(pub(super) IdentityPayload);

#[async_trait]
impl HttpFilter for PolicyFilter {
    fn referenced_files(&self) -> Vec<std::path::PathBuf> {
        // The policy document. Declaring it is what lets an operator edit policy
        // and have it take effect without a restart.
        vec![std::path::PathBuf::from(&self.cfg.config_path)]
    }

    fn name(&self) -> &'static str {
        "policy"
    }

    fn request_body_access(&self) -> BodyAccess {
        // `ReadOnly` is the minimum that gets us into `on_request_body`
        // (we need the body phase to fire so we can dispatch CMF after
        // the protocol classifier filter populates its metadata). Operators opt into
        // `ReadWrite` via `body_access: read_write` when they want APL
        // field mutators (`redact()` / `assign()` on `args.<field>`) to
        // rewrite the upstream body. Chain-level scoping keeps non-policy
        // traffic out of this filter so the buffering cost is bounded
        // either way.
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly => BodyAccess::ReadOnly,
            BodyAccessMode::ReadWrite => BodyAccess::ReadWrite,
        }
    }

    fn request_body_mode(&self) -> BodyMode {
        // In `ReadWrite` mode we MUST buffer the whole body before the
        // filter runs — otherwise praxis would stream chunks upstream
        // as they arrive, and a body rewrite at end-of-stream would
        // race against an already-finished upstream write.
        // `StreamBuffer` accumulates chunks, calls our filter exactly
        // once at EOS with the full body, and forwards whatever we put
        // back into `body`. `ReadOnly` inherits the default `Stream`.
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly => BodyMode::Stream,
            BodyAccessMode::ReadWrite => BodyMode::StreamBuffer {
                max_bytes: Some(self.cfg.max_buffer_bytes),
            },
        }
    }

    fn response_body_access(&self) -> BodyAccess {
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly => BodyAccess::ReadOnly,
            BodyAccessMode::ReadWrite => BodyAccess::ReadWrite,
        }
    }

    fn response_body_mode(&self) -> BodyMode {
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly => BodyMode::Stream,
            BodyAccessMode::ReadWrite => BodyMode::StreamBuffer {
                max_bytes: Some(self.cfg.max_buffer_bytes),
            },
        }
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        // A StreamBuffer filter can force the body phase to run before this
        // header phase. In that case admission already ran in on_request_body,
        // and re-running it could fail after credential-stripping mutations.
        if Self::admission_complete(ctx) {
            tracing::trace!(target: "policy.filter", "admission already completed in body phase; skipping header phase");
            return Ok(FilterAction::Continue);
        }

        // Pure L7 policy (a `global` HTTP policy, no entity routes): authorize
        // here over `http.*` + identity. Authorization is an admission check
        // with no body, and no classifier is involved, so this is the
        // efficient path for Praxis as an L7 HTTP proxy.
        if self.http_global && !self.entity_routes {
            // Box the (large CMF-typed) future so it lives on the heap
            // rather than inflating this method's stack frame.
            let action = Box::pin(self.on_request_http_authz(ctx)).await?;
            if matches!(action, FilterAction::Continue) {
                Self::mark_admission_complete(ctx);
            }
            return Ok(action);
        }

        // Otherwise (entity-aware policy, or identity-only): early identity
        // gate. Saves the per-request body-buffer cost on un-auth'd traffic —
        // if there's no valid token, we never reach `on_request_body` and the
        // body never gets buffered.
        // Boxing keeps the identity payload out of this method's stack frame.
        let action = Box::pin(self.identity_gate(ctx)).await?;
        if !self.entity_routes && matches!(action, FilterAction::Continue) {
            Self::mark_admission_complete(ctx);
        }
        Ok(action)
    }

    #[expect(
        clippy::large_stack_frames,
        clippy::too_many_lines,
        reason = "async handler with multiple await points over large CMF types; linear phase flow"
    )]
    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        // A downstream StreamBuffer filter makes this body hook run before
        // on_request. Pure-L7 and identity-only admission needs no body, so run
        // it on the first chunk before any later body filter can act. In the
        // normal header-first lifecycle, the completion marker makes this a
        // no-op and prevents duplicate validation.
        if !self.entity_routes {
            if Self::admission_complete(ctx) {
                return Ok(FilterAction::BodyDone);
            }
            let action = if self.http_global {
                Box::pin(self.on_request_http_authz(ctx)).await?
            } else {
                self.identity_gate(ctx).await?
            };
            if matches!(action, FilterAction::Continue) {
                Self::mark_admission_complete(ctx);
                return Ok(FilterAction::BodyDone);
            }
            return Ok(action);
        }

        // Entity CMF dispatch waits for the full body so the protocol
        // classifier has finished writing route metadata.
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        // This policy declares entity routes (tool/prompt/resource), so it
        // needs the request classified into an entity before authorization.
        // Missing `mcp.method` means the protocol classifier filter (from
        // praxis-ai) did not run before us — the classifier is absent or
        // ordered after `policy` in the chain. Fail closed so the misconfig is
        // loud at the first request. Operators intentionally running this
        // policy for identity-only enforcement can opt out via
        // `require_protocol_metadata: false`.
        let Some(method) = ctx.get_metadata("mcp.method").map(str::to_owned) else {
            if self.cfg.require_protocol_metadata {
                tracing::error!(
                    target: "policy.filter",
                    "policy declares entity routes (tool/prompt/resource) which require a protocol \
                     classifier filter ordered before `policy` in the chain, but no `mcp.method` \
                     metadata was found — the classifier is missing or misordered. Denying (fail-closed). \
                     Set `require_protocol_metadata: false` only to run this policy for identity-only enforcement.",
                );
                return Ok(FilterAction::Reject(missing_protocol_metadata_rejection()));
            }
            tracing::trace!(target: "policy.filter", "no mcp.method in metadata; no CMF dispatch");
            return self.complete_gated_admission(ctx).await;
        };
        let Some((entity_type, hook_name)) = entity_for_protocol_method(&method) else {
            tracing::trace!(
                target: "policy.filter",
                protocol_method = %method,
                "JSON-RPC method has no entity binding; no CMF dispatch",
            );
            return self.complete_gated_admission(ctx).await;
        };
        let Some(entity_name) = ctx.get_metadata("mcp.name").map(str::to_owned) else {
            tracing::error!(
                target: "policy.filter",
                protocol_method = %method,
                "entity-bound JSON-RPC method is missing mcp.name metadata; denying fail-closed",
            );
            return Ok(FilterAction::Reject(missing_protocol_metadata_rejection()));
        };

        // Snapshot headers once for both identity resolution and
        // extensions building (avoids iterating the header map twice).
        let headers = Self::snapshot_headers(ctx);

        // Resolve identity once here, then stash it so the response phase
        // can rebuild `Extensions` without re-validating the token.
        let identity = match self
            .resolve_identity(ctx, headers.clone(), entity_type, &entity_name)
            .await
        {
            Ok(id) => id,
            Err(rej) => return Ok(FilterAction::Reject(rej)),
        };
        Self::take_gated_identity(ctx);
        Self::publish_authenticated_identity(ctx, &identity);
        let mut extensions = Self::extensions_from_identity(&headers, &identity, entity_type, &entity_name);
        // Attach the HTTP request line + headers so a single policy can combine
        // entity/`args.*` checks with `http.*` predicates in one evaluation.
        // The engine grants entity route handlers the `read_headers` capability, so
        // these `http.*` attributes reach the CEL/APL bag at the entity phase.
        Self::attach_http_attributes(ctx, &mut extensions, headers);
        ctx.extensions.insert(ResolvedIdentity(identity));

        // Parse the JSON-RPC body to build the typed CMF content part.
        // The protocol classifier filter already parsed once but only stashed
        // method/name in `filter_metadata`, not the `params.arguments`
        // that APL `args.*` predicates need. We re-parse here. The
        // body is already in memory; the duplicate parse is
        // microseconds.
        let body_bytes = body.as_ref().cloned().unwrap_or_else(Bytes::new);
        // Parse once for this phase: the id, the typed content, and the
        // deny-path id echo all read the same DOM.
        let parsed = ParsedEnvelope::parse(&body_bytes);
        let id = parsed.id_string();
        let content = build_content_for_method(&method, &entity_name, &id, &parsed);

        // Dispatch the CMF hook. The route annotation (installed by
        // the APL visitor at config-load time) drives policy
        // evaluation; if no APL route matches, the hook is a no-op.
        //
        // Policy evaluation (APL predicates, Cedar/CEL PDP queries, PII
        // scanning) can be CPU-intensive for complex rule sets or large
        // input data. Offload to the blocking thread pool so the async
        // runtime stays responsive to other concurrent requests.
        let payload = MessagePayload {
            message: Message::with_content(Role::User, content),
        };
        let mgr = Arc::clone(&self.mgr);
        let handle = tokio::runtime::Handle::current();
        let cmf_result = tokio::task::spawn_blocking(move || {
            handle.block_on(async {
                let (r, _bg) = mgr.invoke_named::<CmfHook>(hook_name, payload, extensions, None).await;
                r
            })
        })
        .await
        .map_err(|e| -> FilterError { format!("policy: CMF request-phase hook task failed: {e}").into() })?;

        if !cmf_result.continue_processing {
            let request_id = parsed.id_value();
            tracing::debug!(
                target: "policy.filter",
                hook = %hook_name,
                entity = %entity_name,
                "CMF deny",
            );
            return Ok(FilterAction::Reject(json_rpc_error_rejection(
                cmf_result.violation.as_ref(),
                &request_id,
            )));
        }

        // Allow path. If APL `delegate(...)` steps minted any outbound
        // tokens, the delegators wrote them into
        // `modified_extensions.raw_credentials.delegated_tokens`.
        // Attach each one to the upstream request as the configured
        // header.
        let attached = attach_delegated_tokens(ctx, cmf_result.modified_extensions.as_ref());
        if attached > 0 {
            tracing::debug!(
                target: "policy.filter",
                count = attached,
                "attached delegated tokens to upstream request",
            );
        }
        // Apply assertions after delegation so strip rules govern delegated headers.
        let (set, removed) =
            apply_request_assertions(ctx, cmf_result.modified_extensions.as_ref(), &self.request_assertions);
        if set > 0 || removed > 0 {
            tracing::debug!(
                target: "policy.filter",
                set, removed,
                "applied request assertions to upstream request",
            );
        }

        // If body_access is ReadWrite AND APL mutated the payload
        // (a `redact()` / `assign()` step fired), re-serialize the
        // mutated `MessagePayload` back into the JSON-RPC body so the
        // upstream service receives the rewritten args.
        if matches!(self.cfg.body_access, BodyAccessMode::ReadWrite)
            && let Some(mp) = cmf_result.modified_payload.as_ref()
            && let Some(updated) = mp.as_any().downcast_ref::<MessagePayload>()
        {
            // The rewrite mutates the DOM this phase already parsed;
            // handing it over avoids a second O(body) parse.
            if let Some(new_bytes) = reserialize_json_rpc_body(parsed.into_value(), &method, &updated.message) {
                // Praxis recomputes upstream `Content-Length` from the
                // rewritten body via `mutated_request_body_len` →
                // `apply_mutated_content_length`, so we ship the bytes
                // as-is (no pad). Padding here would corrupt byte-exact
                // bodies that the upstream verifies via signature /
                // hash, and the response-path pad-on-shrink (where
                // `Content-Length` IS frozen) is unaffected.
                tracing::debug!(
                    target: "policy.filter",
                    method = %method,
                    new_len = new_bytes.len(),
                    original_len = body_bytes.len(),
                    "rewriting upstream body from mutated MessagePayload",
                );
                *body = Some(new_bytes);
            }
        }

        tracing::trace!(
            target: "policy.filter",
            hook = %hook_name,
            entity = %entity_name,
            "CMF allow",
        );
        Self::mark_admission_complete(ctx);
        Ok(FilterAction::BodyDone)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "linear response-phase flow: rebuild identity, dispatch, apply the contract"
    )]
    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(hook) = self.response_hook else {
            return Ok(FilterAction::Continue);
        };
        let Some(response) = ctx.response_header.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        let response_headers = snapshot_response_headers(&response.headers);
        let status = response.status.as_u16();

        // Reuse admitted identity without revalidating a token mid-exchange.
        let request_headers = Self::snapshot_headers(ctx);
        let mut extensions = if let Some(ResolvedIdentity(identity)) = ctx.extensions.get::<ResolvedIdentity>() {
            Self::extensions_from_identity(&request_headers, identity, ENTITY_HTTP, ENTITY_NAME_GLOBAL)
        } else {
            tracing::debug!(
                target: "policy.filter",
                "no request-phase identity stashed for the response half; \
                 an entry sourced from it renders nothing",
            );
            Extensions {
                meta: Some(Arc::new(MetaExtension {
                    entity_type: Some(ENTITY_HTTP.to_owned()),
                    entity_name: Some(ENTITY_NAME_GLOBAL.to_owned()),
                    ..Default::default()
                })),
                ..Default::default()
            }
        };
        Self::attach_http_attributes(ctx, &mut extensions, request_headers);
        // Preserve request coordinates so response assertions resolve the same route.
        let mut http = extensions.http.as_ref().map(|arc| (**arc).clone()).unwrap_or_default();
        http.response_headers = response_headers;
        http.status = Some(status);
        extensions.http = Some(Arc::new(http));

        let mgr = Arc::clone(&self.mgr);
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::spawn_blocking(move || {
            handle.block_on(async {
                let (r, _bg) = mgr.invoke_named::<HttpHook>(hook, HttpPayload, extensions, None).await;
                r
            })
        })
        .await
        .map_err(|e| -> FilterError { format!("policy: HTTP response-phase hook task failed: {e}").into() })?;

        if !result.continue_processing {
            tracing::warn!(
                target: "policy.filter",
                violation = ?result.violation,
                "http response deny; replacing the upstream response",
            );
            return Ok(FilterAction::Reject(super::error::http_authz_rejection(
                result.violation.as_ref(),
            )));
        }

        let Some(response) = ctx.response_header.as_mut() else {
            return Ok(FilterAction::Continue);
        };
        let (set, removed) = apply_response_assertions(
            &mut response.headers,
            result.modified_extensions.as_ref(),
            &self.response_assertions,
        );
        if set > 0 || removed > 0 {
            ctx.response_headers_modified = true;
            tracing::debug!(
                target: "policy.filter",
                set, removed,
                "applied response assertions to the downstream response",
            );
        }
        Ok(FilterAction::Continue)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "linear response-phase flow (rebuild identity, dispatch, deny/rewrite); splitting obscures it"
    )]
    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        // Response-phase entity work only applies to entity-aware policies;
        // a pure L7 (or identity-only) policy has no per-entity post hook.
        if !self.entity_routes {
            return Ok(FilterAction::Continue);
        }
        // No point doing anything if the operator hasn't opted into
        // response rewriting.
        if !matches!(self.cfg.body_access, BodyAccessMode::ReadWrite) {
            return Ok(FilterAction::Continue);
        }

        // The protocol classifier filter stashes method/name during the request
        // phase and praxis preserves `filter_metadata` across phases,
        // so we can route the post-phase hook without re-parsing the
        // body.
        let Some(method) = ctx.get_metadata("mcp.method").map(str::to_owned) else {
            return Ok(FilterAction::Continue);
        };
        let Some((entity_type, hook_name)) = entity_for_protocol_method_post(&method) else {
            return Ok(FilterAction::Continue);
        };
        let Some(entity_name) = ctx.get_metadata("mcp.name").map(str::to_owned) else {
            return Ok(FilterAction::Continue);
        };

        let body_bytes = body.as_ref().cloned().unwrap_or_else(Bytes::new);
        // Parse once for this phase; the id string, the deny-path id
        // echoes, and the typed content all read the same DOM.
        let parsed = ParsedEnvelope::parse(&body_bytes);
        let id_str = parsed.id_string();

        // Rebuild `Extensions` from the identity resolved in the request
        // phase (stashed in `ctx.extensions`), rather than re-running the
        // identity hook here. This is a pure, synchronous field-mapping —
        // no token re-validation — so a token that expired between the
        // request and this (already-served) response can't produce a
        // false deny on a request that was authorized.
        let Some(ResolvedIdentity(identity)) = ctx.extensions.get::<ResolvedIdentity>() else {
            // Fail closed: a response we can no longer attribute to a
            // request-phase identity must be denied rather than passed
            // through, which would skip configured response-side
            // redaction and leak the upstream payload. We can't change
            // the already-sent status/headers, but we can replace the
            // body with a deny envelope fitted to the committed length.
            tracing::error!(
                target: "policy.filter",
                method = %method,
                entity = %entity_name,
                "no request-phase identity stashed; failing closed \
                 (replacing response body with deny envelope)",
            );
            let request_id = parsed.id_value();
            let violation = PluginViolation::new(
                "identity.post_phase_unavailable",
                "no request-phase identity available for response processing",
            );
            let envelope = json_rpc_error_envelope_bytes(Some(&violation), &request_id);
            *body = Some(fit_to_original_length(
                envelope,
                body_bytes.len(),
                method.as_str(),
                "post-phase identity failure",
            ));
            return Ok(FilterAction::Continue);
        };
        let headers = Self::snapshot_headers(ctx);
        let extensions = Self::extensions_from_identity(&headers, identity, entity_type, &entity_name);

        let content = build_response_content_for_method(&method, &entity_name, &id_str, &parsed);
        if content.is_empty() {
            return Ok(FilterAction::Continue);
        }
        let payload = MessagePayload {
            message: Message::with_content(Role::Assistant, content),
        };
        let mgr = Arc::clone(&self.mgr);
        let handle = tokio::runtime::Handle::current();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        tokio::task::spawn_blocking(move || {
            let result = handle.block_on(async move {
                let (r, _bg) = mgr.invoke_named::<CmfHook>(hook_name, payload, extensions, None).await;
                r
            });
            drop(tx.send(result));
        });
        let cmf_result = rx.recv().map_err(|_recv| -> FilterError {
            "policy: response-phase CMF dispatch failed (spawn_blocking channel closed)".into()
        })?;

        // Post-phase deny — the upstream's response carries something
        // the operator wants suppressed (output PII, late policy
        // violation, etc.). We can't change the HTTP status or
        // headers from `on_response_body`, but we CAN replace the
        // body bytes with a JSON-RPC error envelope so the client
        // sees a structured deny instead of the upstream's payload.
        // Fits within the original Content-Length via the same
        // pad-with-trailing-spaces trick used for ReadWrite rewrites
        // (the envelope is almost always shorter than a real
        // response body, so padding is the common case).
        if !cmf_result.continue_processing {
            tracing::warn!(
                target: "policy.filter",
                method = %method,
                entity = %entity_name,
                violation = ?cmf_result.violation,
                "post-phase deny — replacing response body with JSON-RPC error envelope",
            );
            // Reuse `body_bytes` (the original response body cloned above);
            // it has not been reassigned on this path.
            let request_id = parsed.id_value();
            let envelope = json_rpc_error_envelope_bytes(cmf_result.violation.as_ref(), &request_id);
            *body = Some(fit_to_original_length(
                envelope,
                body_bytes.len(),
                method.as_str(),
                "post-phase deny",
            ));
            return Ok(FilterAction::Continue);
        }

        if let Some(mp) = cmf_result.modified_payload.as_ref()
            && let Some(updated) = mp.as_any().downcast_ref::<MessagePayload>()
        {
            // Capture the id before the rewrite consumes the parsed DOM
            // (handing the DOM over avoids a second O(body) parse); only
            // the overflow arm below still needs it.
            let request_id = parsed.id_value();
            if let Some(new_bytes) = reserialize_json_rpc_response_body(parsed.into_value(), &method, &updated.message)
            {
                let final_bytes = if new_bytes.len() > body_bytes.len() {
                    // The rewrite grew the body past the committed
                    // response Content-Length. We can't enlarge the
                    // response, and truncating the redacted payload would
                    // ship corrupt JSON. Fail closed: replace it with a
                    // structured deny envelope fitted to length, so the
                    // client gets a clean error rather than a mangled
                    // (and potentially under-redacted) body.
                    tracing::warn!(
                        target: "policy.filter",
                        method = %method,
                        new_len = new_bytes.len(),
                        original_len = body_bytes.len(),
                        "response rewrite exceeds committed Content-Length; \
                         failing closed with deny envelope",
                    );
                    let violation = PluginViolation::new(
                        "gateway.response_rewrite_overflow",
                        "response rewrite exceeded the committed response length",
                    );
                    let envelope = json_rpc_error_envelope_bytes(Some(&violation), &request_id);
                    fit_to_original_length(envelope, body_bytes.len(), method.as_str(), "response rewrite overflow")
                } else {
                    fit_to_original_length(new_bytes, body_bytes.len(), method.as_str(), "response-side rewrite")
                };
                tracing::debug!(
                    target: "policy.filter",
                    method = %method,
                    new_len = final_bytes.len(),
                    original_len = body_bytes.len(),
                    "rewriting downstream response body from mutated MessagePayload",
                );
                *body = Some(final_bytes);
            }
        }
        Ok(FilterAction::Continue)
    }
}

/// Fit a freshly-built body to the original `Content-Length`, always
/// returning **exactly** `original_len` bytes: pad with trailing ASCII
/// spaces on shrink (JSON parsers ignore them); truncate on grow.
///
/// The downstream response `Content-Length` is committed by the time
/// `on_response_body` runs — praxis has no response-side equivalent of
/// `apply_mutated_content_length` (that path is request-only). Emitting
/// more bytes than `original_len` is therefore an HTTP/1.1 framing
/// desync: the trailing bytes would be parsed as the start of the next
/// response (a response-smuggling primitive). Truncating to
/// `original_len` corrupts the JSON the client parses but cannot smuggle
/// — it is the safe failure mode. Callers that can do better (the
/// response-rewrite path) substitute a length-fitting deny envelope
/// before reaching the grow case, so truncation is a last-resort
/// backstop, not the common path.
///
/// Used only on the response side. The request side is unaffected:
/// praxis repairs request framing via `mutated_request_body_len` →
/// `apply_mutated_content_length` (`stream_buffer.rs` → `with_body.rs`),
/// so padding there would only corrupt byte-exact bodies the upstream
/// might verify via signature / hash.
pub(super) fn fit_to_original_length(new_bytes: Bytes, original_len: usize, method: &str, reason: &str) -> Bytes {
    match new_bytes.len().cmp(&original_len) {
        std::cmp::Ordering::Less => {
            let mut padded = Vec::with_capacity(original_len);
            padded.extend_from_slice(&new_bytes);
            padded.resize(original_len, b' ');
            Bytes::from(padded)
        },
        std::cmp::Ordering::Equal => new_bytes,
        std::cmp::Ordering::Greater => {
            tracing::warn!(
                target: "policy.filter",
                method = %method,
                new_len = new_bytes.len(),
                original_len,
                "{reason}: rewritten body larger than original Content-Length; \
                 truncating to preserve HTTP/1.1 framing (response Content-Length \
                 is already committed and cannot grow)",
            );
            new_bytes.slice(0..original_len)
        },
    }
}

/// Rejection emitted when `require_protocol_metadata` is on (default) and
/// no `mcp.method` metadata was set by an upstream filter. HTTP 500
/// because the misconfiguration is server-side, not client-side.
fn missing_protocol_metadata_rejection() -> Rejection {
    Rejection::status(500)
        .with_header("Content-Type", "text/plain")
        .with_header(VIOLATION_HEADER, "config.missing_protocol_metadata")
        .with_body(Bytes::from_static(
            b"policy: no mcp.method in filter metadata. A protocol classifier filter \
              (from the praxis-ai package) must be present in the chain \
              and ordered before `policy`. Set the filter's \
              `require_protocol_metadata: false` to disable this guard \
              for non-classified traffic.",
        ))
}

// -----------------------------------------------------------------------------
// attach_delegated_tokens
// -----------------------------------------------------------------------------

/// Walk the minted delegated tokens on the resolved `Extensions` and
/// push them as upstream request headers. Returns the count attached
/// (0 when no delegation ran or no extensions were returned). Each
/// token's `outbound_header` field decides where it goes; the value
/// is `Bearer <token>` (RFC 6750 wire format — what every audience
/// expects). Uses `request_headers_to_set` rather than
/// `extra_request_headers` because authorization tokens are
/// overwrites, not appends.
///
/// Multiple tokens targeting the same outbound header are a
/// configuration ambiguity — praxis's `request_headers_to_set`
/// would otherwise let the last writer silently win, with order
/// determined by `HashMap` iteration. Apply first-writer-wins keyed
/// on `(outbound_header_lc, audience)`, log a warn on each skip so
/// the operator can fix the overlapping delegators.
#[expect(
    clippy::too_many_lines,
    reason = "single linear pass attaching delegated tokens with first-writer-wins dedupe"
)]
pub(super) fn attach_delegated_tokens(ctx: &mut HttpFilterContext<'_>, extensions: Option<&Extensions>) -> usize {
    let Some(ext) = extensions else {
        return 0;
    };
    let Some(raw) = ext.raw_credentials.as_ref() else {
        return 0;
    };

    // Stable-order the tokens before we attach. `delegated_tokens` is
    // a `HashMap`, so iteration order is non-deterministic — two
    // tokens targeting the same outbound header would otherwise
    // produce order-dependent results (praxis's
    // `request_headers_to_set` is overwrite semantics). Sorting by
    // `(outbound_header_lc, audience)` gives first-writer-wins where
    // "first" is alphabetically lowest audience for that header.
    let mut sorted: Vec<&_> = raw.delegated_tokens.values().collect();
    sorted.sort_by(|a, b| {
        a.outbound_header
            .to_ascii_lowercase()
            .cmp(&b.outbound_header.to_ascii_lowercase())
            .then_with(|| a.audience.cmp(&b.audience))
    });

    let mut attached_outbound: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut count = 0;
    for tok in sorted {
        let outbound_lc = tok.outbound_header.to_ascii_lowercase();
        if !attached_outbound.insert(outbound_lc.clone()) {
            // A token for this outbound header was already attached
            // earlier in the sorted pass — refuse to overwrite. Warn
            // loudly so an operator notices the policy ambiguity
            // (two delegators racing for the same header is almost
            // always a mistake in route/global config layering).
            tracing::warn!(
                target: "policy.filter",
                outbound_header = %tok.outbound_header,
                audience = %tok.audience,
                "skipping delegated token: another token already targets this outbound header \
                 (first-writer-wins by audience asc); fix overlapping delegators in policy",
            );
            continue;
        }
        let Ok(name) = http::header::HeaderName::try_from(tok.outbound_header.as_str()) else {
            tracing::warn!(
                target: "policy.filter",
                header = %tok.outbound_header,
                "delegated token outbound_header is not a valid HTTP header name; skipping",
            );
            attached_outbound.remove(&outbound_lc);
            continue;
        };
        // `tok.token` is already `Zeroizing`; keep the freshly-minted
        // `Bearer …` plaintext in a `Zeroizing` buffer too so it is wiped
        // as soon as the `HeaderValue` has copied its bytes, rather than
        // lingering on the heap until the allocator reuses the page.
        let bearer = zeroize::Zeroizing::new(format!("Bearer {}", tok.token.as_str()));
        let Ok(value) = http::header::HeaderValue::try_from(bearer.as_str()) else {
            tracing::warn!(
                target: "policy.filter",
                audience = %tok.audience,
                "minted token bytes are not a valid HTTP header value; skipping",
            );
            attached_outbound.remove(&outbound_lc);
            continue;
        };
        ctx.request_headers_to_set.push((name, value));
        count += 1;
    }

    // Strip the inbound credential headers — but only when we
    // actually attached delegated tokens, and only headers that are
    // NOT also being set by an outbound (collision case —
    // `request_headers_to_set` overwrites, no remove needed).
    if count > 0 {
        for inbound in raw.inbound_tokens.values() {
            let normalized = inbound.source_header.to_ascii_lowercase();
            if attached_outbound.contains(&normalized) {
                continue;
            }
            if let Ok(n) = http::header::HeaderName::try_from(inbound.source_header.as_str()) {
                ctx.request_headers_to_remove.push(n);
            } else {
                tracing::warn!(
                    target: "policy.filter",
                    header = %inbound.source_header,
                    "inbound source_header is not a valid HTTP header name; cannot strip",
                );
            }
        }
    }

    count
}
