// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `PolicyFilter` — embeds the CPEX runtime in-process to resolve and
//! validate identity, evaluate APL routes, optionally mint delegated
//! credentials, scan for PII, emit audit records, and optionally
//! rewrite request/response bodies.

use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use async_trait::async_trait;
use bytes::Bytes;
use cpex::cpex_core::{
    cmf::{CmfHook, Message, MessagePayload, Role},
    error::{PluginError, PluginViolation},
    hooks::Extensions,
    identity::{HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource},
    manager::PluginManager,
};

use super::{
    common_message_format::{entity_for_protocol_method, entity_for_protocol_method_post},
    config::{BodyAccessMode, PolicyFilterConfig},
    error::{VIOLATION_HEADER, auth_rejection, json_rpc_error_envelope_bytes, json_rpc_error_rejection},
    json_rpc::{
        build_content_for_method, build_response_content_for_method, json_rpc_id, json_rpc_id_value,
        reserialize_json_rpc_body, reserialize_json_rpc_response_body,
    },
};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// PolicyFilter
// -----------------------------------------------------------------------------

// State of the one-shot tokio runtime-flavor check performed on the
// first request. See `PolicyFilter::on_request` for the rationale.

/// Initial state — no request has been served yet.
const RUNTIME_UNCHECKED: u8 = 0;
/// First request saw a multi-thread runtime; subsequent requests skip the check.
const RUNTIME_OK: u8 = 1;
/// First request saw a current-thread runtime; all requests reject.
const RUNTIME_REJECTED: u8 = 2;

/// Embeds the CPEX policy engine in-process to enforce multi-source JWT
/// identity, APL route policy, RFC 8693 token exchange, PII
/// scanning, audit emission, and (under `body_access: read_write`)
/// request / response body rewriting.
///
/// Experimental: requires the `cpex-policy-engine` cargo feature, which
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
/// (declared in the CPEX YAML) gate the tool/prompt/resource call by
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
/// config_path: /etc/praxis/cpex-policy.yaml
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
    /// CPEX plugin manager — owns the loaded plugin instances and
    /// dispatches hook chains. Wrapped in `Arc` so the post-phase
    /// `block_in_place` closure can hold its own handle without
    /// borrowing `&self`.
    mgr: Arc<PluginManager>,
    /// One-shot runtime-flavor check. `on_response_body` drives async
    /// work via `block_in_place`, which panics on a current-thread
    /// runtime (praxis `work_stealing: false`). We can't query the
    /// flavor from `new()` (no runtime attached yet), so we check on
    /// the first request and cache the result. A fuller fix would
    /// require `on_response_body` to be async upstream in praxis.
    runtime_check: AtomicU8,
}

impl PolicyFilter {
    /// Construct a filter from a parsed config. Loads the CPEX YAML
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
    pub fn new(cfg: PolicyFilterConfig) -> Result<Self, FilterError> {
        let yaml = std::fs::read_to_string(&cfg.config_path).map_err(|e| -> FilterError {
            format!("policy: failed to read config_path {}: {e}", cfg.config_path).into()
        })?;

        let mgr = Arc::new(PluginManager::default());
        cpex::install_builtins(&mgr);

        mgr.load_config_yaml(&yaml)
            .map_err(|e: Box<PluginError>| -> FilterError { format!("policy: load_config_yaml failed: {e}").into() })?;

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
                    Ok(Err(e)) => Err(format!("policy: PluginManager::initialize failed: {e}")),
                    Err(_) => Err(format!(
                        "policy: PluginManager::initialize timed out after {}s \
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
            format!("policy: PluginManager::initialize panicked in init thread: {msg}")
        })?;
        init.map_err(|s: String| -> FilterError { s.into() })?;

        Ok(Self {
            cfg,
            mgr,
            runtime_check: AtomicU8::new(RUNTIME_UNCHECKED),
        })
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
    fn snapshot_headers(ctx: &HttpFilterContext<'_>) -> std::collections::HashMap<String, String> {
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

    /// Resolve identity by invoking the identity hook chain. Returns the
    /// resolved [`IdentityPayload`] (subject / client / workload / raw
    /// credentials / delegation) or a rejection when no identity
    /// continues. Cheap — the JWT verifier hits its in-process key cache.
    async fn resolve_identity(
        &self,
        headers: std::collections::HashMap<String, String>,
    ) -> Result<IdentityPayload, Rejection> {
        let (id_result, _bg) = self
            .mgr
            .invoke_named::<IdentityHook>(
                HOOK_IDENTITY_RESOLVE,
                Self::identity_payload(headers),
                Extensions::default(),
                None,
            )
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
}

/// Request-scoped carrier for the identity resolved in the request phase,
/// stashed in [`HttpFilterContext::extensions`] so the response phase can
/// rebuild `Extensions` without re-validating the (possibly-expired)
/// token. Held as typed state rather than serialized metadata so the
/// inbound credentials never land in a plaintext string.
struct ResolvedIdentity(IdentityPayload);

#[async_trait]
impl HttpFilter for PolicyFilter {
    fn name(&self) -> &'static str {
        "policy"
    }

    fn request_body_access(&self) -> BodyAccess {
        // `ReadOnly` is the minimum that gets us into `on_request_body`
        // (we need the body phase to fire so we can dispatch CMF after
        // the protocol classifier filter populates its metadata). Operators opt into
        // `ReadWrite` via `body_access: read_write` when they want APL
        // field mutators (`redact()` / `assign()` on `args.<field>`) to
        // rewrite the upstream body. Chain-level scoping keeps non-CPEX
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
        // One-shot runtime-flavor check. `on_response_body` uses
        // `block_in_place` to drive async work from a sync trait
        // method, and that primitive panics on a current-thread
        // tokio runtime (praxis `work_stealing: false`). Rather than
        // crash mid-response, refuse to operate up front. After the
        // first request this collapses to a single atomic load.
        match self.runtime_check.load(Ordering::Acquire) {
            RUNTIME_UNCHECKED => {
                let flavor = tokio::runtime::Handle::current().runtime_flavor();
                if matches!(flavor, tokio::runtime::RuntimeFlavor::CurrentThread) {
                    self.runtime_check.store(RUNTIME_REJECTED, Ordering::Release);
                    return Err(current_thread_runtime_error());
                }
                self.runtime_check.store(RUNTIME_OK, Ordering::Release);
            },
            RUNTIME_REJECTED => return Err(current_thread_runtime_error()),
            _ => {}, // RUNTIME_OK — fall through.
        }

        // Early identity gate. Saves the per-request body-buffer cost
        // on un-auth'd traffic — if there's no valid token, we never
        // reach `on_request_body` and the body never gets buffered.
        let (result, _bg) = self
            .mgr
            .invoke_named::<IdentityHook>(
                HOOK_IDENTITY_RESOLVE,
                Self::identity_payload(Self::snapshot_headers(ctx)),
                Extensions::default(),
                None,
            )
            .await;

        if !result.continue_processing {
            tracing::debug!(target: "policy.filter", "identity deny (on_request)");
            return Ok(FilterAction::Reject(auth_rejection(result.violation.as_ref())));
        }

        tracing::trace!(target: "policy.filter", "identity allow (on_request)");
        Ok(FilterAction::Continue)
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
        // CMF dispatch only fires once the full body has been seen
        // (so the protocol classifier filter has finished parsing and writing its
        // metadata). For streaming chunks we just pass.
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        // Pull Protocol-derived entity coords from durable filter_metadata.
        // Missing `protocol.method` means the protocol classifier filter (from praxis-ai)
        // didn't run before us — almost always a misconfigured chain
        // (missing or ordered after `policy`). Default to fail-closed
        // so the misconfig is loud at first request. Operators
        // fronting non-classified traffic can opt out via
        // `require_protocol_metadata: false`.
        let Some(method) = ctx.get_metadata("protocol.method").map(str::to_owned) else {
            if self.cfg.require_protocol_metadata {
                tracing::warn!(
                    target: "policy.filter",
                    "no protocol.method in metadata — likely the protocol classifier filter (praxis-ai) \
                     is missing or ordered after `policy` in the chain; rejecting \
                     (set `require_protocol_metadata: false` to disable this guard)",
                );
                return Ok(FilterAction::Reject(missing_protocol_metadata_rejection()));
            }
            tracing::trace!(target: "policy.filter", "no protocol.method in metadata; no CMF dispatch");
            return Ok(FilterAction::BodyDone);
        };
        let Some((entity_type, hook_name)) = entity_for_protocol_method(&method) else {
            tracing::trace!(
                target: "policy.filter",
                protocol_method = %method,
                "JSON-RPC method has no entity binding; no CMF dispatch",
            );
            return Ok(FilterAction::BodyDone);
        };
        let Some(entity_name) = ctx.get_metadata("protocol.name").map(str::to_owned) else {
            tracing::debug!(
                target: "policy.filter",
                protocol_method = %method,
                "JSON-RPC method missing protocol.name metadata; skipping CMF dispatch",
            );
            return Ok(FilterAction::BodyDone);
        };

        // Snapshot headers once for both identity resolution and
        // extensions building (avoids iterating the header map twice).
        let headers = Self::snapshot_headers(ctx);

        // Resolve identity once here, then stash it so the response phase
        // can rebuild `Extensions` without re-validating the token.
        let identity = match self.resolve_identity(headers.clone()).await {
            Ok(id) => id,
            Err(rej) => return Ok(FilterAction::Reject(rej)),
        };
        let extensions = Self::extensions_from_identity(&headers, &identity, entity_type, &entity_name);
        ctx.extensions.insert(ResolvedIdentity(identity));

        // Parse the JSON-RPC body to build the typed CMF content part.
        // The protocol classifier filter already parsed once but only stashed
        // method/name in `filter_metadata`, not the `params.arguments`
        // that APL `args.*` predicates need. We re-parse here. The
        // body is already in memory; the duplicate parse is
        // microseconds.
        let body_bytes = body.as_ref().cloned().unwrap_or_else(Bytes::new);
        let id = json_rpc_id(&body_bytes);
        let content = build_content_for_method(&method, &entity_name, &id, &body_bytes);

        // Dispatch the CMF hook. The route annotation (installed by
        // the APL visitor at config-load time) drives policy
        // evaluation; if no APL route matches, the hook is a no-op.
        let payload = MessagePayload {
            message: Message::with_content(Role::User, content),
        };
        let (cmf_result, _bg) = self
            .mgr
            .invoke_named::<CmfHook>(hook_name, payload, extensions, None)
            .await;

        if !cmf_result.continue_processing {
            let request_id = json_rpc_id_value(&body_bytes);
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

        // If body_access is ReadWrite AND APL mutated the payload
        // (a `redact()` / `assign()` step fired), re-serialize the
        // mutated `MessagePayload` back into the JSON-RPC body so the
        // upstream service receives the rewritten args.
        if matches!(self.cfg.body_access, BodyAccessMode::ReadWrite)
            && let Some(mp) = cmf_result.modified_payload.as_ref()
            && let Some(updated) = mp.as_any().downcast_ref::<MessagePayload>()
        {
            // `body_bytes` (cloned above) still holds the original body —
            // it has not been reassigned — so reuse it instead of cloning
            // the buffer a second time.
            if let Some(new_bytes) = reserialize_json_rpc_body(&body_bytes, &method, &updated.message) {
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
        Ok(FilterAction::BodyDone)
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
        // No point doing anything if the operator hasn't opted into
        // response rewriting.
        if !matches!(self.cfg.body_access, BodyAccessMode::ReadWrite) {
            return Ok(FilterAction::Continue);
        }

        // The protocol classifier filter stashes method/name during the request
        // phase and praxis preserves `filter_metadata` across phases,
        // so we can route the post-phase hook without re-parsing the
        // body.
        let Some(method) = ctx.get_metadata("protocol.method").map(str::to_owned) else {
            return Ok(FilterAction::Continue);
        };
        let Some((entity_type, hook_name)) = entity_for_protocol_method_post(&method) else {
            return Ok(FilterAction::Continue);
        };
        let Some(entity_name) = ctx.get_metadata("protocol.name").map(str::to_owned) else {
            return Ok(FilterAction::Continue);
        };

        let body_bytes = body.as_ref().cloned().unwrap_or_else(Bytes::new);
        let id_str = json_rpc_id(&body_bytes);

        // Rebuild `Extensions` from the identity resolved in the request
        // phase (stashed in `ctx.extensions`), rather than re-running the
        // identity hook here. This is a pure, synchronous field-mapping —
        // no `block_in_place`, no token re-validation — so a token that
        // expired between the request and this (already-served) response
        // can't produce a false deny on a request that was authorized.
        let Some(ResolvedIdentity(identity)) = ctx.extensions.get::<ResolvedIdentity>() else {
            // Fail closed: a response we can no longer attribute to a
            // request-phase identity must be denied rather than passed
            // through, which would skip configured response-side
            // redaction and leak the upstream payload. We can't change
            // the already-sent status/headers, but we can replace the
            // body with a deny envelope fitted to the committed length.
            tracing::warn!(
                target: "policy.filter",
                method = %method,
                entity = %entity_name,
                "no request-phase identity stashed; failing closed \
                 (replacing response body with deny envelope)",
            );
            let request_id = json_rpc_id_value(&body_bytes);
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

        let content = build_response_content_for_method(&method, &entity_name, &id_str, &body_bytes);
        if content.is_empty() {
            return Ok(FilterAction::Continue);
        }
        let payload = MessagePayload {
            message: Message::with_content(Role::Assistant, content),
        };
        let mgr = Arc::clone(&self.mgr);
        let cmf_result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let (r, _bg) = mgr.invoke_named::<CmfHook>(hook_name, payload, extensions, None).await;
                r
            })
        });

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
            let request_id = json_rpc_id_value(&body_bytes);
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
            // Reuse `body_bytes` (the original response body cloned above)
            // rather than cloning the buffer again.
            if let Some(new_bytes) = reserialize_json_rpc_response_body(&body_bytes, &method, &updated.message) {
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
                    let request_id = json_rpc_id_value(&body_bytes);
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

// -----------------------------------------------------------------------------
// runtime-flavor error
// -----------------------------------------------------------------------------

/// Error returned from `on_request` when the filter has been mounted
/// into a current-thread tokio runtime. Hoisted into a helper so the
/// first-request and cached-rejection branches return identical text.
fn current_thread_runtime_error() -> FilterError {
    "policy filter requires a multi-threaded tokio runtime \
     (server config `work_stealing: true`); current-thread runtime \
     is unsupported because response-phase body transformation \
     requires `block_in_place`"
        .into()
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
/// no `protocol.method` metadata was set by an upstream filter. HTTP 500
/// because the misconfiguration is server-side, not client-side.
fn missing_protocol_metadata_rejection() -> Rejection {
    Rejection::status(500)
        .with_header("Content-Type", "text/plain")
        .with_header(VIOLATION_HEADER, "config.missing_protocol_metadata")
        .with_body(Bytes::from_static(
            b"policy: no protocol.method in filter metadata. An protocol classifier filter \
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
