// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `PolicyFilter` — embeds the policy engine in-process to resolve and
//! validate identity, evaluate APL routes, optionally mint delegated
//! credentials, run the host plugins a policy names, emit audit records,
//! and optionally rewrite request/response bodies.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use async_trait::async_trait;
use bytes::Bytes;
use ppe::praxis_policy_core::{
    assertions::Direction,
    cmf::{
        CmfHook, Message, MessagePayload, Role,
        constants::{
            ENTITY_HTTP, ENTITY_LLM, ENTITY_NAME_GLOBAL, HOOK_CMF_LLM_INPUT, HOOK_CMF_LLM_OUTPUT,
            HOOK_CMF_PROMPT_POST_INVOKE, HOOK_CMF_PROMPT_PRE_INVOKE, HOOK_CMF_RESOURCE_POST_FETCH,
            HOOK_CMF_RESOURCE_PRE_FETCH, HOOK_CMF_TOOL_POST_INVOKE, HOOK_CMF_TOOL_PRE_INVOKE,
        },
    },
    engine::PolicyEngine,
    error::{PluginError, PluginViolation},
    executor::PipelineResult,
    extensions::{Credential, LLMExtension, LlmRequestDocument, MetaExtension, http::SecretHeaderProvenance},
    hooks::{Extensions, HookTypeDef},
    http_hook::{HOOK_HTTP_REQUEST, HOOK_HTTP_RESPONSE, HttpHook, HttpPayload},
    identity::{HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource},
    ratelimit_hook::{HOOK_RATELIMIT_POST_IDENTITY, HOOK_RATELIMIT_PRE_IDENTITY},
    secrets::backends::EnvSecretProviderFactory,
};
use praxis_core::{connectivity::CidrRange, subrequest::SubRequestConnector};

use super::{
    assertions::{
        GovernedNames, apply_request_assertions, apply_response_assertions, snapshot_response_headers,
        unreachable_response_levels,
    },
    common_message_format::{entity_for_protocol_method, entity_for_protocol_method_post},
    config::{BodyAccessMode, PolicyFilterConfig},
    construction::{
        engine_error, parse_trusted_proxies, refuse_fips_blockers, refuse_query_credentials_with_delegation,
        require_dpop_external_base_url,
    },
    context::{PolicyResponseContext, PolicyResponseOutput},
    dispatch::{block_on_bounded, ensure_dispatch_runtime, response_dispatch_timeout},
    error::{
        VIOLATION_HEADER, auth_rejection, deny_with_body, json_rpc_error_envelope_bytes, json_rpc_error_rejection,
        llm_deny_rejection, llm_error_envelope_bytes_within, rate_limit_json_rpc_rejection, rate_limit_rejection,
    },
    json_rpc::{
        ParsedEnvelope, build_content_for_method, build_response_content_for_method, reserialize_json_rpc_body,
        reserialize_json_rpc_response_body,
    },
    llm::{ParsedLlmRequest, ParsedLlmResponse, request_message, response_message},
    request_facts::{RequestFacts, RequestView},
    request_headers,
    request_state::{MetadataResponseDispatch, state, state_mut},
    response_rules::{ensure_supported_entity_results, metadata_only_policy},
    transport::PolicyHttpTransport,
};
use crate::{
    AuthenticatedIdentity, FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Empty request body used for parsing bodyless requests.
static EMPTY_BODY: Bytes = Bytes::new();

/// How a response policy handled the custom extension namespace.
pub(super) enum ResponseCustomState {
    /// The policy did not return modified extensions.
    Unmodified,
    /// The policy returned a replacement custom namespace.
    Replaced(Arc<std::collections::HashMap<String, serde_json::Value>>),
    /// The policy explicitly removed the custom namespace.
    Removed,
}

// -----------------------------------------------------------------------------
// PolicyFilter
// -----------------------------------------------------------------------------

/// Embeds the Praxis Policy Engine in-process to enforce multi-source
/// identity, APL route policy, RFC 8693 token exchange, field redaction,
/// session taint, audit emission, and (under `body_access: read_write`)
/// request / response body rewriting. Content scanning is a host plugin
/// the engine dispatches, not a bundled one.
///
/// Registered under the YAML filter name `policy`. The default build
/// selects `policy-builtins`, which registers every Policy builtin plugin
/// kind, including the experimental `ratelimit/limitador`. A narrower build
/// names `policy-engine` or individual `policy-*` builtins plus one crypto
/// backend; a policy naming a plugin kind the build did not compile in
/// fails to load. `--no-default-features` leaves the filter out.
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
/// Policies with `llm:` routes authorize the top-level request `model`
/// through `cmf.llm_input`, without classifier metadata. Missing,
/// unlisted, and ambiguous models fail closed by default.
///
/// OPA, CEL, and Cedar `pre_invocation` steps on `llm:` routes also read the
/// parsed request body as `llm.request` (`input.llm.request` in OPA, `context.llm.request`
/// in Cedar), so a rule can inspect `tools`, `messages`, or `input`. Only a
/// request attributed to a model carries it: a JSON body with a usable
/// top-level `model`, no JSON-RPC envelope, and no `mcp.method` metadata.
/// Other requests carry none. CEL and Cedar deny when a rule reads it, and
/// so does an OPA boolean or object decision, but an OPA deny set needs its
/// own guard. On allow the upstream receives the original bytes. A body
/// over `llm.max_request_bytes` receives HTTP 413 before any authorization
/// rule runs. Policy judges the body as it reaches this filter, so order
/// body-rewriting filters before `policy`.
/// For rule syntax, engine types, and absent-value behavior, see
/// [Structured request input] in the policy engine docs.
///
/// Chat Completions and Anthropic Messages requests also expose normalized
/// `llm.input.*` facts for instructions, offered tools, tool choice, completion
/// limits, sampling and stop sequences. Unsupported shapes, unknown fields
/// and malformed values leave these facts absent; rules that require them
/// should deny their absence. See the [normalized LLM input example].
///
/// PPE 0.4.1 changes OPA and CEL `args` on `tool:` routes to native JSON.
/// Before upgrading, review rules that read `args`: for example, a numeric
/// ID in `args.ids` must be compared with `13`, not `"13"`. A schema-backed
/// `cedar-direct` PDP must set `structured_context: true` or the policy
/// fails to load. Its schema must also declare the optional `args` and `llm`
/// context fields its actions can receive, or those requests are denied.
/// See the [PPE 0.4.1 changelog] and
/// [args migration guidance].
///
/// PPE 0.5.0 tightens OAuth `delegate(...)` by default. A token-exchange
/// response must name an access-token or JWT `issued_token_type`. When the
/// step requests scopes, a granted scope that was neither requested nor
/// listed in `allowed_extra_scopes` is refused; a step that requests none
/// accepts the identity provider's defaults. When the minted token is a JWT,
/// its `aud` must contain the step's `audience`, and on a token exchange its
/// `sub` must match the caller. `strict_response_validation: false` turns
/// these checks off. A JWT with an unsupported `crit` header is rejected, and an `env` secret provider with
/// settings it does not use fails to load. CEL `size()` now counts code
/// points rather than bytes, and `exists()` returns true when one element
/// matches even if another errors, so some requests that were denied may now
/// be allowed. See the [PPE 0.5.0 changelog].
///
/// Every hook sees the downstream request as this filter first received
/// it: method, path, raw query, the validated host lowercased without a port,
/// the effective client address, and headers. Trusted reserved-prefix and
/// `context_headers` updates remain visible to later hooks. The scheme is
/// `https` only when the downstream connection is TLS; `X-Forwarded-Proto`
/// is never trusted. Place `policy`
/// before `path_rewrite`, `url_rewrite` and header-rewriting filters so the
/// request it authorizes is the one the client sent. A `DPoP` issuer must set
/// `dpop.external_base_url`, so a proof's `htu` is never checked against the
/// client-sent `Host`.
///
/// `http.client_address` is the TCP peer, without a port. When the peer is in
/// `trusted_proxies`, it is the rightmost `X-Forwarded-For` hop outside those
/// ranges instead, or the leftmost hop when every hop is trusted; hops left of
/// the client are ignored; a malformed hop reached before it leaves no client
/// address. RFC 7239 `Forwarded` is not supported. Only
/// policy input changes: `ip_acl` and `forwarded_headers` still see the peer.
///
/// A policy with `rate_limits:` runs `ratelimit.pre_identity` once per
/// request before the first identity resolution, on the HTTP coordinates
/// (`http`, `*`) and the request as first received, and
/// `ratelimit.post_identity` once after the last, on the final route and the
/// resolved identity, before authorization and forwarding. Two `policy`
/// filters in one chain each run both stages. A denial ends the request with
/// its declared status (429, 400, 401 or 503), fixed text per code, and only
/// the `limit`, `remaining`, `retry_after_seconds` and `window_seconds`
/// details; a positive `retry_after_seconds` sets `Retry-After`. The
/// plugin's reason is never sent. On a classified JSON-RPC call the body is a
/// JSON-RPC error carrying the request `id`, under the same status. Counters
/// belong to each limiter instance: they are not shared between replicas and
/// reset when the configuration reloads. Each IPv6 /64 is one address key,
/// so pair a per-address limit with a coarser one.
///
/// Policy can read a credential from a query parameter
/// (`credential: { kind: query_param, name: ... }`, with the `read_query`
/// capability). The filter does not rewrite the URL, so the parameter
/// reaches the upstream, and access logs, CDN logs and browser history
/// outside Policy can record it. A policy that combines a query credential
/// with `delegate(...)` fails to load. At request time, a delegated token is
/// never forwarded while an inbound credential sits where the filter cannot
/// strip it; that request receives HTTP 500
/// (`policy.unstrippable_credential`). A delegation none of whose tokens
/// forms a valid upstream header receives HTTP 500
/// (`policy.delegation_failed`) rather than forwarding the inbound one.
///
/// The filter registers only the `env` secret provider. A `secrets:` block
/// naming any other provider kind, including `file`, fails to load. Secret
/// values are read when the filter is built, so a changed value takes effect
/// on the next restart.
///
/// The configured policy receives the full parsed inference request. Treat
/// policy documents and custom plugins as trusted: a rule or an explicit
/// outbound call can disclose fields it reads. Review policy authorship and
/// outbound endpoints before enabling structured request input.
///
/// On a policy with `llm:` routes, a bodyless request (a `GET`, `HEAD`,
/// `OPTIONS`, `TRACE` or `CONNECT` with no body), such as `GET /v1/models`,
/// runs the policy's HTTP authorization, delegation and request assertions
/// before it is admitted: a matching `http:` route, the `global` rules
/// otherwise. It carries no inference request, so a global rule that reads
/// `llm.request` denies it; keep such rules in `llm:` routes or
/// `global.defaults.llm`. A policy with neither HTTP rules nor request
/// assertions admits it on identity. A body with no usable `model` under
/// `llm.require_model: false` runs the same HTTP admission after parsing and
/// classification checks. MCP-only policies with `require_protocol_metadata:
/// false` still admit unclassified requests on identity alone and warn when
/// HTTP rules or request assertions exist. Classified non-entity MCP methods
/// also retain their identity-only admission.
///
/// On a policy with `llm:` routes, any request body without `mcp.method`
/// metadata that repeats a key within one JSON object, at any depth,
/// including keys that differ only in case,
/// receives HTTP 400 with violation code `llm.duplicate_key` before any
/// authorization rule runs, since backends disagree on which copy wins.
/// This covers bodies with no `model` and unclaimed JSON-RPC envelopes too.
/// The response names neither the key nor any value. A body that is not
/// valid JSON is not refused for being malformed: it carries no usable
/// `model`, so it is handled like any other body without one.
///
/// A lone differently cased field such as `Tools` is not a duplicate.
/// `llm.request` keeps the wire spelling, so a rule checking only `tools`
/// will not see `Tools`. If an upstream accepts such aliases, cover them
/// explicitly in policy or require canonical field spelling at its boundary.
///
/// The CMF prompt text that APL steps and scanners read is projected from
/// `system`, Responses `instructions`, `messages[].content`, legacy
/// `prompt`, and `input`. For Responses and embeddings `input`, only text
/// counts: a string, string items, and `input_text`, `text`,
/// `output_text`, `reasoning_text`, or `summary_text` parts. Message items
/// contribute their `content`. Every other item type, including tool calls,
/// tool outputs, and reasoning, contributes its `arguments`, `input`,
/// `output`, `text`, `content`, and `summary`. File search result `text`, code
/// interpreter `code` and output `logs`, and listed MCP tool `description`
/// are also projected. Token-ID arrays, images, and files are skipped.
///
/// `body_access: read_write` enables the JSON-RPC re-serialization
/// round-trip so APL field mutators (`redact()`, `assign()`) rewrite
/// the upstream request body and the downstream response. It also enables
/// `cmf.llm_output` for non-streaming inference responses. APL field
/// mutators do not rewrite inference bodies.
///
/// `body_access: read_write` also enables response-phase `tool:`, `prompt:`,
/// and `resource:` rules, including attribute-only `post_invocation` rules. Under `read_only`, these
/// rules are skipped and a warning is emitted. A response-only route adds no
/// request-phase route rule; identity checks and `global` policy still apply.
/// When tool response hooks are configured, a nonempty classified `tools/call`
/// response that is malformed or contains neither a result nor a valid
/// JSON-RPC error produces a filter error instead of silently skipping
/// inspection. The pipeline's `failure_mode` controls that error; valid
/// JSON-RPC error responses continue unchanged.
///
/// `result.<field>` projection for `prompt:` and `resource:` routes remains
/// blocked on [policy #75]; host-side content projection is tracked in [Praxis #1330].
/// A `result:` field pipeline on either entity, including an inherited one,
/// is rejected at load so its controls cannot be silently skipped.
///
/// [policy #75]: https://github.com/praxis-proxy/policy/issues/75
/// [Praxis #1330]: https://github.com/praxis-proxy/praxis/issues/1330
///
/// Policies with MCP entity routes cannot declare `authorization:` on an
/// `http:` route. Use `global` for shared authorization; route-scoped
/// `authentication:` remains supported.
///
/// Response-body hooks run on a small dedicated runtime while the worker
/// waits, for at most twice the engine's per-plugin timeout
/// (`engine_settings.plugin_timeout`, so 60 seconds by default). A hook
/// that does not finish in time is aborted and the response fails under
/// the filter's `failure_mode`: `closed` truncates the response, `open`
/// passes the body through unfiltered.
///
/// Outbound policy calls share the proxy's sub-request limits and circuit
/// breaker, use HTTP/1.1, and keep a separate 1 MiB response ceiling. Calls
/// made by response-body hooks use their own pool on the dispatch runtime,
/// with the same connection limit but no circuit breaker. TLS
/// uses the platform trust store; cluster private CAs and client
/// certificates do not apply. A private destination requires
/// `trusted_private_endpoints` for a specific host, or `allow_private_idp`
/// to relax every callout.
///
/// An endpoint URL may name an IP address over `http`, but not over
/// `https`: an IP carries no SNI, and Pingora peers skip certificate
/// verification entirely when SNI is empty. Use a hostname for `https`.
///
/// [Structured request input]: https://github.com/praxis-proxy/policy/blob/main/docs/content/apl/pdp.md#structured-request-input
/// [PPE 0.4.1 changelog]: https://github.com/praxis-proxy/policy/blob/v0.4.1/CHANGELOG.md#041---2026-10-05
/// [PPE 0.5.0 changelog]: https://github.com/praxis-proxy/policy/blob/v0.5.0/CHANGELOG.md#050---2026-10-13
/// [args migration guidance]: https://github.com/praxis-proxy/policy/blob/v0.4.1/docs/content/apl/pdp.md#migrating-args-policies
/// [normalized LLM input example]: https://github.com/praxis-proxy/praxis/blob/main/examples/configs/security/policy-llm-input.yaml
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
/// max_buffer_bytes: 10485760
/// llm:
///   require_model: true
///   require_route: true
///   provider: openai
/// ```
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts derived from the policy document; they combine rather than \
              enumerate, so a state machine would not model them"
)]
pub struct PolicyFilter {
    /// Filter-level configuration parsed from the YAML block. Held so
    /// `request_body_access` / `request_body_mode` / their response
    /// counterparts can branch on `body_access` per request.
    cfg: PolicyFilterConfig,
    /// Policy engine plugin manager — owns the loaded plugin instances and
    /// dispatches hook chains. Wrapped in `Arc` so offloaded hook
    /// dispatches can hold their own handle without borrowing `&self`.
    mgr: Arc<PolicyEngine>,
    /// Policy engine view containing only post rules that can run without a response body.
    response_context_mgr: Option<Arc<PolicyEngine>>,
    /// Derived from the loaded policy: it declares per-entity routes
    /// (tool/prompt/resource/llm). When true, authorization runs at the
    /// body phase, once the request is attributed to an entity.
    entity_routes: bool,
    /// Whether the policy declares MCP entity routes.
    mcp_routes: bool,
    /// Whether a tool response hook can inspect classified tool responses.
    mcp_post_tool: bool,
    /// Whether the policy declares inference routes.
    llm_routes: bool,
    /// Whether the policy declares inference response hooks.
    llm_post: bool,
    /// Whether a limiter runs at `ratelimit.pre_identity`.
    limit_pre: bool,
    /// Whether a limiter runs at `ratelimit.post_identity`.
    limit_post: bool,
    /// Whether `http.request` has work: a handler or request assertions.
    /// Without entity routes, the filter is a pure L7 policy authorized at
    /// `on_request`; unclassified inference fallbacks use the same rules in
    /// the body phase.
    http_request_policy: bool,
    /// Header names governed by request assertions.
    request_assertions: GovernedNames,
    /// Header names governed by response assertions.
    response_assertions: GovernedNames,
    /// Response hook to dispatch when the policy has response work.
    response_hook: Option<&'static str>,
    /// Route table used to match inference models.
    llm_route_table: Option<Arc<ppe::praxis_policy_core::config::PolicyConfig>>,
    /// Whether the inference request-mutator warning was emitted.
    llm_request_mutator_warned: AtomicBool,
    /// Whether the inference response-mutator warning was emitted.
    llm_response_mutator_warned: AtomicBool,
    /// Bound on one response-phase hook dispatch, derived from the engine's
    /// per-plugin timeout.
    response_dispatch_timeout: std::time::Duration,
    /// Proxies trusted to report the client in `X-Forwarded-For`.
    trusted_proxies: Vec<CidrRange>,
    /// The transport installed on the engine, kept so tests can see which
    /// connector policy calls go through.
    #[cfg(all(test, feature = "policy-builtins"))]
    transport: Arc<PolicyHttpTransport>,
}

impl PolicyFilter {
    /// Construct a filter from a parsed config. Loads the policy document
    /// referenced by `cfg.config_path`, registers bundled plugin
    /// factories, wires the APL visitor, and initializes the manager.
    /// Errors abort filter chain construction at server startup —
    /// failing fast is what we want for misconfigured policy.
    ///
    /// Policy calls, including the JWKS fetches made while initializing, go
    /// through `subrequest_connector`, or through a pool of their own without
    /// one.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the referenced YAML cannot be read,
    /// the policy document fails to parse, or plugin initialization
    /// fails (e.g., a JWKS endpoint is unreachable).
    ///
    /// [`FilterError`]: FilterError
    #[expect(
        clippy::too_many_lines,
        reason = "linear construction + init steps; splitting obscures the startup flow"
    )]
    pub(crate) fn new(
        cfg: PolicyFilterConfig,
        subrequest_connector: Option<SubRequestConnector>,
    ) -> Result<Self, FilterError> {
        cfg.validate_context_headers()
            .map_err(|e| -> FilterError { format!("policy: {e}").into() })?;
        refuse_fips_blockers(praxis_tls::provider::required())?;

        // Validate addressable, nonzero limits. The pipeline additionally clamps
        // accumulation to body_limits.max_buffer_bytes before invoking this filter.
        if cfg.max_buffer_bytes == 0 {
            return Err("policy: max_buffer_bytes must be > 0".into());
        }
        if cfg.max_buffer_bytes > praxis_core::config::MAX_BUFFER_BYTES {
            return Err(format!(
                "policy: max_buffer_bytes ({}) exceeds the maximum ({})",
                cfg.max_buffer_bytes,
                praxis_core::config::MAX_BUFFER_BYTES
            )
            .into());
        }
        if cfg.llm.max_request_bytes == 0 {
            return Err("policy: llm.max_request_bytes must be > 0".into());
        }
        if cfg.llm.max_request_bytes > praxis_core::config::MAX_BUFFER_BYTES {
            return Err(format!(
                "policy: llm.max_request_bytes ({}) exceeds the maximum ({})",
                cfg.llm.max_request_bytes,
                praxis_core::config::MAX_BUFFER_BYTES
            )
            .into());
        }

        // Reject a malformed pinned-endpoint entry at startup rather than let it
        // silently never match at request time.
        praxis_core::connectivity::validate_host_entries("policy", &cfg.trusted_private_endpoints)?;
        let trusted_proxies = parse_trusted_proxies(&cfg.trusted_proxies)?;

        let yaml = std::fs::read_to_string(&cfg.config_path).map_err(|e| -> FilterError {
            format!("policy: failed to read config_path {}: {e}", cfg.config_path).into()
        })?;

        let session_store: Arc<dyn ppe::SessionStore> = Arc::new(ppe::MemorySessionStore::new());
        let mgr = Arc::new(PolicyEngine::default());
        Self::install_plugins(&mgr, Arc::clone(&session_store));

        // The lazy connection pool must not bind to the temporary init runtime.
        let transport = Self::http_transport(
            subrequest_connector,
            cfg.allow_private_idp,
            &cfg.trusted_private_endpoints,
        );
        if !mgr.set_http_transport(Arc::<PolicyHttpTransport>::clone(&transport)) {
            // Set-once, and this manager was just constructed, so a refusal
            // means the engine changed under us rather than a double install.
            tracing::warn!(
                target: "policy.filter",
                "policy: an HTTP transport was already installed on a fresh engine"
            );
        }

        // `env` only. PPE's `file` provider confirms `base_dir` containment by
        // resolving the path again after opening it, so a writer inside
        // `base_dir` who swaps a symlink between the two can have a file
        // outside it accepted. A document whose `secrets:` block names any
        // other provider kind fails at `initialize()`, naming `env`.
        let mut secret_providers = ppe::SecretProviderRegistry::new();
        secret_providers.register(Box::new(EnvSecretProviderFactory));
        if !mgr.set_secret_providers(secret_providers) {
            tracing::warn!(
                target: "policy.filter",
                "policy: secret providers were already registered on a fresh engine"
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

        // Parsed separately because the engine does not retain the document.
        // The DPoP check runs before the engine builds any plugin, since the
        // JWT factory reads keys and installs its crypto provider. A parse
        // error is reported after the engine's own, more specific one.
        let parsed = ppe::praxis_policy_core::config::parse_config(&yaml);
        if let Ok(document) = &parsed {
            require_dpop_external_base_url(document)?;
            refuse_query_credentials_with_delegation(document)?;
        }
        mgr.load_config_yaml(&yaml)
            .map_err(|e: Box<PluginError>| engine_error("load_config_yaml", &cfg.config_path, &e))?;

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
        let config_path = cfg.config_path.clone();
        let init: Result<(), FilterError> = std::thread::spawn(move || -> Result<(), FilterError> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("policy: failed to build init runtime: {e}"))?;
            rt.block_on(async move {
                match tokio::time::timeout(init_timeout, mgr_for_init.initialize()).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(engine_error("PolicyEngine::initialize", &config_path, &e)),
                    Err(_) => Err(format!(
                        "policy: PolicyEngine::initialize timed out after {}s \
                         (init_timeout_secs); likely a JWKS / OAuth endpoint is unreachable",
                        init_timeout.as_secs(),
                    )
                    .into()),
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
        init?;

        // Derive the evaluation shape from the loaded policy so the filter
        // needs no operator-set mode. `has_hooks_for` reports whether a hook
        // was wired by the policy (registered handler or route annotation).
        let http_global = mgr.has_hooks_for(HOOK_HTTP_REQUEST);
        // The engine installs a route's pre and post halves independently, so a
        // route whose only declarations are `result.<field>` pipelines or
        // `post_invocation` steps registers the post hook and no pre hook. Both
        // halves count toward `mcp_routes`: the response phase dispatches off
        // `entity_routes`, so a post-only policy needs it true.
        let mcp_pre = mgr.has_hooks_for(HOOK_CMF_TOOL_PRE_INVOKE)
            || mgr.has_hooks_for(HOOK_CMF_PROMPT_PRE_INVOKE)
            || mgr.has_hooks_for(HOOK_CMF_RESOURCE_PRE_FETCH);
        // Split by entity: tool post hooks evaluate with projected content,
        // while prompt and resource post hooks dispatch with an empty payload
        // (content projection is tools/call only). Attribute-only rules
        // (identity and subject/meta predicates) work for all three;
        // `result.<field>` projection for prompts and resources is still
        // blocked on policy work.
        let mcp_post_tool = mgr.has_hooks_for(HOOK_CMF_TOOL_POST_INVOKE);
        let mcp_post_prompt_resource =
            mgr.has_hooks_for(HOOK_CMF_PROMPT_POST_INVOKE) || mgr.has_hooks_for(HOOK_CMF_RESOURCE_POST_FETCH);
        let mcp_post = mcp_post_tool || mcp_post_prompt_resource;
        let mcp_routes = mcp_pre || mcp_post;
        let llm_post = mgr.has_hooks_for(HOOK_CMF_LLM_OUTPUT);
        // A post-only route still needs request state for response dispatch.
        let llm_routes = mgr.has_hooks_for(HOOK_CMF_LLM_INPUT) || llm_post;
        let entity_routes = mcp_routes || llm_routes;

        let policy_config = parsed.map_err(|e: Box<PluginError>| -> FilterError {
            format!(
                "policy: the engine accepted {} but praxis could not re-read it for the \
                     assertions contract: {e}",
                cfg.config_path
            )
            .into()
        })?;
        let dispatch_timeout = response_dispatch_timeout(policy_config.engine_settings.plugin_timeout);
        ensure_supported_entity_results(&yaml, &policy_config)?;
        let response_context_mgr = if llm_post {
            metadata_only_policy(&yaml)?
                .map(|filtered| {
                    Self::load_policy_engine(
                        &filtered,
                        &cfg.config_path,
                        Arc::clone(&transport),
                        cfg.init_timeout_secs,
                        Arc::clone(&session_store),
                    )
                })
                .transpose()?
        } else {
            None
        };
        if entity_routes {
            ensure_dispatch_runtime()
                .map_err(|e| -> FilterError { format!("policy: response hooks cannot run: {e}").into() })?;
        }
        let request_assertions = GovernedNames::from_config(&policy_config, Direction::Request);
        let response_assertions = GovernedNames::from_config(&policy_config, Direction::Response);
        let http_request_policy = http_global || !request_assertions.is_empty();
        if entity_routes && http_request_policy {
            for message in identity_only_fallback_warnings(&cfg, mcp_routes, llm_routes) {
                tracing::warn!(target: "policy.filter", "{message}");
            }
        }

        if llm_routes {
            Self::warn_on_inference_gaps(&policy_config, &cfg, llm_post);
        }
        Self::warn_on_inert_inference_defaults(&policy_config, llm_routes);
        warn_on_rate_limits(&policy_config, &cfg.config_path);
        Self::warn_on_entity_response_gaps(&cfg, mcp_post_tool, mcp_post_prompt_resource);

        // Reject an `http:` route that no classified request can reach.
        if let Some(message) = Self::http_route_beside_entity_routes(&yaml, mcp_routes) {
            return Err(message.into());
        }

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

        let llm_route_table = llm_routes.then(|| Arc::new(policy_config));
        let limit_pre = mgr.has_hooks_for(HOOK_RATELIMIT_PRE_IDENTITY);
        let limit_post = mgr.has_hooks_for(HOOK_RATELIMIT_POST_IDENTITY);

        Ok(Self {
            cfg,
            mgr,
            response_context_mgr,
            entity_routes,
            mcp_routes,
            mcp_post_tool,
            llm_routes,
            llm_post,
            limit_pre,
            limit_post,
            http_request_policy,
            request_assertions,
            response_assertions,
            response_hook,
            llm_route_table,
            llm_request_mutator_warned: AtomicBool::new(false),
            llm_response_mutator_warned: AtomicBool::new(false),
            response_dispatch_timeout: dispatch_timeout,
            trusted_proxies,
            #[cfg(all(test, feature = "policy-builtins"))]
            transport,
        })
    }

    /// Load and initialize one PPE view of the policy document.
    #[expect(
        clippy::too_many_lines,
        reason = "linear engine registration, load, and bounded initialization"
    )]
    fn load_policy_engine(
        yaml: &str,
        source: &str,
        transport: Arc<PolicyHttpTransport>,
        init_timeout_secs: u64,
        session_store: Arc<dyn ppe::SessionStore>,
    ) -> Result<Arc<PolicyEngine>, FilterError> {
        let manager = Arc::new(PolicyEngine::default());
        Self::install_plugins(&manager, session_store);
        let mut secret_providers = ppe::SecretProviderRegistry::new();
        secret_providers.register(Box::new(EnvSecretProviderFactory));
        if !manager.set_secret_providers(secret_providers) {
            tracing::warn!(
                target: "policy.filter",
                "policy: secret providers were already registered on a fresh engine"
            );
        }
        if !manager.set_http_transport(transport) {
            tracing::warn!(
                target: "policy.filter",
                "policy: an HTTP transport was already installed on a fresh engine"
            );
        }

        let host_factories = super::host_plugins::host_plugin_factories();
        if !host_factories.is_empty() {
            tracing::info!(
                count = super::host_plugins::host_plugin_count(),
                "policy: registering host-supplied plugin factories"
            );
        }
        for (kind, factory) in host_factories {
            tracing::debug!(target: "policy.filter", kind = %kind, "registering host plugin factory");
            manager.register_factory(kind, factory);
        }
        manager
            .load_config_yaml(yaml)
            .map_err(|error: Box<PluginError>| -> FilterError {
                format!("policy: load_config_yaml failed for {source}: {error}").into()
            })?;

        let manager_for_init = Arc::clone(&manager);
        let init_timeout = std::time::Duration::from_secs(init_timeout_secs);
        let init = std::thread::spawn(move || -> Result<(), String> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("policy: failed to build init runtime: {error}"))?;
            runtime.block_on(async move {
                match tokio::time::timeout(init_timeout, manager_for_init.initialize()).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => Err(format!("policy: PolicyEngine::initialize failed: {error}")),
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
            let message = panic
                .downcast_ref::<&str>()
                .map(|value| (*value).to_owned())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<no panic message>".to_owned());
            format!("policy: PolicyEngine::initialize panicked in init thread: {message}")
        })?;
        init.map_err(|message: String| -> FilterError { message.into() })?;
        Ok(manager)
    }

    /// Test accessor for the transport installed on the engine.
    #[cfg(all(test, feature = "policy-builtins"))]
    pub(super) fn transport(&self) -> &PolicyHttpTransport {
        &self.transport
    }

    /// Test accessor for the hook the response half dispatches, if any.
    #[cfg(all(test, feature = "policy-builtins"))]
    pub(super) fn response_hook(&self) -> Option<&'static str> {
        self.response_hook
    }

    /// Test accessor for the shape derived from the loaded policy:
    /// `(http_request_policy, entity_routes)`.
    #[cfg(all(test, feature = "policy-builtins"))]
    pub(super) fn derived_shape(&self) -> (bool, bool) {
        (self.http_request_policy, self.entity_routes)
    }

    /// Return `(limit_pre, limit_post)` for tests.
    #[cfg(all(test, feature = "policy-builtins"))]
    pub(super) fn limit_stages(&self) -> (bool, bool) {
        (self.limit_pre, self.limit_post)
    }

    /// Return `(llm_routes, llm_post)` for tests.
    #[cfg(all(test, feature = "policy-builtins"))]
    pub(super) fn derived_llm_shape(&self) -> (bool, bool) {
        (self.llm_routes, self.llm_post)
    }

    /// Warn about inference configurations that can skip policy evaluation.
    fn warn_on_inference_gaps(
        policy_config: &ppe::praxis_policy_core::config::PolicyConfig,
        cfg: &PolicyFilterConfig,
        llm_post: bool,
    ) {
        let has_catch_all = policy_config
            .routes
            .iter()
            .filter_map(|route| route.llm.as_ref())
            .any(selector_matches_any_model);
        if !has_catch_all && !cfg.llm.require_route {
            tracing::warn!(
                target: "policy.filter",
                "policy declares `llm:` routes, no catch-all `llm: \"*\"` route, and \
                 `llm.require_route: false`: a model no route selects is evaluated by no policy at \
                 all and is admitted. Keep `llm.require_route: true` (default) to fail closed, or \
                 add a catch-all route that denies.",
            );
            Self::warn_on_list_form_catch_all(policy_config);
        }
        if llm_post {
            Self::warn_on_inference_response_gaps(cfg);
        }
    }

    /// Report inference response rules that cannot cover every response.
    fn warn_on_inference_response_gaps(cfg: &PolicyFilterConfig) {
        if !matches!(cfg.body_access, BodyAccessMode::ReadWrite) {
            tracing::warn!(
                target: "policy.filter",
                "policy declares response-phase `llm:` rules (`post_invocation`) but \
                 `body_access` is `read_only`, which does not buffer the response: rules that \
                 need response content will not run. A host may still trigger metadata-only \
                 response policy by supplying `PolicyResponseContext`; otherwise set \
                 `body_access: read_write`.",
            );
        }
        tracing::debug!(
            target: "policy.filter",
            "policy declares response-phase `llm:` rules: a response the upstream streams as \
             server-sent events carries no single completion, so those rules cannot run for it. \
             Deny `custom.llm.stream` in the request phase for the models this policy must \
             enforce on the way back.",
        );
    }

    /// Warn when configured MCP entity response rules cannot run.
    fn warn_on_entity_response_gaps(cfg: &PolicyFilterConfig, post_tool: bool, post_prompt_resource: bool) {
        if post_tool && !matches!(cfg.body_access, BodyAccessMode::ReadWrite) {
            tracing::warn!(
                target: "policy.filter",
                "policy declares response-phase `tool:` rules (`result.<field>` or \
                 `post_invocation`) but `body_access` is `read_only`, which does not buffer the \
                 response: those rules will never run. Set `body_access: read_write` to enable \
                 them.",
            );
        }
        if post_prompt_resource && !matches!(cfg.body_access, BodyAccessMode::ReadWrite) {
            tracing::warn!(
                target: "policy.filter",
                "policy declares response-phase `prompt:` or `resource:` rules, but \
                 `body_access` is `read_only`, which does not buffer the response: those \
                 rules will never run. Set `body_access: read_write` to enable them.",
            );
        } else if post_prompt_resource {
            tracing::info!(
                target: "policy.filter",
                "policy declares response-phase `prompt:` or `resource:` rules: \
                 `post_invocation` predicates over identity and attributes are dispatched, but \
                 `result.<field>` projection remains blocked on praxis-proxy/policy#75; \
                 host-side content projection is tracked in praxis-proxy/praxis#1330.",
            );
        }
    }

    /// Return a load error for an `http:` authorization route alongside MCP
    /// entity routes, or `None` when no such route exists.
    pub(super) fn http_route_beside_entity_routes(yaml: &str, mcp_routes: bool) -> Option<String> {
        if !mcp_routes {
            return None;
        }
        // RouteEntry omits authorization steps, so inspect the raw YAML and
        // reject a parse failure rather than skip this check.
        let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(yaml) else {
            return Some(
                "policy: praxis could not re-read the policy document to check the `http:` route \
                 contract. Refusing to load, because an `http:` route whose `authorization:` \
                 never runs cannot be ruled out."
                    .to_owned(),
            );
        };
        let routes = doc.get("routes").and_then(serde_yaml::Value::as_sequence)?;
        let offenders = routes
            .iter()
            .filter(|route| route.get("http").is_some() && route.get("authorization").is_some())
            .count();
        if offenders == 0 {
            return None;
        }
        Some(format!(
            "policy: {offenders} `http:` route(s) declare `authorization:` alongside MCP entity \
             routes. A classified MCP request is evaluated against its entity route, so those \
             steps never run for a tool, prompt, or resource call and the route would gate \
             nothing. Move cross-cutting rules into the `global` block, which is layered into \
             every entity route, or front non-MCP traffic with a separate listener/filter. A \
             route-scoped `authentication:` list is unaffected and may stay."
        ))
    }

    /// Warn when inference defaults have no route to apply them.
    fn warn_on_inert_inference_defaults(
        policy_config: &ppe::praxis_policy_core::config::PolicyConfig,
        llm_routes: bool,
    ) {
        if llm_routes || !policy_config.global.defaults.contains_key(ENTITY_LLM) {
            return;
        }
        tracing::warn!(
            target: "policy.filter",
            "policy declares `global.defaults.llm` but no `llm:` route: the defaults layer only \
             stacks onto routes, so no inference call is evaluated. Add an `llm:` route (a \
             catch-all `llm: \"*\"` at minimum) for the defaults to apply to.",
        );
    }

    /// Warn when a list containing `"*"` is mistaken for a catch-all.
    fn warn_on_list_form_catch_all(policy_config: &ppe::praxis_policy_core::config::PolicyConfig) {
        let has_list_form = policy_config
            .routes
            .iter()
            .filter_map(|route| route.llm.as_ref())
            .any(selector_lists_any_model_literal);
        if has_list_form {
            tracing::warn!(
                target: "policy.filter",
                "policy declares an `llm:` route whose selector is a LIST containing \"*\": a list \
                 selector matches model names exactly, so that route selects only a model literally \
                 named `*`. Write the catch-all as the bare string `llm: \"*\"`.",
            );
        }
    }

    /// Build a filter from its YAML config without the runtime's sub-request
    /// connector, so its policy calls open a connection pool of their own.
    ///
    /// A [`FilterRegistry`] builds `policy` filters with the connector handed
    /// to [`FilterRegistry::set_policy_connector`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the config block fails to parse
    /// as a `PolicyFilterConfig` or filter construction fails.
    ///
    /// [`FilterRegistry`]: crate::FilterRegistry
    /// [`FilterRegistry::set_policy_connector`]: crate::FilterRegistry::set_policy_connector
    /// [`FilterError`]: FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: PolicyFilterConfig = parse_filter_config("policy", config)?;
        Ok(Box::new(Self::new(cfg, None)?))
    }

    /// Build a filter from its YAML config whose policy calls go through
    /// `subrequest_connector`, or through a pool of their own without one.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the config block fails to parse
    /// as a `PolicyFilterConfig` or filter construction fails.
    ///
    /// [`FilterError`]: FilterError
    pub(crate) fn from_config_with_connector(
        config: &serde_yaml::Value,
        subrequest_connector: Option<SubRequestConnector>,
    ) -> Result<Self, FilterError> {
        let cfg: PolicyFilterConfig = parse_filter_config("policy", config)?;
        Self::new(cfg, subrequest_connector)
    }

    /// The current request's headers, lowercased, duplicate field lines
    /// comma-joined. Identity and policy input read [`RequestFacts`] instead;
    /// this is for comparing against what the upstream will receive.
    ///
    /// [`RequestFacts`]: RequestFacts
    pub(super) fn snapshot_headers(ctx: &HttpFilterContext<'_>) -> std::collections::HashMap<String, String> {
        super::request_facts::snapshot_headers(&ctx.request.headers)
    }

    /// Capture this pipeline instance's [`RequestFacts`] at its first callback.
    ///
    /// [`RequestFacts`]: RequestFacts
    fn capture_request_facts(&self, ctx: &mut HttpFilterContext<'_>) {
        if ctx.current_filter_id.is_some() && Self::stored_request_facts(ctx).is_none() {
            let facts = Arc::new(RequestFacts::capture(ctx, &self.trusted_proxies));
            state_mut(ctx).facts = Some(facts);
        }
    }

    /// The facts this instance captured, if any.
    fn stored_request_facts(ctx: &HttpFilterContext<'_>) -> Option<Arc<RequestFacts>> {
        state(ctx).and_then(|state| state.facts.clone())
    }

    /// Invoke `hook`, threading this instance's context table through it.
    ///
    /// # Errors
    ///
    /// Fails when an earlier dispatch lost the table.
    async fn invoke<H: HookTypeDef>(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        hook: &'static str,
        payload: H::Payload,
        extensions: Extensions,
    ) -> Result<PipelineResult, FilterError> {
        let table = state_mut(ctx).take_table()?;
        // The engine owns these tasks; awaiting their handles would delay the request.
        let (mut result, _background) = Box::pin(self.mgr.invoke_named::<H>(hook, payload, extensions, table)).await;
        state_mut(ctx).restore_table(std::mem::take(&mut result.context_table));
        Ok(result)
    }

    /// What a hook invocation sees of the request: the captured facts, the
    /// trusted header overlays, and the secret provenance of applied
    /// assertions. Without a capture, the facts are captured per call.
    fn request_view(
        ctx: &HttpFilterContext<'_>,
        context_headers: &std::collections::HashMap<super::config::ContextField, String>,
        trusted_proxies: &[CidrRange],
    ) -> RequestView {
        let facts =
            Self::stored_request_facts(ctx).unwrap_or_else(|| Arc::new(RequestFacts::capture(ctx, trusted_proxies)));
        let mut headers = facts.headers_with_reserved(&ctx.request.headers);
        Self::overlay_effective_context_headers(ctx, &mut headers, context_headers);
        let secret_headers = ctx
            .extensions
            .get::<AssertedSecretHeaders>()
            .map(|asserted| asserted.0.clone())
            .unwrap_or_default();
        RequestView::new(facts, headers, secret_headers)
    }

    /// Overlay effective header values for `context_headers` targets onto
    /// a pre-built snapshot. [`snapshot_headers`] reads only the original
    /// request; a filter ahead of `policy` that sets a reserved-prefix
    /// header in `on_request` (or promotes one during pre-read) writes to
    /// the pending-mutation queues, not to `ctx.request.headers`. This
    /// method reads those pending writes through [`EffectiveHeaders`] for
    /// the specific header names referenced by `context_headers`, so the
    /// body-phase `extensions_from_identity` sees them.
    ///
    /// [`snapshot_headers`]: Self::snapshot_headers
    /// [`EffectiveHeaders`]: crate::context::EffectiveHeaders
    fn overlay_effective_context_headers(
        ctx: &HttpFilterContext<'_>,
        snapshot: &mut std::collections::HashMap<String, String>,
        context_headers: &std::collections::HashMap<super::config::ContextField, String>,
    ) {
        use crate::{condition::HeaderSource as _, context::EffectiveHeaders};

        if context_headers.is_empty() {
            return;
        }
        let effective = EffectiveHeaders(ctx);
        for header_name in context_headers.values() {
            let lower = header_name.to_ascii_lowercase();
            let Ok(hname) = http::header::HeaderName::from_bytes(lower.as_bytes()) else {
                continue;
            };
            if let Ok(Some(v)) = effective.header(&hname) {
                snapshot.insert(lower, v.into_owned());
            }
        }
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
        view: &RequestView,
        entity_type: &str,
        entity_name: &str,
        scope: Option<&str>,
    ) -> Extensions {
        Extensions {
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some(entity_type.to_owned()),
                entity_name: Some(entity_name.to_owned()),
                scope: scope.map(ToOwned::to_owned),
                ..Default::default()
            })),
            http: Some(Arc::new(view.http_extension())),
            ..Default::default()
        }
    }

    /// Run `ratelimit.pre_identity` once per request, on the HTTP coordinates
    /// and the request as first captured, before any identity resolution.
    ///
    /// # Errors
    ///
    /// Fails when an earlier dispatch lost the context table.
    async fn pre_identity_limit(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        view: &RequestView,
    ) -> Result<Option<Rejection>, FilterError> {
        if !self.limit_pre || state(ctx).is_some_and(|state| state.limits.pre_identity) {
            return Ok(None);
        }
        state_mut(ctx).limits.pre_identity = true;
        let ext = Self::identity_extensions(
            view,
            ENTITY_HTTP,
            ENTITY_NAME_GLOBAL,
            self.cfg.context_meta.scope.as_deref(),
        );
        let result = self
            .invoke::<HttpHook>(ctx, HOOK_RATELIMIT_PRE_IDENTITY, HttpPayload, ext)
            .await?;
        if result.continue_processing {
            return Ok(None);
        }
        tracing::debug!(target: "policy.filter", "rate limit deny (pre-identity)");
        Ok(Some(rate_limit_rejection(result.violation.as_ref())))
    }

    /// Whether `ratelimit.post_identity` still has to run for this request.
    fn post_identity_limit_pending(&self, ctx: &HttpFilterContext<'_>) -> bool {
        self.limit_post && !state(ctx).is_some_and(|state| state.limits.post_identity)
    }

    /// Run `ratelimit.post_identity` once per request, after the final
    /// identity resolution and before authorization, on `extensions`: the
    /// final route coordinates and the resolved identity.
    ///
    /// # Errors
    ///
    /// Fails when an earlier dispatch lost the context table.
    async fn post_identity_limit(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        extensions: &Extensions,
    ) -> Result<Option<LimitDenied>, FilterError> {
        if !self.post_identity_limit_pending(ctx) {
            return Ok(None);
        }
        state_mut(ctx).limits.post_identity = true;
        let result = self
            .invoke::<HttpHook>(ctx, HOOK_RATELIMIT_POST_IDENTITY, HttpPayload, extensions.clone())
            .await?;
        if result.continue_processing {
            return Ok(None);
        }
        tracing::debug!(target: "policy.filter", "rate limit deny (post-identity)");
        Ok(Some(LimitDenied(result.violation)))
    }

    /// [`Self::post_identity_limit`] on the entity-less HTTP coordinates, for
    /// admissions that end at identity.
    ///
    /// # Errors
    ///
    /// Fails when an earlier dispatch lost the context table.
    ///
    /// [`Self::post_identity_limit`]: Self::post_identity_limit
    async fn post_identity_limit_http(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        identity: &IdentityPayload,
    ) -> Result<Option<Rejection>, FilterError> {
        if !self.post_identity_limit_pending(ctx) {
            return Ok(None);
        }
        let view = Self::request_view(ctx, &self.cfg.context_headers, &self.trusted_proxies);
        let ext = Self::extensions_from_identity(&view, identity, ENTITY_HTTP, ENTITY_NAME_GLOBAL, &self.cfg);
        Ok(self.post_identity_limit(ctx, &ext).await?.map(|denied| denied.http()))
    }

    /// Resolve identity by invoking the identity hook chain. Returns the
    /// resolved [`IdentityPayload`] (subject / client / workload / raw
    /// credentials / delegation) or a rejection when no identity
    /// continues.
    #[expect(clippy::large_stack_frames, reason = "async handler over large CMF/pipeline types")]
    async fn resolve_identity(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        view: &RequestView,
        entity_type: &str,
        entity_name: &str,
    ) -> Result<Result<IdentityPayload, Rejection>, FilterError> {
        if let Some(rejection) = self.pre_identity_limit(ctx, view).await? {
            return Ok(Err(rejection));
        }
        let route_ext =
            Self::identity_extensions(view, entity_type, entity_name, self.cfg.context_meta.scope.as_deref());
        let payload = Self::identity_payload(view.headers().clone());
        let id_result = self
            .invoke::<IdentityHook>(ctx, HOOK_IDENTITY_RESOLVE, payload, route_ext)
            .await?;
        Ok(identity_from_result(&id_result))
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
        view: &RequestView,
        identity: &IdentityPayload,
        entity_type: &str,
        entity_name: &str,
        cfg: &PolicyFilterConfig,
    ) -> Extensions {
        let headers = view.headers();
        let mut ext = identity.apply_to_extensions(Extensions {
            http: Some(Arc::new(view.http_extension())),
            ..Default::default()
        });

        // -- meta: entity identity (from protocol classifier) + operator config --
        let mut meta = ext.meta.as_ref().map(|arc| (**arc).clone()).unwrap_or_default();
        meta.entity_type = Some(entity_type.to_owned());
        meta.entity_name = Some(entity_name.to_owned());
        if let Some(scope) = &cfg.context_meta.scope {
            meta.scope = Some(scope.clone());
        }
        if !cfg.context_meta.tags.is_empty() {
            meta.tags.extend(cfg.context_meta.tags.iter().cloned());
        }
        if !cfg.context_meta.properties.is_empty() {
            meta.properties
                .extend(cfg.context_meta.properties.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        ext.meta = Some(Arc::new(meta));

        // -- agent.session_id: dedicated handling (bound to subject) --
        if let Some(session_id) = headers.get("x-session-id").filter(|value| !value.is_empty()).cloned() {
            let mut agent = ext.agent.as_ref().map(|arc| (**arc).clone()).unwrap_or_default();
            agent.session_id = Some(session_id);
            ext.agent = Some(Arc::new(agent));
        }

        // -- context_headers: map reserved-prefix headers → extension fields --
        if !cfg.context_headers.is_empty() {
            Self::apply_context_headers(headers, &cfg.context_headers, &mut ext);
        }

        ext
    }

    /// Read headers named in `context_headers` and write their values
    /// into the corresponding `agent.*` / `framework.*` extension fields.
    #[expect(
        clippy::too_many_lines,
        reason = "single match over ContextField variants; splitting obscures the mapping"
    )]
    pub(super) fn apply_context_headers(
        headers: &std::collections::HashMap<String, String>,
        context_headers: &std::collections::HashMap<super::config::ContextField, String>,
        ext: &mut Extensions,
    ) {
        use super::config::ContextField;
        macro_rules! set {
            ($f:expr, $d:expr, $v:expr) => {{
                $f = Some($v.to_owned());
                $d = true;
            }};
        }

        let mut agent = ext.agent.as_ref().map(|arc| (**arc).clone()).unwrap_or_default();
        let mut fw = ext.framework.as_ref().map(|arc| (**arc).clone()).unwrap_or_default();
        let (mut ad, mut fd) = (false, false);

        for (field, hdr) in context_headers {
            let lc = hdr.to_ascii_lowercase();
            let Some(value) = headers.get(&lc).filter(|v| !v.is_empty()) else {
                continue;
            };
            match field {
                ContextField::AgentConversationId => set!(agent.conversation_id, ad, value),
                ContextField::AgentAgentId => set!(agent.agent_id, ad, value),
                ContextField::AgentParentAgentId => set!(agent.parent_agent_id, ad, value),
                ContextField::AgentInput => set!(agent.input, ad, value),
                ContextField::AgentTurn => {
                    if let Ok(n) = value.parse::<u32>() {
                        agent.turn = Some(n);
                        ad = true;
                    } else {
                        tracing::trace!(target: "policy.filter", header = %hdr, value_len = value.len(),
                        "context_headers: skipping agent.turn — not a valid u32");
                    }
                },
                ContextField::FrameworkFramework => set!(fw.framework, fd, value),
                ContextField::FrameworkFrameworkVersion => set!(fw.framework_version, fd, value),
                ContextField::FrameworkNodeId => set!(fw.node_id, fd, value),
                ContextField::FrameworkGraphId => set!(fw.graph_id, fd, value),
            }
        }
        if ad {
            ext.agent = Some(Arc::new(agent));
        }
        if fd {
            ext.framework = Some(Arc::new(fw));
        }
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

    /// Register the compiled builtin factories and the APL visitor on `mgr`.
    ///
    /// An engine-only build supports APL but refuses policies naming builtin
    /// plugin kinds.
    #[expect(
        clippy::too_many_lines,
        reason = "the feature-gated factory list mirrors Cargo's independently selectable Policy builtins"
    )]
    fn install_plugins(mgr: &Arc<PolicyEngine>, session_store: Arc<dyn ppe::SessionStore>) {
        #[cfg(any(
            feature = "policy-builtins",
            feature = "policy-api-key",
            feature = "policy-jwt",
            feature = "policy-jwt-openssl-fips",
            feature = "policy-oauth",
            feature = "policy-delegator-vault",
            feature = "policy-elicitation-ciba",
            feature = "policy-cedar",
            feature = "policy-cel",
            feature = "policy-opa",
            feature = "policy-valkey",
            feature = "policy-experimental-ratelimit",
        ))]
        {
            ppe::register_builtin_plugins(mgr);
            ppe::register_apl(
                mgr,
                ppe::AplOptions {
                    dispatch_cache: Arc::new(ppe::DispatchCache::new()),
                    session_store,
                    pdps: Vec::new(),
                    pdp_factories: ppe::builtin_pdp_factories(),
                    session_store_factories: ppe::builtin_session_store_factories(),
                    base_capabilities: None,
                },
            );
        }
        #[cfg(not(any(
            feature = "policy-builtins",
            feature = "policy-api-key",
            feature = "policy-jwt",
            feature = "policy-jwt-openssl-fips",
            feature = "policy-oauth",
            feature = "policy-delegator-vault",
            feature = "policy-elicitation-ciba",
            feature = "policy-cedar",
            feature = "policy-cel",
            feature = "policy-opa",
            feature = "policy-valkey",
            feature = "policy-experimental-ratelimit",
        )))]
        {
            let mut options = ppe::AplOptions::in_process();
            options.session_store = session_store;
            let _visitor = ppe::register_apl(mgr, options);
        }
    }

    /// Build the proxy-backed transport with the configured destination policy.
    fn http_transport(
        subrequest_connector: Option<SubRequestConnector>,
        allow_private: bool,
        trusted_private_endpoints: &[String],
    ) -> Arc<PolicyHttpTransport> {
        if allow_private {
            tracing::info!(
                target: "policy.filter",
                "policy: allowing the engine to reach private and loopback IdP addresses"
            );
        }
        let allowlist: Arc<std::collections::HashSet<String>> = Arc::new(
            trusted_private_endpoints
                .iter()
                .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
                .collect(),
        );
        if !allowlist.is_empty() {
            tracing::info!(
                target: "policy.filter",
                count = allowlist.len(),
                "policy: permitting private addresses for pinned policy endpoints"
            );
        }
        Arc::new(PolicyHttpTransport::with_connector(
            subrequest_connector,
            allow_private,
            allowlist,
        ))
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
        state(ctx).is_some_and(|state| state.admitted)
    }

    /// Record that this instance admitted the request.
    fn mark_admission_complete(ctx: &mut HttpFilterContext<'_>) {
        state_mut(ctx).admitted = true;
    }

    /// Keep the full identity this instance admitted, for its later hooks.
    fn store_identity(ctx: &mut HttpFilterContext<'_>, identity: IdentityPayload) {
        let state = state_mut(ctx);
        state.gated = None;
        state.identity = Some(identity);
    }

    /// The full identity this instance admitted, if any.
    fn admitted_identity<'c>(ctx: &'c HttpFilterContext<'_>) -> Option<&'c IdentityPayload> {
        state(ctx).and_then(|state| state.identity.as_ref())
    }

    /// Resolve the global identity gate without publishing route-scoped state.
    ///
    /// Reserved entity-less coordinates select global authentication; absent
    /// coordinates would be rejected as an unidentified request.
    #[expect(clippy::large_stack_frames, reason = "async PPE identity payload")]
    async fn resolve_gated_identity(
        &self,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<Result<IdentityPayload, Rejection>, FilterError> {
        let view = Self::request_view(ctx, &self.cfg.context_headers, &self.trusted_proxies);
        if let Some(rejection) = self.pre_identity_limit(ctx, &view).await? {
            return Ok(Err(rejection));
        }
        let gate_ext = Self::identity_extensions(
            &view,
            ENTITY_HTTP,
            ENTITY_NAME_GLOBAL,
            self.cfg.context_meta.scope.as_deref(),
        );
        let payload = Self::identity_payload(view.headers().clone());
        let result = self
            .invoke::<IdentityHook>(ctx, HOOK_IDENTITY_RESOLVE, payload, gate_ext)
            .await?;
        Ok(identity_from_result(&result))
    }

    /// The identity the early gate resolved, or a fresh gate resolution when
    /// the body phase runs first.
    ///
    /// # Errors
    ///
    /// Fails when an earlier dispatch lost the context table.
    async fn gated_identity(
        &self,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<Result<IdentityPayload, Rejection>, FilterError> {
        match state_mut(ctx).gated.take() {
            Some(identity) => Ok(Ok(identity)),
            None => self.resolve_gated_identity(ctx).await,
        }
    }

    /// Finish an identity-only admission after classification establishes that
    /// no entity-specific resolver can apply.
    #[expect(
        clippy::large_stack_frames,
        reason = "PPE identity resolution carries large async payloads"
    )]
    async fn complete_gated_admission(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let identity = match self.gated_identity(ctx).await? {
            Ok(identity) => identity,
            Err(rejection) => return Ok(FilterAction::Reject(rejection)),
        };
        if let Some(rejection) = self.post_identity_limit_http(ctx, &identity).await? {
            return Ok(FilterAction::Reject(rejection));
        }
        Self::publish_authenticated_identity(ctx, &identity);
        Self::store_identity(ctx, identity);
        Self::mark_admission_complete(ctx);
        Ok(FilterAction::BodyDone)
    }

    /// Early identity gate: resolve identity in `on_request` so
    /// un-authenticated traffic is rejected before the body-buffer cost is
    /// paid. For entity-aware policies, authorization runs later, in
    /// `on_request_body`, once the request is classified.
    #[expect(
        clippy::large_stack_frames,
        reason = "PPE identity resolution carries large async payloads"
    )]
    async fn identity_gate(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        // When a downstream body-buffering filter (e.g. the protocol
        // classifier) forces a pre-read, praxis runs `on_request_body` BEFORE
        // this header phase. That body phase already resolved and enforced
        // identity (keeping it in this instance's state) and may have stripped the
        // inbound identity headers (`X-User-Token`, `Authorization`) for the
        // upstream. Re-resolving here would fail on the now-stripped headers
        // and spuriously reject an already-authorized request. The body phase
        // is authoritative — skip the early gate when it already ran.
        if Self::admitted_identity(ctx).is_some() {
            tracing::trace!(target: "policy.filter", "identity already resolved in body phase; skipping early gate");
            return Ok(FilterAction::Continue);
        }

        let identity = match self.resolve_gated_identity(ctx).await? {
            Ok(identity) => identity,
            Err(rejection) => {
                tracing::debug!(target: "policy.filter", "identity deny (on_request)");
                return Ok(FilterAction::Reject(rejection));
            },
        };
        // Entity-routed policies resolve again once classifier metadata gives
        // PPE the authoritative route coordinates. Publishing this unscoped
        // gate result could expose a principal from the wrong route resolver.
        if self.entity_routes {
            state_mut(ctx).gated = Some(identity);
        } else {
            if let Some(rejection) = self.post_identity_limit_http(ctx, &identity).await? {
                return Ok(FilterAction::Reject(rejection));
            }
            Self::publish_authenticated_identity(ctx, &identity);
            Self::store_identity(ctx, identity);
        }
        tracing::trace!(target: "policy.filter", "identity allow (on_request)");
        Ok(FilterAction::Continue)
    }

    /// Authorize an inference request through `cmf.llm_input`.
    #[expect(
        clippy::large_stack_frames,
        clippy::too_many_lines,
        reason = "async handler over large CMF types; linear resolve/authz/delegate flow"
    )]
    async fn dispatch_llm_request(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        parsed: ParsedLlmRequest,
        model: String,
    ) -> Result<FilterAction, FilterError> {
        let (entity_type, hook_name) = (ENTITY_LLM, HOOK_CMF_LLM_INPUT);

        // Reject before identity because an unmatched model has no policy to run.
        if self.cfg.llm.require_route && !self.llm_route_selects(&model) {
            tracing::debug!(
                target: "policy.filter",
                model = %model,
                "no `llm:` route selects this model; denying (fail-closed). Add a route for it, \
                 a catch-all `llm: \"*\"`, or set `llm.require_route: false` to admit it \
                 unevaluated.",
            );
            return Ok(FilterAction::Reject(llm_deny_rejection(Some(&no_route_violation()))));
        }

        let view = Self::request_view(ctx, &self.cfg.context_headers, &self.trusted_proxies);
        let identity = match self.resolve_identity(ctx, &view, entity_type, &model).await? {
            Ok(id) => id,
            Err(rej) => return Ok(FilterAction::Reject(rej)),
        };
        Self::publish_authenticated_identity(ctx, &identity);

        // Read what the handler needs before the document moves into the extensions.
        let payload = MessagePayload {
            message: request_message(&parsed),
        };
        let streaming = parsed.is_streaming();

        let mut extensions = Self::extensions_from_identity(&view, &identity, entity_type, &model, &self.cfg);
        // Attach before the limit so a limiter can bind the model.
        self.attach_llm_attributes(&mut extensions, parsed, &model);
        if let Some(denied) = self.post_identity_limit(ctx, &extensions).await? {
            return Ok(FilterAction::Reject(denied.http()));
        }
        Self::store_identity(ctx, identity);
        state_mut(ctx).inference_model = Some(model.clone());

        let cmf_result = self.invoke::<CmfHook>(ctx, hook_name, payload, extensions).await?;

        if !cmf_result.continue_processing {
            tracing::debug!(target: "policy.filter", model = %model, "inference deny");
            return Ok(FilterAction::Reject(llm_deny_rejection(cmf_result.violation.as_ref())));
        }

        let attached = match attach_delegated_tokens(ctx, cmf_result.modified_extensions.as_ref()) {
            Ok(attached) => attached,
            Err(rejection) => return Ok(FilterAction::Reject(rejection)),
        };
        if attached > 0 {
            tracing::debug!(
                target: "policy.filter",
                count = attached,
                "attached delegated tokens to upstream request (inference)",
            );
        }
        // Apply assertions after delegation so strip rules govern delegated headers.
        let (set, removed) =
            apply_request_assertions(ctx, cmf_result.modified_extensions.as_ref(), &self.request_assertions);
        if set > 0 || removed > 0 {
            tracing::debug!(
                target: "policy.filter",
                set, removed,
                "applied request assertions to upstream request (inference)",
            );
        }

        // CMF cannot losslessly rebuild multi-part inference bodies, so keep
        // the original instead of applying a partial mutation.
        if matches!(self.cfg.body_access, BodyAccessMode::ReadWrite)
            && cmf_result.modified_payload.is_some()
            && !self.llm_request_mutator_warned.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                target: "policy.filter",
                model = %model,
                "policy mutated the inference request payload, but request-body rewriting is not \
                 supported on the inference path; the upstream receives the original body. \
                 Reported once per filter instance.",
            );
        }

        // Response policy requires readable JSON, so do not request compression.
        if self.llm_post {
            ctx.request_headers_to_remove.push(http::header::ACCEPT_ENCODING);
        }

        // Metadata exposes the model downstream without trusting a client header.
        ctx.set_metadata("llm.model", model.clone());
        if streaming {
            ctx.set_metadata("llm.stream", "true");
        }

        tracing::trace!(target: "policy.filter", model = %model, "inference allow");
        Self::mark_admission_complete(ctx);
        Ok(FilterAction::BodyDone)
    }

    /// Whether the policy's route resolver selects `model`.
    fn llm_route_selects(&self, model: &str) -> bool {
        let Some(config) = self.llm_route_table.as_ref() else {
            return false;
        };
        let scope = self.cfg.context_meta.scope.as_deref();
        ppe::praxis_policy_core::config::resolve_route(
            config,
            ppe::praxis_policy_core::config::RouteQuery::named(ENTITY_LLM, model).with_scope(scope),
        )
        .is_some()
    }

    /// Add inference attributes used by APL rules and the parsed body for PDPs.
    fn attach_llm_attributes(&self, ext: &mut Extensions, parsed: ParsedLlmRequest, model: &str) {
        ext.llm = Some(Arc::new(LLMExtension {
            model_id: Some(model.to_owned()),
            provider: self.cfg.llm.provider.clone(),
            capabilities: Vec::new(),
        }));

        let promoted = parsed.promoted_params(&self.cfg.llm.promote_params);
        let parts = parsed.parts();
        let document = LlmRequestDocument::new(parsed.into_value());
        ext.llm_request = Some(match parts {
            Some(parts) => document.with_parts(parts),
            None => document,
        });
        if promoted.is_empty() {
            return;
        }
        let mut custom = ext.custom.as_ref().map(|arc| (**arc).clone()).unwrap_or_default();
        custom.insert("llm".to_owned(), serde_json::Value::Object(promoted));
        ext.custom = Some(Arc::new(custom));
    }

    /// Evaluate `cmf.llm_output` over a buffered inference response.
    /// A denial can replace only the response body at this phase.
    #[expect(
        clippy::too_many_lines,
        reason = "linear response-phase flow (skip checks, rebuild identity, dispatch, deny); splitting obscures it"
    )]
    fn dispatch_llm_response(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<FilterAction, FilterError> {
        let Some(model) = Self::llm_response_model(ctx) else {
            return Ok(FilterAction::Continue);
        };

        let body_bytes = body.as_ref().cloned().unwrap_or_else(Bytes::new);

        // Fail closed because this filter cannot evaluate encoded content.
        if let Some(encoding) = Self::response_content_encoding(ctx) {
            tracing::warn!(
                target: "policy.filter",
                model = %model,
                encoding = %encoding,
                "inference response is content-encoded and cannot be evaluated; failing closed \
                 (replacing the response body with the deny envelope)",
            );
            let violation = PluginViolation::new(
                "llm.response_unreadable",
                "inference response is content-encoded and cannot be evaluated",
            );
            *body = Some(llm_deny_body(
                Some(&violation),
                body_bytes.len(),
                "content-encoded inference response",
            ));
            return Ok(FilterAction::Continue);
        }

        let parsed = ParsedLlmResponse::parse(&body_bytes);
        if !parsed.is_object() {
            if ctx.extensions.get::<PolicyResponseContext>().is_some() {
                return self.dispatch_llm_response_context(ctx);
            }
            tracing::debug!(
                target: "policy.filter",
                model = %model,
                "inference response body is not a JSON object; skipping the response-phase policy",
            );
            return Ok(FilterAction::Continue);
        }

        let (entity_type, hook_name) = (ENTITY_LLM, HOOK_CMF_LLM_OUTPUT);
        let view = Self::request_view(ctx, &self.cfg.context_headers, &self.trusted_proxies);
        let Some(identity) = Self::admitted_identity(ctx) else {
            // Missing request identity would otherwise skip response policy.
            tracing::error!(
                target: "policy.filter",
                model = %model,
                "no request-phase identity stashed; failing closed \
                 (replacing inference response body with deny envelope)",
            );
            let violation = post_phase_identity_unavailable_violation();
            *body = Some(llm_deny_body(
                Some(&violation),
                body_bytes.len(),
                "post-phase identity failure",
            ));
            return Ok(FilterAction::Continue);
        };

        let mut extensions = Self::extensions_from_identity(&view, identity, entity_type, &model, &self.cfg);
        extensions.llm = Some(Arc::new(LLMExtension {
            model_id: Some(model.clone()),
            provider: self.cfg.llm.provider.clone(),
            capabilities: Vec::new(),
        }));
        extensions.completion = Some(Arc::new(parsed.completion()));
        let response_context = ctx
            .extensions
            .get::<PolicyResponseContext>()
            .map(PolicyResponseContext::custom);
        if let Some(custom) = response_context.as_ref() {
            extensions.custom = Some(Arc::clone(custom));
        }

        let payload = MessagePayload {
            message: response_message(&parsed),
        };
        let cmf_result = match self.dispatch_response_cmf(ctx, hook_name, payload, extensions) {
            Ok(result) => result,
            Err(error) if response_context.is_some() => {
                let violation = PluginViolation::new("llm.response_context_unavailable", error.to_string());
                if let Some(host_custom) = response_context.clone() {
                    Self::publish_response_output(
                        ctx,
                        host_custom.as_ref(),
                        ResponseCustomState::Unmodified,
                        Some(violation),
                    );
                }
                tracing::warn!(target: "policy.filter", %error, "response policy dispatch failed; applying failure_mode");
                return Err(error);
            },
            Err(error) => return Err(error),
        };
        if let Some(host_custom) = response_context {
            let custom_state =
                cmf_result
                    .modified_extensions
                    .as_ref()
                    .map_or(ResponseCustomState::Unmodified, |modified| {
                        modified
                            .custom
                            .clone()
                            .map_or(ResponseCustomState::Removed, ResponseCustomState::Replaced)
                    });
            Self::publish_response_output(ctx, host_custom.as_ref(), custom_state, cmf_result.violation.clone());
        }

        if !cmf_result.continue_processing {
            tracing::warn!(
                target: "policy.filter",
                model = %model,
                violation = ?cmf_result.violation,
                "inference post-phase deny — replacing response body with the provider error envelope",
            );
            *body = Some(llm_deny_body(
                cmf_result.violation.as_ref(),
                body_bytes.len(),
                "inference post-phase deny",
            ));
            return Ok(FilterAction::Continue);
        }

        // Keep the original because CMF cannot rebuild multi-choice responses.
        if cmf_result.modified_payload.is_some() && !self.llm_response_mutator_warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                target: "policy.filter",
                model = %model,
                "policy mutated the inference response payload, but response-body rewriting is not \
                 supported on the inference path; the client receives the upstream body. \
                 Reported once per filter instance.",
            );
        }
        Ok(FilterAction::Continue)
    }

    /// Evaluate response policy over host-provided context without response content.
    #[expect(
        clippy::too_many_lines,
        reason = "linear trusted-context construction, dispatch, and output publication"
    )]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "response-phase dispatch shares the fallible hook signature with content evaluation"
    )]
    fn dispatch_llm_response_context(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(host_custom) = ctx
            .extensions
            .get::<PolicyResponseContext>()
            .map(PolicyResponseContext::custom)
        else {
            return Ok(FilterAction::Continue);
        };
        if state(ctx)
            .is_some_and(|state| matches!(state.metadata_response_dispatch, MetadataResponseDispatch::Complete))
        {
            return Ok(FilterAction::Continue);
        }
        state_mut(ctx).metadata_response_dispatch = MetadataResponseDispatch::Complete;
        if self.response_context_mgr.is_none() {
            Self::publish_response_output(ctx, host_custom.as_ref(), ResponseCustomState::Unmodified, None);
            return Ok(FilterAction::Continue);
        }
        let Some(model) = state(ctx).and_then(|state| state.inference_model.clone()) else {
            Self::publish_response_output(ctx, host_custom.as_ref(), ResponseCustomState::Unmodified, None);
            return Ok(FilterAction::Continue);
        };
        let Some(identity) = state(ctx).and_then(|state| state.identity.clone()) else {
            let violation = PluginViolation::new(
                "llm.response_context_unavailable",
                "request identity unavailable for metadata-only response policy",
            );
            Self::publish_response_output(
                ctx,
                host_custom.as_ref(),
                ResponseCustomState::Unmodified,
                Some(violation),
            );
            return Ok(FilterAction::Continue);
        };
        let view = Self::request_view(ctx, &self.cfg.context_headers, &self.trusted_proxies);
        let mut extensions = Self::extensions_from_identity(&view, &identity, ENTITY_LLM, &model, &self.cfg);
        if let Some(http) = extensions.http.as_ref() {
            let mut http = (**http).clone();
            if let Some(state) = state(ctx) {
                http.response_headers.clone_from(&state.response_headers);
                http.status = state.response_status;
            }
            extensions.http = Some(Arc::new(http));
        }
        extensions.llm = Some(Arc::new(LLMExtension {
            model_id: Some(model),
            provider: self.cfg.llm.provider.clone(),
            capabilities: Vec::new(),
        }));
        extensions.custom = Some(Arc::clone(&host_custom));
        let payload = MessagePayload {
            message: Message::with_content(Role::Assistant, Vec::new()),
        };
        let result = match self.dispatch_metadata_response_cmf(ctx, payload, extensions) {
            Ok(result) => result,
            Err(error) => {
                let violation = PluginViolation::new("llm.response_context_unavailable", error.to_string());
                Self::publish_response_output(
                    ctx,
                    host_custom.as_ref(),
                    ResponseCustomState::Unmodified,
                    Some(violation),
                );
                tracing::warn!(target: "policy.filter", %error, "metadata-only response policy dispatch failed; continuing");
                return Ok(FilterAction::Continue);
            },
        };
        let custom_state = result
            .modified_extensions
            .as_ref()
            .map_or(ResponseCustomState::Unmodified, |modified| {
                modified
                    .custom
                    .clone()
                    .map_or(ResponseCustomState::Removed, ResponseCustomState::Replaced)
            });
        let violation = ctx
            .extensions
            .get::<PolicyResponseOutput>()
            .and_then(|output| output.violation().cloned())
            .or_else(|| result.violation.clone());
        Self::publish_response_output(ctx, host_custom.as_ref(), custom_state, violation.clone());
        if !result.continue_processing {
            tracing::warn!(
                target: "policy.filter",
                violation = ?violation,
                "metadata-only inference response policy denied after response content was released; host receives the denial in PolicyResponseOutput",
            );
            return Ok(FilterAction::Continue);
        }
        Ok(FilterAction::Continue)
    }

    /// Publish host-visible response output without erasing an earlier denial.
    pub(super) fn publish_response_output(
        ctx: &mut HttpFilterContext<'_>,
        host_custom: &std::collections::HashMap<String, serde_json::Value>,
        custom_state: ResponseCustomState,
        violation: Option<PluginViolation>,
    ) {
        let earlier_output = ctx.extensions.get::<PolicyResponseOutput>();
        let mut custom =
            earlier_output.map_or_else(std::collections::HashMap::new, |output| (*output.custom()).clone());
        let custom_modified = !matches!(custom_state, ResponseCustomState::Unmodified);
        let current = match custom_state {
            ResponseCustomState::Unmodified if earlier_output.is_none() => host_custom.clone(),
            ResponseCustomState::Replaced(values) => (*values).clone(),
            ResponseCustomState::Unmodified | ResponseCustomState::Removed => std::collections::HashMap::new(),
        };
        // A modified namespace is authoritative for host keys: an omitted host
        // key was intentionally removed. Preserve keys produced by earlier
        // policy instances, then let the later instance win on conflicts.
        if custom_modified {
            for key in host_custom.keys().filter(|key| !current.contains_key(*key)) {
                custom.remove(key);
            }
        }
        custom.extend(current);
        let earlier = earlier_output.and_then(|output| output.violation().cloned());
        ctx.extensions
            .insert(PolicyResponseOutput::new(Arc::new(custom), earlier.or(violation)));
    }

    /// Return the request model for a non-streaming inference response.
    fn llm_response_model(ctx: &HttpFilterContext<'_>) -> Option<String> {
        let model = state(ctx)?.inference_model.as_ref()?;
        if Self::response_is_event_stream(ctx) {
            tracing::debug!(
                target: "policy.filter",
                model = %model,
                "streamed inference response; skipping the response-phase policy",
            );
            return None;
        }
        Some(model.clone())
    }

    /// Whether inference response evaluation will skip this stream.
    fn inference_response_is_streamed(&self, ctx: &HttpFilterContext<'_>) -> bool {
        self.llm_post
            && state(ctx).is_some_and(|state| state.inference_model.is_some())
            && Self::response_is_event_stream(ctx)
    }

    /// Whether the upstream is streaming this response as server-sent events.
    fn response_is_event_stream(ctx: &HttpFilterContext<'_>) -> bool {
        Self::response_header_value(ctx, &http::header::CONTENT_TYPE)
            .is_some_and(|value| media_type_is(value, "text/event-stream"))
    }

    /// Return a non-identity response content encoding.
    fn response_content_encoding(ctx: &HttpFilterContext<'_>) -> Option<String> {
        Self::response_header_value(ctx, &http::header::CONTENT_ENCODING)
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty() && value != "identity")
    }

    /// Reject an inference request over its configured body limit.
    fn reject_oversized_inference_body(&self, body: Option<&Bytes>) -> Option<Rejection> {
        let len = body.map_or(0, Bytes::len);
        if len <= self.cfg.llm.max_request_bytes {
            return None;
        }
        tracing::warn!(
            target: "policy.filter",
            len,
            ceiling = self.cfg.llm.max_request_bytes,
            "inference request body exceeds `llm.max_request_bytes`; denying. Another filter in the chain buffered more than this filter asked for.",
        );
        Some(oversized_body_rejection())
    }

    /// One response header as a string, when the response carries it.
    fn response_header_value<'h>(ctx: &'h HttpFilterContext<'_>, name: &http::header::HeaderName) -> Option<&'h str> {
        ctx.response_header
            .as_ref()
            .and_then(|response| response.headers.get(name))
            .and_then(|value| value.to_str().ok())
    }

    /// Generic-HTTP (L7) authorization: resolve identity, populate the
    /// HTTP request line + headers into the attribute bag, and evaluate the
    /// `global` policy via the `http.request` hook. A deny maps to a
    /// plain HTTP response ([`super::error::http_authz_rejection`]); an
    /// identity failure is the usual 401. Both request-phase and pre-read
    /// admission use this body-independent policy boundary.
    #[expect(clippy::large_stack_frames, reason = "async handler over large CMF/pipeline types")]
    async fn on_request_http_authz(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let view = Self::request_view(ctx, &self.cfg.context_headers, &self.trusted_proxies);
        let identity = match self
            .resolve_identity(ctx, &view, ENTITY_HTTP, ENTITY_NAME_GLOBAL)
            .await?
        {
            Ok(id) => id,
            Err(rej) => return Ok(FilterAction::Reject(rej)),
        };
        Box::pin(self.authorize_http(ctx, &view, identity)).await
    }

    /// Authorize a resolved identity at `http.request`, then attach delegated
    /// tokens and apply request assertions. `Continue` means allowed; the
    /// caller marks admission.
    ///
    /// # Errors
    ///
    /// Fails when an earlier dispatch lost the context table.
    async fn authorize_http(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        view: &RequestView,
        identity: IdentityPayload,
    ) -> Result<FilterAction, FilterError> {
        Self::publish_authenticated_identity(ctx, &identity);
        let extensions = Self::extensions_from_identity(view, &identity, ENTITY_HTTP, ENTITY_NAME_GLOBAL, &self.cfg);
        if let Some(denied) = self.post_identity_limit(ctx, &extensions).await? {
            return Ok(FilterAction::Reject(denied.http()));
        }
        let result = self
            .invoke::<HttpHook>(ctx, HOOK_HTTP_REQUEST, HttpPayload, extensions)
            .await?;
        if !result.continue_processing {
            tracing::debug!(target: "policy.filter", "http authz deny");
            return Ok(FilterAction::Reject(super::error::http_authz_rejection(
                result.violation.as_ref(),
            )));
        }
        if let Some(rejection) = self.apply_http_grants(ctx, result.modified_extensions.as_ref()) {
            return Ok(FilterAction::Reject(rejection));
        }
        // Reuse the admitted identity so mid-exchange token expiry cannot cause a late deny.
        Self::store_identity(ctx, identity);
        tracing::trace!(target: "policy.filter", "http authz allow");
        Ok(FilterAction::Continue)
    }

    /// Attach delegated tokens, then apply request assertions, so strip rules
    /// govern delegated headers.
    fn apply_http_grants(&self, ctx: &mut HttpFilterContext<'_>, extensions: Option<&Extensions>) -> Option<Rejection> {
        let attached = match attach_delegated_tokens(ctx, extensions) {
            Ok(attached) => attached,
            Err(rejection) => return Some(rejection),
        };
        if attached > 0 {
            tracing::debug!(target: "policy.filter", count = attached, "attached delegated tokens (http authz)");
        }
        let (set, removed) = apply_request_assertions(ctx, extensions, &self.request_assertions);
        if set > 0 || removed > 0 {
            tracing::debug!(target: "policy.filter", set, removed, "applied request assertions (http authz)");
        }
        None
    }

    /// Admit an unclassified HTTP fallback on an inference policy: the gate's identity,
    /// then HTTP authorization, delegation and assertions when the policy
    /// installs any; identity alone otherwise.
    ///
    /// # Errors
    ///
    /// Fails when an earlier dispatch lost the context table.
    #[expect(clippy::large_stack_frames, reason = "async handler over large CMF/pipeline types")]
    async fn admit_http_fallback(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if Self::admission_complete(ctx) {
            return Ok(FilterAction::BodyDone);
        }
        if !self.http_request_policy {
            return self.complete_gated_admission(ctx).await;
        }
        let identity = match self.gated_identity(ctx).await? {
            Ok(identity) => identity,
            Err(rejection) => return Ok(FilterAction::Reject(rejection)),
        };
        let view = Self::request_view(ctx, &self.cfg.context_headers, &self.trusted_proxies);
        let action = Box::pin(self.authorize_http(ctx, &view, identity)).await?;
        if !matches!(action, FilterAction::Continue) {
            return Ok(action);
        }
        Self::mark_admission_complete(ctx);
        Ok(FilterAction::BodyDone)
    }

    /// The extensions a response-phase invocation carries: the identity admitted
    /// on the way in, the request line, and the upstream's headers and status.
    ///
    /// Reuses the admitted identity rather than resolving again, so a token that
    /// expired mid-exchange cannot deny an already-authorized response.
    pub(super) fn response_extensions(
        ctx: &HttpFilterContext<'_>,
        response_headers: std::collections::HashMap<String, String>,
        status: u16,
        cfg: &PolicyFilterConfig,
        trusted_proxies: &[CidrRange],
    ) -> Extensions {
        let view = Self::request_view(ctx, &cfg.context_headers, trusted_proxies);
        let mut extensions = if let Some(identity) = Self::admitted_identity(ctx) {
            Self::extensions_from_identity(&view, identity, ENTITY_HTTP, ENTITY_NAME_GLOBAL, cfg)
        } else {
            tracing::debug!(
                target: "policy.filter",
                "no request-phase identity stashed for the response half; \
                 an entry sourced from it renders nothing",
            );
            let mut ext = Self::entity_less_extensions();
            if let (Some(scope), Some(meta)) = (&cfg.context_meta.scope, ext.meta.as_ref()) {
                let mut m = (**meta).clone();
                m.scope = Some(scope.clone());
                ext.meta = Some(Arc::new(m));
            }
            ext
        };
        // Keep the request line, so a response contract resolves the same route
        // the request half did.
        let mut http = view.http_extension();
        http.response_headers = response_headers;
        http.status = Some(status);
        extensions.http = Some(Arc::new(http));
        extensions
    }

    /// The reserved entity-less coordinates and nothing else.
    fn entity_less_extensions() -> Extensions {
        Extensions {
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some(ENTITY_HTTP.to_owned()),
                entity_name: Some(ENTITY_NAME_GLOBAL.to_owned()),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    /// Dispatch a CMF hook from the synchronous response-body phase, blocking
    /// for at most the filter's response dispatch bound.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] when the hook times out or yields no result,
    /// so the response fails under the filter's `failure_mode`. The context
    /// table moved into the hook is then lost, and later hooks refuse to run.
    ///
    /// [`FilterError`]: FilterError
    fn dispatch_response_cmf(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        hook: &'static str,
        payload: MessagePayload,
        extensions: Extensions,
    ) -> Result<PipelineResult, FilterError> {
        let table = state_mut(ctx).take_table()?;
        let mgr = Arc::clone(&self.mgr);
        let invoke = async move {
            let (result, _background) = Box::pin(mgr.invoke_named::<CmfHook>(hook, payload, extensions, table)).await;
            result
        };
        let mut result = block_on_bounded(invoke, self.response_dispatch_timeout)
            .map_err(|e| -> FilterError { format!("policy: {hook} dispatch failed: {e}").into() })?;
        state_mut(ctx).restore_table(std::mem::take(&mut result.context_table));
        Ok(result)
    }

    /// Dispatch against the independent metadata-only policy engine.
    #[expect(
        clippy::large_stack_frames,
        reason = "PPE response dispatch carries its typed hook inputs into the bounded future"
    )]
    fn dispatch_metadata_response_cmf(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        payload: MessagePayload,
        extensions: Extensions,
    ) -> Result<PipelineResult, FilterError> {
        let manager = self
            .response_context_mgr
            .as_ref()
            .ok_or_else(|| -> FilterError { "policy: metadata-only response engine unavailable".into() })?;
        let mut table = state_mut(ctx).take_table()?;
        if let Some(table) = table.as_mut() {
            Self::remap_plugin_local_states(&self.mgr, manager, table);
        }
        let response_manager = Arc::clone(manager);
        let invoke = async move {
            let (result, _background) = response_manager
                .invoke_named::<CmfHook>(HOOK_CMF_LLM_OUTPUT, payload, extensions, table)
                .await;
            result
        };
        let mut result = block_on_bounded(invoke, self.response_dispatch_timeout).map_err(|error| -> FilterError {
            format!("policy: metadata-only response dispatch failed: {error}").into()
        })?;
        Self::remap_plugin_local_states(manager, &self.mgr, &mut result.context_table);
        state_mut(ctx).restore_table(std::mem::take(&mut result.context_table));
        Ok(result)
    }

    /// Re-key private state for same-named plugin instances in two engines.
    fn remap_plugin_local_states(
        source: &PolicyEngine,
        destination: &PolicyEngine,
        table: &mut ppe::praxis_policy_core::context::PluginContextTable,
    ) {
        for name in destination.plugin_names() {
            let Some((source_id, destination_id)) = source
                .get_plugin(&name)
                .zip(destination.get_plugin(&name))
                .map(|(source, destination)| (source.id(), destination.id()))
            else {
                continue;
            };
            if source_id != destination_id
                && let Some(local_state) = table.local_states.remove(&source_id)
            {
                table.local_states.insert(destination_id, local_state);
            }
        }
    }

    /// Capture the final response facts visible at this filter's header phase.
    fn snapshot_response_context(ctx: &mut HttpFilterContext<'_>) {
        let Some(response) = ctx.response_header.as_ref() else {
            return;
        };
        let headers = snapshot_response_headers(&response.headers);
        let status = response.status.as_u16();
        let state = state_mut(ctx);
        state.response_headers = headers;
        state.response_status = Some(status);
    }

    /// Whether the final response is complete when its headers are delivered.
    fn response_ends_at_headers(ctx: &HttpFilterContext<'_>) -> bool {
        let Some(response) = ctx.response_header.as_ref() else {
            return false;
        };
        if response.status.is_informational() {
            return false;
        }
        if crate::bodyless_response(response.status, &ctx.request.method) {
            return true;
        }
        if response.headers.contains_key(http::header::TRANSFER_ENCODING) {
            return false;
        }
        let mut values = response.headers.get_all(http::header::CONTENT_LENGTH).iter();
        let Some(first) = values.next() else {
            return false;
        };
        std::iter::once(first).chain(values).all(|value| {
            value
                .to_str()
                .ok()
                .is_some_and(|value| value.split(',').all(|part| part.trim() == "0"))
        })
    }

    /// Run the configured generic HTTP response hook, when present.
    async fn dispatch_http_response_hook(
        &self,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<Option<FilterAction>, FilterError> {
        let Some(hook) = self.response_hook else {
            return Ok(None);
        };
        let Some(response) = ctx.response_header.as_ref() else {
            return Ok(None);
        };
        let extensions = Self::response_extensions(
            ctx,
            snapshot_response_headers(&response.headers),
            response.status.as_u16(),
            &self.cfg,
            &self.trusted_proxies,
        );
        let result = self.invoke::<HttpHook>(ctx, hook, HttpPayload, extensions).await?;
        if !result.continue_processing {
            tracing::warn!(
                target: "policy.filter",
                violation = ?result.violation,
                "http response deny; replacing the upstream response",
            );
            return Ok(Some(FilterAction::Reject(super::error::http_authz_rejection(
                result.violation.as_ref(),
            ))));
        }
        self.write_response_assertions(ctx, result.modified_extensions.as_ref());
        Ok(None)
    }

    /// Remember an SSE classification until the clean body EOF callback.
    fn record_streamed_inference_response(&self, ctx: &mut HttpFilterContext<'_>) {
        if self.llm_post
            && state(ctx).is_some_and(|state| state.inference_model.is_some())
            && Self::response_is_event_stream(ctx)
        {
            state_mut(ctx).streamed_inference_response = true;
        }
    }

    /// Put the rendered response contract on the response the client receives.
    fn write_response_assertions(&self, ctx: &mut HttpFilterContext<'_>, extensions: Option<&Extensions>) {
        let Some(response) = ctx.response_header.as_mut() else {
            return;
        };
        let (set, removed) = apply_response_assertions(&mut response.headers, extensions, &self.response_assertions);
        if set > 0 || removed > 0 {
            ctx.response_headers_modified = true;
            tracing::debug!(
                target: "policy.filter",
                set, removed,
                "applied response assertions to the downstream response",
            );
        }
    }
}

/// Whether an inference selector is the bare `*` catch-all.
fn selector_matches_any_model(selector: &ppe::praxis_policy_core::config::StringOrList) -> bool {
    matches!(
        selector,
        ppe::praxis_policy_core::config::StringOrList::Single(pattern) if pattern.as_str() == "*"
    )
}

/// Whether an inference selector is a list containing the literal `"*"`.
fn selector_lists_any_model_literal(selector: &ppe::praxis_policy_core::config::StringOrList) -> bool {
    matches!(
        selector,
        ppe::praxis_policy_core::config::StringOrList::List(patterns)
            if patterns.iter().any(|pattern| pattern.as_str() == "*")
    )
}

/// A limiter denial, mapped to the wire by the path that hit it.
struct LimitDenied(Option<PluginViolation>);

impl LimitDenied {
    /// The plain HTTP rejection.
    fn http(&self) -> Rejection {
        rate_limit_rejection(self.0.as_ref())
    }

    /// The JSON-RPC rejection keeping `request_id`.
    fn json_rpc(&self, request_id: &serde_json::Value) -> Rejection {
        rate_limit_json_rpc_rejection(self.0.as_ref(), request_id)
    }
}

/// The identity a resolution produced, or the rejection it ended in.
fn identity_from_result(result: &PipelineResult) -> Result<IdentityPayload, Rejection> {
    if !result.continue_processing {
        return Err(auth_rejection(result.violation.as_ref()));
    }
    IdentityPayload::from_pipeline_result(result).ok_or_else(|| {
        Rejection::status(500).with_body(Bytes::from_static(b"policy: identity result missing modified payload"))
    })
}

/// Render a validated claim into the identity projection's string format.
///
/// Strings remain unquoted; other values use compact JSON.
fn flatten_claim(value: &serde_json::Value) -> String {
    value.as_str().map_or_else(|| value.to_string(), str::to_owned)
}

/// Engine provenance for secret assertion headers applied to the request.
///
/// Applied headers reach the request snapshot that later phases read, so
/// every `HttpExtension` built from that snapshot must carry these markers.
/// Without them, plugins and PDPs on those phases receive the credential
/// instead of its redaction marker.
pub(super) struct AssertedSecretHeaders(pub(super) SecretHeaderProvenance);

/// Build an inference denial body that fits the committed response size.
fn llm_deny_body(violation: Option<&PluginViolation>, original_len: usize, reason: &str) -> Bytes {
    let chosen = deny_with_body(violation)
        .filter(|body| body.len() <= original_len)
        .unwrap_or_else(|| llm_error_envelope_bytes_within(violation, original_len));
    fit_to_original_length(chosen, original_len, "llm", reason)
}

/// Whether a header has the given media type, ignoring case and parameters.
fn media_type_is(header: &str, media_type: &str) -> bool {
    header
        .split(';')
        .next()
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case(media_type))
}

/// Whether both the method and received bytes indicate a bodyless request.
fn carries_no_body(ctx: &HttpFilterContext<'_>, body: Option<&Bytes>) -> bool {
    let bodyless_method = matches!(
        ctx.request.method,
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS | http::Method::TRACE | http::Method::CONNECT
    );
    bodyless_method && body.is_none_or(Bytes::is_empty)
}

/// Build a missing inference model violation.
fn missing_model_violation() -> PluginViolation {
    PluginViolation::new("llm.model_missing", "request body carries no usable top-level `model`")
}

/// Build an HTTP 413 rejection for an oversized inference request.
fn oversized_body_rejection() -> Rejection {
    let violation = PluginViolation::new(
        "llm.body_too_large",
        "inference request body exceeds the configured ceiling",
    );
    Rejection::status(413)
        .with_header(VIOLATION_HEADER, violation.code.clone())
        .with_header("Content-Type", "application/json")
        .with_body(llm_error_envelope_bytes_within(Some(&violation), usize::MAX))
}

/// Build an HTTP 400 rejection for a request body that repeats a JSON
/// object key. The body names neither the key nor any value.
fn duplicate_key_rejection() -> Rejection {
    let violation = PluginViolation::new("llm.duplicate_key", "request body repeats a JSON object key");
    Rejection::status(400)
        .with_header(VIOLATION_HEADER, violation.code.clone())
        .with_header("Content-Type", "application/json")
        .with_body(llm_error_envelope_bytes_within(Some(&violation), usize::MAX))
}

/// Build an unmatched inference route violation.
fn no_route_violation() -> PluginViolation {
    PluginViolation::new("llm.no_route", "no policy route permits this model")
}

/// Build a violation for conflicting inference and JSON-RPC coordinates.
fn ambiguous_entity_violation() -> PluginViolation {
    PluginViolation::new(
        "llm.ambiguous_entity",
        "request carries both a JSON-RPC envelope and a top-level `model`",
    )
}

/// The violation reported when the response phase cannot find the
/// identity the request phase stashed. Shared by the MCP and inference
/// post paths, which both fail closed on it.
fn post_phase_identity_unavailable_violation() -> PluginViolation {
    PluginViolation::new(
        "identity.post_phase_unavailable",
        "no request-phase identity available for response processing",
    )
}

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
            BodyAccessMode::ReadOnly => BodyAccess::ReadOnly(crate::BodyRequirement::Required),
            BodyAccessMode::ReadWrite => BodyAccess::ReadWrite(crate::BodyRequirement::Required),
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
        //
        // Inference needs its own buffer because it has no classifier.
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly if !self.llm_routes => BodyMode::Stream,
            BodyAccessMode::ReadOnly => BodyMode::StreamBuffer {
                max_bytes: Some(self.cfg.llm.max_request_bytes),
            },
            // Both halves apply, so take whichever ceiling is lower.
            BodyAccessMode::ReadWrite if self.llm_routes => BodyMode::StreamBuffer {
                max_bytes: Some(self.cfg.max_buffer_bytes.min(self.cfg.llm.max_request_bytes)),
            },
            BodyAccessMode::ReadWrite => BodyMode::StreamBuffer {
                max_bytes: Some(self.cfg.max_buffer_bytes),
            },
        }
    }

    fn response_body_access(&self) -> BodyAccess {
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly => BodyAccess::ReadOnly(crate::BodyRequirement::Required),
            BodyAccessMode::ReadWrite => BodyAccess::ReadWrite(crate::BodyRequirement::Required),
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
        self.capture_request_facts(ctx);
        // A StreamBuffer filter can force the body phase to run before this
        // header phase. In that case admission already ran in on_request_body,
        // and re-running it could fail after credential-stripping mutations.
        if Self::admission_complete(ctx) {
            tracing::trace!(target: "policy.filter", "admission already completed in body phase; skipping header phase");
            return Ok(FilterAction::Continue);
        }

        // Pure L7 policy (`global` HTTP rules or assertions, no entity routes): authorize
        // here over `http.*` + identity. Authorization is an admission check
        // with no body, and no classifier is involved, so this is the
        // efficient path for Praxis as an L7 HTTP proxy.
        if self.http_request_policy && !self.entity_routes {
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
        self.capture_request_facts(ctx);
        // A downstream StreamBuffer filter makes this body hook run before
        // on_request. Pure-L7 and identity-only admission needs no body, so run
        // it on the first chunk before any later body filter can act. In the
        // normal header-first lifecycle, the completion marker makes this a
        // no-op and prevents duplicate validation.
        if !self.entity_routes {
            if Self::admission_complete(ctx) {
                return Ok(FilterAction::BodyDone);
            }
            let action = if self.http_request_policy {
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

        // MCP routes use classifier metadata; inference routes use the body model.
        let Some(method) = ctx.get_metadata("mcp.method").map(str::to_owned) else {
            if self.llm_routes
                && let Some(rejection) = self.reject_oversized_inference_body(body.as_ref())
            {
                return Ok(FilterAction::Reject(rejection));
            }
            if self.llm_routes && carries_no_body(ctx, body.as_ref()) {
                tracing::trace!(
                    target: "policy.filter",
                    "request carries no body; no inference dispatch",
                );
                return Box::pin(self.admit_http_fallback(ctx)).await;
            }

            // A repeated key makes the body mean different things to
            // different parsers, so no policy can judge it.
            let Ok(parsed) = self
                .llm_routes
                .then(|| ParsedLlmRequest::parse(body.as_ref().unwrap_or(&EMPTY_BODY)))
                .transpose()
            else {
                tracing::debug!(
                    target: "policy.filter",
                    "request body repeats a JSON object key; denying (fail-closed)",
                );
                return Ok(FilterAction::Reject(duplicate_key_rejection()));
            };

            // A JSON-RPC envelope belongs to the classifier, not inference.
            let carries_envelope = parsed.as_ref().is_some_and(ParsedLlmRequest::carries_json_rpc_envelope);

            if let Some(parsed) = parsed {
                match (carries_envelope, parsed.model().map(str::to_owned)) {
                    (true, Some(_)) => {
                        tracing::warn!(
                            target: "policy.filter",
                            "request carries both a JSON-RPC envelope and a top-level `model` and no \
                             classifier claimed it; denying (fail-closed) rather than choosing \
                             between the MCP and inference entity",
                        );
                        return Ok(FilterAction::Reject(llm_deny_rejection(Some(
                            &ambiguous_entity_violation(),
                        ))));
                    },
                    (false, Some(model)) => {
                        return Box::pin(self.dispatch_llm_request(ctx, parsed, model)).await;
                    },
                    // Preserve the classifier error for an unclaimed envelope.
                    (_, None) => {},
                }
            }

            // Report missing classification before a missing inference model.
            if self.mcp_routes && (!self.llm_routes || carries_envelope) && self.cfg.require_protocol_metadata {
                tracing::error!(
                    target: "policy.filter",
                    "policy declares entity routes (tool/prompt/resource) which require a protocol \
                     classifier filter ordered before `policy` in the chain, but no `mcp.method` \
                     metadata was found — the classifier is missing or misordered. Denying (fail-closed). \
                     Set `require_protocol_metadata: false` only to run this policy for identity-only enforcement.",
                );
                return Ok(FilterAction::Reject(missing_protocol_metadata_rejection()));
            }
            if self.llm_routes && self.cfg.llm.require_model {
                tracing::debug!(
                    target: "policy.filter",
                    "policy declares `llm:` routes but the request body carries no usable top-level \
                     `model`; denying (fail-closed). Set `llm.require_model: false` to admit such a \
                     request on this policy's other paths.",
                );
                return Ok(FilterAction::Reject(llm_deny_rejection(Some(
                    &missing_model_violation(),
                ))));
            }
            tracing::trace!(target: "policy.filter", "request carries no entity coordinates; no CMF dispatch");
            if self.llm_routes {
                return Box::pin(self.admit_http_fallback(ctx)).await;
            }
            return self.complete_gated_admission(ctx).await;
        };

        // Refuse conflicting coordinates rather than choose the wrong policy.
        if self.llm_routes
            && ParsedLlmRequest::parse_last_wins(body.as_ref().unwrap_or(&EMPTY_BODY))
                .model()
                .is_some()
        {
            tracing::warn!(
                target: "policy.filter",
                protocol_method = %method,
                "request carries both a JSON-RPC envelope and a top-level `model`; denying \
                 (fail-closed) rather than choosing between the MCP and inference entity",
            );
            return Ok(FilterAction::Reject(llm_deny_rejection(Some(
                &ambiguous_entity_violation(),
            ))));
        }
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

        let view = Self::request_view(ctx, &self.cfg.context_headers, &self.trusted_proxies);

        // Resolve identity once here, then stash it so the response phase
        // can rebuild `Extensions` without re-validating the token.
        let identity = match self.resolve_identity(ctx, &view, entity_type, &entity_name).await? {
            Ok(id) => id,
            Err(rej) => return Ok(FilterAction::Reject(rej)),
        };
        Self::publish_authenticated_identity(ctx, &identity);
        // The engine grants entity route handlers `read_headers` and
        // `read_query`, so one policy can combine `args.*` with `http.*`.
        let extensions = Self::extensions_from_identity(&view, &identity, entity_type, &entity_name, &self.cfg);
        let body_bytes = body.as_ref().cloned().unwrap_or_else(Bytes::new);
        let parsed = ParsedEnvelope::parse(&body_bytes);
        if let Some(denied) = self.post_identity_limit(ctx, &extensions).await? {
            return Ok(FilterAction::Reject(denied.json_rpc(&parsed.id_value())));
        }
        Self::store_identity(ctx, identity);

        // Parse the JSON-RPC body to build the typed CMF content part.
        // The protocol classifier filter already parsed once but only stashed
        // method/name in `filter_metadata`, not the `params.arguments`
        // that APL `args.*` predicates need. We re-parse here. The
        // body is already in memory; the duplicate parse is
        // microseconds.
        let id = parsed.id_string();
        let content = build_content_for_method(&method, &entity_name, &id, &parsed);

        // Dispatch the CMF hook. The route annotation (installed by
        // the APL visitor at config-load time) drives policy
        // evaluation; if no APL route matches, the hook is a no-op.
        //
        // Awaited on the worker runtime on purpose. The engine runs every
        // handler in a task it spawns onto the current runtime, so the
        // evaluation lands on the workers however it is invoked; a
        // blocking-pool hop would only park a pool thread on the join handle
        // and, under load, queue requests behind the pool's thread cap.
        let payload = MessagePayload {
            message: Message::with_content(Role::User, content),
        };
        let cmf_result = self.invoke::<CmfHook>(ctx, hook_name, payload, extensions).await?;

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
        let attached = match attach_delegated_tokens(ctx, cmf_result.modified_extensions.as_ref()) {
            Ok(attached) => attached,
            Err(rejection) => return Ok(FilterAction::Reject(rejection)),
        };
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

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.record_streamed_inference_response(ctx);
        if ctx.response_header.is_none() {
            return Ok(FilterAction::Continue);
        }
        if let Some(action) = self.dispatch_http_response_hook(ctx).await? {
            return Ok(action);
        }
        Self::snapshot_response_context(ctx);
        if Self::response_ends_at_headers(ctx) && self.entity_routes && self.llm_post {
            return self.dispatch_llm_response_context(ctx);
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
        // Release SSE chunks immediately because there is no single completion to buffer.
        // Keep the clean-EOF callback available for metadata-only response policy.
        if !end_of_stream
            && matches!(self.cfg.body_access, BodyAccessMode::ReadWrite)
            && (self.inference_response_is_streamed(ctx)
                || state(ctx).is_some_and(|state| state.streamed_inference_response))
        {
            return Ok(FilterAction::Release);
        }
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        // Response-phase entity work only applies to entity-aware policies;
        // a pure L7 (or identity-only) policy has no per-entity post hook.
        if !self.entity_routes {
            return Ok(FilterAction::Continue);
        }
        if self.llm_post
            && ctx.extensions.get::<PolicyResponseContext>().is_some()
            && (matches!(self.cfg.body_access, BodyAccessMode::ReadOnly)
                || self.inference_response_is_streamed(ctx)
                || state(ctx).is_some_and(|state| state.streamed_inference_response))
        {
            return self.dispatch_llm_response_context(ctx);
        }
        // Response hooks require the buffering enabled by `read_write`.
        if !matches!(self.cfg.body_access, BodyAccessMode::ReadWrite) {
            return Ok(FilterAction::Continue);
        }

        if self.llm_post && state(ctx).is_some_and(|state| state.inference_model.is_some()) {
            return self.dispatch_llm_response(ctx, body);
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
        let parsed = if self.mcp_post_tool && method == "tools/call" && !body_bytes.is_empty() {
            ParsedEnvelope::try_parse(&body_bytes)
                .map_err(|_error| -> FilterError { "policy: malformed JSON-RPC response cannot be inspected".into() })?
        } else {
            ParsedEnvelope::parse(&body_bytes)
        };
        let id_str = parsed.id_string();

        // Rebuild `Extensions` from the identity resolved in the request
        // phase (stashed in `ctx.extensions`), rather than re-running the
        // identity hook here. This is a pure, synchronous field-mapping —
        // no token re-validation — so a token that expired between the
        // request and this (already-served) response can't produce a
        // false deny on a request that was authorized.
        let Some(identity) = Self::admitted_identity(ctx) else {
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
            let violation = post_phase_identity_unavailable_violation();
            let envelope = json_rpc_error_envelope_bytes(Some(&violation), &request_id);
            *body = Some(fit_to_original_length(
                envelope,
                body_bytes.len(),
                method.as_str(),
                "post-phase identity failure",
            ));
            return Ok(FilterAction::Continue);
        };
        let view = Self::request_view(ctx, &self.cfg.context_headers, &self.trusted_proxies);
        let extensions = Self::extensions_from_identity(&view, identity, entity_type, &entity_name, &self.cfg);

        let content = build_response_content_for_method(&method, &entity_name, &id_str, &parsed);
        // A valid tools/call error has no result to inspect. Unknown shapes
        // are not equivalent: treating them as errors would skip an active
        // tool response policy without checking the upstream data. For prompts and
        // resources, content projection is not yet implemented (tools/call
        // only), so content is always empty, but attribute-only post rules
        // (identity, CEL predicates over subject/meta) are still valid.
        if content.is_empty() && method == "tools/call" {
            if self.mcp_post_tool && !body_bytes.is_empty() && !parsed.is_json_rpc_error() {
                return Err("policy: JSON-RPC tool response has no inspectable result or valid error".into());
            }
            return Ok(FilterAction::Continue);
        }
        let payload = MessagePayload {
            message: Message::with_content(Role::Assistant, content),
        };
        let cmf_result = self.dispatch_response_cmf(ctx, hook_name, payload, extensions)?;

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

/// Push the minted delegated tokens on the resolved `Extensions` as upstream
/// request headers and strip the inbound credentials they replace. Returns
/// the count attached (0 when no delegation ran). Each token's
/// `outbound_header` decides where it goes; the value is its
/// `outbound_prefix` followed by the token. Delegated headers replace existing
/// values.
///
/// # Errors
///
/// Returns a rejection, attaching nothing, when a token would be forwarded
/// while an inbound credential sits where it cannot be stripped (a query
/// parameter, or a location this build does not know): the upstream would
/// receive the caller's credential beside the delegated one. Also rejects
/// when delegation ran but no token forms a valid header, so the inbound
/// credential is never forwarded in the delegated one's place.
pub(super) fn attach_delegated_tokens(
    ctx: &mut HttpFilterContext<'_>,
    extensions: Option<&Extensions>,
) -> Result<usize, Rejection> {
    let Some(raw) = extensions.and_then(|ext| ext.raw_credentials.as_ref()) else {
        return Ok(0);
    };
    let outbound = delegated_headers(raw);
    if outbound.is_empty() {
        if raw.delegated_tokens.is_empty() {
            return Ok(0);
        }
        tracing::warn!(
            target: "policy.filter",
            "refusing to forward the request: no delegated token forms a valid upstream header, \
             so the inbound credential would travel in its place",
        );
        return Err(delegation_failed_rejection());
    }
    refuse_unstrippable_inbound(raw)?;
    let attached: std::collections::HashSet<http::header::HeaderName> =
        outbound.iter().map(|(name, _)| name.clone()).collect();
    let count = outbound.len();
    for (name, value) in outbound {
        request_headers::set(ctx, name, value);
    }
    for inbound in raw.inbound_tokens.values() {
        strip_inbound_header(ctx, &inbound.source, &attached);
    }
    Ok(count)
}

/// Refuse delegation while an inbound credential in `raw` sits where it
/// cannot be stripped.
///
/// # Errors
///
/// Returns [`unstrippable_credential_rejection`] for such a credential.
///
/// [`unstrippable_credential_rejection`]: unstrippable_credential_rejection
fn refuse_unstrippable_inbound(
    raw: &ppe::praxis_policy_core::extensions::raw_credentials::RawCredentialsExtension,
) -> Result<(), Rejection> {
    let Some(inbound) = raw
        .inbound_tokens
        .values()
        .find(|inbound| inbound_source_header(&inbound.source).is_none())
    else {
        return Ok(());
    };
    tracing::warn!(
        target: "policy.filter",
        source = %inbound.source,
        "refusing to forward a delegated token: the inbound credential cannot be stripped \
         from the upstream request",
    );
    Err(unstrippable_credential_rejection())
}

/// The `(header, value)` pairs for the delegated tokens in `raw`.
///
/// Returns one token per header, choosing the first valid token by audience
/// in ascending order when delegators target the same header.
fn delegated_headers(
    raw: &ppe::praxis_policy_core::extensions::raw_credentials::RawCredentialsExtension,
) -> Vec<(http::header::HeaderName, http::header::HeaderValue)> {
    let mut sorted: Vec<&_> = raw.delegated_tokens.values().collect();
    sorted.sort_by(|a, b| {
        a.outbound_header
            .to_ascii_lowercase()
            .cmp(&b.outbound_header.to_ascii_lowercase())
            .then_with(|| a.audience.cmp(&b.audience))
    });
    let mut out: Vec<(http::header::HeaderName, http::header::HeaderValue)> = Vec::new();
    for tok in sorted {
        let Some((name, value)) = delegated_header(tok) else {
            continue;
        };
        if out.iter().any(|(attached, _)| *attached == name) {
            tracing::warn!(
                target: "policy.filter",
                outbound_header = %tok.outbound_header,
                audience = %tok.audience,
                "skipping delegated token: another token already targets this outbound header \
                 (first-writer-wins by audience asc); fix overlapping delegators in policy",
            );
            continue;
        }
        out.push((name, value));
    }
    out
}

/// The upstream header for one delegated token, or `None` (logged) when its
/// name or value is not valid HTTP.
fn delegated_header(
    tok: &ppe::praxis_policy_core::extensions::raw_credentials::RawDelegatedToken,
) -> Option<(http::header::HeaderName, http::header::HeaderValue)> {
    let Ok(name) = http::header::HeaderName::try_from(tok.outbound_header.as_str()) else {
        tracing::warn!(
            target: "policy.filter",
            header = %tok.outbound_header,
            "delegated token outbound_header is not a valid HTTP header name; skipping",
        );
        return None;
    };
    // Zeroized so the prefixed plaintext is wiped once the value copies it.
    let credential = zeroize::Zeroizing::new(format!("{}{}", tok.outbound_prefix, tok.token.as_str()));
    let Ok(value) = http::header::HeaderValue::try_from(credential.as_str()) else {
        tracing::warn!(
            target: "policy.filter",
            audience = %tok.audience,
            "minted token bytes are not a valid HTTP header value; skipping",
        );
        return None;
    };
    Some((name, value))
}

/// Remove the header carrying an inbound credential, unless a delegated token
/// overwrites it.
fn strip_inbound_header(
    ctx: &mut HttpFilterContext<'_>,
    source: &Credential,
    attached: &std::collections::HashSet<http::header::HeaderName>,
) {
    let Some(source_header) = inbound_source_header(source) else {
        return;
    };
    match http::header::HeaderName::try_from(source_header) {
        Ok(name) if attached.contains(&name) => {},
        Ok(name) => request_headers::remove(ctx, name),
        Err(_) => tracing::warn!(
            target: "policy.filter",
            header = source_header,
            "inbound credential source is not a valid HTTP header name; cannot strip",
        ),
    }
}

/// Rejection for a delegated token that would travel beside an inbound
/// credential the filter cannot strip. HTTP 500: the policy is
/// misconfigured, and the body names no credential.
fn unstrippable_credential_rejection() -> Rejection {
    Rejection::status(500)
        .with_header("Content-Type", "text/plain")
        .with_header(VIOLATION_HEADER, "policy.unstrippable_credential")
        .with_body(Bytes::from_static(
            b"policy: a delegated token cannot be forwarded while the inbound credential \
              sits in a location the filter cannot strip from the upstream request",
        ))
}

/// Rejection for a delegation whose every token failed to form an upstream
/// header. HTTP 500: the body names no credential.
fn delegation_failed_rejection() -> Rejection {
    Rejection::status(500)
        .with_header("Content-Type", "text/plain")
        .with_header(VIOLATION_HEADER, "policy.delegation_failed")
        .with_body(Bytes::from_static(
            b"policy: no delegated token could be attached to the upstream request",
        ))
}

/// Startup warnings for fallbacks that admit on identity alone, skipping the
/// policy's HTTP rules and request assertions.
pub(super) fn identity_only_fallback_warnings(
    cfg: &PolicyFilterConfig,
    mcp_routes: bool,
    llm_routes: bool,
) -> Vec<&'static str> {
    let unclassified = (mcp_routes && !llm_routes && !cfg.require_protocol_metadata).then_some(
        "policy declares HTTP rules or request assertions alongside `require_protocol_metadata: \
         false`: an unclassified request is admitted on identity alone, without HTTP \
         authorization, delegation or request assertions",
    );
    unclassified.into_iter().collect()
}

/// Warn when the loaded policy declares `rate_limits:`, which runs the
/// experimental limiter. Runs on every construction, so on every reload too.
fn warn_on_rate_limits(policy_config: &ppe::praxis_policy_core::config::PolicyConfig, config_path: &str) {
    if declares_rate_limits(policy_config) {
        tracing::warn!(
            target: "policy.filter",
            config_path,
            "policy declares `rate_limits:`; Policy rate limiting is experimental and outside its \
             semver guarantees, and should not be relied on in production",
        );
    }
}

/// Whether any layer of `policy_config` declares a `rate_limits:` block.
pub(super) fn declares_rate_limits(policy_config: &ppe::praxis_policy_core::config::PolicyConfig) -> bool {
    let global = &policy_config.global;
    // Parsing moves top-level `groups:` into `global.bundles`; read both.
    global.rate_limits.is_some()
        || global.bundles.values().any(|group| group.rate_limits.is_some())
        || global.defaults.values().any(|group| group.rate_limits.is_some())
        || policy_config.groups.values().any(|group| group.rate_limits.is_some())
        || policy_config.routes.iter().any(|route| route.rate_limits.is_some())
}

/// Map a Policy credential location to the HTTP header that can be stripped.
fn inbound_source_header(source: &Credential) -> Option<&str> {
    match source {
        Credential::Header { name } => Some(name),
        Credential::Cookie { .. } => Some(http::header::COOKIE.as_str()),
        Credential::QueryParam { .. } => None,
        other => {
            tracing::warn!(
                target: "policy.filter",
                source = %other,
                "unsupported inbound credential location; cannot strip",
            );
            None
        },
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::PolicyFilter;

    #[test]
    fn snapshot_headers_comma_joins_duplicate_field_lines() {
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers
            .append(http::header::HeaderName::from_static("x-role"), "user".parse().unwrap());
        req.headers.append(
            http::header::HeaderName::from_static("x-role"),
            "admin".parse().unwrap(),
        );
        let ctx = crate::test_utils::make_filter_context(&req);

        let snapshot = PolicyFilter::snapshot_headers(&ctx);
        assert_eq!(
            snapshot.get("x-role").map(String::as_str),
            Some("user, admin"),
            "duplicate header field-lines must be comma-joined, not collapsed to the last value"
        );
    }
}
