# Praxis Hook System and Plugin Support

Status: draft

This document specifies the hook system and plugin runtime for Praxis. Hooks complement the existing `HttpFilter` / `TcpFilter` surface with typed, capability-gated plugins that observe or enforce policy at well-defined lifecycle (e.g., startup, auth) and protocol-semantic (e.g., MCP, A2A) points. The runtime is [CPEX](https://github.com/contextforge-org/contextforge-plugins-framework), embedded in-process.

## Contents

1. [Scope (v1)](#1-scope-v1)
2. [Goals and non-goals](#2-goals-and-non-goals)
3. [Integration architecture](#3-integration-architecture)
4. [Protocol hook design](#4-protocol-hook-design)
5. [Hook catalog (v1)](#5-hook-catalog-v1)
6. [Plugin runtime model](#6-plugin-runtime-model)
7. [Plugin authoring and loading](#7-plugin-authoring-and-loading)
8. [Configuration](#8-configuration)
9. [Security invariants and hook mapping](#9-security-invariants-and-hook-mapping)
10. [Staged rollout](#10-staged-rollout)
11. [Open questions](#11-open-questions)
12. [Appendix A: Full hook catalog and payload sketches](#appendix-a-full-hook-catalog-and-payload-sketches)
13. [Appendix B: Configuration example](#appendix-b-configuration-example)

## 1. Scope (v1)

The hook system v1 includes:

1. One new Praxis crate, `praxis-hooks`, plus one new builtin filter at `filter/src/builtins/http/mcp/`. One external dependency, `cpex-core`.
2. CPEX `PluginManager` wired through `run_server`. All hooks flow through the same dispatcher: lifecycle and protocol-semantic hooks. See the [CPEX Rust spec](https://github.com/contextforge-org/contextforge-plugins-framework/blob/dev/docs/specs/cpex-rust-spec.md).
3. Initial set of 12 hooks registered, including lifecycle hooks, identity hooks (`praxis.identity.resolve`, `praxis.identity.delegate`), and MCP tool hooks (`praxis.mcp.tool_pre_invoke`, `praxis.mcp.tool_post_invoke`).
4. Tool hooks ship via the MCP gateway filter described in §4.4 with _route-driven body mode_ (§4.3). A protocol-native `McpProxy` service (§4.2) is described as an upgrade path if the filter approach under-performs. Hook names are stable across options; plugin code does not change.
5. Plugins are Rust crates registered programmatically (`register_handler` / `register_handler_for_names`). Dynamic loading via `cdylib` plus `libloading` is in the spec and ships as a parallel phase.
6. Mutation flows through CPEX `Extensions` and capability-gated `WriteToken`s. Field-level write authority uses type-system enforcement (`Sealed<T>`, `MutabilityTier`, `Guarded<T>`) when needed; v1's capability-gated Extensions and WriteTokens are sufficient.

Out of scope in v1:

- A2A, LLM, prompt, and resource protocol-semantic hooks. Planned; names reserved in [Appendix A](#appendix-a-full-hook-catalog-and-payload-sketches).
- WASM, Python, and sidecar plugin hosts. It will be possible through future releases of CPEX, but need to consider use case and performance requirements.
- Hot reload. Plugins load at startup and release on shutdown.

## 2. Goals and non-goals

### 2.1 Goals

- **A second extension surface.** `HttpFilter` and `TcpFilter` handle per-request transformation well. They are insufficient for lifecycle observation (TLS handshake, connect, session end), policy enforcement at security boundaries the pipeline does not expose, and policy targeted at protocol-semantic events rather than HTTP primitives. Hooks fill those gaps.
- **A common runtime.** CPEX provides a common runtime for configuring, registering, and dispatching plugins at hook points; Praxis is the host owning the hook points and a reference to CPEX `PluginManager` (the hook dispatcher). Plugins targeting Praxis hooks can also target other CPEX hosts where payload types overlap. CPEX `MessagePayload` (CMF) payloads (the tool hooks) are the clearest example.
- **Latency-budgeted.** Hooks run on the request hot path. Native AFIT in CPEX means a `HookHandler::handle` with no `.await` compiles to a ready future with no scheduler interaction; the cost is a direct call.
- **Tighten-only composition.** Plugins may strengthen the security boundaries catalogued in [§9](#9-security-invariants-and-hook-mapping). They cannot silently weaken any. The dispatcher enforces this structurally.
- **Zero cost when unused.** A deployment without a `plugins:` block pays a single `PluginManager::has_hooks_for` lookup at each call site. No dispatcher traversal, no allocations.

### 2.2 Non-goals

- **Replacing filters.** Filters remain the right abstraction for per-request transformation. Hooks wrap filters, not the other way around.
- **Hot reload.** Startup-only loading keeps the trust model simple.
- **Arbitrary cross-hook ordering.** Within a hook point, plugins run in CPEX's [execution order](https://contextforge-org.github.io/contextforge-plugins-framework/docs/execution-modes/) at configured priority. Across hook points, order is set by the request lifecycle.
- **Field-level payload write policy.** Not needed in v1. The `Guarded<T>` / `WriteToken` mechanism enforces write authority at the type level. Future tightening beyond `WriteToken` will use `Sealed<T>` / `MutabilityTier` type-system enforcement, not a runtime policy mechanism.
- **Policy evaluation language ([APL](https://github.com/contextforge-org/contextforge-plugins-framework/blob/eaedce7af05ec3f63ef48fa469035bb5948b38e3/docs/specs/apl-dsl-spec.md)).** Praxis hosts CPEX hooks; policy-evaluation integration via APL or `PolicyEvaluator` is out of scope for v1. May land as a Phase 5+ item if a concrete consumer warrants it.

## 3. Integration architecture

### 3.1 CPEX runtime

Praxis embeds the CPEX `PluginManager` in-process. A plugin call is a function call, not an IPC hop. CPEX provides the typed dispatcher, phase executor, capability-gated extensions, plugin lifecycle, and registration. Praxis provides lifecycle call sites, payload construction, protocol gateway filters (e.g., MCP), and the tighten-only composition rules for its policy hooks.

### 3.2 Crate layout

A single new crate joins the Praxis workspace.

```
praxis/
  hooks/                          NEW: praxis-hooks crate
    src/
      lib.rs                      register_hooks!, public types
      payloads/{startup,tls,tcp,http,mcp}.rs
      dispatcher/{mod,http,tcp,tls,mcp,tighten}.rs
      config.rs                   YAML to CPEX config adapter
      metrics.rs                  praxis_hook_* emitters
  filter/src/builtins/http/mcp/   NEW: MCP gateway filter (§4.4)
  server/                         depends on praxis-hooks
  protocol/                       depends on praxis-hooks
  tls/                            depends on praxis-hooks
```

Workspace dependency:

```toml
cpex-core = { git = "https://github.com/contextforge-org/contextforge-plugins-framework", branch = "dev" }
```

`branch = "dev"` indicates the source branch. In practice, Praxis pins to a specific commit or dev tag (see [§11 Open Question 1](#11-open-questions)). The lockfile records the exact resolved commit.

`cpex-sdk` can be imported when implementing out-of-tree plugins without importing the entire `cpex-core` machinery. WASM, Python, and sidecar hosts are not in cpex-core today; when they ship, they enter via additive `cpex-hosts::*` crates without changing the Praxis surface.

### 3.3 Lifecycle integration

The `PluginManager` is owned by `server::run_server`, built after pipelines are resolved and before `server.run_forever()`.

```
server/src/server.rs::run_server
  enforce_root_check
  warn_insecure_key_permissions
  build_health_registry
  resolve_pipelines
  PluginManager::new(ManagerConfig::default())
  register_handler::<H, _>(...) for each compiled-in plugin
  load_config(plugins_yaml)                          (dynamic plugins, when shipped)
  manager.initialize().await                         (calls Plugin::initialize on each)
  invoke S1 praxis.startup.config_loaded             (fail-closed)
  PingoraServerRuntime::new(..., manager)
  PingoraHttp.register(..., manager)
  PingoraTcp.register(..., manager)
  // S3 praxis.startup.listeners_bound               (reserved; no-op until promoted)
  server.run_forever()
```

Protocol handlers receive the manager as `Arc<PluginManager>`, parallel to how they receive `Arc<FilterPipeline>` today. A manager with no registered handlers for a hook short-circuits `invoke::<H>` to a zero-cost path, so a Praxis deployment without plugins pays one registry lookup per call site.

### 3.4 Call-site contract

Every call site in the [hook catalog](#5-hook-catalog-v1) must:

1. Fast-path check `manager.has_hooks_for(H::NAME)`. CPEX's registry uses `ArcSwap` for lock-free reads; a miss is one atomic load.
2. If hooks exist, build the typed payload from local context.
3. Invoke via `manager.invoke::<H>(payload, extensions, ctx_table).await`, which returns `(PipelineResult, BackgroundTasks)`.
4. Apply the returned `PipelineResult` per the hook's interaction class (see [§6.7](#67-interaction-enforcement)).
5. Emit the per-site metric (see [§8.6](#86-observability)).

Call sites use the `praxis_hooks::invoke_hook!` macro to keep boilerplate out of the request path.

### 3.5 What CPEX provides (public API)

| CPEX feature | Praxis usage |
|---|---|
| `Plugin` trait | Plugin lifecycle (`initialize`, `shutdown`). |
| `HookTypeDef` | Praxis hook types; typed dispatch via `invoke::<H>`. |
| `HookHandler<H>::handle` | The plugin-author surface. Async by default; AFIT makes sync bodies free. |
| `PluginManager` | Owned by `run_server`. One instance per process. |
| `PluginConfig` | YAML schema; trusted source of priority, mode, capabilities. |
| `PluginMode` | Sequential, Transform, Audit, Concurrent, FireAndForget, Disabled (YAML: `sequential`, `transform`, `audit`, `concurrent`, `fire_and_forget`, `disabled`). |
| `OnError` | Surfaced verbatim in YAML: `fail`, `ignore`, `disable`. |
| `Extensions` | Capability-gated sidecar data for headers, identity, MCP entity metadata. |
| `PluginContext` | `local_state` (per-plugin, cross-hook) and `global_state` (cross-plugin, per-invoke). |
| `MessagePayload` (CMF) | Tool hook payload. Reused without modification. |
| `register_handler_for_names` | CMF-style multi-name registration. |
| `invoke_named::<H>` | Tool hook dispatch (one type, multiple names). |

Finer-grained field-level write authority beyond `WriteToken` will use type-system enforcement (`Sealed<T>`, `MutabilityTier`) when needed. Praxis v1 does not require it. Capability-gated `Extensions` cover header mutation; full-payload `modify_payload` covers the rest.

## 4. Protocol hook design

Hooks fall into two families: **lifecycle** (operate on HTTP/TCP primitives — headers, methods, URIs, client addresses, TLS info, upstream selection; no body access needed) and **protocol-semantic** (operate on parsed protocol payloads like MCP `tools/call`; require body buffering). Lifecycle hooks are cheap by construction. The design challenge is delivering protocol-semantic hooks without imposing buffering costs on unrelated traffic or inverting Praxis's layering.

In v1, tool hooks (`praxis.mcp.tool_pre_invoke`, `praxis.mcp.tool_post_invoke`) ship through the MCP gateway filter (§4.4). Bodies buffer only for routes the operator marks as MCP-aware (§4.3). Non-`tools/call` MCP methods stream through. Future protocol-semantic hooks (A2A, LLM, prompts, resources) are reserved in [Appendix A](#appendix-a-full-hook-catalog-and-payload-sketches); promoted when a concrete consumer warrants it.

### 4.1 Why protocol-semantic hooks cost something

Praxis ranks body modes `StreamBuffer > SizeLimit > Stream`. Streaming is the default. Recent versions of Praxis addressed the "listener-wide collapse" failure mode where one filter forcing `Buffer` promoted the whole listener: `Buffer` is gone, and filters opt into buffering per request via `ctx.set_request_body_mode(...)` and `ctx.set_response_body_mode(...)` (commit `0f0f656`).

The surviving failure mode is _indiscriminate per-request buffering_. A content-aware filter that does not predicate body access by route or method still pays buffering cost on every request its filter chain matches. The cost is narrower than before but not free, and naive content-type sniffing inside a filter is the easy way to fall into it.

A second cost is _abstraction inversion_. A filter that parses JSON-RPC method names and dispatches per-tool hooks bakes protocol knowledge into the HTTP layer. The HTTP layer should know headers, methods, URIs, and bodies-as-bytes. Protocol semantics belong in the component that routes the protocol.

Both costs survive the gateway filter approach. Sections §4.2 and §4.3 introduce mechanisms that make them bounded and explicit.

### 4.2 Protocol hooks: gateway filter vs. protocol-native service

Two implementation paths for protocol-semantic hooks. Both dispatch against the same `Arc<PluginManager>`. Hook names are stable across both. Plugin code does not change between them.

**Protocol gateway filters (v1).** For MCP hooks, v1 defines a builtin filter under `filter/src/builtins/http/mcp/`. The filter runs only on routes that opt in via the route-level `body_mode:` declaration (§4.3). On matched routes, the filter consumes the buffered body, parses JSON-RPC (using `filter/src/builtins/http/payload_processing/json_rpc/`), constructs `MessagePayload` for `tools/call` methods, and dispatches `praxis.mcp.tool_pre_invoke` and `_post_invoke`. This works today with no new architectural pieces beyond the route field. The §4.1 costs apply: bounded buffering on matched routes, protocol parsing in the filter layer. See §4.4 for the full filter spec.

**Protocol-native services (future option).** Using MCP as an example, this approach defines a new crate sibling to `protocol/src/http/` and `protocol/src/tcp/`, registered as a new `ProtocolKind::Mcp` listener. It owns its accept loop, parses JSON-RPC at the head, buffers selectively only for methods that carry payloads (`tools/call`, `prompts/get`, `resources/read`), and dispatches `praxis.mcp.*` against the same `Arc<PluginManager>`. This is the long-term home. It removes the abstraction-inversion cost and lets the buffering decision live with the protocol parser. Significantly more work: listener wiring, lifecycle parity with HTTP, SSE-aware response streaming, integration tests.

> **Decision.** Ship the gateway filter in v1 to validate the hook payload shapes, the `filter_metadata` plumbing, and operator-facing config against real plugins. Promote to the protocol-native service when the filter-layer parsing becomes a bottleneck or when abstraction inversion bites in practice. Plugins written against the gateway filter retarget to the protocol-native service without code changes. Hook names are the stable contract.

### 4.3 Route-driven body mode

This proposed mechanism makes the gateway filter operator-friendly and provides a canonical way to enable buffering for protocol-aware routes.

**Assumption.** Praxis routes have shape `path_match: PathMatch` plus `cluster: Arc<str>` (`core/src/config/route.rs`). The cluster is resolved before body chunks flow. The pipeline knows, pre-body, whether the request is destined for a protocol-aware backend.

**Mechanism.** A route gains an optional `body_mode:` block:

```yaml
routes:
  - path_prefix: /mcp/
    cluster: mcp-backend
    body_mode:
      request:
        stream_buffer:
          max_bytes: 65536
      response:
        stream_buffer:
          max_bytes: 262144
```

The pipeline applies the declared `BodyMode` to the request context immediately after route resolution, before pipeline filters run. The MCP filter then runs unconditionally on matched routes and is a true no-op on unmatched ones. No content-type sniffing in code. No per-request branching for the common case.

**Why this beats in-filter sniffing.**

- *Declarative.* The operator decides which backends are MCP-aware in YAML.
- *Cheap.* Routing already happens. One extra `cluster` to `BodyMode` lookup. The MCP filter's hot path is "is metadata set, dispatch hook; else fall through."
- *Decoupled.* The filter carries no protocol-detection logic.
- *Upgrade-safe.* When the protocol-native service lands, the route still names the cluster. Operator config does not change.

**Praxis change required.** `core/src/config/route.rs` gains an optional `body_mode: Option<RouteBodyMode>`, where `RouteBodyMode { request: Option<BodyMode>, response: Option<BodyMode> }`. The pipeline calls `ctx.set_request_body_mode(...)` and `ctx.set_response_body_mode(...)` from the route binding before filters execute. Route-declared `body_mode` participates in `apply_body_limits` ceilings; an unbounded `StreamBuffer { max_bytes: None }` at the route level is rejected unless `allow_unbounded_body` is set, matching the existing filter-declared invariant.

**Fallback.** Filters retain the right to call `ctx.set_request_body_mode(...)` per request when route-driven config is not appropriate (a filter that decides based on a header the route does not see). Both paths converge on the same context API.

### 4.4 The MCP gateway filter

The single piece of Praxis-side code beyond `praxis-hooks` that v1 adds.

**Location.** `filter/src/builtins/http/mcp/`.

**Activation.** Operator opts in by adding `mcp_gateway` to a listener's filter chain. The filter only takes work for requests where the route declared a buffered body mode (§4.3) and the JSON-RPC payload classifies as `tools/call`. All other paths fall through as no-ops.

**Behavior.**

1. On request, check whether the route enabled buffering (§4.3). If not, fall through.
2. On buffered routes, after body-done, run the JSON-RPC parser at `filter/src/builtins/http/payload_processing/json_rpc/` to extract `method`, `id`, `params`.
3. If `method == "tools/call"`, construct a `MessagePayload` with the parsed tool name and arguments and dispatch `praxis.mcp.tool_pre_invoke` via the `PluginManager` handle the pipeline already holds.
4. If `PipelineResult.is_denied()`, emit a JSON-RPC error response without contacting upstream. If `modified_payload.is_some()`, write the redacted arguments back into the buffered request body before forwarding. If `modified_extensions.is_some()`, merge extension changes (header writes, label appends) back into the request context before forwarding; the merge follows CPEX's copy-on-write semantics with `WriteToken` authority preserved.
5. For JSON-RPC batch requests (array of method calls), the filter dispatches tool hooks per individual call within the batch. Batch identity (array index, batch request ID) is carried in `PluginContext::local_state` so plugins can correlate calls. If any call is denied, only that call's response is replaced with a JSON-RPC error; other calls in the batch proceed independently.
6. On response, if the original request was a `tools/call`, parse the JSON-RPC response, build the post-payload, dispatch `praxis.mcp.tool_post_invoke`. Thread the `PluginContextTable` from M1 into M2 so `local_state` carries through. Apply `modified_payload` back into the response body if any plugin redacted output. If `modified_extensions.is_some()`, merge post-invoke extension mutations into the response context before forwarding to client.
7. Non-`tools/call` methods bypass hook dispatch. The JSON-RPC parse runs once on buffered routes; the dispatch is gated on method.
8. Per-request metadata (parsed method, tool name, JSON-RPC id) goes into `filter_metadata` so it survives to H14 / `session_logged` for audit plugins downstream.

**What the filter does not do.**

- It does not own protocol routing. Praxis routing already does.
- It does not own buffering policy. The route declares it (§4.3).
- It does not own plugin invocation semantics. CPEX does.
- It does not validate tool argument schemas. Plugins do.

**Acknowledged cost.** The abstraction-inversion cost from §4.1 remains. The protocol-native service (§4.2) is the upgrade. Hook names are stable across both approaches; plugins do not change.

**Tests.** Unit tests for JSON-RPC method classification. Integration tests using `examples/configs/protocols/mcp/` with a fake MCP upstream that exercises `tools/call` end-to-end, including plugin-driven denial and argument or response redaction.

## 5. Hook catalog (v1)

This section covers the 12 hooks registered in v1. "Status: v1" means the hook is registered and usable by the end of the initial release sequence (Phases 1–4 in [§10](#10-staged-rollout)); it does not imply all hooks ship in the same phase. The full catalog (including reserved hooks and their payload sketches) is in [Appendix A](#appendix-a-full-hook-catalog-and-payload-sketches).

### 5.1 Conventions

- **ID** is a stable short identifier: `S` startup, `L` TLS, `T` TCP, `H` HTTP, `M` MCP.
- **Name** is the string CPEX registers under and the value operators write in YAML `hooks:` lines.
- **Interaction** is `observe`, `mutating`, or `policy`, mapped to allowed modes in [§6.6](#66-mode-constraints).

### 5.2 Lifecycle hooks

| ID | Name | Interaction | Default mode | Call site | Rationale |
|---|---|---|---|---|---|
| S1 | `praxis.startup.config_loaded` | policy | sequential | `server.rs` after `Config::load` | Validate or veto config before pipelines are built. Failing here aborts startup. |
| S4 | `praxis.startup.shutdown` | observe | audit | on SIGTERM path | Flush buffered state, deregister. Bounded by `shutdown_timeout_secs`. |
| L3 | `praxis.tls.cert_reloaded` | observe | audit | `tls/src/reload.rs::reload` | Fires on success and failure of cert rotation. |
| I1 | `praxis.identity.resolve` | policy | sequential | `request_filter/mod.rs` at H4, before pipeline | Identity resolution via CPEX `IdentityResolve`. Slot collision rejection at config load; identity sealed immutable post-resolution. |
| I2 | `praxis.identity.delegate` | mutating | transform | after route resolution, at H10 site | Token delegation via CPEX `TokenDelegate`. Framework-enforced scope narrowing, raw-credential boundary, `(subject, audience, scopes, mode)`-keyed cache. |
| H4 | `praxis.http.pre_request_pipeline` | policy | sequential | `request_filter/mod.rs` before pipeline | Short-circuit before filters run. Ext-authz home. |
| H7 | `praxis.http.pre_upstream_select` | policy | sequential | just before `upstream_peer::execute` | Final pre-select gate. |
| H9 | `praxis.http.upstream_connect_failure` | policy | sequential | `handle_connect_failure` | Deny to suppress retry; built-in idempotency check applies independently. |
| H11 | `praxis.http.upstream_response_header` | policy | sequential | `response_filter.rs` after hop-by-hop strip | First look at upstream response. May veto. |
| H14 | `praxis.http.session_logged` | observe | fire_and_forget | `handler/mod.rs` after `logging_cleanup` | Terminal; fires exactly once per request. |

Praxis hosts the CPEX `IdentityResolve` and `TokenDelegate` framework hooks (I1, I2) to get structural guarantees that ad-hoc H4/H10 plugins cannot provide: slot collision rejection at config load (no two resolvers write the same identity slot), immutable sealing post-resolution (mid-pipeline plugins cannot overwrite `security.subject`), capability-gated writes (`write_subject`, `write_client`, `write_workload`), a raw-credential boundary (`Zeroizing<String>`, `#[serde(skip)]`), and a token cache with invalidation API. Plugins authored against either CPEX or Praxis work on both hosts.

### 5.3 Protocol-semantic hooks

| ID | Name | Interaction | Default mode | Payload | Rationale |
|---|---|---|---|---|---|
| M1 | `praxis.mcp.tool_pre_invoke` | policy | sequential | `MessagePayload` | Gate or redact tool arguments before upstream. |
| M2 | `praxis.mcp.tool_post_invoke` | mutating | transform | `MessagePayload` | Redact or transform tool results before the client. |

Dispatch site is the MCP gateway filter (§4.4). The filter runs only on routes that opt in via `body_mode:` (§4.3). Non-`tools/call` MCP methods bypass hook dispatch.

Plugin authors register both names against a single `CmfHook` handler with `register_handler_for_names`. The filter calls `manager.invoke_named::<CmfHook>("praxis.mcp.tool_pre_invoke", ...)` and `..._post_invoke`. `PluginContext::local_state` threads per-tool state from M1 to M2 (a timer, a redaction decision).

### 5.4 Identity and authorization patterns

Identity and authorization use the dedicated framework hooks (I1, I2) rather than ad-hoc H4/H10 plugin patterns:

- **Identity resolution (I1).** JWT decoding, mTLS subject extraction, or API-key lookup registers as an `IdentityResolve` handler. The framework populates `SecurityExtension` slots (`subject`, `client`, `caller_workload`) and seals them immutable before the pipeline runs. Downstream plugins read identity via `read_subject` / `read_client` capabilities.
- **External authz.** Dispatches at H4 (for pipeline preemption) or H7 (for upstream-specific policy), reading the sealed identity from `SecurityExtension`.
- **Token delegation (I2).** Outbound token minting (OAuth token exchange, SPIFFE SVID, scoped API key) registers as a `TokenDelegate` handler at the H10 call site. The framework enforces scope narrowing (delegated token cannot exceed the inbound subject's authority), maintains a `(subject, audience, scopes, mode)`-keyed cache, and isolates raw credentials behind `RawCredentialsExtension` with `Zeroizing<String>` and `#[serde(skip)]`.

## 6. Plugin runtime model

CPEX binds each hook type to a payload and a result:

```rust
pub trait HookTypeDef: Send + Sync + 'static {
    type Payload: PluginPayload + Clone;
    type Result: Clone;
    const NAME: &'static str;
}
```

Every registered Praxis hook has one `HookTypeDef` in `praxis_hooks::payloads::*`. Payload structs borrow request-scoped data rather than clone it; plugins that need to retain anything clone explicitly. Full signatures for v1 hooks are in [Appendix A](#appendix-a-full-hook-catalog-and-payload-sketches).

### 6.1 The shared HTTP context

Every HTTP-family hook (H4–H14) receives an `HttpHookCtx<'a>` carrying client address, HTTP version, listener name, timing, request ID, and routing state. The context grows richer as the lifecycle progresses: `cluster`, `upstream`, and `rewritten_path` are `None` at H4 and earlier, populated after route resolution. Full struct definition in [Appendix A](#appendix-a-full-hook-catalog-and-payload-sketches).

### 6.2 Extensions

`Extensions` is a separate parameter, never folded into the payload. CPEX uses capabilities and `WriteToken`s to enforce read and write authority:

```rust
pub struct Extensions {
    pub http: Option<Arc<HttpExtension>>,               // request / response headers
    pub security: Option<Arc<SecurityExtension>>,       // subject, client, workload, labels
    pub request: Option<Arc<RequestExtension>>,         // request-id, trace-id, timing
    pub agent: Option<Arc<AgentExtension>>,             // session / conversation context
    pub delegation: Option<Arc<DelegationExtension>>,   // monotonic delegation chain
    pub raw_credentials: Option<Arc<RawCredentialsExtension>>,  // capability-gated, serde-skipped
    pub mcp: Option<Arc<MCPExtension>>,                 // MCP entity metadata (Praxis-defined)
}
```

`SecurityExtension` carries: `subject` (authenticated user), `client` (OAuth client / gateway), `caller_workload` (inbound SPIFFE), `this_workload` (our outbound SPIFFE), and `labels` (monotonic append-only). `AgentExtension` carries session/conversation context (`agent_id`, `parent_agent_id`, `session_id`, `conversation_id`, `turn`) — distinct from security credentials. `DelegationExtension` carries the monotonic delegation chain (`hops`, `depth`, `origin_subject_id`, `actor_subject_id`, `age_seconds`); written by the framework, read-only for plugins. `RawCredentialsExtension` holds inbound tokens and delegated tokens behind per-slot capabilities, with `Zeroizing<String>` storage and `#[serde(skip)]` to prevent leakage into logs or traces. `MCPExtension` is Praxis-defined and carries tool server metadata for hook dispatch.

Common Praxis capabilities:

| Capability | Grants |
|---|---|
| `read_headers` | `HttpExtension.request_headers` (read) |
| `write_headers` | `HttpExtension.response_headers` (read plus write token) |
| `read_subject` | `SecurityExtension.subject` (read) |
| `write_subject` | `SecurityExtension.subject` (write; identity resolvers only) |
| `read_client` | `SecurityExtension.client` (read) |
| `write_client` | `SecurityExtension.client` (write; identity resolvers only) |
| `read_workload` | `SecurityExtension.caller_workload` / `this_workload` (read) |
| `read_labels` | `SecurityExtension.labels` (read) |
| `write_labels` | `SecurityExtension.labels` (append-only) |
| `read_classification` | `SecurityExtension.classification` (read) |
| `read_agent` | `AgentExtension` (read) |
| `write_agent` | `AgentExtension` (write) |
| `read_delegation` | `DelegationExtension` (read; framework writes) |
| `read_inbound_credentials` | `RawCredentialsExtension.inbound_tokens` (read) |
| `read_delegated_tokens` | `RawCredentialsExtension.delegated_tokens` (read) |

Header writes go through a copy-on-write token. `OwnedExtensions.http` is `Option<Guarded<HttpExtension>>`. The `Guarded` wrapper enforces write authority at the type level:

```rust
async fn handle(
    &self,
    payload: &CompletedRequest,
    extensions: &Extensions,
    _ctx: &mut PluginContext,
) -> PluginResult<CompletedRequest> {
    let mut owned = extensions.cow_copy();
    if let Some(token) = &owned.http_write_token {
        if let Some(guarded_http) = owned.http.as_mut() {
            guarded_http.write(token).set_response_header("X-Audit-Plugin", "true");
        }
    }
    PluginResult::modify_extensions(owned)
}
```

A plugin without `write_headers` sees `http_write_token == None` and silently cannot write. The token is the type-system enforcement of the YAML capability. Plugins do not need to check capabilities at runtime.

### 6.3 PluginContext

Every `HookHandler::handle` call receives `&mut PluginContext`:

```rust
pub struct PluginContext {
    pub local_state: HashMap<String, Value>,    // per-plugin, persists across hooks in one request
    pub global_state: HashMap<String, Value>,   // shared across plugins, scoped to one invoke chain
}
```

The plugin's identity (`Uuid`) is tracked externally in `PluginContextTable`, which indexes each plugin's `local_state` by ID.

`local_state` is the cross-hook state mechanism. A plugin that registers against both M1 and M2 stashes per-tool data (a timer, a redaction decision) in `local_state` at M1 and reads it at M2. The embedder threads the `PluginContextTable` returned from M1's `PipelineResult` into M2's `invoke_named` call, and CPEX populates each plugin's `local_state` from the table.

`global_state` is cross-plugin. An identity-resolving plugin at H4 writes `user_id` to `global_state`; downstream plugins read it.

### 6.4 Handler signature

```rust
pub trait HookHandler<H: HookTypeDef>: Plugin + Send + Sync {
    fn handle(
        &self,
        payload: &H::Payload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> impl std::future::Future<Output = H::Result> + Send;
}
```

Plugin authors write `async fn handle(...) -> PluginResult<P>`. Native AFIT means handlers with no `.await` compile to a ready future with no scheduler interaction. Handlers that need to await (a JWKS refresh, an authz RPC, a dynamic policy lookup) just use `.await` inside the body.

The latency budget reflects two plugin shapes:

| Shape | Per-hook cost |
|---|---|
| Sync body (no `.await`) | Single-digit microseconds; equivalent to a direct call. |
| Async body (with `.await`) | Plus the cost of whatever was awaited, plus one boxed future at the `AnyHookHandler` boundary. |

### 6.5 CMF payloads and the tool hooks

Tool hooks reuse CPEX's `MessagePayload` directly. No new Praxis payload type. The MCP gateway filter constructs a `MessagePayload` whose `Message.content` carries a `ContentPart::ToolCall { tool_call_id, name, arguments, .. }` parsed from the JSON-RPC body.

Plugin authors:

```rust
manager.register_handler_for_names::<CmfHook, _>(
    Arc::clone(&plugin),
    config,
    &[
        "praxis.mcp.tool_pre_invoke",
        "praxis.mcp.tool_post_invoke",
    ],
)?;
```

The gateway filter dispatches:

```rust
let (result, _bg) = manager.invoke_named::<CmfHook>(
    "praxis.mcp.tool_pre_invoke",
    message_payload,
    extensions,
    Some(prev_ctx_table),  // None on M1; threaded into M2
).await;
```

Identity flows through `SecurityExtension`, so the plugin sees the same subject Praxis sees at H4 and H7. The MCP entity metadata (tool server ID, registry coordinates) flows through `MCPExtension`.

### 6.6 Mode constraints

Plugin YAML `mode:` must match the hook's interaction class; violations abort startup. Omitted `mode:` falls back to the hook's default. Within a phase, plugins run by ascending `priority:`, then YAML position. Phase execution order follows CPEX's [5-phase model](https://contextforge-org.github.io/contextforge-plugins-framework/docs/execution-modes/).

Interaction class to allowed mode:

| Interaction | Allowed `mode:` values |
|---|---|
| observe | `audit`, `fire_and_forget` |
| mutating | `transform` |
| policy | `sequential`, `concurrent` |

`concurrent` is offered only where plugin ordering is irrelevant (parallel audit lookups that all must agree). Disagreement semantics: deny-wins — if any concurrent policy plugin returns `deny`, the aggregate result is `deny`. The first violation message is preserved as the primary; others are attached to `PipelineResult.errors` for observability. Plugins cannot mutate payload in `concurrent` mode.

### 6.7 Interaction enforcement

After the CPEX executor returns a `PipelineResult`, the call site applies it per class:

| Class | `continue_processing` | `is_denied` | `modified_payload` / `modified_extensions` |
|---|---|---|---|
| observe | proceed | log at error, proceed | discarded |
| mutating | proceed | log at error, proceed | apply payload replacement; apply extension changes via `WriteToken` merge |
| policy | proceed | abort per [§6.11](#611-short-circuit-behavior) | applied in `sequential` only; `concurrent` cannot mutate |

### 6.8 Failure modes and timeouts

Each plugin has `on_error:` (`fail`, `ignore`, `disable`) and `timeout_ms:` (passed through as `tokio::time::timeout`). Defaults:

| Class | Default `on_error` | Default `timeout_ms` |
|---|---|---|
| observe | ignore | 50 |
| mutating | fail | 20 |
| policy | fail | 100 |
| tool hooks (M1, M2)* | fail | 100 |

*Tool hooks override class defaults; JSON-RPC parsing and payload construction justify the higher budget.

`Ignore` and `Disable` failures land in `PipelineResult.errors` as `PluginErrorRecord`. `Fail` failures populate `PipelineResult.violation` and set `continue_processing = false`.

L1 and L4 are reserved in v1, so the sync-dispatch story is deferred. When promoted, they require a dedicated `dispatch_tls_hook_sync` design.

### 6.9 Tighten-only composition

The tighten-only guarantee from [§2.1](#2-goals-and-non-goals) is enforced structurally by CPEX: once any plugin in a sequential or concurrent phase returns `PluginResult::deny(...)`, `PipelineResult.continue_processing` is `false` and no subsequent plugin can revert it. Praxis's built-in security invariants ([§9](#9-security-invariants-and-hook-mapping)) run independently of plugins and enforce all 18 boundaries regardless of plugin decisions.

### 6.10 Mutation surface

Plugins mutate one of:

- **Headers.** Through `Extensions` with `write_headers` capability and `WriteToken`. The executor merges modified extensions back at phase boundaries.
- **Payload.** Through `PluginResult::modify_payload(p)` in `sequential` or `transform` mode. The call site applies the replacement before forwarding.

Field-level write restriction beyond full-payload replacement is not enforced in v1. The cost is that a misbehaving plugin can rewrite parts of a payload it should not touch. Mitigations: plugin provenance is the operator's responsibility (the trust model is the same as for built-in code). Future tightening will use type-system enforcement (`Sealed<T>`, `MutabilityTier`) rather than a runtime policy mechanism.

### 6.11 Short-circuit behavior

| Hook | What "short-circuit" does |
|---|---|
| S1 | `run_server` returns `Err`, non-zero exit before any listener binds. |
| H4, H7 | `send_rejection(session, rejection)` emits a response from the plugin violation. |
| H9 | `err.set_retry(false)`. Suppresses the retry; built-in idempotency check still applies independently. |
| H11 | Replace upstream response with the plugin-provided response; downstream sees the sanitized version. |
| M1 | MCP gateway filter emits a JSON-RPC error response without contacting upstream. |
| M2 | Response body is replaced with the plugin-provided body before forwarding to the client. |

## 7. Plugin authoring and loading

Two coexisting loading paths. Static loading is the primary v1 path. Dynamic loading is in the spec; it lands as a parallel phase without changing the static-plugin surface.

### 7.1 Static plugins (primary v1 path)

A static plugin is a Rust crate depending on `cpex-sdk` (or `cpex-core` directly for in-tree plugins). It implements `Plugin` and one or more `HookHandler<H>` impls. It compiles into the Praxis binary as a regular workspace member or external crate dependency.

Registration:

```rust
manager.register_handler::<H, _>(Arc::clone(&plugin), config)?;
// or, for one plugin handling many CMF hook names:
manager.register_handler_for_names::<CmfHook, _>(
    Arc::clone(&plugin),
    config,
    &["praxis.mcp.tool_pre_invoke", "praxis.mcp.tool_post_invoke"],
)?;
```

Trust boundary: runs with Praxis process privileges. Plugin provenance is the operator's responsibility. Cross-version compatibility: plugin and Praxis are built from the same workspace lockfile, so Rust ABI instability does not apply.

### 7.2 Dynamic plugins (forthcoming, parallel phase)

A dynamic plugin is a Rust crate compiled to `cdylib`, loaded at startup via `libloading` (which uses `dlopen` underneath). The plugin exports a registration entry point:

```rust
#[no_mangle]
pub extern "C" fn praxis_plugin_register(
    host: &PluginManager,
) -> Result<(), Box<PluginError>>
```

Inside that function, the plugin constructs its own `TypedHandlerAdapter<H, P>` and registers via `PluginManager::register_raw::<H>(plugin, config, handler)` (CPEX §5.1). The `register_raw` API already exists in cpex-core; the missing piece is the `cpex-hosts::native` loader.

YAML wires dynamic plugins via a `dylib` factory kind:

```yaml
plugins:
  - name: sni-filter
    kind: dylib
    hooks: [praxis.tls.client_hello]
    config:
      path: /opt/praxis/plugins/libsnifilter.so
```

The `dylib` factory is registered by Praxis at startup when the dynamic-loading phase ships. Trust boundary: same as static (process privileges). Cross-version: plugin and host must be built with the same `rustc` and the same `cpex-core` version; the loader rejects mismatched ABIs at startup with a clear error. Panic isolation: every `AnyHookHandler::invoke` is wrapped in `catch_unwind` at the host adapter, same rule the FFI path already follows.

When dynamic loading ships, no migration is required for static plugins. The registration call shape inside the plugin's entry point is identical to what a static plugin already does.

### 7.3 Future hosts

Out of scope for v1, listed so authors know what to expect:

- **WASM.** Waits on `cpex-hosts::wasm`. Wasmtime sandbox, fuel-bounded execution.
- **Python.** Not supported in Praxis for latency reasons. CPEX has a PyO3 host; Praxis will not enable it.
- **Sidecar / UDS gRPC.** Waits on `cpex-hosts::sidecar`. Reserved for async non-policy hooks where 50 to 500 microsecond IPC is acceptable.

Each enters via an additive factory kind. None requires changes to the static-plugin authoring model.

## 8. Configuration

### 8.1 YAML surface

`praxis.yaml` gains one top-level section, `plugins:`. The `routes:` section gains an optional `body_mode:` block (§4.3). All other sections are unchanged. A comprehensive example covering all hook families is in [Appendix B](#appendix-b-configuration-example).

```yaml
plugins:
  - name: ext-authz
    kind: builtin/ext-authz
    hooks: [praxis.http.pre_upstream_select]
    mode: sequential
    priority: 10
    on_error: fail
    capabilities: [read_subject, read_headers]
    config:
      grpc_url: unix:///var/run/authz.sock
      cache_ttl_ms: 5000

  - name: mcp-tool-authz
    kind: builtin/mcp-tool-authz
    hooks: [praxis.mcp.tool_pre_invoke, praxis.mcp.tool_post_invoke]
    mode: sequential
    on_error: fail
    capabilities: [read_subject, read_labels]
    config:
      policy_file: /etc/praxis/mcp-tool-policy.yaml

routes:
  - path_prefix: /mcp/
    cluster: mcp-backend
    body_mode:
      request:
        stream_buffer:
          max_bytes: 65536
      response:
        stream_buffer:
          max_bytes: 262144
```

### 8.2 Field semantics

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Unique plugin identifier; used in logs and metrics. |
| `kind` | yes | Factory key; looked up in `PluginFactoryRegistry`. `builtin/<name>` for in-tree plugins, `dylib` for dynamic (when shipped). |
| `version` | no | Advisory string, logged at startup. |
| `hooks` | yes | One or more hook names from [§5](#5-hook-catalog-v1). |
| `mode` | no | CPEX mode. Default from the catalog; validated against interaction class. |
| `priority` | no | Ordering within a phase; default 100. |
| `on_error` | no | Default per class (see [§6.8](#68-failure-modes-and-timeouts)). |
| `timeout_ms` | no | Default per class. |
| `capabilities` | no | Extension capabilities granted to this plugin. |
| `config` | no | Opaque plugin-specific JSON; handed to `Plugin::initialize`. |

A plugin that needs different modes per hook registers twice with different `mode:` and the same `name`. CPEX accepts this.

### 8.3 Startup validation

Startup fails when:

- Two plugins share a `name`.
- A `hooks:` entry names a hook that does not exist in the [catalog](#5-hook-catalog-v1).
- A `hooks:` entry names a reserved hook. The error names the hook and points at the staged-rollout section.
- A `mode:` is not allowed for the hook's interaction class.
- A plugin's `Plugin::initialize` returns `Err` and `on_error: fail`.
- An S1 plugin rejects the config.
- A dynamic plugin's ABI version does not match the host (when dynamic loading ships).

Unknown fields under a plugin entry are rejected, consistent with Praxis's `deny_unknown_fields` convention.

### 8.4 `insecure_options` interplay

Plugins observe config, not mutate it. An S1 plugin can reject startup when any `insecure_*` flag is set. The example above uses this to enforce a production-hardening policy.

### 8.5 Environment interpolation

Praxis does not yet support `${ENV_VAR}` interpolation in YAML config. The hook system requires this for `plugins[].config` secrets. Implementation adds a pre-parse substitution pass to `core/src/config/mod.rs` before `serde_yaml::from_str`, resolving `${VAR}` patterns against `std::env::var`. This ships as part of Phase 1 (foundation). Secrets flow through env vars, not YAML literals.

### 8.6 Observability

Three metric series per plugin-hook pair:

```
praxis_hook_invocations_total{plugin, hook, outcome}    continue | denied | error | timeout | soft_error
praxis_hook_duration_seconds{plugin, hook}              histogram
praxis_hook_last_error_timestamp_seconds{plugin, hook}
```

Aggregate counters:

```
praxis_hook_fast_path_hits_total
praxis_hook_fast_path_misses_total
praxis_plugins_loaded_total{kind}
praxis_plugins_disabled_total{reason}
```

Tracing integrates with Praxis's existing `tracing` output. Each dispatch emits a `trace!` at invocation and a `debug!` at result. The request span gains a `plugins.invoked` counter plus a `plugins.rejected_by` attribute populated on policy denial.

Plugin-owned metrics surface under `praxis_plugin_user_<plugin_name>_<metric_name>` via `PluginContext::metadata`.

## 9. Security invariants and hook mapping

### 9.1 Built-in boundary catalogue

Praxis enforces the following invariants today. The hook system lets plugins strengthen any without silently weakening any. Escape hatches default off.

| # | Boundary | Enforced at | Escape hatch |
|---|---|---|---|
| 1 | Refuse UID 0 | `server.rs::check_root_privilege` | `allow_root` |
| 2 | TLS key perms ≤ 0600 (advisory) | `server.rs::warn_insecure_key_permissions` | (warn) |
| 3 | Host header present, single-valued | `request_filter/validation.rs` (RFC 9112 §3.2) | none |
| 4 | Max-Forwards TRACE redaction | same | none |
| 5 | Request hop-by-hop strip | `handler/hop_by_hop.rs` | none |
| 6 | Response hop-by-hop strip | same | none |
| 7 | Via header injection | `handler/via.rs` | none |
| 8 | Rewritten path validation | `handler/upstream_request.rs` | none |
| 9 | Upstream SNI required for TLS | `handler/upstream_peer.rs::derive_sni` | `allow_tls_without_sni` |
| 10 | Idempotent-only retries, max 3 | `handler/mod.rs::handle_connect_failure` | none |
| 11 | Body size ceilings | `filter/src/pipeline/mod.rs::apply_body_limits` | `allow_unbounded_body` |
| 12 | Pipeline ordering validation | `server/src/pipelines.rs::validate_pipeline` | `skip_pipeline_validation` |
| 13 | Health probe allowlist | `config/validate/cluster/endpoints.rs` | `allow_private_health_checks` |
| 14 | Admin not on 0.0.0.0 / :: | `config/validate/listener/address.rs` | `allow_public_admin` |
| 15 | Duplicate SNI cert rejection | `tls/setup/sni.rs::build_sni_resolver` | none |
| 16 | SNI parser rejects IP literals | `tls/sni.rs` (RFC 6066 §3) | none |
| 17 | Cert reload fail-safe | `tls/reload.rs::reload` | none |
| 18 | YAML ingest safety | `config/parse.rs::check_yaml_safety` | none |

### 9.2 Hook mapping

| # | Boundary | Hook | Status | Direction |
|---|---|---|---|---|
| 1 | Refuse UID 0 | S1 | v1 | observe + startup veto |
| 2 | TLS key perms | S1 | v1 | observe + startup veto |
| 3 | Host validation | H4 | v1 | observe (non-bypassable built-in; H4 can add policy) |
| 4 | TRACE redaction | — | — | built-in only; no hook needed |
| 5 | Request hop-by-hop strip | H10 (post-strip) | reserved | observe |
| 6a | Response hop-by-hop strip | H11 | v1 | observe |
| 6b | Response hop-by-hop strip | H12 | reserved | observe |
| 7a | Via injection | H10 | reserved | observe |
| 7b | Via injection | H12 | reserved | observe |
| 8 | Rewritten path | H10 | reserved | observe |
| 9 | Upstream SNI required | H7 | v1 | tighten |
| 10 | Idempotent-only retries | H9 | v1 | tighten (deny suppresses retry) |
| 11a | Body size ceilings | H6 | reserved | observe |
| 11b | Body size ceilings | H13 | reserved | observe |
| 12 | Pipeline ordering | S2 | reserved | tighten |
| 13 | Health probe allowlist | S1 | v1 | tighten |
| 14 | Admin not public | S1 | v1 | tighten |
| 15a | Duplicate SNI cert | S2 | reserved | observe |
| 15b | Duplicate SNI cert | L2 | reserved | observe |
| 16 | SNI IP literals | L1 | reserved | observe |
| 17 | Cert reload fail-safe | L3 | v1 | observe + alert |
| 18 | YAML ingest safety | S1 | v1 | observe |

Reducing the v1 hook surface does not weaken any invariant. Built-in enforcement remains. Observer hooks for the reserved invariants are deferred, not removed.

## 10. Staged rollout

Each phase is independently shippable. Phases are ordered by priority to the MCP gateway use case.

**Phase 1, foundation.** `praxis-hooks` crate with `cpex-core` pinned against a git commit. Hook type definitions for the 12 registered names plus the reserved set. `PluginManager` wired into `run_server`. Environment variable interpolation in `plugins:` config. S1 `praxis.startup.config_loaded` registered as the first fail-closed gate. Acceptance: S1 plugin rejects a bad config and aborts startup; `praxis_hook_*` metrics emit; CI green with the new crate.

**Phase 2, MCP tool hooks.** Route-driven body mode (§4.3). MCP gateway filter at `filter/src/builtins/http/mcp/` (§4.4). M1 and M2 registered against `MessagePayload`. `mcp-tool-authz` as the reference plugin. Acceptance: an MCP `tools/call` plugin denial returns a JSON-RPC error to the client without contacting upstream; argument and response redaction work end-to-end; non-`tools/call` MCP methods (`ping`, `initialize`) do not allocate body buffers on the route.

**Phase 3, lifecycle observers.** S4, L3, H14. `cert-rotation-alert` and `audit-log` as compiled-in plugins. Acceptance: rotation events visible end-to-end; audit-log plugin at 50k RPS with under 1% tail-latency impact.

**Phase 4, HTTP policy and identity.** H4, H7, H9, H11, I1, I2. Tighten-only `PluginViolation`. Identity hooks (I1, I2) route to CPEX `IdentityResolve` and `TokenDelegate` execution paths; `ext-authz` reference plugin. Acceptance: ext-authz denies within budget; identity resolution seals `SecurityExtension` before pipeline; delegation enforces scope narrowing; a plugin can deny to suppress retry on any request but cannot force a retry on a non-idempotent request (the built-in check applies independently); integration test verifies tighten-only behavior.

**Phase 5+, future work.** Each item below ships when a concrete consumer warrants it:

- **Reserved hook promotions.** TCP family, body family (H6, H13), sync TLS (L1, L4), mutating HTTP (H10, H12). Each promotion is its own PR with a design note, a consumer plugin, and an integration test.
- **Dynamic loading.** `dylib` factory backed by `libloading` and `register_raw`. Ships when cpex-core's `register_raw` story stabilizes and `cpex-hosts::native` lands. Static-plugin spec does not change.
- **Protocol-native service.** `McpProxy` protocol-native service (§4.2). Triggered if Phase 2's filter-layer parsing becomes a bottleneck or abstraction inversion bites in practice. Hook names and plugin code do not change; the dispatch site moves from the gateway filter to the protocol-native service.
- **Broader protocol-semantic hooks.** A2A task hooks and LLM input/output, gated on demand. Same `MessagePayload` shape, same registration pattern.

## 11. Open questions

1. **CPEX version pinning.** cpex-core is unreleased. Pin against a git commit or dev tag until cpex-core ships a tagged release. Preference: pin tightly, refresh deliberately.

2. **Per-plugin CPU accounting.** Tokio has no cheap per-task accounting. A `sequential` plugin within its timeout but burning CPU stays invisible. Options: process-level quota, push expensive plugins to `fire_and_forget`, require WASM for untrusted plugins when the host ships. Revisit after Phase 2.

3. **Body-chunk back-pressure.** When H6 and H13 are promoted, per-chunk deadlines plus a per-request cumulative budget are likely both needed. A slow plugin stalls HTTP/1.1 connections and HTTP/2 streams. Confirm in the H6 / H13 promotion design note.

4. **JSON-RPC batch requests.** Resolved: tool hooks fire per call within a batch; batch identity (array index, batch request ID) is carried in `PluginContext::local_state`. Per-call denial replaces only that call's response. See §4.4 step 5.

5. **SSE response streaming for M2.** Tool responses may stream via SSE. v1 buffers the response or skips M2 on streaming responses, with the operator's `body_mode:` declaration as the explicit knob. Per-chunk M2 belongs in the protocol-native service.

6. **Route-mode interaction with body ceilings.** Route-declared `body_mode:` participates in `apply_body_limits`. Confirm in Phase 2 that an unbounded `StreamBuffer { max_bytes: None }` at the route level interacts cleanly with `allow_unbounded_body`.

7. **ABI compatibility for dynamic loading.** Pin scheme to be decided: lockfile sharing, `=` version requirements, or `abi_stable`. Decision deferred until dynamic loading ships (Phase 5+).

8. **When does a reserved hook get promoted?** Suggested gate: a written design note, a concrete consumer plugin, and an integration test.

## Appendix A: Full hook catalog and payload sketches

The complete hook catalog including reserved hooks. The loader rejects subscription to reserved hooks until they are promoted (gate: design note, consumer plugin, integration test).

### Startup

| ID | Name | Interaction | Default mode | Status | Call site |
|---|---|---|---|---|---|
| S1 | `praxis.startup.config_loaded` | policy | sequential | v1 | `server.rs` after `Config::load` |
| S2 | `praxis.startup.pipelines_built` | policy | sequential | reserved | after `resolve_pipelines` |
| S3 | `praxis.startup.listeners_bound` | observe | audit | reserved | before `server.run_forever` |
| S4 | `praxis.startup.shutdown` | observe | audit | v1 | on SIGTERM path |

### TLS

| ID | Name | Interaction | Default mode | Status | Call site |
|---|---|---|---|---|---|
| L1 | `praxis.tls.client_hello` | policy | sequential | reserved | `tls/src/setup/sni.rs` (sync) |
| L2 | `praxis.tls.cert_resolved` | observe | audit | reserved | same, after successful match (sync) |
| L3 | `praxis.tls.cert_reloaded` | observe | audit | v1 | `tls/src/reload.rs::reload` |
| L4 | `praxis.tls.mtls_client_cert` | policy | sequential | reserved | rustls `ClientCertVerifier` (sync) |

### TCP (all reserved)

| ID | Name | Interaction | Default mode | Status | Call site |
|---|---|---|---|---|---|
| T1 | `praxis.tcp.accept` | policy | sequential | reserved | `protocol/src/tcp/` accept loop |
| T2 | `praxis.tcp.sni_peeked` | policy | sequential | reserved | after SNI peek |
| T3 | `praxis.tcp.pre_connect` | policy | sequential | reserved | before upstream connect |
| T4 | `praxis.tcp.upstream_selected` | observe | audit | reserved | after `build_peer` |
| T5 | `praxis.tcp.upstream_connected` | observe | audit | reserved | after upstream handshake |
| T6 | `praxis.tcp.session_end` | observe | fire_and_forget | reserved | on session close |
| T7 | `praxis.tcp.post_disconnect` | observe | fire_and_forget | reserved | after cleanup |

### HTTP

| ID | Name | Interaction | Default mode | Status | Call site |
|---|---|---|---|---|---|
| H4 | `praxis.http.pre_request_pipeline` | policy | sequential | v1 | `request_filter/mod.rs` before pipeline |
| H5 | `praxis.http.post_request_pipeline` | policy | sequential | reserved | after `run_pipeline` |
| H6 | `praxis.http.request_body_chunk` | mutating | transform | reserved | `request_body_filter.rs` |
| H7 | `praxis.http.pre_upstream_select` | policy | sequential | v1 | before `upstream_peer::execute` |
| H8 | `praxis.http.upstream_selected` | observe | audit | reserved | after `build_peer` |
| H9 | `praxis.http.upstream_connect_failure` | policy | sequential | v1 | `handle_connect_failure` |
| H10 | `praxis.http.pre_upstream_request_write` | mutating | transform | reserved | after strip + rewrite + Via |
| H11 | `praxis.http.upstream_response_header` | policy | sequential | v1 | after hop-by-hop strip |
| H12 | `praxis.http.post_response_pipeline` | mutating | transform | reserved | after response filters, before Via |
| H13 | `praxis.http.response_body_chunk` | mutating | transform | reserved | `response_body_filter.rs` |
| H14 | `praxis.http.session_logged` | observe | fire_and_forget | v1 | after `logging_cleanup` |

### Identity

| ID | Name | Interaction | Default mode | Status | Call site |
|---|---|---|---|---|---|
| I1 | `praxis.identity.resolve` | policy | sequential | v1 | `request_filter/mod.rs` at H4, before pipeline |
| I2 | `praxis.identity.delegate` | mutating | transform | v1 | after route resolution, at H10 site |

### Protocol-semantic

| ID | Name | Interaction | Default mode | Status | Payload |
|---|---|---|---|---|---|
| M1 | `praxis.mcp.tool_pre_invoke` | policy | sequential | v1 | `MessagePayload` |
| M2 | `praxis.mcp.tool_post_invoke` | mutating | transform | v1 | `MessagePayload` |

Reserved protocol-semantic hooks (all use `MessagePayload`):

```
praxis.mcp.prompt_pre_fetch
praxis.mcp.prompt_post_fetch
praxis.mcp.resource_pre_fetch
praxis.mcp.resource_post_fetch
praxis.a2a.task_created
praxis.a2a.task_updated
praxis.a2a.task_completed
praxis.llm.input
praxis.llm.output
```

### Payload sketches

Payload sketches below use `&'a` borrows to show logical data flow. Concrete implementations use owned types (`Arc<str>`, `Bytes`, cloned headers) to satisfy `PluginPayload: Clone + Send + Sync + 'static`. The borrow notation is for readability; the implementation clones at the call-site boundary.

```rust
// --- v1 payloads ---

pub struct ConfigLoadedPayload<'a> { pub config: &'a Config }

pub struct ShutdownPayload { pub deadline: Instant }

pub struct CertReloadedPayload<'a> {
    pub cert_path: &'a str,
    pub outcome: Result<CertFingerprint, &'a TlsError>,
}

pub struct HttpHookCtx<'a> {
    pub client_addr: Option<IpAddr>,
    pub client_http_version: http::Version,
    pub listener: &'a str,
    pub request_start: Instant,
    pub request_id: Option<&'a str>,
    pub cluster: Option<&'a str>,
    pub upstream: Option<&'a Upstream>,
    pub rewritten_path: Option<&'a str>,
    pub retries: u32,
}

pub struct HttpRequestPipelinePayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub request: &'a praxis_filter::Request,
    pub pre_read_body: Option<&'a [Bytes]>,
}

pub struct UpstreamConnectFailurePayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub err: &'a pingora_core::Error,
    pub retry_count: u32,
    pub is_idempotent: bool,
}

pub struct UpstreamResponseHeaderPayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub upstream_response: &'a pingora_http::ResponseHeader,
}

pub struct SessionLoggedPayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub status: http::StatusCode,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub duration: Duration,
    pub outcome: SessionOutcome,
}

// Identity hooks route to CPEX IdentityResolve / TokenDelegate framework execution paths.
// Payloads are defined by cpex-core; Praxis passes them through.
// IdentityResolve payload: raw credentials + request context → populates SecurityExtension slots.
// TokenDelegate payload: sealed identity + audience + requested scopes → mints delegated token.

// Tool hooks reuse cpex_core::cmf::MessagePayload directly.

// --- Praxis-defined extensions ---

/// MCP entity metadata for tool hook dispatch (Praxis-defined, not CPEX-defined).
pub struct MCPExtension {
    pub tool_server_id: Option<Arc<str>>,
    pub registry_uri: Option<Arc<str>>,
    pub protocol_version: Option<Arc<str>>,
}

// --- Reserved payloads ---

pub struct PipelinesBuiltPayload<'a> {
    pub config: &'a Config,
    pub pipelines: &'a ListenerPipelines,
    pub health_registry: &'a HealthRegistry,
}

pub struct ListenersBoundPayload<'a> { pub listeners: &'a [ListenerBinding] }

pub struct ClientHelloPayload<'a> {
    pub sni: Option<&'a str>,
    pub cipher_suites: &'a [u16],
    pub alpn_protocols: &'a [&'a [u8]],
    pub remote_addr: IpAddr,
    pub listener: &'a str,
}

pub struct CertResolvedPayload<'a> {
    pub sni: Option<&'a str>,
    pub cert_fingerprint: CertFingerprint,
    pub listener: &'a str,
}

pub struct MtlsClientCertPayload<'a> {
    pub chain: &'a [CertificateDer<'a>],
    pub sni: Option<&'a str>,
    pub remote_addr: IpAddr,
}

pub struct TcpConnInfo<'a> {
    pub remote_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub listener: &'a str,
    pub accepted_at: Instant,
}

pub struct TcpAcceptPayload<'a> { pub conn: TcpConnInfo<'a> }

pub struct TcpSniPeekedPayload<'a> {
    pub conn: TcpConnInfo<'a>,
    pub sni: Option<&'a str>,
    pub peeked_bytes: &'a [u8],
}

pub struct TcpSessionEndPayload<'a> {
    pub conn: TcpConnInfo<'a>,
    pub upstream_addr: Option<&'a str>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration: Duration,
    pub close_reason: TcpCloseReason,
}

pub struct PreUpstreamRequestWritePayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub upstream_request: &'a pingora_http::RequestHeader,
}

pub struct BodyChunkPayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub chunk: Option<&'a Bytes>,
    pub end_of_stream: bool,
}
```

## Appendix B: Configuration example

A `plugins:` block covering all 10 registered hook families, plus the matching `routes:` body-mode declaration:

```yaml
plugins:
  - name: prod-hardening
    kind: builtin/insecure-options-guard
    hooks: [praxis.startup.config_loaded]
    mode: sequential
    on_error: fail
    config:
      forbid_flags:
        - allow_root
        - allow_public_admin
        - allow_unbounded_body
        - skip_pipeline_validation
        - allow_tls_without_sni
        - allow_private_health_checks

  - name: graceful-drain
    kind: builtin/graceful-drain
    hooks: [praxis.startup.shutdown]
    mode: audit
    on_error: ignore
    config:
      drain_timeout_ms: 5000

  - name: cert-rotation-alert
    kind: builtin/cert-rotation-alert
    hooks: [praxis.tls.cert_reloaded]
    mode: audit
    on_error: ignore
    config:
      pagerduty_routing_key: ${PD_KEY}

  - name: ext-authz
    kind: builtin/ext-authz
    hooks:
      - praxis.http.pre_request_pipeline
      - praxis.http.pre_upstream_select
    mode: sequential
    priority: 10
    on_error: fail
    capabilities: [read_subject, read_headers]
    config:
      grpc_url: unix:///var/run/authz.sock
      cache_ttl_ms: 5000

  - name: retry-policy
    kind: builtin/retry-policy
    hooks: [praxis.http.upstream_connect_failure]
    mode: sequential
    on_error: fail
    config:
      methods_no_retry: [POST, PUT, PATCH]

  - name: response-policy
    kind: builtin/response-policy
    hooks: [praxis.http.upstream_response_header]
    mode: sequential
    priority: 50
    on_error: fail
    capabilities: [write_headers]
    config:
      strip_response_headers: [Server, X-Powered-By]

  - name: audit-log
    kind: builtin/audit-log
    hooks: [praxis.http.session_logged]
    mode: fire_and_forget
    on_error: ignore
    config:
      sink: https://audit.internal/v1/events

  - name: mcp-tool-authz
    kind: builtin/mcp-tool-authz
    hooks:
      - praxis.mcp.tool_pre_invoke
      - praxis.mcp.tool_post_invoke
    mode: sequential
    priority: 20
    on_error: fail
    capabilities: [read_subject, read_labels]
    config:
      policy_file: /etc/praxis/mcp-tool-policy.yaml

routes:
  - path_prefix: /mcp/
    cluster: mcp-backend
    body_mode:
      request:
        stream_buffer:
          max_bytes: 65536
      response:
        stream_buffer:
          max_bytes: 262144

  - path_prefix: /api/
    cluster: api-backend
```
