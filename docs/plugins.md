# Praxis Hook System and Plugin Support

Status: draft

This document specifies the hook system and plugin runtime for Praxis. Hooks complement the existing `HttpFilter` / `TcpFilter` surface with typed, capability-gated plugins that observe or enforce policy at well-defined lifecycle points. The runtime is CPEX (ContextForge Plugin Extensibility), embedded in-process.

## 1. Scope

2. [Goals and Non-Goals](#2-goals-and-non-goals).
3. [Integration architecture](#3-integration-architecture).
4. [Layering model](#4-layering-model).
5. [Hook catalog: startup, TLS, TCP, HTTP lifecycle](#5-hook-catalog-lifecycle-hooks).
6. [Typed payloads per hook](#6-hook-payloads) (full signatures in [Appendix A](#appendix-a-payload-type-sketches)).
7. [Dispatch semantics: phase scheduling, failure modes, timeouts, tighten-only composition](#7-dispatch-semantics).
8. [Plugin ABI](#8-plugin-abi).
9. [YAML configuration](#9-configuration) (full example in [Appendix B](#appendix-b-configuration-examples)).
10. [Observability](#10-observability), [security boundary mapping](#11-security-invariants-and-hook-mapping), [staged rollout](#12-staged-rollout), [open questions](#13-open-questions).

Out of scope:

- CPEX internals (payload dispatch, capability gating, CMF extension format). See the CPEX spec.
- Protocol-semantic hooks for MCP, A2A, or LLM payloads. [How protocol-semantic hooks ship later](#43-how-protocol-semantic-hooks-ship-later) explains why they are deferred and where they belong instead.
- Hot-swapping plugins at runtime. Plugins are loaded at startup and released on shutdown.
- The Python plugin host. CPEX supports it; Praxis does not, for latency reasons.

## 2. Goals and Non-Goals

### 2.1 Goals

- **A second extension surface.** `HttpFilter` / `TcpFilter` handle per-request transformation well. They are insufficient for lifecycle observation (TLS handshake, connect, session end), policy enforcement at security boundaries the pipeline does not expose, and out-of-process dispatch. Hooks fill those gaps.
- **A common runtime for extensibility.** CPEX is the runtime; Praxis is a host. Plugins that target Praxis hooks can also target other hosts where payload types overlap.
- **Latency-budgeted.** Hooks run on the request hot path. Native plugin overhead must stay in single-digit microseconds per hook; WASM plugins under 100 µs. [Failure modes and timeouts](#73-failure-modes-and-timeouts) enumerates enforceable budgets.
- **Tighten-only composition.** Policy hooks may strengthen any of the 18 security boundaries catalogued in [Security Invariants and Hook Mapping](#11-security-invariants-and-hook-mapping). They must not silently weaken any. The dispatcher enforces this structurally (see [Tighten-only composition](#74-tighten-only-composition)).
- **Zero cost when unused.** Deployments without a `plugins:` section in YAML pay a single `AtomicBool` check at each call site. No dispatcher traversal, no allocations.

### 2.2 Non-Goals

- **Replacing filters.** Filters remain the right abstraction for per-request transformation. Hooks wrap filters, not the other way around.
- **Hot reload.** Startup-only loading keeps the trust model simple. Reload-without-restart is deferred.
- **Arbitrary cross-hook ordering.** Within a hook point, plugins run in CPEX's 5-phase order at configured priority. Across hook points, order is set by the request lifecycle.
- **Semantic payload parsing in the HTTP filter layer.** See [How protocol-semantic hooks ship later](#43-how-protocol-semantic-hooks-ship-later).

## 3. Integration Architecture

### 3.1 CPEX as runtime, Praxis as host

Praxis embeds the CPEX `PluginManager` in-process. A plugin call is a function call, not an IPC hop. CPEX provides the typed dispatcher, phase executor, payload policy enforcement, and host loaders (`native`, `wasm`). Praxis provides lifecycle call sites, payload construction, and the tighten-only composition monoid.

### 3.2 Crate layout

A single new crate joins the Praxis workspace.

```
praxis/
  hooks/                          NEW: praxis-hooks crate
    src/
      lib.rs                      register_hooks!, public types
      payloads/{startup,tls,tcp,http}.rs
      dispatcher/{mod,http,tcp,tls,tighten}.rs
      config.rs                   YAML → CPEX config adapter
      metrics.rs                  praxis_hook_* emitters
      policy.rs                   HookPayloadPolicy builders
  server/                         depends on praxis-hooks
  protocol/                       depends on praxis-hooks
  tls/                            depends on praxis-hooks
```

Workspace dependencies:

```toml
cpex-core  = { version = "0.2", default-features = false }
cpex-hosts = { version = "0.2", default-features = false,
               features = ["native", "wasm"] }
cpex-sdk   = { version = "0.2" }   # dev-dep, for test plugins only
```

The `plugins-native` and `plugins-wasm` Cargo features are on by default. Building with `--no-default-features --features plugins-native` produces a binary that rejects WASM plugins at load time.

### 3.3 Lifecycle integration

The `PluginManager` is owned by `server::run_server`, built after pipelines are resolved and before `server.run_forever()`.

```
server/src/server.rs::run_server
  enforce_root_check
  warn_insecure_key_permissions
  build_health_registry
  resolve_pipelines
  HookDispatcher::from_config(&config)            NEW
    register_all_praxis_hook_types                (HookTypeDefs)
    load_plugins_from_config
    validate_subscriptions
    run S1 on_config_loaded                       (fail-closed)
  PingoraServerRuntime::new(..., dispatcher)
  PingoraHttp.register(..., dispatcher)
  PingoraTcp.register(..., dispatcher)
  run S3 on_listeners_bound                       (fail-open)
  server.run_forever()
```

Protocol handlers receive the dispatcher as `Arc<HookDispatcher>`, parallel to how they receive `Arc<FilterPipeline>` today. A `None` dispatcher (no `plugins:` section) collapses every call site to a single `Option::is_some()` branch.

### 3.4 Call-site contract

Every call site in the [hook catalog](#5-hook-catalog-lifecycle-hooks) must:

1. Fast-path check `dispatcher.is_enabled(HOOK_ID)`: a compile-time-indexed `[AtomicBool; 29]`.
2. If enabled, build the typed payload from local context.
3. Invoke via `dispatcher.invoke::<HookId>(payload, ctx).await`, or the sync variant for L1 and L4.
4. Apply the returned `PipelineResult` per the hook's interaction class (see [Interaction enforcement](#72-interaction-enforcement)).
5. Emit the per-site metric (see [Observability](#10-observability)).

Call sites use the `praxis_hooks::invoke_hook!` macro to keep boilerplate out of the request path.

### 3.5 What CPEX provides

| CPEX feature | Praxis usage |
|---|---|
| `Plugin` trait (lifecycle) | Startup and shutdown of plugin-owned resources. |
| `HookTypeDef` | Praxis hook types, zero-cost borrow dispatch for native plugins. |
| `HookHandler<H>::handle` | The user-visible plugin surface. |
| `PluginRef.trusted_config` | Praxis reads priority, mode, and capabilities from the loader, never from plugin-reported values. |
| Plugin executor | Plugin [dispatching modes](#71-phase-selection). |
| `HookPayloadPolicy` | Declares field-level writability per hook (see [HookPayloadPolicy](#75-hookpayloadpolicy)). |
| `OnError` | Surfaced verbatim in YAML: `fail` / `ignore` / `disable`. |
| Capability gating on extensions | Reserved for v2 (see [Extensions](#65-extensions-reserved-for-v2)). |

Praxis does not rely on CPEX `SessionStore` (no cross-request plugin state in v1) nor on CPEX's own route/policy config loader.

## 4. Layering Model

The hardest design question for this system is where content-aware logic lives. One approach is to dispatch MCP, A2A, and LLM hooks from inside a single `HttpFilter`. That choice has two costs large enough to warrant an explicit layering model.

### 4.1 Why content hooks do not belong in `HttpFilter`

**Cost 1: the streaming model collapses.** Praxis ranks body modes `Buffer > StreamBuffer > SizeLimit > Stream` precisely so that streaming stays the default. A filter that forces `BodyMode::Buffer { max_bytes: 1 MiB }` on every request promotes the entire listener to buffered mode, adding per-request latency equal to upstream-body-arrival time and up to 1 MiB of residency per in-flight request. A feature touched by a narrow minority of requests should not pay this cost on every request.

**Cost 2: abstraction inversion.** An `HttpFilter` parsing JSON-RPC method names and dispatching per-tool hooks bakes protocol knowledge into the HTTP layer. That is the wrong home for it. The HTTP layer should know headers, methods, URIs, and bodies-as-bytes. Protocol semantics belong in whatever component routes the protocol.

### 4.2 Two hook categories, one deferred

**Lifecycle hooks (this spec).** Startup, TLS, TCP, and HTTP lifecycle points. Operate on HTTP and TCP primitives: methods, URIs, headers, client addresses, TLS info, upstream selection, connect failures, response headers, byte counters. Header-level identity and authorization (JWT decoding, DPoP, external authz) fit naturally here: they attach to H2, H4, H7, or H10 and read or inject headers without parsing bodies. Body access is opt-in per plugin via H6 and H13 and participates in the existing `BodyCapabilities` budget.

**Protocol-semantic hooks (deferred).** MCP `tools/call`, A2A tasks, LLM inputs and outputs, prompt and resource fetches. These require parsing a structured body into a protocol-typed message before they can fire. They belong in a protocol-native host that parses once during routing, not in an HTTP filter that buffers speculatively. This spec names no such hooks. [How protocol-semantic hooks ship later](#43-how-protocol-semantic-hooks-ship-later) describes the path.

### 4.3 How protocol-semantic hooks ship later

Protocol-semantic hooks are unblocked when Praxis grows protocol-native proxy services peered with `ProxyHttp`. Plausible shapes:

- An `McpProxy` service recognizes JSON-RPC over HTTP POST, parses methods and parameters once, and dispatches `praxis.mcp.tool_pre_invoke` / `praxis.mcp.tool_post_invoke` from inside the service loop. Bodies are buffered only for methods known to carry semantic payloads (`tools/call`, `prompts/get`, `resources/read`). Methods like `ping` or `initialize` stream through.
- An `A2aProxy` service models the task lifecycle and dispatches `praxis.a2a.task_created`, `_updated`, `_completed`.
- An LLM-aware service (OpenAI-compatible or Bedrock-compatible) dispatches `praxis.llm.input` and `praxis.llm.output` with proper streaming semantics for SSE response bodies.

Each of these would register its own `HookTypeDef`s with the same CPEX dispatcher Praxis already owns. Plugins that target MCP or A2A today can continue to target them tomorrow without code changes; only the host module changes. Until those services land, protocol-semantic hook names are reserved (namespace `praxis.mcp.*`, `praxis.a2a.*`, `praxis.llm.*`) but unregistered.

This split keeps the spec shippable, the hot path streaming, and the semantic surface evolvable.

## 5. Hook Catalog (lifecycle hooks)

### 5.1 Conventions

- **ID** is a stable short identifier: `S` startup, `L` TLS, `T` TCP, `H` HTTP. IDs are stable across the API lifetime; payload types evolve under semver.
- **Name** is the string CPEX registers under and the value operators write in YAML `subscribe:` blocks.
- **Interaction** is `observe`, `mutating`, or `policy`, mapped to phases in [Dispatch Semantics](#7-dispatch-semantics).
- **Sync?** filled circle for hooks that must run synchronously (rustls path); open circle for async.

### 5.2 Startup hooks

| ID | Name | Call site | Interaction | Default phase | Sync? | Rationale |
|---|---|---|---|---|---|---|
| S1 | `praxis.startup.config_loaded` | `server.rs` after `Config::load` | policy | sequential | ○ | Validate or veto config before pipelines are built. Failing here aborts startup. |
| S2 | `praxis.startup.pipelines_built` | after `resolve_pipelines` | policy | sequential | ○ | Inspect assembled pipelines; reject inconsistent compositions. |
| S3 | `praxis.startup.listeners_bound` | before `server.run_forever` | observe | audit | ○ | Publish to service discovery, warm caches, open watchers. |
| S4 | `praxis.startup.shutdown` | on SIGTERM path | observe | sequential | ○ | Flush buffered state, deregister. Bounded by `shutdown_timeout_secs`. |

Example: an S1 plugin rejects startup if any `insecure_options` flag is set in a production environment. An S2 plugin enforces "every listener has `rate_limit` before `router`".

### 5.3 TLS hooks

| ID | Name | Call site | Interaction | Default phase | Sync? | Rationale |
|---|---|---|---|---|---|---|
| L1 | `praxis.tls.client_hello` | `tls/src/setup/sni.rs` in `ResolvesServerCert::resolve` | policy | sequential | ● | Pre-handshake SNI gating. Rustls calls `resolve` synchronously. |
| L2 | `praxis.tls.cert_resolved` | same, after successful match | observe | audit | ● | Audit trail: which cert served which SNI. |
| L3 | `praxis.tls.cert_reloaded` | `tls/src/reload.rs::reload` | observe | audit | ○ | Fires on success and failure paths of cert rotation. |
| L4 | `praxis.tls.mtls_client_cert` | rustls `ClientCertVerifier::verify_client_cert` adapter | policy | sequential | ● | Custom chain validation beyond rustls default. |

L1 and L4 run on the rustls blocking thread. Their plugin hosts are restricted to `native` (always) and `wasm` with fuel-bounded execution (see [Failure modes and timeouts](#73-failure-modes-and-timeouts)). Sidecar plugins are rejected at startup for these hooks.

### 5.4 TCP hooks

| ID | Name | Call site | Interaction | Default phase | Rationale |
|---|---|---|---|---|---|
| T1 | `praxis.tcp.accept` | `protocol/src/tcp/proxy.rs` after `extract_addrs` | policy | sequential | Cheap IP gating before any byte is read. |
| T2 | `praxis.tcp.sni_peeked` | after `peek_sni` | policy | sequential | SNI allowlist and tenant routing. |
| T3 | `praxis.tcp.pre_connect` | before `run_connect_filters` | policy | sequential | Short-circuit the TCP filter chain (e.g., maintenance mode). |
| T4 | `praxis.tcp.upstream_selected` | after `run_connect_filters` | policy | sequential | Veto the filter-chosen upstream. |
| T5 | `praxis.tcp.upstream_connected` | after `connect_upstream` | observe | audit | Upstream TCP is live. |
| T6 | `praxis.tcp.session_end` | after `forward`, before disconnect filters | observe | fire_and_forget | Non-blocking session audit with final byte counts. |
| T7 | `praxis.tcp.post_disconnect` | after disconnect filters | observe | fire_and_forget | Terminal; publish derived metrics. |

All TCP hooks are async. The TCP lifecycle has no sync bridge.

### 5.5 HTTP lifecycle hooks

| ID | Name | Call site | Interaction | Default phase | Notes |
|---|---|---|---|---|---|
| H1 | `praxis.http.early_request` | `early_request_filter` | observe | audit | Raw request line decoded; Host / Max-Forwards not yet validated. |
| H2 | `praxis.http.host_validated` | after `validate_host_header` | observe | audit | Canonicalised Host available. |
| H3 | `praxis.http.max_forwards_handled` | after terminal `handle_max_forwards` | observe | audit | Fires only for TRACE/OPTIONS at count 0. |
| H4 | `praxis.http.pre_request_pipeline` | `request_filter/mod.rs:98` before `execute_http_request` | policy | sequential | Short-circuit before filters run. |
| H5 | `praxis.http.post_request_pipeline` | `request_filter/mod.rs:146` after `run_pipeline` | policy | sequential | Cluster, upstream, rewritten_path known. |
| H6 | `praxis.http.request_body_chunk` | `request_body_filter.rs` per mode | mutating | transform | Opt-in; participates in `BodyCapabilities`. |
| H7 | `praxis.http.pre_upstream_select` | just before `upstream_peer::execute` | policy | sequential | Final pre-select gate. |
| H8 | `praxis.http.upstream_selected` | `upstream_peer.rs` after `build_peer` | observe | audit | Last view before upstream I/O. |
| H9 | `praxis.http.upstream_connect_failure` | `handle_connect_failure` | policy (voting) | sequential | Returns `RetryVote`. |
| H10 | `praxis.http.pre_upstream_request_write` | after strip + rewrite + Via | mutating | transform | Final shape of upstream request. |
| H11 | `praxis.http.upstream_response_header` | `response_filter.rs` after `strip_hop_by_hop_response` | policy | sequential | First look at upstream response. May veto 5xx. |
| H12 | `praxis.http.post_response_pipeline` | after `execute_http_response`, before Via | mutating | transform | Response after filters ran. |
| H13 | `praxis.http.response_body_chunk` | `response_body_filter.rs` per mode | mutating | transform | Sync from Pingora's perspective; bounded deadline. |
| H14 | `praxis.http.session_logged` | `handler/mod.rs:186` after `logging_cleanup` | observe | fire_and_forget | Terminal; fires exactly once per request. |

Header-level identity and authorization fit here without new hook kinds:

- JWT decoding attaches to H2 or H4 and sets per-request state that downstream plugins read.
- External authz dispatches at H4 (for pipeline preemption) or H7 (for upstream-specific policy).
- Delegated token injection attaches to H10.

None of these require body buffering.

### 5.6 Summary

| Family | Count | Sync mix | Phase mix (default) |
|---|---|---|---|
| Startup | 4 | async | 3 sequential, 1 audit |
| TLS | 4 | 3 sync, 1 async | 2 sequential, 2 audit |
| TCP | 7 | async | 4 sequential, 1 audit, 2 fire_and_forget |
| HTTP | 14 | async (H13 sync context) | 5 sequential, 5 transform, 3 audit, 1 fire_and_forget |
| **Total** | **29** | | |

## 6. Hook Payloads

CPEX binds each hook type to a payload and a result:

```rust
pub trait HookTypeDef: Send + Sync + 'static {
    type Payload: PluginPayload + Clone;
    type Result: Clone;
    const NAME: &'static str;
}
```

Every hook in the [catalog](#5-hook-catalog-lifecycle-hooks) has one `HookTypeDef` in `praxis_hooks::payloads::*`. Payload structs borrow request-scoped data rather than clone it; plugins that need to retain anything clone explicitly. Full signatures are in [Appendix A](#appendix-a-payload-type-sketches).

The shared HTTP context view is:

```rust
pub struct HttpHookCtx<'a> {
    pub client_addr: Option<IpAddr>,
    pub client_http_version: http::Version,
    pub listener: &'a str,
    pub request_start: Instant,
    pub request_id: Option<&'a str>,
    pub cluster: Option<&'a str>,           // None before H5/H7
    pub upstream: Option<&'a Upstream>,     // None before H7
    pub rewritten_path: Option<&'a str>,
    pub retries: u32,
}
```

The context grows richer as the lifecycle progresses. Fields `cluster`, `upstream`, and `rewritten_path` are `None` at H1 through H4, populated at H5 and later.

H9 is the one hook returning a custom vote type:

```rust
pub enum RetryVote { Retry, NoRetry, NoOpinion }
```

The [tighten-only monoid](#74-tighten-only-composition) composes plugin votes with the built-in idempotency check.

### 6.5 Extensions (reserved for v2)

CPEX supports capability-gated `Extensions` on payloads. Praxis v1 attaches none. v2 candidates include `SecurityLabels` (monotonic set) and a `DelegationChain`. Reserved until a concrete consumer lands.

## 7. Dispatch Semantics

### 7.1 Phase selection

For each hook in the [catalog](#5-hook-catalog-lifecycle-hooks) the dispatcher enforces:

1. **Allowed modes.** Plugin YAML `mode:` must match the interaction class. Violations abort startup.
2. **Default mode.** Omitted `mode:` falls back to the "Default phase" column in the [catalog](#5-hook-catalog-lifecycle-hooks).
3. **Ordering within a phase.** By ascending `priority:`, then YAML position.
4. **Phase order.** Canonical CPEX order `sequential → transform → audit → concurrent → fire_and_forget`.

Interaction-class to allowed-phase mapping:

| Interaction | Allowed `mode:` values |
|---|---|
| observe | `audit`, `fire_and_forget` |
| mutating | `transform` |
| policy | `sequential`, `concurrent` |

`concurrent` is offered only where plugin ordering is irrelevant (e.g., parallel audit lookups that all must agree).

### 7.2 Interaction enforcement

After the CPEX executor returns a `PipelineResult`, the call site applies it per class:

| Class | `allowed` | `denied` | `modified_payload` |
|---|---|---|---|
| observe | proceed | log at error, proceed | discarded |
| mutating | proceed | log at error, proceed | replace payload, re-validate via `HookPayloadPolicy` |
| policy | proceed | abort per [Short-circuit behavior](#76-short-circuit-behavior) | accepted in `sequential` only; `concurrent` cannot mutate |

A plugin returning a modified payload whose forbidden fields differ fails per its `on_error:` setting.

### 7.3 Failure modes and timeouts

Each plugin has `on_error:` (from CPEX: `fail`, `ignore`, `disable`) and `timeout_ms:` (passed through as `tokio::time::timeout`). Defaults:

| Class | Default `on_error` | Default `timeout_ms` |
|---|---|---|
| observe | ignore | 50 |
| mutating | fail | 20 |
| policy | fail | 100 |
| body chunk (H6, H13) | fail | 10 per chunk |

**Synchronous hooks (L1, L4).** These run on the rustls blocking thread and cannot `await`. The dispatcher exposes `dispatch_tls_hook_sync` which:

- Rejects non-`native` and non-`wasm` plugin kinds at startup.
- Runs native plugins on the current thread with a hard deadline (default 2 ms) checked after each plugin.
- Runs WASM plugins with wasmtime fuel-bounded execution (default 100 000 fuel units, roughly 1 ms on typical workloads).

### 7.4 Tighten-only composition

For every `policy` hook, plugin results compose with the built-in check via a monoid that can only tighten:

```rust
pub trait Tighten { fn tighten(self, other: Self) -> Self; }

// AllowVote: Continue < Reject. Reject wins.
// RetryVote: Retry < NoOpinion < NoRetry. NoRetry wins.
```

This is enforced in the dispatcher's reduce step, not per call site. A plugin voting `Continue` never overrides a built-in `Reject`. A plugin voting `Retry` on a non-idempotent request is rejected at startup as a `HookError::BoundaryViolation` and the plugin is disabled.

### 7.5 HookPayloadPolicy

CPEX's `HookPayloadPolicy` declares writable fields for `transform` and `sequential` phases. Praxis ships one policy per mutating or policy hook:

| Hook | Writable | Forbidden |
|---|---|---|
| H6 | `chunk` in place | changing `end_of_stream`, exceeding body ceiling |
| H10 | header insert / remove on `upstream_request` | altering `:path` (owned by `rewritten_path`), reintroducing stripped hop-by-hop headers |
| H11 | `upstream_response` status and headers, or a rejection | response bodies exceeding write capacity |
| H12 | response headers | changing status (already committed), reintroducing hop-by-hop |
| H13 | `chunk` in place | same as H6 |

Violations are treated per the plugin's `on_error:`.

### 7.6 Short-circuit behavior

| Hook | What "short-circuit" does |
|---|---|
| S1 | `run_server` returns `Err`, non-zero exit before any listener binds. |
| L1 | `resolve` returns `None`; rustls aborts with `unrecognised_name`. |
| L4 | Verifier returns `Err(BadCertificate)`; rustls aborts. |
| T1 through T4 | Connection closes before `forward`; peeked bytes discarded. |
| H4, H5, H7 | `send_rejection(session, rejection)` emits a response from the plugin violation. |
| H9 | `err.set_retry(false)`. Built-in idempotency check already handled. |
| H11 | Replace upstream response with the plugin-provided response; downstream sees the sanitized version. |

## 8. Plugin ABI

### 8.1 Supported hosts

| Host | CPEX feature | Praxis default | Notes |
|---|---|---|---|
| Native (`.so` / `.dylib`) | `cpex-hosts::native` | on | Primary path. Zero marshalling. |
| WASM (`.wasm`) | `cpex-hosts::wasm` | on | wasmtime sandbox. 20 to 50 µs marshalling per hook. |
| Python (PyO3) | `cpex-hosts::python` | **off, unsupported** | Incompatible with Praxis latency budget. |
| Sidecar (UDS gRPC) | future | off | Reserved for async non-policy hooks. |

### 8.2 Plugin declaration

A Praxis plugin is a crate that depends on `cpex-sdk`, implements one or more `HookHandler<H>` for Praxis hook types, and compiles to `cdylib` (native) or `wasm32-wasip1`. No other formats are supported.

### 8.3 Trust boundary

All plugins run with Praxis process privileges except the WASM sandbox. Consequences:

- Native plugins can crash Praxis, leak memory, or call syscalls. Plugin provenance is the operator's responsibility.
- WASM plugins cannot escape the sandbox; they can exhaust fuel and time out.
- No plugin can widen a boundary from [Security Invariants and Hook Mapping](#11-security-invariants-and-hook-mapping). Attempts fail at startup or fire a `BoundaryViolation` at dispatch (see [Tighten-only composition](#74-tighten-only-composition)).
- `insecure_options` flags are visible to S1 plugins so a policy plugin can reject startup if any flag is set.

### 8.4 Load order

1. Praxis builds the CPEX `PluginManager` and registers all `HookTypeDef`s.
2. For each plugin in YAML order, select the host from the `kind:` scheme, load the binary, call `Plugin::initialize`.
3. For each `subscribe:` entry, look up the hook and register the handler with mode, priority, and `on_error`.
4. Run S1 `config_loaded` across all plugins. Any failure aborts startup.

### 8.5 Unload

Plugins are released on SIGTERM via `Plugin::shutdown`, bounded by `shutdown_timeout_secs`. Runtime reload is deferred; when added it will follow the cert-reload pattern (`ArcSwap<PluginManager>`).

## 9. Configuration

### 9.1 YAML surface

`praxis.yaml` gains one top-level section, `plugins:`. All existing sections are unchanged. A small example:

```yaml
plugins:
  - name: sni-allowlist
    kind: native:///opt/praxis/plugins/libsniallow.so
    subscribe:
      - hook: praxis.tls.client_hello       # L1, synchronous
        on_error: fail
        timeout_ms: 2
    config:
      allowlist_path: /etc/praxis/sni_allowed.txt

  - name: audit-log
    kind: wasm:///opt/praxis/plugins/audit.wasm
    subscribe:
      - hook: praxis.http.session_logged    # H14
        mode: fire_and_forget
    config:
      sink: https://audit.internal/v1/events
```

A broader configuration spanning multiple hook families is in [Appendix B](#appendix-b-configuration-examples).

### 9.2 Field semantics

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Unique plugin identifier; used in logs and metrics. |
| `kind` | yes | Scheme-prefixed location: `native://`, `wasm://`, `builtin:<name>`. Selects the host. |
| `version` | no | Advisory string, logged at startup. |
| `subscribe[].hook` | yes | Hook name from the [catalog](#5-hook-catalog-lifecycle-hooks). |
| `subscribe[].mode` | no | CPEX mode; default from the [catalog](#5-hook-catalog-lifecycle-hooks); validated against interaction class. |
| `subscribe[].priority` | no | Ordering within a phase; default 100. |
| `subscribe[].on_error` | no | Default per class (see [Failure modes and timeouts](#73-failure-modes-and-timeouts)). |
| `subscribe[].timeout_ms` | no | Default per class (see [Failure modes and timeouts](#73-failure-modes-and-timeouts)). |
| `config` | no | Opaque plugin-specific YAML; handed to `Plugin::initialize` as JSON. |

### 9.3 Startup validation

Startup fails when:

- Two plugins share a `name`.
- A `subscribe[].hook` is not a registered Praxis hook.
- A `subscribe[].mode` is not allowed for the hook's interaction class.
- A synchronous hook (L1, L4) subscribes to a plugin whose `kind` is `sidecar://`.
- WASM host is disabled at compile time and a plugin requests `wasm://`.
- A plugin's `Plugin::initialize` returns `Err` with `on_error: fail`.
- Any S1 plugin rejects the config.

Unknown fields under a plugin entry are rejected, consistent with Praxis' `deny_unknown_fields` convention elsewhere.

### 9.4 `insecure_options` interplay

Plugins cannot flip `insecure_options`: they observe config, not mutate it. An S1 plugin can, however, reject startup when any `insecure_*` flag is set. Teams use this to enforce production-hardening policies.

### 9.5 Environment interpolation

Existing `${ENV_VAR}` resolution in `core/src/config/parse.rs` applies to `plugins[].config`. Secrets should flow through env vars, not YAML literals.

## 10. Observability

Three metric series per plugin-hook pair:

```
praxis_hook_invocations_total{plugin, hook, outcome}        continue | reject | error | timeout
praxis_hook_duration_seconds{plugin, hook}                  histogram
praxis_hook_last_error_timestamp_seconds{plugin, hook}
```

Aggregate counters:

```
praxis_hook_dispatch_cache_hits_total        AtomicBool fast path
praxis_hook_dispatch_cache_misses_total
praxis_plugins_loaded_total{host}
praxis_plugins_disabled_total{reason}
```

Tracing integrates with Praxis' existing `tracing` output: each dispatch emits a `trace!` at invocation and a `debug!` at result, and the request span gains a `plugins.invoked` counter plus a `plugins.rejected_by` attribute populated on policy denial.

Plugin-owned metrics flow through `PluginContext::metadata` and surface under `praxis_plugin_user_<plugin_name>_<metric_name>`.

## 11. Security Invariants and Hook Mapping

### 11.1 Built-in boundary catalogue

Praxis enforces 18 load-bearing invariants today. The hook system lets plugins strengthen any without silently weakening any. Escape hatches listed; all default off.

| # | Boundary | Enforced at | Escape hatch |
|---|---|---|---|
| 1 | Refuse UID 0 | `server.rs::check_root_privilege` | `allow_root` |
| 2 | TLS key perms ≤ 0600 (advisory) | `server.rs::warn_insecure_key_permissions` | (warn) |
| 3 | Host header present, single-valued | `request_filter/validation.rs` (RFC 9112 §3.2) | — |
| 4 | Max-Forwards TRACE redaction | same | — |
| 5 | Request hop-by-hop strip | `handler/hop_by_hop.rs` | — |
| 6 | Response hop-by-hop strip | same | — |
| 7 | Via header injection | `handler/via.rs` | — |
| 8 | Rewritten path validation | `handler/upstream_request.rs` | — |
| 9 | Upstream SNI required for TLS | `handler/upstream_peer.rs::derive_sni` | `allow_tls_without_sni` |
| 10 | Idempotent-only retries, max 3 | `handler/mod.rs::handle_connect_failure` | — |
| 11 | Body size ceilings | `filter/src/pipeline/mod.rs::apply_body_limits` | `allow_unbounded_body` |
| 12 | Pipeline ordering validation | `server/src/pipelines.rs::validate_pipeline` | `skip_pipeline_validation` |
| 13 | Health probe allowlist | `config/validate/cluster/endpoints.rs` | `allow_private_health_checks` |
| 14 | Admin not on 0.0.0.0 / :: | `config/validate/listener/address.rs` | `allow_public_admin` |
| 15 | Duplicate SNI cert rejection | `tls/setup/sni.rs::build_sni_resolver` | — |
| 16 | SNI parser rejects IP literals | `tls/sni.rs` (RFC 6066 §3) | — |
| 17 | Cert reload fail-safe | `tls/reload.rs::reload` | — |
| 18 | YAML ingest safety | `config/parse.rs::check_yaml_safety` | — |

### 11.2 Hook mapping

| # | Boundary | Hook(s) | Direction |
|---|---|---|---|
| 1 | Refuse UID 0 | S1 | observe + startup veto |
| 2 | TLS key perms | S1 | observe + startup veto |
| 3 | Host validation | H2 | observe (non-bypassable) |
| 4 | TRACE redaction | H3 | observe |
| 5 | Request hop-by-hop strip | H10 (post-strip) | observe |
| 6 | Response hop-by-hop strip | H11, H12 | observe |
| 7 | Via injection | H10, H12 | observe |
| 8 | Rewritten path | H10 | observe |
| 9 | Upstream SNI required | H7 | tighten |
| 10 | Idempotent-only retries | H9 | tighten (`RetryVote::NoRetry`) |
| 11 | Body size ceilings | H6, H13 | observe |
| 12 | Pipeline ordering | S2 | tighten |
| 13 | Health probe allowlist | S1 | tighten |
| 14 | Admin not public | S1 | tighten |
| 15 | Duplicate SNI cert | S2, L2 | observe |
| 16 | SNI IP literals | L1 | observe |
| 17 | Cert reload fail-safe | L3 | observe + alert |
| 18 | YAML ingest safety | S1 | observe |

Every "tighten" row maps to a specific monoid instance (see [Tighten-only composition](#74-tighten-only-composition)). No code path lets a plugin widen any boundary.

## 12. Staged Rollout

Each phase is independently shippable.

**Phase 0, crate skeleton.** `praxis-hooks` crate, CPEX dependency pinned, CI-only. Publishes [Goals and Non-Goals](#2-goals-and-non-goals) types and [Hook Payloads](#6-hook-payloads) sketches.

**Phase 1, startup and TLS observation (S1 through S4, L2, L3).** Wire the dispatcher into `run_server`. Ship `cert_rotation_alert` as the first `builtin:` plugin. Acceptance: rotation events visible end-to-end; startup-rejects-root example plugin passes.

**Phase 2, HTTP observation (H1, H2, H3, H8, H14).** All observer-only, fail-open. Validates dispatcher fast path, metrics, and tracing at production rates. Acceptance: audit-log plugin at 50k RPS with <1% tail-latency impact.

**Phase 3, TLS policy (L1, L4).** Sync dispatcher variant; fuel-bounded wasmtime for WASM plugins on this path. Ship `sni_allowlist` as reference. Acceptance: 1000-entry allowlist adds <10 µs p99 per handshake.

**Phase 4, HTTP policy (H4, H5, H7, H9, H11).** Tighten-only monoid and `RetryVote` plumbing. Acceptance: ext-authz plugin denies within budget; integration test verifies a plugin can force `NoRetry` on a GET but not `Retry` on a POST.

**Phase 5, TCP hooks (T1 through T7).** Linear lifecycle, no sync context. Acceptance: T1 IP denylist adds <5 µs per accepted connection.

**Phase 6, mutating HTTP (H6, H10, H12, H13).** Requires `HookPayloadPolicy` enforcement and body-mode participation in `BodyCapabilities`. Acceptance: DLP plugin at H13 redacts bodies correctly; H10 injects mTLS-derived headers; body ceiling regressions remain green.

**Phase 7, protocol-native services (optional).** If and when `McpProxy`, `A2aProxy`, or LLM-aware services land, they expose `praxis.mcp.*`, `praxis.a2a.*`, `praxis.llm.*` hook types against the same dispatcher. Not scheduled; driven by demand.

**Phase 8, sidecar host (optional).** UDS gRPC to a local sidecar, limited to async non-policy hooks.

## 13. Open Questions

1. **CPEX version pinning.** CPEX PR #13 is Phase 1a and unreleased. Options: wait for CPEX 0.2 before starting Praxis Phase 0, or vendor the Rust core as a git submodule during Phase 0 and un-vendor on release. Preference: wait.

2. **WASM on synchronous hooks.** [Failure modes and timeouts](#73-failure-modes-and-timeouts) allows fuel-bounded WASM on L1 and L4. Keeping handshake paths unambiguously in-process argues for native-only here. Decision deferred; leaning native-only for v1.

3. **Body-chunk back-pressure.** H6 and H13 default to 10 ms per chunk. A slow plugin stalls HTTP/1.1 connections and HTTP/2 streams. A per-request cumulative budget (e.g., 50 ms across all chunks) in addition to per-chunk deadlines is likely required. To be confirmed in Phase 6.

4. **Hook-filter ordering.** Filters run between H4 and H5 in the request path, so H5 plugins see post-filter state. H10 and H12 hooks run after filters in their respective directions. Worth a dedicated example in the developer guide.

5. **Per-plugin CPU accounting.** Tokio has no cheap per-task accounting. A `sequential` plugin within its timeout but burning CPU stays invisible. Options: process-level quota, push expensive plugins to `fire_and_forget`, require WASM for untrusted plugins (fuel accounts for work). Revisit after Phase 4.

6. **Cross-hook state.** A WAF-style plugin needs shared state between H4 (decision) and H14 (audit). CPEX's `PluginContext::local_state` is per-invocation. A `praxis-hooks::PerRequestState<T>` helper keyed by `request_id` and pruned at H14 likely fills the gap. Design in Phase 4.

7. **Protocol-semantic hooks design work.** The MCP and A2A protocol-native services described in [How protocol-semantic hooks ship later](#43-how-protocol-semantic-hooks-ship-later) are speculative. A design doc for at least one (probably `McpProxy` first) is a prerequisite for Phase 7 and should be started in parallel with Phase 2, independent of the dispatcher work.

## Appendix A: Payload type sketches

```rust
// Startup

pub struct ConfigLoadedPayload<'a> { pub config: &'a Config }

pub struct PipelinesBuiltPayload<'a> {
    pub config: &'a Config,
    pub pipelines: &'a ListenerPipelines,
    pub health_registry: &'a HealthRegistry,
}

pub struct ListenersBoundPayload<'a> { pub listeners: &'a [ListenerBinding] }

pub struct ShutdownPayload { pub deadline: Instant }

// TLS

pub struct ClientHelloPayload<'a> {
    pub sni: Option<&'a str>,
    pub cipher_suites: &'a [u16],
    pub alpn_protocols: &'a [&'a [u8]],
    pub remote_addr: IpAddr,
    pub listener: &'a str,
}

pub struct CertResolvedPayload<'a> {
    pub sni: Option<&'a str>,
    pub cert_fingerprint: CertFingerprint,    // sha256, 32 bytes
    pub listener: &'a str,
}

pub struct CertReloadedPayload<'a> {
    pub cert_path: &'a str,
    pub outcome: Result<CertFingerprint, &'a TlsError>,
}

pub struct MtlsClientCertPayload<'a> {
    pub chain: &'a [CertificateDer<'a>],
    pub sni: Option<&'a str>,
    pub remote_addr: IpAddr,
}

// TCP

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

pub struct TcpUpstreamCandidatePayload<'a> {
    pub conn: TcpConnInfo<'a>,
    pub sni: Option<&'a str>,
    pub upstream_addr: Option<Cow<'a, str>>,
}

pub struct TcpUpstreamConnectedPayload<'a> {
    pub conn: TcpConnInfo<'a>,
    pub upstream_addr: &'a str,
    pub upstream_peer: SocketAddr,
}

pub struct TcpSessionEndPayload<'a> {
    pub conn: TcpConnInfo<'a>,
    pub upstream_addr: Option<&'a str>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration: Duration,
    pub close_reason: TcpCloseReason,
}

// HTTP

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

pub struct EarlyRequestPayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub request_header: &'a pingora_http::RequestHeader,
}

pub struct HttpRequestPipelinePayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub request: &'a praxis_filter::Request,
    pub pre_read_body: Option<&'a [Bytes]>,
}

pub struct UpstreamSelectedPayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub upstream: &'a Upstream,
    pub peer: &'a pingora_load_balancing::prelude::HttpPeer,
}

pub struct UpstreamConnectFailurePayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub err: &'a pingora_core::Error,
    pub retry_count: u32,
    pub is_idempotent: bool,
}
pub enum RetryVote { Retry, NoRetry, NoOpinion }

pub struct PreUpstreamRequestWritePayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub upstream_request: &'a mut pingora_http::RequestHeader,
}

pub struct UpstreamResponseHeaderPayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub upstream_response: &'a mut pingora_http::ResponseHeader,
}

pub struct PostResponsePipelinePayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub response: &'a mut praxis_filter::Response,
}

pub struct BodyChunkPayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub chunk: Option<&'a mut Bytes>,
    pub end_of_stream: bool,
}

pub struct SessionLoggedPayload<'a> {
    pub ctx: HttpHookCtx<'a>,
    pub status: http::StatusCode,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub duration: Duration,
    pub outcome: SessionOutcome,
}
```

## Appendix B: Configuration examples

A `plugins:` block covering multiple hook families:

```yaml
plugins:
  - name: ext-authz
    kind: native:///opt/praxis/plugins/libextauthz.so
    version: "1.0.2"
    subscribe:
      - hook: praxis.http.pre_upstream_select       # H7
        mode: sequential
        priority: 10
        on_error: fail
        timeout_ms: 50
    config:
      grpc_url: unix:///var/run/authz.sock
      cache_ttl_ms: 5000

  - name: audit-log
    kind: wasm:///opt/praxis/plugins/audit.wasm
    version: "0.3.0"
    subscribe:
      - hook: praxis.http.session_logged            # H14
        mode: fire_and_forget
        priority: 100
        on_error: ignore
        timeout_ms: 200
      - hook: praxis.tcp.session_end                # T6
        mode: fire_and_forget
    config:
      sink: https://audit.internal/v1/events

  - name: cert-rotation-alert
    kind: builtin:cert_rotation_alert               # ships in praxis
    subscribe:
      - hook: praxis.tls.cert_reloaded              # L3
        mode: audit
    config:
      pagerduty_routing_key: ${PD_KEY}

  - name: sni-allowlist
    kind: native:///opt/praxis/plugins/libsniallow.so
    subscribe:
      - hook: praxis.tls.client_hello               # L1 synchronous
        mode: sequential
        on_error: fail
        timeout_ms: 2
    config:
      allowlist_path: /etc/praxis/sni_allowed.txt

  - name: prod-hardening
    kind: builtin:insecure_options_guard
    subscribe:
      - hook: praxis.startup.config_loaded          # S1
        on_error: fail
    config:
      forbid_flags:
        - allow_root
        - allow_public_admin
        - allow_unbounded_body
        - skip_pipeline_validation
        - allow_tls_without_sni
        - allow_private_health_checks
```

## Appendix C: Reserved protocol-semantic hook names

These names are reserved but unregistered. They become live hook points when the corresponding protocol-native services (see [How how protocol-semantic hooks ship later](#43-how-protocol-semantic-hooks-ship-later)) land.

```
praxis.mcp.tool_pre_invoke
praxis.mcp.tool_post_invoke
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

Plugins must not `subscribe:` to these names in v1; the loader will reject any subscription to an unregistered hook. Authors designing MCP or A2A plugins today target the HTTP hooks (H4, H7, H10, H11) and re-target to protocol-semantic names once the corresponding service ships.
