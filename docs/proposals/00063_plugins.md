---
issue: https://github.com/praxis-proxy/praxis/issues/63
status: blocked
authors:
  - araujof
graduation_criteria:
  - CPEX core publishes a tagged release
  - Phase 1 foundation delivered and validated
  - Reference plugin demonstrates the authoring API
stakeholders:
  - shaneutt
  - twghu
---

# Hook System and Plugin Support

## What?

A hook system and plugin runtime for Praxis. Hooks
complement the existing `HttpFilter` / `TcpFilter`
surface with typed, capability-gated plugins that
observe or enforce policy at well-defined lifecycle
(startup, shutdown, cert rotation) and
protocol-semantic (MCP tool invocation) points. The
runtime is [CPEX], embedded in-process.

[CPEX]: https://github.com/contextforge-org/cpex

### Goals

- **Second extension surface.** Filters handle
  per-request transformation. Hooks fill the gaps:
  lifecycle observation (TLS handshake, connect,
  session end), policy enforcement at security
  boundaries the pipeline does not expose, and
  protocol-semantic events (MCP `tools/call`).
- **Common runtime.** CPEX provides configuration,
  registration, and dispatch. Plugins targeting
  Praxis hooks can also target other CPEX hosts
  where payload types overlap.
- **Latency-budgeted.** Hooks run on the request
  hot path. Native AFIT means sync handlers compile
  to ready futures with no scheduler interaction.
- **Tighten-only composition.** Plugins may
  strengthen security boundaries. They cannot
  silently weaken any.
- **Zero cost when unused.** A deployment without
  a `plugins:` block pays one
  `PluginManager::has_hooks_for` lookup per call
  site.

### Non-goals

- Replacing filters (filters remain the per-request
  transformation abstraction)
- Hot reload (startup-only loading keeps the trust
  model simple)
- Arbitrary cross-hook ordering
- Field-level payload write policy in v1
- Policy evaluation language (APL)

## Why?

### Motivation

`HttpFilter` and `TcpFilter` handle per-request
transformation well but are insufficient for three
categories of extension:

1. **Lifecycle observation.** TLS handshake events,
   cert rotation, startup validation, and graceful
   shutdown have no filter call site.
2. **Security boundary enforcement.** Policy
   decisions at points the filter pipeline does not
   expose (pre-pipeline auth gating, upstream
   connect failure handling) require hooks.
3. **Protocol-semantic events.** MCP `tools/call`
   gating and redaction operate on parsed protocol
   payloads, not HTTP primitives. A filter that
   parses JSON-RPC to dispatch per-tool hooks bakes
   protocol knowledge into the HTTP layer.

### User Stories

- As a proxy operator, I want to reject configs at
  startup that violate security policy so that
  production hardening is enforced automatically.
- As a security engineer, I want to gate or redact
  MCP tool invocations so that tool access is
  controlled by policy.
- As a platform engineer, I want to observe TLS
  cert rotations so that I can alert on rotation
  failures.
- As an auditor, I want to observe completed
  sessions so that all access is logged to an
  external sink.
- As a plugin author, I want to write a single
  Rust crate that works on both Praxis and other
  CPEX hosts so that I do not maintain separate
  integrations.

## Consideration A

> **Note:** This section was grandfathered from a
> pre-proposal design document. Normally the How?
> arrives in a follow-up PR after the What? and
> Why? are accepted.

### Scope (v1)

**In scope:**

1. One new crate (`praxis-hooks`) plus one new
   builtin filter (`filter/src/builtins/http/mcp/`).
   One external dependency: `cpex-core`.
2. CPEX `PluginManager` wired through `run_server`.
3. 12 initial hooks: lifecycle (S1, S4, L3),
   identity (I1, I2), HTTP policy (H4, H7, H9,
   H11, H14), and MCP tool hooks (M1, M2).
4. Tool hooks ship via the MCP gateway filter with
   route-driven body mode. Hook names are stable
   across the gateway and future protocol-native
   options.
5. Plugins are Rust crates registered
   programmatically. Dynamic `cdylib` loading ships
   as a parallel phase.
6. Mutation flows through CPEX `Extensions` and
   capability-gated `WriteToken`s.

**Out of scope in v1:** A2A/LLM/prompt/resource
hooks (reserved), WASM/Python/sidecar hosts, hot
reload.

### Integration Architecture

Praxis embeds the CPEX `PluginManager` in-process.
A plugin call is a function call, not an IPC hop.

**Crate layout.** A single new crate
(`praxis-hooks`) joins the workspace, containing
hook type definitions, typed payloads, dispatcher
logic, config adapter, and metrics emitters. The
MCP gateway filter lives at
`filter/src/builtins/http/mcp/`. `cpex-core` is a
git dependency pinned to a specific commit.

**Lifecycle integration.** The `PluginManager` is
owned by `run_server`, built after pipelines are
resolved and before `server.run_forever()`.
Protocol handlers receive it as
`Arc<PluginManager>`, parallel to how they receive
`Arc<FilterPipeline>`. Startup sequence: enforce
root check, build health registry, resolve
pipelines, create `PluginManager`, register
handlers, initialize plugins, fire S1
`config_loaded`, build runtime, register
protocols, run.

**Call-site contract.** Each hook call site:
fast-path checks `has_hooks_for` (one atomic load
on miss), builds the typed payload, invokes via
the dispatcher, applies the result per interaction
class, and emits metrics.

### Protocol Hook Design

Hooks are either **lifecycle** (operate on
HTTP/TCP primitives; no body access) or
**protocol-semantic** (operate on parsed protocol
payloads; require body buffering). The design
challenge is delivering protocol-semantic hooks
without imposing buffering costs on unrelated
traffic.

**Gateway filter (v1).** An MCP gateway filter at
`filter/src/builtins/http/mcp/` runs only on
routes that opt in via a route-level `body_mode:`
declaration. On matched routes, the filter parses
JSON-RPC, constructs `MessagePayload` for
`tools/call`, and dispatches M1/M2 hooks.
Non-`tools/call` methods bypass dispatch.

**Protocol-native service (future).** A dedicated
`ProtocolKind::Mcp` listener that owns its accept
loop and parses JSON-RPC natively. Removes the
abstraction-inversion cost. Plugins written against
the gateway filter retarget without code changes.

**Route-driven body mode.** Routes gain an optional
`body_mode:` block declaring request/response
buffer limits. The pipeline applies the declared
mode after route resolution, before filters run.
The MCP filter is a true no-op on unmatched routes.

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

### Hook Catalog (v1)

12 hooks registered in v1. Conventions: `S`
startup, `L` TLS, `T` TCP, `H` HTTP, `I` identity,
`M` MCP. Interaction is `observe`, `mutating`, or
`policy`.

**Lifecycle hooks:**

| ID | Name | Interaction | Call site |
|----|------|-------------|-----------|
| S1 | `praxis.startup.config_loaded` | policy | after config load |
| S4 | `praxis.startup.shutdown` | observe | SIGTERM path |
| L3 | `praxis.tls.cert_reloaded` | observe | cert rotation |
| I1 | `praxis.identity.resolve` | policy | pre-pipeline |
| I2 | `praxis.identity.delegate` | mutating | post-route |
| H4 | `praxis.http.pre_request_pipeline` | policy | before pipeline |
| H7 | `praxis.http.pre_upstream_select` | policy | before upstream |
| H9 | `praxis.http.upstream_connect_failure` | policy | connect failure |
| H11 | `praxis.http.upstream_response_header` | policy | response header |
| H14 | `praxis.http.session_logged` | observe | after logging |

**Protocol-semantic hooks:**

| ID | Name | Interaction | Payload |
|----|------|-------------|---------|
| M1 | `praxis.mcp.tool_pre_invoke` | policy | `MessagePayload` |
| M2 | `praxis.mcp.tool_post_invoke` | mutating | `MessagePayload` |

Identity hooks (I1, I2) route to CPEX
`IdentityResolve` and `TokenDelegate` framework
execution paths, providing slot collision
rejection, immutable sealing post-resolution,
capability-gated writes, a raw-credential
boundary, and a token cache.

Reserved hooks (not registered in v1) cover
TCP (T1-T7), additional startup (S2, S3),
TLS (L1, L2, L4), body chunks (H6, H13),
and additional HTTP lifecycle points (H5, H8,
H10, H12). Reserved protocol-semantic hooks
include MCP prompt/resource and A2A task hooks.
A full catalog with payload sketches will be added
when the hook system graduates to experimental.

### Plugin Runtime Model

**Extensions.** A separate parameter carrying
HTTP headers, security identity, request metadata,
agent context, delegation chain, raw credentials,
and MCP entity metadata. Capabilities and
`WriteToken`s enforce read/write authority at the
type level. A plugin without `write_headers` sees
`http_write_token == None` and silently cannot
write.

**PluginContext.** `local_state` persists
per-plugin across hooks in one request (e.g., a
timer from M1 read at M2). `global_state` is
cross-plugin within one invoke chain.

**Mode constraints.** Plugin YAML `mode:` must
match the hook's interaction class:

| Interaction | Allowed modes |
|-------------|---------------|
| observe | `audit`, `fire_and_forget` |
| mutating | `transform` |
| policy | `sequential`, `concurrent` |

**Interaction enforcement.** Observe results are
logged but never block. Mutating results apply
payload and extension changes. Policy denials
trigger short-circuit behavior per hook site
(e.g., S1 denial aborts startup; H4/H7 denial
emits a rejection response; M1 denial emits a
JSON-RPC error without contacting upstream).

**Failure modes.** Each plugin has `on_error:`
(`fail`, `ignore`, `disable`) and `timeout_ms:`
with class-specific defaults: observe
50ms/ignore, mutating 20ms/fail, policy
100ms/fail.

**Tighten-only composition.** Once any plugin
denies, `continue_processing` is `false` and no
subsequent plugin can revert it.

### Plugin Authoring

**Static plugins (v1).** Rust crates implementing
`Plugin` and `HookHandler<H>`, compiled into the
Praxis binary. Registered via
`register_handler::<H, _>()` or
`register_handler_for_names::<CmfHook, _>()` for
CMF-based hooks.

**Dynamic plugins (future).** Rust `cdylib` crates
loaded via `libloading` at startup. Same
registration API. ABI compatibility enforced at
load time.

**Future hosts.** WASM (wasmtime), sidecar (UDS
gRPC). Each enters as an additive factory kind
without changing the static-plugin surface.

### Configuration

`praxis.yaml` gains a top-level `plugins:` section.
Each entry specifies `name`, `kind`, `hooks`, and
optional `mode`, `priority`, `on_error`,
`timeout_ms`, `capabilities`, and `config`.
Startup validation rejects duplicate names,
unknown hooks, reserved hooks, mode/interaction
mismatches, and unknown fields.

Environment variable interpolation (`${VAR}`) is
required for secrets in `plugins[].config`.

Three metric series per plugin-hook pair:
invocations, duration histogram, and last error
timestamp.

### Security Invariants

Praxis enforces 18 built-in security boundaries
(root check, TLS key perms, Host validation,
hop-by-hop stripping, body size ceilings, etc.).
The hook system lets plugins strengthen any
boundary without weakening any. Each boundary
maps to a v1 or reserved hook with a direction
(observe, tighten, or startup veto). Built-in
enforcement remains regardless of plugin
decisions.

### Staged Rollout

1. **Phase 1 (foundation).** `praxis-hooks` crate,
   `PluginManager` in `run_server`, env var
   interpolation, S1 hook.
2. **Phase 2 (MCP tool hooks).** Route-driven body
   mode, MCP gateway filter, M1/M2 hooks,
   reference plugin.
3. **Phase 3 (lifecycle observers).** S4, L3, H14.
4. **Phase 4 (HTTP policy and identity).** H4, H7,
   H9, H11, I1, I2, tighten-only enforcement.
5. **Phase 5+ (future).** Reserved hook promotions,
   dynamic loading, protocol-native service,
   broader protocol-semantic hooks.

### Open Questions

1. **CPEX version pinning.** Pin against a git
   commit until cpex-core publishes a tagged
   release.
2. **Per-plugin CPU accounting.** Tokio has no
   cheap per-task accounting; revisit after
   Phase 2.
3. **Body-chunk back-pressure.** Per-chunk
   deadlines plus per-request cumulative budget
   needed when H6/H13 are promoted.
4. **SSE response streaming for M2.** v1 buffers
   or skips M2 on streaming responses.
5. **Route-mode interaction with body ceilings.**
   Confirm in Phase 2.
6. **ABI compatibility for dynamic loading.**
   Deferred until dynamic loading ships.
7. **Reserved hook promotion gate.** Design note,
   consumer plugin, integration test.
