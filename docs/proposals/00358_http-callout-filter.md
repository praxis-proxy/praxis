---
issue: https://github.com/praxis-proxy/praxis/issues/358
discussion: https://github.com/praxis-proxy/praxis/discussions/87
status: proposed
authors:
  - usize
graduation_criteria:
  - How? section with requirements and design
  - HTTP client pool and lifecycle design
  - SSRF prevention model validated
stakeholders:
  - shaneutt
  - twghu
  - nerdalert
---

# HTTP Callout Filter

## What?

An `http_callout` filter that makes outbound HTTP requests to
external services during request processing. The filter sends
a request to a configured target, extracts fields from the
response, and writes them into filter results for downstream
branch-chain evaluation.

This is the first concrete deliverable from the sub-request
orchestration primitive described in
[discussion #87](https://github.com/praxis-proxy/praxis/discussions/87),
scoped to inline HTTP callouts with fail-open/closed
semantics without requiring ext-proc.

### Goals

- Async HTTP client available to filters during request
  processing
- Connection pooling to callout targets, independent of
  Pingora's upstream pool
- Per-target timeout and circuit breaker configuration
- Configurable fail-open / fail-closed semantics
- Callout targets declared in config (SSRF prevention)
- Tracing spans and metrics for callout requests
- Compose with existing branch chains for
  continue-or-reject logic

## Why?

See [discussion #87](https://github.com/praxis-proxy/praxis/discussions/87)
for the full motivation, including the ext_proc orchestration
gap, P/D disaggregation failure modes, and the AI Gateway
Working Group's Payload Processing proposal. This section
summarizes the immediate motivation for the callout filter.

### Motivation

Praxis filter pipelines today are policy chains: each filter
inspects the request, makes a decision (continue or reject),
and optionally mutates headers or metadata. When a policy
decision requires consulting an external service — a
content-safety API, an authorization endpoint, a feature
store — there is no mechanism to do so without deploying a
full ext-proc sidecar.

ext_proc is powerful but operationally heavy: it requires a
separate gRPC service, bidirectional streaming, and careful
lifecycle management. Many callout use cases are simpler:
POST a payload to an HTTP endpoint, inspect the response,
continue or reject.

[Lakera Guard](https://docs.lakera.ai/docs/api/guard) is a
concrete example. It screens LLM interactions for prompt
injection, PII leakage, and harmful content via a single
HTTP POST to `/v2/guard`, returning
`{"flagged": true, "categories": {...}}`. Today, integrating
it with a proxy requires either an ext-proc sidecar or
application-level integration. The same applies to the
[OpenAI Moderation API](https://platform.openai.com/docs/guides/moderation),
[Azure AI Content Safety](https://learn.microsoft.com/en-us/azure/api-management/llm-content-safety-policy),
and any HTTP-accessible policy service.

An `http_callout` filter would let operators wire these
services into the proxy pipeline declaratively. Beyond
policy callouts, this primitive also opens the door to
orchestrating multi-stage inference workflows — such as
coordinating prefill and decode execution across
disaggregated GPU pools — from within the filter pipeline.
The [llm-d](https://github.com/llm-d/llm-d) project's
routing sidecar faces known limitations around failure
recovery when a decode pod dies during prefill
([llm-d/llm-d-router#712](https://github.com/llm-d/llm-d-router/issues/712))
and lack of failover to alternate prefill targets
([llm-d/llm-d-router#711](https://github.com/llm-d/llm-d-router/issues/711)).
An independent proxy with sub-request capability could
hold context across stages and retry individual steps.
Fully realizing this pattern will require a follow-up
proposal for replacing the upstream response with the
result of a sub-request, but the HTTP client primitive
built here is the necessary foundation.

```yaml
listeners:
  - name: ai-gateway
    address: "0.0.0.0:8080"
    filter_chains: [safety-check, routing]

filter_chains:
  - name: safety-check
    filters:
      - filter: http_callout
        name: lakera-guard
        target:
          url: "https://api.lakera.ai/v2/guard"
          timeout: 2s
          tls: {}
          headers:
            Authorization: "Bearer ${LAKERA_API_KEY}"
        request:
          body_from: request_body
          max_body_bytes: 1048576  # 1 MiB
        response:
          extract:
            - json_path: "$.flagged"
              result_key: "flagged"
            - json_path: "$.categories.prompt_injection"
              result_key: "prompt_injection"
        failure_mode: closed
        circuit_breaker:
          failure_threshold: 5
          recovery_timeout: 30s
        branch_chains:
          - name: block_flagged
            on_result:
              filter: lakera-guard
              key: flagged
              value: "true"
            rejoin: terminal
            chains:
              - name: reject
                filters:
                  - filter: static_response
                    status: 403

  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/v1/"
            cluster: llm-backend
      - filter: load_balancer
        clusters:
          - name: llm-backend
            endpoints:
              - "10.0.1.10:8000"
```

### User Stories

- As an AI gateway operator, I want to call Lakera Guard
  (or a similar content-safety API) inline so that prompt
  injection and PII are detected at the proxy layer without
  requiring ext-proc or application changes.
- As a security engineer, I want callout failures to fail
  closed by default so that an unreachable guardrail service
  does not silently bypass content policy.
- As an SRE, I want per-target circuit breakers so that a
  failing callout target does not add latency to every
  request.
- As a platform engineer, I want callout connection pools
  to survive config reloads so that hot-reload does not
  cause connection storms to external services.
- As a proxy operator, I want callout targets declared in
  config — not constructible from request data — so that
  filters cannot be used for SSRF.

### Non-Goals

- Response source replacement — callouts that become the
  upstream response (needed for P/D orchestration; see
  [discussion #87](https://github.com/praxis-proxy/praxis/discussions/87)).
- MCP, A2A, or gRPC sub-requests — higher-level protocols
  built on top of this HTTP primitive.
- Parallel fan-out — concurrent callouts to multiple
  targets.
- Callout body templating DSL — start with full-body
  forwarding; structured request construction is a
  follow-on.
- WASM host-call interface — bridged separately via
  [#18](https://github.com/praxis-proxy/praxis/issues/18).

### Prior Art

- **Envoy ext_authz** — single HTTP/gRPC callout for
  authorization with fail-open/closed, timeout, and status
  code mapping.
- **Envoy ext_proc** — bidirectional gRPC stream for
  external processing. Praxis vendors the proto definitions
  in `praxis-proto`.
- **NGINX auth_request** — sub-request to an authorization
  endpoint; response status controls access.

## How?

### Requirements

1. **HTTP client pool** — a connection-pooled
   `reqwest::Client` per filter instance, independent of
   Pingora's upstream pool. Each filter instance owns its
   own client — never shared across instances — to
   prevent credential and connection leakage in
   multi-tenant deployments (see "Connection and TLS
   isolation"). Created once during `from_config()`.
   Pools survive config reloads because the filter struct
   lives inside `Arc<ArcSwap<FilterPipeline>>` — old
   pipelines drop only after all in-flight requests
   drain.

2. **SSRF prevention** — callout targets are fully
   declared in config (URL, headers, TLS settings). The
   filter never constructs a target URL from request data.
   Validation at config load time rejects targets with
   template variables in the host or path components.
   Only the request body is forwarded; the callout URL is
   static.

3. **Per-target circuit breaker** — the callout crate
   owns its own circuit breaker implementation. The
   state machine (closed/open/half-open with threshold
   and recovery window) is similar to the existing
   `circuit_breaker` filter, but the two operate
   differently: the traffic management filter spans
   `on_request` → upstream → `on_response`, while the
   callout checks and records within a single async
   call. Keeping them independent avoids coupling and
   allows the callout's failure semantics to evolve
   separately (e.g. backoff-based recovery, different
   probe logic). The callout filter owns one circuit
   breaker per instance, checking state before the
   call and recording success/failure after. When the
   circuit is open, the filter applies the configured
   failure mode immediately without making the HTTP
   call.

4. **Fail-open / fail-closed** — configurable per filter
   instance. Default: `closed` (reject on callout error).
   Applies to connection errors, timeouts, non-2xx
   responses, and open circuits. Fail-open continues the
   pipeline with no results written; fail-closed returns
   `FilterAction::Reject` with a configurable status code
   (default 502).

5. **Response extraction** — extract values from the
   callout JSON response via [RFC 9535] JSONPath
   expressions and write them into `FilterResultSet`
   for branch-chain evaluation. Uses the
   [`serde_json_path`] crate, which implements
   `serde::Deserialize` on its `JsonPath` type so
   expressions are parsed and validated at config load
   time. Scalar values are coerced to strings
   (`true` → `"true"`, numbers → decimal). Arrays and
   objects are serialized to compact JSON strings.
   `null` and missing matches write nothing (no error),
   so partial responses degrade gracefully.

   [RFC 9535]: https://www.rfc-editor.org/rfc/rfc9535
   [`serde_json_path`]: https://crates.io/crates/serde_json_path

6. **Body forwarding** — the filter buffers the inbound
   request body and sends it as the callout POST body.
   Uses `BodyAccess::ReadOnly` and
   `BodyMode::StreamBuffer { max_bytes }` to buffer
   without mutating. The `max_body_bytes` config field
   sets the limit via the standard body mode
   declaration; the pipeline enforces it with a 413
   response before the filter ever runs. The callout
   itself runs in `on_request_body` at
   `end_of_stream`, after the full body is available.

7. **Header forwarding** — in addition to static headers
   declared in config, operators can specify a list of
   downstream request headers to forward to the callout
   target (e.g. `traceparent`, `x-request-id`). The
   filter copies matching headers from
   `ctx.request.headers` at callout time. This enables
   trace correlation without exposing all downstream
   headers to the external service.

8. **Response header injection** — the callout target
   can return headers that get injected into the
   upstream request. Operators declare an allowlist of
   header names via `inject_headers`; matching headers
   from the callout response are added to
   `ctx.request.headers` before the pipeline continues.
   This enables the classify-then-route pattern: a
   callout to a content-safety API can set
   `x-content-policy: safe` and downstream router or
   branch-chain filters can match on it without
   needing `FilterResultSet` extraction.

9. **Client headers on denial** — when the callout
   triggers a rejection (via branch chain or
   fail-closed), certain headers from the callout
   response can be forwarded to the client in the
   rejection response. Operators declare these via
   `on_denied_headers`. Useful for returning
   `Retry-After`, policy-violation categories, or
   correlation IDs in the 403/502 body.

10. **Loop prevention** — if a callout target points back
   at the proxy (directly, via DNS, or through a load
   balancer), the request would re-enter the pipeline
   and trigger the same callout indefinitely. The
   filter prevents this with a depth header:

   - Every outbound callout injects
     `x-praxis-callout-depth: <N+1>` where N is the
     current depth (0 if absent).
   - On inbound requests, the filter reads the depth
     header before making the call. If the depth meets
     or exceeds `max_depth` (default: 1, meaning no
     re-entry), the filter applies `failure_mode`
     without making the callout.
   - The `x-praxis-callout-depth` header is a reserved
     internal header. It must be stripped from external
     client requests on ingress (following the same
     pattern as other `x-praxis-*` headers) so that
     external clients cannot forge it to bypass the
     callout or inflate the depth to suppress it.

   This works across proxy hops: if two Praxis
   instances chain callouts through each other, the
   depth increments at each hop and terminates at the
   configured max.

11. **Timeout scope** — the `timeout` config field
    applies only to the outbound HTTP request
    (connection + response from the callout target).
    It does not include time spent buffering the
    inbound request body, which is governed by the
    pipeline's own timeouts and the listener-level
    read timeout.

12. **Tracing** — each callout emits a `tracing` span
    with target URL, response status, latency, and
    circuit breaker state. Errors are logged at `warn`
    level.

### Design

#### Crate layout

The callout capability is split into two layers:

1. **`praxis-callout`** (`callout/`) — the shared HTTP
   callout client library. Provides the connection-pooled
   `reqwest::Client` wrapper, circuit breaker, timeout
   handling, failure mode semantics, and tracing. Any
   filter that needs to make outbound HTTP requests
   depends on this crate. This is the sub-request
   harness — the reusable primitive that
   `ai_guardrails`, `ext_authz`, and future filters
   build on.

2. **`praxis-http-callout`** (`filter/http-callout/`) —
   the `http_callout` filter itself. A thin `HttpFilter`
   wrapper that wires `praxis-callout` into the filter
   pipeline with config-driven target, JSONPath
   extraction, and body forwarding. This is the
   reference implementation and a standalone filter
   operators can use directly.

This separation means `ai_guardrails` (#138) can depend
on `praxis-callout` directly for its `NemoProvider`
HTTP calls without depending on the `http_callout`
filter or reinventing its own HTTP client. Any filter
that needs to call an external service gets the same
pooled client, circuit breaker, and failure semantics
out of the box.

```text
server
  ├── praxis-http-callout (filter, opt-in)
  │     ├── praxis-callout (shared client)
  │     ├── praxis-filter (HttpFilter, FilterResultSet)
  │     └── serde_json_path
  │
  └── praxis-filter
        └── praxis-callout (available to any builtin)

callout/  (praxis-callout)
  └── reqwest [rustls-tls]
```

The `praxis-callout` crate contains its own circuit
breaker implementation rather than sharing the one in
the traffic management filter. The two have similar
state machines but different operational models (see
requirement 3), and the ~80 lines of state machine
code do not justify the coupling.

#### Feature gating

The `http_callout` filter is opt-in via a cargo feature
flag, following the same chain as `ext-proc`:

```toml
# Cargo.toml (workspace root)
[workspace]
members = [
    # ...
    "callout",
    "filter/http-callout",
]

[workspace.dependencies]
praxis-callout = { version = "...", path = "callout" }
praxis-http-callout = { version = "...", path = "filter/http-callout" }

# server/Cargo.toml
[features]
default = ["ai-inference"]
http-callout = ["dep:praxis-http-callout"]

[dependencies]
praxis-http-callout = { workspace = true, optional = true }
```

The server binary registers the filter conditionally:

```rust
// server/src/server.rs (or wherever registry is built)
let mut registry = FilterRegistry::with_builtins();

#[cfg(feature = "http-callout")]
registry.register(
    "http_callout",
    praxis_filter::http_builtin(
        praxis_http_callout::HttpCalloutFilter::from_config,
    ),
).expect("http_callout registration");
```

Operators who don't need the `http_callout` filter pay
no binary-size cost. The `praxis-callout` crate itself
is a regular (non-optional) dependency of
`praxis-filter`, so any builtin filter can use it —
the feature flag only gates the standalone
`http_callout` filter registration.

> **Note on future crate evolution:** Shane has discussed
> broadening the shared client layer into an
> `integrations` crate covering Valkey, Postgres, and
> other external service clients. `praxis-callout` is
> the natural starting point for that; the HTTP client
> pool and circuit breaker are designed to be extracted
> further if the scope grows. For now, a focused
> `callout` crate avoids coupling unrelated integrations.

#### Filter struct

```rust
pub struct HttpCalloutFilter {
    /// Per-instance HTTP client (never shared across
    /// filter instances — see "Connection and TLS
    /// isolation").
    client: reqwest::Client,

    /// Static callout target URL.
    url: Arc<str>,

    /// Per-request timeout (outbound HTTP request only).
    timeout: Duration,

    /// Static headers injected into every callout request.
    headers: Vec<(HeaderName, HeaderValue)>,

    /// Downstream request headers to forward to the
    /// callout target (e.g. traceparent, x-request-id).
    forward_headers: Vec<HeaderName>,

    /// JSONPath expressions to extract from the response.
    extractions: Vec<Extraction>,

    /// Callout response headers to inject into the
    /// upstream request (allowlist).
    inject_headers: Vec<HeaderName>,

    /// Callout response headers to return to the client
    /// when the callout triggers a rejection.
    on_denied_headers: Vec<HeaderName>,

    /// What to do when the callout fails.
    failure_mode: FailureMode,

    /// HTTP status code for fail-closed rejections.
    status_on_error: u16,

    /// Circuit breaker state for this target.
    circuit_breaker: Option<CircuitBreaker>,

    /// Maximum callout re-entry depth. Default: 1
    /// (no re-entry). See "Loop prevention".
    max_depth: u8,

    /// Maximum request body bytes to buffer and forward.
    /// Declared via BodyMode::StreamBuffer; the pipeline
    /// enforces the limit with 413.
    max_body_bytes: usize,
}
```

#### Extraction

```rust
struct Extraction {
    /// Compiled RFC 9535 JSONPath expression.
    /// Parsed and validated at config load time via
    /// serde_json_path's Deserialize impl.
    path: serde_json_path::JsonPath,

    /// Key written to FilterResultSet.
    result_key: Arc<str>,
}
```

At config load time, JSONPath expressions are parsed
and compiled — invalid expressions fail the config
validation. At runtime, each extraction queries the
callout response `serde_json::Value`. The first match
is coerced to a string and written to `FilterResultSet`:

- Booleans: `true` → `"true"`
- Numbers: decimal representation
- Strings: as-is
- Arrays and objects: compact JSON (e.g.
  `{"injection":true}`)
- `null` or no match: nothing written

This means branch chains can match on scalar values
directly (`value: "true"`) and on structured values
via string comparison when needed.

Full JSONPath (RFC 9535) gives operators the flexibility
to handle nested, array, and conditional extractions
without us inventing a bespoke query language. The
`serde_json_path` crate is a maintained, spec-compliant
implementation with no unsafe code.

#### Request flow

```text
on_request_body(end_of_stream=true)
  │
  ├─ depth check ──► >= max_depth? ──► apply failure_mode
  │
  ├─ circuit breaker check ──► Open? ──► apply failure_mode
  │
  ├─ build callout request
  │   POST {url}
  │   headers: static config headers
  │          + forwarded downstream headers
  │          + x-praxis-callout-depth: <N+1>
  │   body: buffered request body
  │
  ├─ send with timeout ──► error? ──► record_failure
  │   (timeout covers only       apply failure_mode
  │    outbound request)
  │
  ├─ check response status ──► non-2xx? ──► record_failure
  │                                          apply failure_mode
  │
  ├─ record_success
  │
  ├─ parse JSON response
  │   extract fields → FilterResultSet
  │
  └─ return FilterAction::Continue
```

For requests without a body (or when the operator only
needs header-phase evaluation), the callout can
optionally run in `on_request` instead. A config field
`phase: request_headers | request_body` controls this.
When `phase: request_headers`, the filter does not
declare body access and the callout fires with an empty
body.

#### Failure mode

```rust
enum FailureMode {
    /// Reject with status_on_error (default).
    Closed,

    /// Continue the pipeline with no results written.
    Open,
}
```

The failure mode applies uniformly to: connection
errors, timeouts, non-2xx responses, JSON parse
failures, and open circuit breakers.

#### Connection and TLS isolation

Each `http_callout` filter instance owns its own
`reqwest::Client`. Clients are **never shared** across
filter instances, even when targeting the same URL.
This is a deliberate multi-tenancy constraint: in a
deployment where different listeners or filter chains
serve different tenants, connection pool sharing would
create two categories of leakage risk:

1. **Credential leakage** — `reqwest::Client` caches
   TLS sessions and may send HTTP/2 connections with
   coalescing. If two filter instances target the same
   host but carry different `Authorization` headers
   (different tenant API keys), a shared client could
   reuse a connection established with tenant A's TLS
   client certificate for tenant B's request.

2. **Timing side-channels** — a shared pool lets one
   tenant's callout latency influence another's
   connection availability. Per-instance pools provide
   natural isolation.

The `reqwest::Client` is configured with:

- `rustls-tls` (matching the workspace TLS stack)
- `pool_max_idle_per_host` capped to prevent
  unbounded connection accumulation
- `no_proxy` enabled — callout targets are
  infrastructure endpoints, not user-facing; proxy
  environment variables must not redirect them
- Optional per-target client certificate for mTLS,
  loaded at config time from the same PEM paths used
  by the `tls` crate

When Praxis gains explicit multi-tenant primitives
(tenant-scoped filter chains, credential stores), the
isolation model here should be re-evaluated. For now,
per-instance clients are the safe default.

#### SSRF prevention model

The callout target URL is a static string parsed and
validated at config load time. The filter does not
support URL templates, path interpolation, or any
mechanism that would allow request data to influence the
target. The only request-derived content is the POST
body (bounded by `max_body_bytes`).

Validation rules enforced in `from_config()`:

- URL must parse as a valid absolute URI
- Scheme must be `http` or `https`
- Host must not be empty
- No `${...}` template variables in the URL string
  (environment variable expansion in headers is handled
  by the config loader, not the filter)

#### Configuration

```yaml
filter: http_callout
name: lakera-guard            # filter instance name
target:
  url: "https://api.lakera.ai/v2/guard"
  timeout: 2s                 # outbound request only
  tls:                        # optional; rustls defaults
    client_cert: /etc/praxis/certs/client.pem
    client_key: /etc/praxis/certs/client.key
  headers:                    # static headers
    Authorization: "Bearer ${LAKERA_API_KEY}"
  forward_headers:            # copy from downstream request
    - traceparent
    - x-request-id
request:
  phase: request_body         # or request_headers
  body_from: request_body     # forward inbound body
  max_body_bytes: 1048576     # 1 MiB (pipeline enforces 413)
response:
  extract:
    - json_path: "$.flagged"
      result_key: "flagged"
    - json_path: "$.categories.prompt_injection"
      result_key: "prompt_injection"
  inject_headers:             # callout response headers
    - x-content-policy        #   added to upstream request
  on_denied_headers:          # callout response headers
    - retry-after             #   returned to client on reject
failure_mode: closed          # or open
status_on_error: 502
max_depth: 1                  # default; no re-entry
circuit_breaker:              # optional
  failure_threshold: 5
  recovery_timeout: 30s
```

### Implementation

Proposed PR sequence:

- **PR 1** — `praxis-callout` crate (`callout/`) with
  the shared HTTP callout client: `reqwest` client pool,
  circuit breaker, timeout, failure mode handling, and
  tracing. Unit tests with a local `wiremock` server.
  This is the reusable primitive any filter can depend
  on.

- **PR 2** — `praxis-http-callout` satellite crate
  (`filter/http-callout/`) with `HttpCalloutFilter`
  struct, config parsing, SSRF validation, JSONPath
  extraction, body forwarding, and unit tests.
  Registered in the server binary behind a feature flag.

- **PR 3** — integration test and example config:
  Lakera Guard example in `examples/configs/ai/`,
  functional integration test in
  `tests/integration/tests/suite/examples/` using a
  mock HTTP server that returns Lakera-shaped responses.

### Relationship to #138 (AI Guardrails)

The `ai_guardrails` filter (#138) needs to call external
providers (NeMo, and potentially Lakera, OpenAI
Moderation, etc.) via HTTP. The `NemoProvider::evaluate`
stub in the current skeleton (#577, #578) is the exact
kind of callout `praxis-callout` provides.

Because the callout client is a shared crate (not locked
inside the `http_callout` filter), `ai_guardrails` can
depend on `praxis-callout` directly. The `NemoProvider`
gets a pooled, circuit-broken HTTP client with
fail-open/closed semantics without building its own
`reqwest` client or duplicating timeout/retry logic.

The `http_callout` filter itself remains useful as the
general-purpose, config-driven option for operators who
want to wire arbitrary HTTP policy services (Lakera,
OpenAI Moderation, custom webhooks) into the pipeline
without writing a dedicated filter.

### Addendum: Lessons from Envoy ext_authz

The design of this filter draws heavily from Envoy's
[`ext_authz`] filter, which has been in production for
years and has iterated through many of the same
problems: failure semantics, header control, body
buffering, and response propagation. Most of those
lessons are reflected in the requirements above
(fail-open/closed, static target declaration, response
header injection, client headers on denial, timeout
scoping).

Three `ext_authz` features were evaluated and
intentionally excluded from the initial scope due to
non-obvious return on effort:

1. **`allow_partial_message`** — sends a truncated body
   to the callout target when the request exceeds
   `max_body_bytes`, rather than rejecting with 413.
   Useful when "evaluate what you can" is better than
   rejecting outright. Excluded because it conflicts
   with the pipeline's `StreamBuffer` enforcement
   model, which rejects at the body-buffering layer
   before the filter runs. Supporting partial sends
   would require a different body mode or a
   filter-level buffer bypass, adding complexity for
   a use case that is unsafe by default for content
   safety APIs (a truncated prompt could pass a
   guardrail that the full prompt would fail).

2. **Per-route disable** — ext_authz supports disabling
   the filter on specific virtual hosts or routes.
   Praxis filter conditions already provide this
   capability (condition the filter on path, host, or
   header matches), so a dedicated per-route override
   mechanism would be redundant.

3. **Shadow mode** — ext_authz can run in shadow mode
   where the callout executes and the decision is
   recorded but not enforced. Valuable for safe
   rollout of new policy services. The `http_callout`
   filter can approximate this today by setting
   `failure_mode: open` and using `FilterResultSet`
   extraction with access log or tracing to observe
   decisions without enforcement. A first-class
   `shadow: true` config field could be added later
   if the approximation proves insufficient.

[`ext_authz`]: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter
