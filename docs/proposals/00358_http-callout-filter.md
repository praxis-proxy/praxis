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
          phase: request_body       # default; sends buffered body
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
  in `praxis-ext-proc`.
- **NGINX auth_request** — sub-request to an authorization
  endpoint; response status controls access.
- **Lakera Guard** — HTTP content-safety API
  (`POST /v2/guard`) that returns structured
  `{"flagged": …, "categories": {…}}` decisions.
  Used throughout this proposal as the motivating
  example of an inline policy callout.
- **OpenAI Moderation API** — similar HTTP endpoint
  for content classification.

## How?

Via a library supporting a call-out client, safely usable within filters.
A generic HTTP call out filter will be supplied both as a utility and a
reference implementation.

### Requirements

1. **HTTP client pool** — per-instance, connection-pooled
   HTTP client independent of Pingora's upstream pool.
   Never shared across filter instances to prevent
   credential and connection leakage in multi-tenant
   deployments.
2. **SSRF prevention** — callout targets fully declared
   in config. The filter never constructs a URL from
   request data.
3. **Per-target circuit breaker** — independent from the
   traffic management circuit breaker filter; the two
   have different operational models and should evolve
   separately.
4. **Response extraction** — [RFC 9535] JSONPath
   extraction from callout responses into
   `FilterResultSet` for branch-chain evaluation.
5. **Body forwarding** — buffer the inbound request body
   via `StreamBuffer` and send it as the callout POST
   body. The pipeline enforces `max_body_bytes` with
   413.
6. **Header forwarding** — forward select downstream
   request headers to the callout target for trace
   correlation (e.g. `traceparent`, `x-request-id`).
7. **Response header injection** — inject allowlisted
   callout response headers into the upstream request,
   enabling classify-then-route patterns.
8. **Client headers on denial** — forward allowlisted
   callout response headers to the client in rejection
   responses (e.g. `Retry-After`).
9. **Loop prevention** — depth header
   (`x-praxis-callout-depth`) prevents infinite
   re-entry when the callout target routes back to
   the proxy.
10. **Timeout scope** — timeout covers only the outbound
    HTTP request, not inbound body buffering.
11. **Tracing** — per-callout `tracing` span with target
    URL, response status, latency, and circuit breaker
    state.

[RFC 9535]: https://www.rfc-editor.org/rfc/rfc9535

### Design

#### Crate layout

```text
server
  ├── praxis-http-callout (filter, opt-in feature flag)
  │     ├── praxis-core (feature = "callout")
  │     ├── praxis-filter (HttpFilter, FilterResultSet)
  │     └── serde_json_path
  │
  └── praxis-filter
        └── praxis-core (feature = "callout")
              └── callout (available to any builtin)

core/src/callout/  (praxis_core::callout, feature = "callout")
  └── reqwest [rustls-tls]
```

**`praxis_core::callout`** (`core/src/callout/`) —
shared HTTP callout client module: pooled
`reqwest::Client`, circuit breaker, timeout, failure
mode, tracing. Gated behind the `callout` cargo
feature flag on `praxis-core` so that downstream
crates only pay the dependency cost when they need
outbound HTTP. Lives in `praxis-core` so custom
proxy builds using the Praxis framework have access
to it without depending on `praxis-filter`. Contains
its own circuit breaker (the traffic management
filter's breaker spans two phases; the callout's
operates within a single async call).

**`praxis-http-callout`** (`filter/http-callout/`) —
thin `HttpFilter` wrapper wiring the callout client
into the pipeline with config-driven target, JSONPath
extraction, and body forwarding. Reference
implementation. Opt-in via cargo feature flag on
`praxis-filter`, gating the satellite crate dependency
and filter registration.

#### Why reqwest

The callout client needs an async HTTP client with
TLS, connection pooling, and timeout support —
independent of Pingora's upstream pool. `reqwest`
is chosen because:

- **Battle-tested** — the most widely used async HTTP
  client in the Rust ecosystem, used by `wiremock`,
  cloud SDKs, and many production proxies.
- **Feature coverage** — connection pooling, redirect
  policy, `no_proxy`, `rustls-tls`, and per-request
  timeout are built in, avoiding hand-rolled pool
  management.
- **Stable API surface** — mature enough that
  breakage risk is low for a long-lived dependency.

**Dependency cost:** reqwest pulls in hyper, h2,
quinn, tower, and rustls transitively. To avoid
imposing this on downstream crates that only need
config types, the callout module is gated behind a
`callout` cargo feature flag on `praxis-core` from
day one. Crates that need outbound HTTP callouts
opt in with `praxis-core = { features = ["callout"] }`.

Alternatives considered: `hyper` directly (requires
manual pool and TLS management), Pingora's upstream
pool (wrong abstraction — it routes to configured
clusters, not arbitrary URLs, and shares connections
across tenants).

#### Filter struct

```rust
pub struct HttpCalloutFilter {
    client: reqwest::Client,
    url: Arc<str>,
    timeout: Duration,
    headers: Vec<(HeaderName, HeaderValue)>,
    forward_headers: Vec<HeaderName>,
    extractions: Vec<Extraction>,
    inject_headers: Vec<HeaderName>,
    on_denied_headers: Vec<HeaderName>,
    failure_mode: FailureMode,
    status_on_error: u16,
    circuit_breaker: Option<CircuitBreaker>,
    max_depth: u8,
    max_body_bytes: usize,
}
```

#### Extraction

JSONPath expressions ([`serde_json_path`]) are parsed
at config load time — invalid expressions fail
validation. At runtime, the first match is coerced to
a string and written to `FilterResultSet`:

- Booleans: `true` → `"true"`
- Numbers: decimal representation
- Strings: as-is
- Arrays/objects: compact JSON
- `null` or no match: nothing written

Branch chains compare extracted values as exact
string matches (`on_result.value: "true"`). For
object or array values, the compact JSON
representation is written verbatim — branch chains
would need to match the exact serialized form, which
is brittle. Prefer JSONPath expressions that extract
leaf scalars (e.g. `$.flagged` rather than
`$.categories`) when the result feeds a branch
condition.

[`serde_json_path`]: https://crates.io/crates/serde_json_path

#### Request flow

The entry point depends on the configured `phase`:

```text
phase: request_headers          phase: request_body (default)
  on_request()                    on_request_body(end_of_stream=true)
  │  (empty body)                 │  (buffered request body)
  │                               │
  └──────────────┬────────────────┘
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
  │   body: buffered request body (or empty)
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

When `phase: request_headers`, the filter does not
declare body access and the callout fires with an empty
body. This is useful for header-only policy checks or
requests without a body.

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

Each filter instance owns its own `CalloutClient`,
which wraps a `reqwest::Client` (connection pool)
and a `CircuitBreaker`. Clients are never shared
across different filter instances. This prevents:

1. **Credential leakage** — HTTP/2 coalescing and TLS
   session caching could reuse a connection
   established with one tenant's credentials for
   another's request.
2. **Timing side-channels** — a shared pool lets one
   tenant's callout latency affect another's
   connection availability.

Clients use `rustls-tls`, capped
`pool_max_idle_per_host`, `no_proxy`, and optional
mTLS client certificates.

#### Connection pool survival across reloads

On config reload, Praxis rebuilds the filter pipeline
and drops old filter instances. Without mitigation,
this kills `reqwest::Client` connection pools and
causes a burst of new TLS handshakes to callout
targets.

To preserve warm pools, a `ConnectionPoolRegistry`
(following the `KvStoreRegistry` pattern) caches
`reqwest::Client` instances keyed by connection
config (URL origin, TLS settings, pool size). The
registry is created once at server startup, stored
in `ServerState`, and passed through unchanged on
reload — the same wiring used by `KvStoreRegistry`
in `watcher.rs` and `reload.rs`.

During `from_config`, a filter requests a
`reqwest::Client` from the registry. If an existing
client matches the connection config, it is reused;
otherwise a new one is built and cached. The
`CalloutClient` is always rebuilt with a fresh
`CircuitBreaker` reflecting the current config, so
changes to `failure_threshold` or `recovery_timeout`
take effect immediately on reload. Circuit breaker
state does reset. For load-shedding breakers this is
uncontroversial, but the callout breaker also serves
a safety role: a fail-closed guardrail that was
correctly shedding traffic to an unreachable service
will briefly re-enable callouts after a reload. This
is acceptable because the breaker trips again after
`failure_threshold` consecutive failures — typically
one to five requests — and fail-closed mode rejects
those requests, so the exposure window is bounded by
the threshold, not the outage duration. The
alternative — preserving breaker state across
reloads — would prevent config changes to
`failure_threshold` and `recovery_timeout` from
taking effect, which is worse for operability.

Clients not referenced after a reload are left in
the registry until their idle connections time out
naturally via `reqwest`'s pool idle timeout.

#### Loop prevention

Every outbound callout injects
`x-praxis-callout-depth: <N+1>` where N is the
current depth (0 if absent on the inbound request).
Before making a callout, the filter reads this header;
if the depth meets or exceeds `max_depth` (default: 1,
meaning no re-entry), the filter applies `failure_mode`
without making the call.

The `x-praxis-callout-depth` header is reserved and
internal. It must be stripped from external client
requests on ingress, following the same pattern as
other `x-praxis-*` headers, so external clients cannot
forge it to bypass the callout or inflate the depth to
suppress it.

Importantly, this works across proxy hops: if two
Praxis instances chain callouts through each other,
the depth increments at each hop and terminates at the
configured max.

#### SSRF prevention

Validation in `from_config()`:

- URL must be a valid absolute URI with `http`/`https`
  scheme and non-empty host
- No `${...}` template variables in the URL (env var
  expansion in headers is handled by the config loader)
- Only the request body is forwarded; the callout URL
  is never constructed from request data

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
  phase: request_body         # or request_headers (empty body)
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
max_depth: 1                  # default; depth >= 1 is rejected (no re-entry)
circuit_breaker:              # optional
  failure_threshold: 5
  recovery_timeout: 30s       # time in Open before probing
```

The circuit breaker uses a standard Closed → Open →
Half-Open state machine. After `failure_threshold`
consecutive failures, the breaker transitions to Open
and rejects all callouts for `recovery_timeout`.
After the timeout elapses, a single probe request is
allowed through (Half-Open). If the probe succeeds,
the breaker closes; if it fails, the breaker reopens
for another `recovery_timeout` window. Only one probe
is permitted at a time — concurrent requests during
the probe window are rejected.

### Implementation

Proposed PR sequence:

- **PR 1** — `praxis_core::callout` module
  (`core/src/callout/`) with the shared HTTP callout
  client: `reqwest` client pool, circuit breaker,
  timeout, failure mode handling, and tracing. Unit
  tests with a local `wiremock` server. Lives in
  `praxis-core` so it is available to custom proxy
  builds.

- **PR 2** — `praxis-http-callout` satellite crate
  (`filter/http-callout/`) with `HttpCalloutFilter`
  struct, config parsing, SSRF validation, JSONPath
  extraction, body forwarding, and unit tests.
  Registered in the server binary behind a feature
  flag. Includes integration test and example config:
  Lakera Guard example in `examples/configs/ai/`,
  functional integration test in
  `tests/integration/tests/suite/examples/` using a
  mock HTTP server that returns Lakera-shaped
  responses.

### Relationship to #138 (AI Guardrails)

The `ai_guardrails` filter (#138, #577, #578) can
depend on `praxis-callout` directly for its
`NemoProvider` HTTP calls — no need to build its own
client or duplicate timeout/retry logic. The
`http_callout` filter remains the config-driven option
for operators wiring arbitrary HTTP policy services
into the pipeline without a dedicated filter.

### Addendum: Lessons from Envoy ext_authz

This design draws from Envoy's [`ext_authz`] filter.
Three ext_authz features were excluded due to
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
