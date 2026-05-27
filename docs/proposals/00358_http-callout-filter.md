---
issue: https://github.com/praxis-proxy/praxis/issues/358
discussion: https://github.com/praxis-proxy/praxis/discussions/87
status: proposed
authors:
  - usize
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
semantics — without requiring ext-proc.

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
- **Lakera Guard** — content-safety HTTP API for prompt
  injection, PII, and harmful content detection
  ([docs](https://docs.lakera.ai/docs/api/guard)).
- **NVIDIA NeMo Guardrails** — self-hosted guardrails
  server with configurable safety rails
  ([docs](https://docs.nvidia.com/nemo/guardrails/latest/user-guides/server-guide.html)).

## How?

### Requirements

- Async HTTP client available during `on_request`,
  `on_response`, and `on_request_body` (the async hooks)
- Connection pooling to callout targets, independent of
  Pingora's upstream pool
- Per-target timeout configuration
- Per-target circuit breaker state that survives config
  reload
- Configurable fail-open / fail-closed per callout instance
- Callout targets statically declared in config (no runtime
  URL construction)
- TLS support per callout target
- Recursion depth guard via header injection
- Tracing spans for callout requests, parented under the
  request span
- Callout latency histogram and outcome counter metrics
- Sub-request response size limit (default: 1 MiB)
- At-least-once execution semantics; filters making
  callouts with side effects must be idempotent (see
  [discussion #87, processor safety contract](https://github.com/praxis-proxy/praxis/discussions/87))

### Design

#### HTTP client ownership and lifecycle

Filters are stateless value objects rebuilt on config
reload. An HTTP client with connection pooling must outlive
individual filter instances and survive reloads — the same
lifecycle problem that `KvStoreRegistry` solves for
key-value state.

**Proposed solution: `CalloutClientRegistry`.**
A `CalloutClientRegistry` lives at the server level alongside
`KvStoreRegistry` and `HealthRegistry`. It vends per-target
`reqwest::Client` instances keyed by callout target name.
Each client has its own connection pool, TLS config, and
timeout defaults. The registry is passed to filters via
`HttpFilterContext` and persists across config reloads.

On reload, targets whose config is unchanged reuse their
existing client. Targets whose config changed (URL, TLS,
timeout) get a new client; the old one drains gracefully.
Targets removed from config are cleaned up after in-flight
requests complete.

```rust
pub struct CalloutClientRegistry {
    clients: Arc<DashMap<Arc<str>, Arc<CalloutClient>>>,
}

pub struct CalloutClient {
    client: reqwest::Client,
    circuit_breaker: CircuitBreaker,
    target_url: Uri,
    timeout: Duration,
}
```

#### Timeout budget

**Proposed solution: independent timeouts with a
simple assertion at load time.**


Each callout target has a configured timeout. By default,
this timeout is independent — the callout runs for up to its
configured duration regardless of the overall request
budget.

To avoid overengineering a solution to the problem of dynamic
timeout budget tracking and allocation, a simple assertion will
be made at load time ensuring that no callout's timeout is
greater than the listener's request timeout.

#### Cancellation on client disconnect

**Proposed solution: inline polling, no detached tasks.**
The callout future is `.await`ed directly inside
`on_request` / `on_request_body`. When Pingora detects a
client disconnect, it drops the request future, which drops
the callout future, which cancels the in-flight HTTP request
via `reqwest`'s drop-based cancellation.

The constraint is that a single callout filter can
only make one callout at a time (no parallelism within a
filter, thus why fan-outs are a non-goal.)

#### Recursion guard

**Proposed solution: depth header with configurable limit.**
Every outbound callout request carries an
`X-Praxis-Callout-Depth` header. On inbound requests, the
filter reads this header. If the depth exceeds
`max_callout_depth` (default: `1`), the callout is skipped
and treated as a failure (subject to `failure_mode`).

The header is incremented, not set, so nested proxies that
both run callout filters accumulate depth correctly. The
header is stripped from upstream requests (non-callout
traffic) by default.

A default value of `1` assumes that in normal use cases
any sort of recursion indicates a misconfiguration.

#### Response body phase exclusion

**Proposed solution: document the constraint, enforce at
build time.**
`on_response_body` is synchronous — sub-requests cannot be
issued from this phase without blocking a Pingora worker
thread. The callout filter operates only in `on_request`
(header-only callouts) and `on_request_body` (body-forwarding
callouts). The `on_response` hook is available for
response-phase callouts (e.g. output moderation) that only
need response headers.

Build-time validation rejects callout filter configurations
that would require response body access (a future concern
if response body callouts are added later, which will be
desirable for response guardrails).

#### Callout request construction

**Proposed solution: two modes — `headers_only` and
`request_body`.**

- `headers_only`: the callout request body is empty or a
  static JSON payload defined in config. The filter operates
  in `on_request` with no body access. Suitable for
  authorization checks where the request URI, method, and
  headers are sufficient.

- `request_body` (shown in the Lakera Guard example): the
  incoming request body is buffered and forwarded as the
  callout request body. The filter declares
  `StreamBuffer { max_bytes }` and issues the callout in
  `on_request_body` when `end_of_stream` is true.

A third mode — structured body construction from request
context (headers, metadata, body fields) — is deferred.
When needed, it should integrate with the condition
expression work
([#191](https://github.com/praxis-proxy/praxis/issues/191))
rather than inventing a separate DSL.

#### Circuit breaker state

**Proposed solution: circuit breaker lives in
`CalloutClient`, owned by `CalloutClientRegistry`.**
Each `CalloutClient` contains a `CircuitBreaker` alongside
the `reqwest::Client`. Because the registry survives config
reloads, circuit breaker state (failure count, last failure
time, open/half-open/closed) persists naturally.

The circuit breaker uses a count-based failure threshold
with a time-based recovery window:

- **Closed**: requests flow normally; consecutive failures
  are counted.
- **Open**: requests are immediately rejected (subject to
  `failure_mode`) without making the callout. Opens when
  `failure_threshold` consecutive failures are reached.
- **Half-open**: after `recovery_timeout` elapses, one
  probe request is allowed. Success resets to closed;
  failure resets to open.

```yaml
circuit_breaker:
  failure_threshold: 5
  recovery_timeout: 30s
```

Circuit breaker state transitions emit tracing events and
increment a `praxis_callout_circuit_breaker_state` gauge
metric.

#### Inter-filter state

**Proposed solution: field extraction into filter results,
with callout response available via context.**
The callout response (status code, headers, body) is stored
on the request context keyed by callout name:

```rust
pub struct CalloutResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}

// On HttpFilterContext:
pub callout_responses: HashMap<Arc<str>, CalloutResponse>,
```

The `response.extract` config is a convenience layer that
auto-promotes specific JSON fields from the callout response
body into `FilterResultSet` entries for branch-chain
evaluation. This keeps simple use cases (Lakera's
`$.flagged`) declarative in config.

Downstream filters that need richer access can read
`ctx.callout_responses.get("lakera-guard")` directly. The
response body is capped at a configurable
`max_response_bytes` (default: 1 MiB) to prevent memory
issues.

This avoids the 256-byte `filter_metadata` limit for
structured data while keeping the common path simple.

#### Memory bounding

Per [discussion #87](https://github.com/praxis-proxy/praxis/discussions/87),
sub-requests create memory pressure: each in-flight request
holds the buffered client body, the sub-request connection,
and the sub-request response simultaneously.

Mitigations:

- **Bounded body retention**: once the callout filter has
  forwarded the request body, it returns `Release` so the
  pipeline does not hold the buffer while awaiting the
  callout response.
- **Response size limit**: `max_response_bytes` per callout
  (default: 1 MiB). Responses exceeding this are truncated
  and treated as failures.
- **Concurrency limit**: a global maximum number of
  concurrent in-flight callouts across all requests
  (`max_concurrent_callouts`, default: 128). Exceeding
  this skips the callout and applies `failure_mode`
  semantics rather than queuing unboundedly.
