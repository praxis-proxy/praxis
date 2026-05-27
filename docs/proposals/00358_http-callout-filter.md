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
- **Lakera Guard** — content-safety HTTP API for prompt
  injection, PII, and harmful content detection
  ([docs](https://docs.lakera.ai/docs/api/guard)).
- **NVIDIA NeMo Guardrails** — self-hosted guardrails
  server with configurable safety rails
  ([docs](https://docs.nvidia.com/nemo/guardrails/latest/user-guides/server-guide.html)).
