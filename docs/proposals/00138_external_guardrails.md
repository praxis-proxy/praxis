---
issue: https://github.com/praxis-proxy/praxis/issues/138
discussion: https://github.com/praxis-proxy/praxis/issues/138
status: proposed
authors:
  - liavweiss
stakeholders:
  - christinaexyou
  - shaneutt
---

# External Guardrail Provider Integration

## What?

Extend the guardrails filter to call external content safety providers
(NeMo Guardrails, AWS Bedrock Guardrails, etc.) via HTTP, inspect
request and response bodies, and act on the provider's verdict: pass,
block, or redact (mask).

A `GuardProvider` trait makes the filter generic - adding a new
provider means implementing one trait, not duplicating filter logic.
The first provider is NeMo Guardrails, using the `/v1/guardrail/checks`
endpoint.

### Goals

- Generic provider trait so new providers are a single-file addition
- Request-side guardrails: evaluate client requests before forwarding to the LLM
- Response-side guardrails: evaluate LLM responses before returning to the client
- Three outcomes: pass (forward unchanged), block (reject with 403), redact (mask sensitive content)
- Common message extraction from OpenAI Chat and MCP body formats, shared by all providers
- Coexistence with existing local string/regex rules in the same filter
- Error handling via the existing pipeline-level `failure_mode` (fail-open/fail-closed)

### Non-goals

- Replacing or modifying existing local rule matching (`rule.rs`)
- Streaming (SSE) response inspection in v1 (buffered-only)
- A generic webhook provider (each provider has its own trait implementation)

## Why?

### Motivation

The current guardrails filter supports local string and regex matching
on headers and request bodies. This catches simple patterns (e.g.
"DROP TABLE") but cannot detect nuanced policy violations, prompt
injection, or PII without calling a specialized external service.

External providers like NeMo Guardrails and AWS Bedrock Guardrails
offer content safety capabilities (topic blocking, PII detection,
prompt injection detection) that are impractical to replicate with
regex rules. Without this integration, operators must either deploy
a separate proxy layer for content safety or accept the limitations
of local pattern matching.

Integrating external providers into the existing guardrails filter
gives operators a single configuration point for both local rules
and external providers, without requiring changes to the proxy
architecture or adding new services in the request path.

### User Stories

- As a proxy operator, I want to route AI requests through NeMo
  Guardrails so that prompt injection and policy violations are
  detected before reaching the LLM.

- As a security engineer, I want LLM responses inspected by an
  external provider so that sensitive data (PII, secrets) is
  masked before reaching the client.

- As a platform engineer, I want to configure fail-open or
  fail-closed behavior when the external provider is unreachable
  so that I can balance availability and safety per deployment.

- As a proxy operator, I want to use local rules and an external
  provider together so that cheap header checks run first and
  expensive provider calls only happen when needed.

- As a developer, I want to add a new guardrail provider (e.g.
  Bedrock) by implementing a single trait so that I do not need
  to understand or modify the filter pipeline.

## Open Questions

1. **Response body async constraint** - `on_response_body` is currently sync.
   Blocked until [#358](https://github.com/praxis-proxy/praxis/issues/358) /
   [#390](https://github.com/praxis-proxy/praxis/pull/390) lands.
   Should we propose making `on_response_body` async?

2. **Streaming responses** - Should the response guardrails account for SSE streaming,
   or is buffered-only acceptable for v1?
