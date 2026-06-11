---
issue: https://github.com/praxis-proxy/praxis/issues/214
discussion: # TBD
status: proposed
authors:
  - noalimoy
graduation_criteria:
  - How? section with requirements and design
stakeholders:
  - shaneutt
  - szedan-rh
---

# Token Usage Response Headers

## What?

A filter that injects token usage counts as HTTP response
headers into downstream responses after token counts are
resolved.

The filter reads token usage from filter metadata
(provided by [#212]) and adds three headers to the
response:

| Header | Value |
|--------|-------|
| `X-Token-Input` | Input/prompt token count |
| `X-Token-Output` | Output/completion token count |
| `X-Token-Total` | Total token count (input + output) |

Headers are only injected when token data is available
in filter metadata. If the upstream response does not
contain token usage (e.g., error responses, non-AI
traffic), no headers are added. For streaming responses,
token counts are only resolved after the full body has
been accumulated ([#211]), parsed ([#216]), and written
to filter metadata ([#212]); header injection in this
case is an open design question (see below).

### Goals

- Inject token usage as HTTP headers into downstream
  responses
- Read token data from filter metadata without
  provider-specific logic
- Support conditional injection (only when data exists)
- Work with both streaming and non-streaming responses

### Non-Goals

- Token counting or parsing ([#210], [#216])
- Streaming token accumulation ([#211])
- Injecting tokens into FilterContext ([#212])

## Why?

### Motivation

Once token counts are available in filter metadata
([#212]), downstream systems need a simple way to access
them at the HTTP level. Response headers are the standard
mechanism for exposing metadata to clients, load
balancers, and monitoring tools without requiring body
parsing.

Without this filter, consumers of token data must:

- Parse provider-specific JSON response bodies
- Handle streaming vs non-streaming formats differently
- Implement provider-aware logic in every consuming system

This filter makes token usage universally accessible at
the HTTP layer, enabling infrastructure-level
consumption.

### User Stories

- As a **platform engineer**, I need token counts in
  response headers so that my billing system can track
  usage without parsing AI provider response bodies.

- As an **SRE**, I need token usage visible in HTTP
  headers so that I can build monitoring dashboards and
  alerts using standard HTTP tooling.

- As a **client application developer**, I need
  predictable headers for token counts so that I can
  display usage to end users without implementing
  provider-specific parsing.

- As a **load balancer operator**, I need token data at
  the HTTP level so that I can make routing decisions
  based on response cost without deep packet inspection.

## Open Questions

### Header naming convention

The proposed header names use the `X-Token-*` prefix.
Praxis already reserves the `x-praxis-*` prefix for
internal proxy metadata. Should downstream-facing token
headers follow a similar convention (e.g.,
`X-Praxis-Token-Input`), or is the current
`X-Token-Input` form sufficient?

### Streaming and header injection timing

For non-streaming responses the filter can add headers
before the body is sent. For streaming responses, token
counts are only available after the final chunk is
processed. In HTTP/1.1, response headers are sent before
the body, so injecting them after streaming completes is
not possible with standard headers. Should the filter
use HTTP trailers, buffer the response, or skip header
injection for streaming responses entirely? This will be
addressed in the How? section.

[#210]: https://github.com/praxis-proxy/praxis/issues/210
[#211]: https://github.com/praxis-proxy/praxis/issues/211
[#212]: https://github.com/praxis-proxy/praxis/issues/212
[#216]: https://github.com/praxis-proxy/praxis/issues/216

