---
issue: https://github.com/praxis-proxy/praxis/issues/211
discussion: https://github.com/praxis-proxy/praxis/issues/20
status: proposed
authors:
  - szedan-rh
graduation_criteria:
  - Token counts available for streaming responses across all five providers
  - Token counts available for non-streaming responses
  - Downstream filters can consume counts without provider-specific logic
  - Response bodies pass through unmodified
stakeholders:
  - shaneutt
  - twghu
---

# Streaming Token Counting via SSE Event Parsing

## What?

A filter that makes token usage counts available for AI
inference responses, regardless of whether the response is
streamed or returned as a single payload. Operators get
unified token counts (input, output, total) that downstream
capabilities (rate limiting, logging, cost tracking) can
consume without needing to understand provider-specific
response formats.

### Goals

- Provide token counts for streaming (SSE) responses across
  all five supported providers (OpenAI, Anthropic, Google
  Gemini, Bedrock, Azure).
- Provide token counts for non-streaming JSON responses
  within the same filter, so operators need only one
  pipeline configuration for both delivery modes.
- Present a provider-agnostic interface to downstream
  consumers: uniform token counts regardless of which
  provider generated the response.
- Be transparent: response bodies and status codes pass
  through unchanged.

### Non-Goals

- Client-side token estimation before the response arrives
  ([#219]).
- Injecting token usage into response headers ([#214]).
- Token-based rate limiting ([#21]).
- Full response normalization across providers -- this filter
  extracts token usage only.

## Why?

### Motivation

**Streaming is the dominant path for AI inference.** Production
AI workloads overwhelmingly use streaming (`stream: true`) to
minimize time-to-first-token latency. All major providers
(OpenAI, Anthropic, Google) use SSE as their primary streaming
transport, and user-facing applications target sub-1s TTFT
which requires streaming delivery ([Zylos Research, 2026]).
A token counting system that only handles non-streaming
responses misses the majority of production traffic, leaving
rate limiting and cost tracking incomplete.

[Zylos Research, 2026]: https://zylos.ai/research/2026-03-28-llm-output-streaming-token-delivery-architectures/

**The foundation exists but nothing uses it yet.** Provider
response parsing ([#216]) and the shared token count fields
([#212]) have been completed. The missing piece is a filter
that ties these together: reading responses, extracting
counts, and making them available to the rest of the pipeline.

**Each provider reports token usage differently during
streaming.** Some providers include counts only in the final
event, others spread them across multiple events, and others
report cumulative totals in every event. A proxy-level
solution absorbs this complexity so that downstream consumers
see a single consistent interface regardless of provider.

**It unblocks the entire downstream value chain.** Token
rate limiting ([#21]) cannot enforce quotas without token
counts. GenAI observability ([#239]) needs token metrics for
OpenTelemetry semantic conventions. Cost tracking, quota
enforcement, and intelligent routing ([#97]) all depend on
knowing how many tokens flowed through a request. This filter
is the critical path item for the Token Counting epic.

### User Stories

- As a **proxy operator**, I want token counts extracted from
  streaming AI responses so that rate limiting and cost tracking
  work for all traffic, not just non-streaming requests.

- As a **platform engineer**, I want a single filter that covers
  both streaming and non-streaming responses so that I don't need
  separate pipeline configurations per delivery mode.

- As a **filter author** building token rate limiting, I want
  token counts available regardless of provider or delivery mode
  so that my filter doesn't need provider-specific parsing logic.

- As an **SRE**, I want the token counting filter to be
  transparent (no body mutation, no status code changes) so that
  I can add it to existing AI pipelines without risk of breaking
  responses.

[#20]: https://github.com/praxis-proxy/praxis/issues/20
[#21]: https://github.com/praxis-proxy/praxis/issues/21
[#97]: https://github.com/praxis-proxy/praxis/issues/97
[#210]: https://github.com/praxis-proxy/praxis/issues/210
[#211]: https://github.com/praxis-proxy/praxis/issues/211
[#212]: https://github.com/praxis-proxy/praxis/issues/212
[#214]: https://github.com/praxis-proxy/praxis/issues/214
[#216]: https://github.com/praxis-proxy/praxis/issues/216
[#219]: https://github.com/praxis-proxy/praxis/issues/219
[#239]: https://github.com/praxis-proxy/praxis/issues/239
[#474]: https://github.com/praxis-proxy/praxis/pull/474
[#491]: https://github.com/praxis-proxy/praxis/pull/491
[#493]: https://github.com/praxis-proxy/praxis/pull/493
[#510]: https://github.com/praxis-proxy/praxis/pull/510
