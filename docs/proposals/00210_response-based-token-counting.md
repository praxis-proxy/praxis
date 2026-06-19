---
issue: https://github.com/praxis-proxy/praxis/issues/210
discussion: https://github.com/praxis-proxy/praxis/issues/210
status: proposed
authors:
  - mkoushni
graduation_criteria:
  - How? section with requirements and design
stakeholders:
  - shaneutt
  - twghu
---

# Response-Based Token Counting from Provider JSON

## What?

A filter that extracts token usage from AI provider response bodies
and writes the counts to filter metadata for downstream consumers.

The filter reads the upstream response body, identifies the provider,
and delegates JSON parsing to the provider mapping library ([#216]).
Once token counts are resolved, they are written to `FilterContext`
([#212]) so that downstream filters (rate limiting, logging, cost
tracking, header injection) can consume them without coupling to
provider-specific formats.

For streaming responses, the filter accumulates SSE chunks until the
stream completes, then parses the final usage payload from the
terminal chunk or `[DONE]` sentinel ([#211]).

Provider extraction sources:

| Provider | Source | Field path |
|----------|--------|------------|
| OpenAI   | JSON body | `usage.prompt_tokens`, `usage.completion_tokens` |
| Anthropic | JSON body | `usage.input_tokens`, `usage.output_tokens` |
| Google (Gemini) | JSON body | `usageMetadata.promptTokenCount`, `usageMetadata.candidatesTokenCount` |
| Bedrock (Converse) | JSON body | `usage.inputTokens`, `usage.outputTokens` |
| Bedrock (InvokeModel) | HTTP response headers | `x-amzn-bedrock-input-token-count`, `x-amzn-bedrock-output-token-count` |
| Azure | JSON body | Same as OpenAI |

> **Note:** Bedrock InvokeModel is the only provider that does not return token counts
> in the response body. Counts are delivered as HTTP response headers instead, making
> its extraction path fundamentally different from all other providers. This distinction
> must be reflected in both the [#216] mapping library and the How? design here.

### Goals

- Extract token usage from non-streaming provider responses
- Extract token usage from streaming (SSE) provider responses
- Write `token_input`, `token_output`, and `token_total` to `FilterContext`
- Delegate all provider-specific JSON parsing to [#216]
- Avoid CPU-bound client-side estimation when provider counts are available

### Non-Goals

- Client-side token estimation (tiktoken-style pre-request counting)
- Token-based rate limiting (separate concern, reads from `FilterContext`)
- Injecting token headers into downstream responses ([#214])
- Provider response translation or normalization beyond token fields

## Why?

### Motivation

AI providers return token usage as the authoritative, zero-CPU-cost
source of truth — either in response bodies (OpenAI, Anthropic, Google,
Bedrock Converse) or in HTTP response headers (Bedrock InvokeModel).
Without a filter that extracts and centralises these counts, every
downstream system (rate limiter, logger, cost tracker) must independently
implement provider-specific parsing and SSE accumulation logic.

This filter is the entry point of the Token Counting epic ([#20]).
It reads provider responses once and makes counts available to all
downstream filters via `FilterContext`, keeping provider-specific
logic in one place.

Provider-returned counts are preferred over client-side estimation
because they are accurate, require no tokenizer dependencies, and
add no CPU overhead to the request path.

### User Stories

- As a **rate limiting filter**, I need token counts written to
  `FilterContext` so that I can enforce per-user token budgets
  without parsing AI response bodies myself.

- As a **cost tracking system**, I need accurate input and output
  token counts per request so that I can attribute spend to the
  correct account without re-implementing provider JSON schemas.

- As a **logging filter**, I need token usage available in
  `FilterContext` at response time so that I can emit structured
  usage records for every AI request.

- As a **platform operator**, I need a single filter to handle all
  supported providers so that adding a new AI backend does not
  require updating multiple downstream filters.

## Open Questions

### Provider identification

The filter needs to know which provider schema to use when parsing
a response. Should provider identity be resolved from the upstream
route configuration, a request header set by a preceding filter, or
auto-detected from the response body shape? Auto-detection avoids
configuration overhead but may be ambiguous for providers with
overlapping schemas (e.g., Azure mirrors OpenAI).

### Streaming completion signal

For SSE streams, the filter must detect when the stream has ended
to trigger final parsing. Should it rely solely on the `[DONE]`
sentinel, on stream close, or on both? Providers do not uniformly
emit `[DONE]` (Google Gemini omits it), so stream close may need
to be the authoritative signal.

### Streaming token accumulation strategy per provider

Providers differ in how and when token counts appear across SSE events:

- **OpenAI**: both `prompt_tokens` and `completion_tokens` arrive together
  in the final chunk, just before the `[DONE]` sentinel.
- **Anthropic**: counts are split across two distinct event types —
  `input_tokens` appears in the `message_start` event at the beginning
  of the stream, while `output_tokens` appears in the `message_delta`
  event near the end. The filter must track both events independently
  and hold `input_tokens` in state until the stream completes.
- **Google (Gemini)**: usage appears in `usageMetadata` on the final chunk;
  no `[DONE]` sentinel is emitted, so stream close is the trigger.

This means a single "read the last chunk" strategy is insufficient.
The How? design must specify a per-provider accumulation model, or a
general event-tagging mechanism that each provider's parser populates.

### Bedrock InvokeModel extraction path

Bedrock InvokeModel returns token counts as HTTP response headers
(`x-amzn-bedrock-input-token-count`, `x-amzn-bedrock-output-token-count`),
not in the JSON body. Should this filter handle header-based extraction
directly, or should it be scoped out as a separate extraction path with
a dedicated design in the How? section? If included, the filter must
inspect response headers before body parsing, and [#216] must be updated
to reflect this.

### Partial usage data

Some providers include incremental usage fields in intermediate SSE
chunks as well as the final chunk. Should the filter accumulate and
sum these, or only use the final chunk's usage payload? Summing
intermediate chunks could double-count if the final chunk already
contains the total.
