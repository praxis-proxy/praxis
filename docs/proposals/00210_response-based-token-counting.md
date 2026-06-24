---
issue: https://github.com/praxis-proxy/praxis/issues/210
discussion: https://github.com/praxis-proxy/praxis/issues/210
status: accepted
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

## How?

### Requirements

1. A new `token_count` filter in `filter/src/builtins/http/ai/token_count.rs`.
2. The filter accepts a single required YAML key `provider` that selects
   the extraction strategy.
3. For non-streaming responses the full body is buffered and parsed once
   at end-of-stream.
4. For SSE streaming responses all chunks are buffered and the assembled
   event stream is scanned for token fields once the stream closes.
5. For Bedrock InvokeModel, token counts are read from HTTP response
   headers in `on_response`; no body parsing is performed.
6. Counts are written to `FilterContext` via `ctx.set_token_usage(input,
   output, total)` so that downstream filters (header injection, logging,
   rate limiting) can read them without parsing provider JSON themselves.
7. The filter delegates all provider-specific JSON parsing to the existing
   `token_usage` library (`filter/src/builtins/http/ai/token_usage/`).

### Answering the Open Questions

#### Provider identification

Provider identity is supplied explicitly via the `provider:` YAML key.
Auto-detection is not implemented. This keeps the filter stateless and
unambiguous — Azure and OpenAI share the same JSON schema, so
auto-detection would be unreliable for those two.

Supported values: `openai`, `anthropic`, `google`, `bedrock`,
`bedrock_invoke_model`, `azure`.

#### Streaming completion signal

The filter uses `BodyMode::StreamBuffer` — the proxy buffers all response
body bytes and calls `on_response_body` once with `end_of_stream: true`.
No per-chunk inspection is needed. Stream close (connection end) is the
authoritative trigger, which correctly handles both providers that emit
`[DONE]` (OpenAI) and providers that do not (Google Gemini).

#### Streaming token accumulation strategy per provider

| Provider | Strategy |
|---|---|
| OpenAI / Azure / Bedrock Converse | Scan all `data:` lines; return the last one that parses successfully — usage appears once in the terminal chunk |
| Google (Gemini) | Same as above — usage is in `usageMetadata` on the final chunk; no `[DONE]` sentinel |
| Anthropic | Two-pass scan: collect `input_tokens` from the `message_start` event, collect `output_tokens` from the `message_delta` event; combine at end |
| Bedrock InvokeModel | Header-only; no SSE parsing |

#### Bedrock InvokeModel extraction path

Handled directly by this filter in `on_response`. When `provider:
bedrock_invoke_model` is configured, the filter reads
`x-amzn-bedrock-input-token-count` and `x-amzn-bedrock-output-token-count`
from the upstream response headers and calls `ctx.set_token_usage` there.
`response_body_access` returns `BodyAccess::None` for this provider so no
body buffering occurs. No changes are required to the `token_usage` library.

#### Partial usage data

Only the final assembled payload is parsed. Intermediate SSE chunks that
contain partial usage fields are ignored. This avoids double-counting for
providers (e.g., Anthropic) that report counts in multiple events — each
relevant event is read exactly once, not summed.

### File Layout

```
filter/src/builtins/http/ai/
  token_count.rs          ← new: TokenCountFilter
  token_usage/            ← existing: TokenUsage, TokenUsageProvider, extract_token_usage
    mod.rs
    providers.rs
    tests.rs
```

### Filter Struct and Config

```rust
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenCountConfig {
    provider: ProviderKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProviderKind {
    /// Variant name matches YAML `snake_case` via serde. Note that
    /// `TokenUsageProvider` in `token_usage/mod.rs` uses `OpenAi`
    /// (capital I). A private `to_library_provider` conversion function
    /// maps `ProviderKind → TokenUsageProvider` at the call site.
    OpenAi,
    Anthropic,
    Google,
    Bedrock,
    BedrockInvokeModel,
    Azure,
}

pub struct TokenCountFilter {
    provider: ProviderKind,
}
```

### HttpFilter Trait Implementation

| Hook | Behaviour |
|---|---|
| `on_request` | No-op; returns `Continue` |
| `on_response` | Detects `text/event-stream` content type and stores an `is_sse` flag in `FilterContext` metadata. For `bedrock_invoke_model`, reads token headers and calls `ctx.set_token_usage` |
| `response_body_access` | `BodyAccess::None` for `bedrock_invoke_model`; `BodyAccess::ReadOnly` for all others |
| `response_body_mode` | `BodyMode::Stream` for `bedrock_invoke_model` (no buffering needed); `BodyMode::StreamBuffer { max_bytes: Some(8 MiB) }` for all others |
| `on_response_body` | Triggered once at `end_of_stream`. Reads the `is_sse` flag; calls `extract_from_sse` for SSE or `extract_token_usage` for JSON; writes result via `ctx.set_token_usage` |

### SSE Extraction Detail

```
extract_from_sse(provider, data)
  ├── Anthropic  → extract_anthropic_sse (two-event scan)
  └── all others → extract_last_usage_from_sse (scan data: lines, keep last valid)
```

`extract_anthropic_sse` scans the full buffered text, accumulates
`input_tokens` from `message_start` and `output_tokens` from
`message_delta`, then constructs a `TokenUsage` only when both are present.

### FilterContext Metadata

Token counts are stored under three keys accessible to downstream filters:

| Key | Value |
|---|---|
| `token.input` | Input/prompt token count as `u64` |
| `token.output` | Output/completion token count as `u64` |
| `token.total` | Sum (or provider-supplied total) as `u64` |

Written via `ctx.set_token_usage(input, output, total)`.

### Module Registration

Add to `filter/src/builtins/http/ai/mod.rs`:

```rust
#[cfg(feature = "ai-inference")]
mod token_count;

#[cfg(feature = "ai-inference")]
pub use token_count::TokenCountFilter;
```

Add to `filter/src/builtins/http/mod.rs`:

```rust
#[cfg(feature = "ai-inference")]
pub use ai::TokenCountFilter;
```

Add to `filter/src/builtins/mod.rs`:

```rust
#[cfg(feature = "ai-inference")]
pub use http::TokenCountFilter;
```

Register in `filter/src/registry.rs`:

```rust
registry.register_http("token_count", TokenCountFilter::from_config);
```

### YAML Configuration Example

```yaml
listeners:
  - name: gateway
    address: "127.0.0.1:8080"
    filter_chains:
      - token-counting

filter_chains:
  - name: token-counting
    filters:
      - filter: token_count
        provider: openai   # openai | anthropic | google | bedrock | bedrock_invoke_model | azure
      - filter: access_log
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: ai-provider
      - filter: load_balancer
        clusters:
          - name: ai-provider
            endpoints:
              - "127.0.0.1:8000"
```

[#20]: https://github.com/praxis-proxy/praxis/issues/20
[#211]: https://github.com/praxis-proxy/praxis/issues/211
[#212]: https://github.com/praxis-proxy/praxis/issues/212
[#214]: https://github.com/praxis-proxy/praxis/issues/214
[#216]: https://github.com/praxis-proxy/praxis/issues/216
