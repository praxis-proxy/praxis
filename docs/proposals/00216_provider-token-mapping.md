---
issue: https://github.com/praxis-proxy/praxis/issues/216
discussion: https://github.com/praxis-proxy/praxis/issues/216#issuecomment-4563373566
status: proposed
authors:
  - yehuditkerido
stakeholders:
  - shaneutt
  - twhgu
---

# Provider-Specific Token Usage Mapping

## What?

An internal module to extract token usage from AI provider responses
and convert them to a unified format.

Each provider returns token counts in different JSON structures:

| Provider  | Field Path |
|-----------|------------|
| OpenAI    | `usage.prompt_tokens`, `usage.completion_tokens` |
| Anthropic | `usage.input_tokens`, `usage.output_tokens` |
| Google    | `usageMetadata.promptTokenCount`, `usageMetadata.candidatesTokenCount` |
| Bedrock (InvokeModel) | `inputTokenCount`, `outputTokenCount` (root level) |
| Bedrock (Converse)    | `usage.inputTokens`, `usage.outputTokens` |
| Azure     | Same as OpenAI |

This proposal adds a mapping library that:

1. Takes a provider identifier and response body
2. Parses the provider-specific JSON structure
3. Returns a unified `TokenUsage` struct

```rust
pub struct TokenUsage { /* fields private */ }

impl TokenUsage {
    pub fn input_tokens(&self) -> u64;
    pub fn output_tokens(&self) -> u64;
    pub fn total_tokens(&self) -> u64;  // from response, or computed: input + output
}

pub enum TokenUsageProvider {
    OpenAi,
    Anthropic,
    Google,
    Bedrock,
    Azure,
}

/// Extracts token usage from a provider's JSON response body.
/// Returns `None` if usage data is missing or malformed.
pub fn extract_token_usage(provider: TokenUsageProvider, body: &[u8]) -> Option<TokenUsage>;
```

### Goals

- Extract token usage from 5 AI provider response formats
- Provide a unified `TokenUsage` representation
- Enable reuse by other filters ([#210], [#212]) and systems

### Non-Goals

- Rate limiting logic (separate issue)
- Streaming-specific logic: SSE parsing, chunk identification ([#211])
- Exposing tokens in headers or metrics ([#214])

**Note on streaming:** This module parses JSON containing `usage` data,
regardless of whether it came from a non-streaming response or the
final chunk of a streaming response. The JSON structure is the same
in both cases. Streaming-specific handling (SSE format, identifying
which chunk has usage) is #211's scope.

## Why?

### Motivation

Other filters and systems need token counts in a consistent
format. Without this library, each consumer would need to
implement provider-specific parsing separately.

This is foundational work for the Token Counting epic ([#20])
that enables:
- Token-based rate limiting
- Usage logging and metrics
- Cost tracking

### User Stories

- As a **rate limiting filter**, I need consistent token counts
  regardless of which AI provider was used, so that I can enforce
  limits without provider-specific code.

- As the **token counting filter ([#210])**, I need a mapping
  from each provider's field names to a unified format, so that I
  can parse any provider's response.

- As a **logging/metrics system**, I need token data in a
  predictable structure, so that I can track usage across all
  providers consistently.

## How?

### Module Location

The module lives at `filter/src/builtins/http/ai/token_usage/` with the
following structure:

```text
token_usage/
├── mod.rs       # Public API: TokenUsage, Provider, extract_token_usage()
├── providers.rs # Internal parsing logic per provider
└── tests.rs     # Unit tests
```

### Implementation Approach

1. **Private fields with public getters** - `TokenUsage` fields are private
   to allow internal representation changes without breaking the API.
   The `total_tokens()` getter returns the provider's value if present,
   otherwise computes `input + output`.

2. **Serde for JSON parsing** - Each provider has internal structs with
   `#[derive(Deserialize)]` that map to their specific JSON format.
   Field renaming (e.g., `camelCase`) is handled via serde attributes.

3. **Bedrock dual-format support** - The parser tries Converse API format
   first (`usage.inputTokens`), then falls back to InvokeModel format
   (`inputTokenCount` at root level).

4. **All-or-nothing parsing** - `extract_token_usage()` returns
   `Option<TokenUsage>`. If parsing succeeds, all fields are present.
   If any required field is missing or JSON is malformed, returns `None`.

### Public API

Exported from `praxis_filter` crate:

```rust
use praxis_filter::{TokenUsage, TokenUsageProvider, extract_token_usage};

let usage = extract_token_usage(TokenUsageProvider::OpenAi, response_body);
if let Some(u) = usage {
    // Access token counts via getters:
    // u.input_tokens(), u.output_tokens(), u.total_tokens()
}
```

## Open Question

This proposal focuses on extracting token usage only. Should
we consider a broader "provider response translator" that
normalizes the entire response to a common format (e.g., OpenAI)?

If there are future requirements that would benefit from full
response translation, it may be worth designing the library
with that in mind.

[#20]: https://github.com/praxis-proxy/praxis/issues/20
[#210]: https://github.com/praxis-proxy/praxis/issues/210
[#211]: https://github.com/praxis-proxy/praxis/issues/211
[#212]: https://github.com/praxis-proxy/praxis/issues/212
[#214]: https://github.com/praxis-proxy/praxis/issues/214
