---
issue: https://github.com/praxis-proxy/praxis/issues/216
status: proposed
authors:
  - yehuditkerido
---

# Provider-Specific Token Usage Mapping

## What?

A library to extract token usage from AI provider responses
and convert them to a unified format.

Each provider returns token counts in different JSON structures:

| Provider  | Field Path |
|-----------|------------|
| OpenAI    | `usage.prompt_tokens`, `usage.completion_tokens` |
| Anthropic | `usage.input_tokens`, `usage.output_tokens` |
| Google    | `usageMetadata.promptTokenCount`, `usageMetadata.candidatesTokenCount` |
| Bedrock   | `inputTokenCount`, `outputTokenCount` (root level) |
| Azure     | Same as OpenAI |

This proposal adds a mapping library that:

1. Takes a provider identifier and response body
2. Parses the provider-specific JSON structure
3. Returns a unified `TokenUsage` struct

```rust
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
}
```

### Non-Goals

- Rate limiting logic (separate issue)
- Streaming support (separate issue #211)
- Exposing tokens in headers or metrics (separate issues)

## Why?

Other filters and systems need token counts in a consistent
format. Without this library, each consumer would need to
implement provider-specific parsing.

This is foundational work that enables:
- Token-based rate limiting
- Usage logging and metrics
- Cost tracking

## Open Question

This proposal focuses on extracting token usage only. Should
we consider a broader "provider response translator" that
normalizes the entire response to a common format (e.g., OpenAI)?

If there are future requirements that would benefit from full
response translation, it may be worth designing the library
with that in mind.
