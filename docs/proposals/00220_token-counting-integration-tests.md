---
issue: https://github.com/praxis-proxy/praxis/issues/220
discussion: https://github.com/praxis-proxy/praxis/issues/220
status: proposed
authors:
  - mkoushni
graduation_criteria:
  - All five provider formats covered by end-to-end tests with mock responses
  - Both non-streaming and SSE streaming scenarios tested
  - Example config in examples/configs/ai/ accepted by stakeholders
  - All integration tests passing in CI
stakeholders:
  - shaneutt
  - twghu
---

# Token Counting Integration Tests and Example Config

## What?

End-to-end integration tests and an example configuration for the
`token_count` filter. Tests use mock provider responses to verify
correct behaviour across all supported AI provider formats and
delivery modes without requiring live API credentials.

### Goals

- Cover all five provider response formats in end-to-end tests:
  OpenAI, Azure OpenAI, Anthropic, AWS Bedrock, and Google Gemini.
- Test both non-streaming JSON responses and SSE streaming responses.
- Verify that the filter is transparent: response bodies and status
  codes pass through unchanged in every scenario.
- Verify correct SSE accumulation for providers (Anthropic) that
  spread token counts across multiple chunks.
- Provide a worked example config in `examples/configs/ai/` that
  operators can copy and adapt.
- Confirm the filter composes cleanly with `access_log` in a single
  pipeline.

### Non-Goals

- Testing tracing log output directly (log capture is not part of the
  integration test harness; covered by filter unit tests).
- Live API calls to external providers.
- Benchmarking or performance testing of the filter.

## Why?

### Motivation

The `token_count` filter extracts token usage from upstream AI
provider responses, emitting counts as structured tracing events and
storing them as durable filter metadata. Without end-to-end tests
against realistic provider payloads, it is easy to miss per-provider
format differences — for example, Anthropic's SSE stream splits
`input_tokens` (in `message_start`) and `output_tokens` (in
`message_delta`) across separate chunks, while OpenAI consolidates
all counts in a single final chunk. A regression in either path could
silently drop token counts with no observable failure.

Example configs are the primary entry point for operators evaluating
a new filter. A single reference YAML that shows `token_count`
alongside `access_log` gives operators a concrete starting point
without requiring them to read the filter source.

### User Stories

- As a proxy operator, I want end-to-end tests for the `token_count`
  filter so that provider-specific regressions are caught before
  release.
- As a contributor, I want an example config showing `token_count`
  alongside `access_log` so that I can quickly set up a working
  pipeline without reading filter source code.
- As an SRE, I want the filter verified against SSE streaming
  responses so that I can confidently deploy it in front of streaming
  inference workloads.
