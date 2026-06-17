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

## How?

### Requirements

- One example config at `examples/configs/ai/token-counting.yaml`
  that operators can copy, verified by its own test file.
- One test file at
  `tests/integration/tests/suite/examples/token_counting.rs`
  registered under `#[cfg(feature = "ai-inference")]` in
  `tests/integration/tests/suite/examples/mod.rs`.
- Tests are self-contained: each test spins up a `Backend::fixed`
  mock, starts the proxy, sends a request, and asserts on response
  headers and body — no external services, no persistent state.
- Token counts are observed via `X-Token-Input`, `X-Token-Output`,
  and `X-Token-Total` response headers injected by the
  `x_token_headers` filter ([#214]) which is included in the
  example pipeline alongside `token_count`.

### Example Config

`examples/configs/ai/token-counting.yaml` — a single-listener proxy
that routes all traffic to a configurable upstream and chains
`token_count` → `x_token_headers` → `access_log`:

```yaml
static_backends:
  - name: ai-provider
    endpoints:
      - address: 127.0.0.1:8000

listeners:
  - address: 127.0.0.1:8080
    routes:
      - match:
          path_prefix: /
        pipeline:
          upstream: ai-provider
          filters:
            - kind: token_count
              provider: openai
            - kind: x_token_headers
            - kind: access_log
```

`token_count` runs first and writes counts into `FilterContext`.
`x_token_headers` reads from `FilterContext` and injects
`X-Token-Input`, `X-Token-Output`, and `X-Token-Total` into the
downstream response. `access_log` runs last and emits a structured
`tracing::info!` log line that includes the token fields alongside
the standard request/response metadata — no custom format string is
needed, as the filter reads directly from `FilterContext`.

> **Note:** `access_log` uses `deny_unknown_fields`; it does not
> accept a `format:` key. Token counts appear in the log output as
> structured fields (e.g., `token_input=10 token_output=20
> token_total=30`) once [#212] adds those fields to
> `HttpFilterContext` and `access_log` is updated to emit them.
> Until then, token visibility is via `X-Token-*` response headers
> only.

The `provider` field is set to `openai` in the reference config.
Tests for other providers build their YAML inline using `patch_yaml`
rather than shipping five separate example files.

### File Layout

```text
examples/configs/ai/
└── token-counting.yaml                         # new example config

tests/integration/tests/suite/examples/
└── token_counting.rs                           # new test file
```

### Streaming Header Injection Timing

HTTP response headers are transmitted before the body, so
`x_token_headers` cannot inject `X-Token-*` headers into the
initial response for SSE streams — the headers have already been
sent by the time the final chunk with usage data is processed.

The following strategies are in scope for the How? design; the
chosen approach must be reflected in the test assertions:

| Strategy | Mechanism | Test assertion |
|----------|-----------|----------------|
| **HTTP Trailers** | `x_token_headers` emits trailers after stream close | Assert on HTTP trailers, not headers |
| **Access log only** | `token_count` writes counts to `FilterContext`; no client-visible injection for streaming | Assert on captured log metadata or `filter_metadata` |
| **Full buffering** | Proxy buffers the entire SSE body before forwarding | Assert on regular response headers; note latency trade-off |

The integration tests must explicitly verify whichever strategy is
chosen. If HTTP Trailers are used, the raw TCP read must scan the
trailer block after the terminal `0\r\n\r\n` chunk. If only
`access_log` captures the counts, the streaming test assertions
focus on body passthrough and metadata presence, not
`X-Token-*` headers.

This decision is an open design question resolved in the How? phase
of [#214].

### Test Structure

Each test function follows the pattern established by
`access_logging.rs` and `a2a.rs`:

1. Start a `Backend::fixed` mock that returns a canned provider
   response with the appropriate `Content-Type` header.
2. Load and patch the YAML config. `patch_yaml` performs string
   substitution of listener/backend port addresses only — it has
   no awareness of YAML keys. To exercise a different provider code
   path, either build the full YAML inline (see YAML helpers in
   `a2a.rs`) or apply an explicit string replacement on top of
   `patch_yaml`, for example:
   ```rust
   let yaml = std::fs::read_to_string(example_config_path("ai/token-counting.yaml")).unwrap();
   let yaml = yaml.replace("provider: openai", "provider: anthropic");
   let patched = patch_yaml(&yaml, proxy_port, &port_map);
   ```
   (`load_example_config_raw` does not exist in the test utilities;
   `std::fs::read_to_string(example_config_path(...))` is the correct
   way to get the raw YAML string for manipulation before parsing.)
   This is necessary to genuinely exercise the Anthropic, Google,
   Bedrock, and Azure parsing branches inside `token_count`, not
   just vary the backend response.
3. Start the proxy with `start_proxy`.
4. Send the request. For both non-streaming and SSE responses,
   `http_send` is sufficient — it calls `read_to_string` which reads
   until the connection closes. `Backend::fixed` closes the
   connection after serving all data, so the full SSE body is
   received without timeout in practice.
   - If the proxy emits `Transfer-Encoding: chunked` for SSE
     responses, use `parse_body` to decode chunked framing before
     asserting on SSE event content. `parse_body` already handles
     this and is used for the same reason in `a2a.rs`.
   - Do not write raw chunked-decoding logic in test code; rely on
     `parse_body` from `praxis_test_utils`.
5. Assert that the response status is 200.
6. Assert that the response body passes through unchanged.
7. For non-streaming: assert that `X-Token-Input`, `X-Token-Output`,
   and `X-Token-Total` response headers carry the expected values.
8. For SSE streaming: assert according to the injection strategy
   resolved in [#214] (trailers, access log, or buffered headers).

### Mock Response Payloads

**Non-streaming responses** — served as `application/json`:

| Provider | Body |
|----------|------|
| OpenAI / Azure | `{"choices":[...],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}` |
| Anthropic | `{"content":[...],"usage":{"input_tokens":10,"output_tokens":20}}` |
| Google (Gemini) | `{"candidates":[...],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":20}}` |
| Bedrock (Converse) | `{"output":{...},"usage":{"inputTokens":10,"outputTokens":20}}` |

Bedrock InvokeModel token counts come from HTTP response headers,
not the body. The mock backend for this case returns a JSON body
without usage fields and sets `x-amzn-bedrock-input-token-count`
and `x-amzn-bedrock-output-token-count` headers instead.

**SSE streaming responses** — served as `text/event-stream`:

| Provider | Event stream |
|----------|--------------|
| OpenAI | Two `data:` chunks then `data: [DONE]`; both tokens in last data chunk's `usage` object |
| Anthropic | `message_start` event with `usage.input_tokens`; intermediate `content_block_delta` chunks; `message_delta` event with `usage.output_tokens`; `message_stop` |
| Google (Gemini) | `usageMetadata` present only on the final chunk; no `[DONE]` sentinel |

The Anthropic SSE case is the most important to cover explicitly
because `input_tokens` and `output_tokens` arrive in different
events; this is the split-accumulation path that differs from all
other providers.

### Test Matrix

| Test name | Provider | Mode | Expected headers |
|-----------|----------|------|-----------------|
| `openai_non_streaming_extracts_token_counts` | OpenAI | JSON | Input: 10, Output: 20, Total: 30 |
| `anthropic_non_streaming_extracts_token_counts` | Anthropic | JSON | Input: 10, Output: 20, Total: 30 |
| `google_non_streaming_extracts_token_counts` | Google | JSON | Input: 10, Output: 20, Total: 30 |
| `bedrock_converse_non_streaming_extracts_token_counts` | Bedrock Converse | JSON | Input: 10, Output: 20, Total: 30 |
| `bedrock_invoke_model_extracts_token_counts_from_headers` | Bedrock InvokeModel | JSON + headers | Input: 10, Output: 20, Total: 30 |
| `azure_non_streaming_extracts_token_counts` | Azure | JSON | Input: 10, Output: 20, Total: 30 |
| `openai_streaming_extracts_token_counts` | OpenAI | SSE | Input: 10, Output: 20, Total: 30 |
| `anthropic_streaming_split_events_extracts_token_counts` | Anthropic | SSE | Input: 10, Output: 20, Total: 30 |
| `google_streaming_no_done_sentinel_extracts_token_counts` | Google | SSE | Input: 10, Output: 20, Total: 30 |

> **Why no Azure SSE or Bedrock streaming tests?**
> Azure's SSE format is identical to OpenAI's (`data: {...}` chunks with the same `usage` field layout) — the `azure` provider code path shares the same SSE parser as `openai`. A dedicated Azure streaming test would be a duplicate of `openai_streaming_extracts_token_counts` and adds no coverage. Bedrock does not use SSE at all: Bedrock Converse returns a binary event-stream format (not `text/event-stream`) and Bedrock InvokeModel returns a single JSON body; neither path exercises the SSE parser. These omissions are intentional and not gaps to fill.

| `token_count_response_body_passes_through_unchanged` | OpenAI | JSON | body == original |
| `missing_usage_fields_no_token_headers_injected` | OpenAI | JSON (no usage) | headers absent |
| `openai_streaming_whitespace_and_comments` | OpenAI | SSE (noisy) | Input: 10, Output: 20, Total: 30 |
| `example_config_token_counting_openai` | OpenAI (via example YAML) | JSON | Input: 10, Output: 20, Total: 30 |

The `openai_streaming_whitespace_and_comments` test serves an SSE
stream that includes:

- Empty lines between events (valid SSE keep-alive spacing)
- SSE comment lines (`": ping"`) that must be ignored by the parser
- A `data:` chunk whose JSON value is pretty-printed with
  indentation rather than minified

The token counts must be extracted correctly and the raw stream
must pass through byte-for-byte unchanged.

### Module Registration

Add to `tests/integration/tests/suite/examples/mod.rs`:

```rust
#[cfg(feature = "ai-inference")]
mod token_counting;
```

[#212]: https://github.com/praxis-proxy/praxis/issues/212
[#214]: https://github.com/praxis-proxy/praxis/issues/214