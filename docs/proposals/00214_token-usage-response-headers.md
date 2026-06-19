---
issue: https://github.com/praxis-proxy/praxis/issues/214
discussion: https://github.com/praxis-proxy/praxis/pull/471
status: proposed
authors:
  - noalimoy
graduation_criteria:
  - Implementation PR with passing tests
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
| `Praxis-Token-Input` | Input/prompt token count |
| `Praxis-Token-Output` | Output/completion token count |
| `Praxis-Token-Total` | Total token count (input + output) |

Headers are only injected when token data is available
in filter metadata. If the upstream response does not
contain token usage (e.g., error responses, non-AI
traffic), no headers are added. For streaming responses,
token counts are only resolved after the full body has
been accumulated ([#211]), parsed ([#216]), and written
to filter metadata ([#212]); header injection for
streaming is an open question (see Open Questions
below).

### Goals

- Inject token usage as HTTP headers into downstream
  responses
- Read token data from filter metadata without
  provider-specific logic
- Support conditional injection (only when data exists)
- Support non-streaming responses; define a path for
  streaming support

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

## How?

### Requirements

- Read token counts from `filter_metadata` keys:
  `token.input`, `token.output`, `token.total`
- Inject headers only when all three values are present
- Operate in the `on_response` filter phase
- Mark `response_headers_modified` when headers are
  added
- No-op when token data is absent (non-AI traffic,
  error responses)
- No configuration options (zero-config filter)
- Use `Praxis-Token-*` header prefix

### Design

#### Module Location

The filter lives at
`filter/src/builtins/http/ai/token_usage_headers.rs`
alongside the existing token counting and inference
filters, since it is only applicable to AI workloads.

#### Data Flow

The filter consumes metadata written by
`set_token_usage()` ([#474]) via `filter_metadata`:

```text
Token Counting Filter (writes via set_token_usage)
  ctx.set_token_usage(150, 350, None)
    → ctx.set_metadata("token.input", "150")
    → ctx.set_metadata("token.output", "350")
    → ctx.set_metadata("token.total", "500")  // auto-computed
       │
       ▼
TokenUsageHeadersFilter (reads via get_metadata)
  ctx.get_metadata("token.input")
       │
       ▼
Response Headers (injected into downstream response)
  Praxis-Token-Input: 150
  Praxis-Token-Output: 350
  Praxis-Token-Total: 500
```

#### Implementation Approach

1. **String-based metadata transport** — per maintainer
   guidance in [#462], token data uses `filter_metadata`
   rather than typed fields on `HttpFilterContext`. This
   keeps the core struct free of AI-specific concerns.

2. **All-or-nothing injection** — if any of the three
   metadata keys is missing, no headers are injected.
   This matches the atomicity guarantee of
   `set_token_usage()` which always writes all three
   keys together.

3. **Compile-time header names** — header constants use
   `HeaderName::from_static()` for zero-cost runtime
   validation.

4. **`Praxis-Token-*` prefix** — the `x-praxis-*`
   prefix is reserved for proxy-internal routing
   metadata: rejected from clients (HTTP 400),
   stripped from upstream responses, and never
   forwarded to clients (`reserved_headers.rs`).
   Using `X-Praxis-Token-*` would place client-facing
   headers inside that reserved namespace, since
   `x-praxis-token-input` starts with `x-praxis-`.

   Existing client-facing headers (`X-Request-ID`,
   `X-RateLimit-*`) are de facto industry standards
   that don't need a vendor prefix. Per-request token
   usage has no such standard — providers report
   remaining quota in headers (`x-ratelimit-*`) but
   expose actual consumption only in the JSON body.
   This filter surfaces per-request usage at the HTTP
   layer, which is Praxis-specific, so a vendor
   prefix identifies the source.

   `Praxis-Token-*` (without `X-`) satisfies both
   constraints: `praxis-token-input` does not match
   the reserved `x-praxis-*` prefix, and the
   `Praxis-` vendor prefix identifies the source.
   Dropping the `X-` prefix also aligns with
   RFC 6648, which deprecates `X-` for new headers.

5. **Streaming** — for non-streaming responses the
   filter operates in `on_response` where
   `response_header` is available. For streaming
   responses, token counts arrive during
   `on_response_body` where `response_header` is
   `None`. The mechanism for streaming header
   injection remains an open question (see below).

#### Pipeline Ordering

The filter must run **after** the token counting filter
in the response phase. Since `on_response` executes in
reverse config order, `token_usage_headers` should
appear **before** the token counting filter in the YAML
filter chain:

```yaml
filters:
  - filter: token_usage_headers
  - filter: token_counting
  - filter: load_balancer
    clusters:
      - name: backend
        endpoints:
          - "127.0.0.1:3000"
```

No explicit dependency configuration is required.

#### YAML Configuration

```yaml
- filter: token_usage_headers
```

No configuration parameters. The filter is enabled by
including it in the filter chain.

## Open Questions

### Streaming header injection

For streaming responses, token counts are only
available after the final chunk is processed. At that
point, `response_header` is `None` in the current
architecture. Options include HTTP trailers, response
buffering, or a new pipeline hook. This will be
resolved during implementation.

[#210]: https://github.com/praxis-proxy/praxis/issues/210
[#211]: https://github.com/praxis-proxy/praxis/issues/211
[#212]: https://github.com/praxis-proxy/praxis/issues/212
[#216]: https://github.com/praxis-proxy/praxis/issues/216
[#462]: https://github.com/praxis-proxy/praxis/pull/462
[#471]: https://github.com/praxis-proxy/praxis/pull/471
[#474]: https://github.com/praxis-proxy/praxis/pull/474

