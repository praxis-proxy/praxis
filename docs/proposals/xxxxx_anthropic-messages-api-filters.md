---
issue: # to be created; rename file to match issue number
discussion: https://github.com/praxis-proxy/praxis/pull/420
status: proposed
authors:
  - franciscojavierarceo
stakeholders:
  - leseb
  - shaneutt
  - nerdalert
---

# Anthropic Messages API Filters

## What?

Add Anthropic Messages API support to Praxis as
composable filters, mirroring the pattern established
by the `OpenAI` Responses API filters in #354. This
enables Praxis to classify, route, and transform
requests between the `Anthropic` Messages API
(`/v1/messages`) and `OpenAI` Chat Completions
(`/v1/chat/completions`).

The `OpenAI` Responses API (`/v1/responses`) is a
fundamentally different protocol with stateful
semantics and is out of scope for format
transformation. Responses API support is covered
separately.

The scope covers five capabilities:

1. **Classification and routing**: detect `Anthropic`
   Messages API requests by body structure and
   promote routing facts to headers for downstream
   filter chains and cluster selection. The
   classifier extends the shared `AiRequestFormat`
   enum (at `ai/classifier/`) with an
   `AnthropicMessages` variant, keeping a single
   classifier for all formats. It must distinguish
   `Anthropic` Messages from `OpenAI` Chat
   Completions even though both use a `messages`
   field, using discriminating signals: top-level
   `system` parameter, required `max_tokens`,
   `anthropic-version` header, and typed content
   blocks. Mid-conversation system messages
   (`"role": "system"` inside the messages array)
   are supported on newer `Anthropic` models per
   the [mid-conversation system messages docs].
   The `anthropic-version` header is the strongest
   signal. The promoted header name is
   `x-praxis-ai-format` (matching the existing
   `responses_format` filter convention).

   [mid-conversation system messages docs]: https://platform.claude.com/docs/en/build-with-claude/mid-conversation-system-messages

2. **Request validation**: validate proxy-needed
   fields before forwarding, following the same
   principle as #354's `request_validate`. Checks
   that `messages` is non-empty, `max_tokens` is
   present and > 0, and `model` is non-empty.
   Message role ordering (e.g. first message must
   be `role: user`) is deferred to the backend,
   consistent with the principle of validating
   only what the proxy needs for its own operation.
   Unlike the Responses API, `Anthropic` Messages
   does not require persistence or stateful
   orchestration, so the validation filter is
   lighter: no shared state struct, no store
   initialization. Let the backend handle parameter
   ranges, model availability, and inference-specific
   validation.

3. **Format transformation**: bidirectional conversion
   between `Anthropic` Messages and `OpenAI` Chat
   Completions so that clients speaking one dialect
   can reach backends speaking the other. This is
   validated by existing production implementations
   in OGX (the open-source agentic API server) which
   performs the same translation in Python. The known
   mapping rules are:

   **Request (`Anthropic` to `OpenAI`):**
   - `system` (top-level string or text block array)
     to prepended `OpenAI` message with
     `role: "system"`
   - Content blocks flattened:
     - `type: "text"` to string content
     - `type: "tool_use"` to `OpenAI` `tool_calls`
       with `function.arguments = JSON-serialized
       input`
     - `type: "tool_result"` to separate `OpenAI`
       message with `role: "tool"` (images in tool
       results promoted to follow-up user messages
       since `OpenAI` tool messages are text-only)
   - `max_tokens` to `max_tokens` (direct mapping)
   - `stop_sequences` to `stop`
   - `tool_choice`: `"any"` to `"required"`,
     `"none"` to `"none"`, default to `"auto"`,
     `{"type": "tool", "name": "X"}` to
     `{"type": "function", "function": {"name": "X"}}`
   - Tool definitions: custom tools convert
     (`input_schema` to `parameters`); server-side
     tools (web_search, bash, text_editor) are
     dropped with a log warning
   - `top_k`: no standard `OpenAI` equivalent,
     passed as extra body parameter for backends
     that support it (e.g. vLLM)
   - `temperature`, `top_p`, `top_k`: not supported
     on newer `Anthropic` models (returns 400);
     transformation must strip these when targeting
     those models
   - `thinking` blocks: dropped (no `OpenAI`
     equivalent)
   - Image blocks: `Anthropic` uses `type: "image"`
     with `source.type: "base64"|"url"|"file"`;
     `OpenAI` uses `type: "image_url"` with
     `image_url.url`. For `source.type: "base64"`
     and `"url"`, structural mapping is applied.
     For `source.type: "file"`, the file reference
     must be resolved to a data URL before
     transformation (deferred to the How section)

   **Response (`OpenAI` to `Anthropic`):**
   - `message.content` string to content block
     with `type: "text"`
   - `tool_calls` to content block per call with
     `type: "tool_use"` and `input = JSON-parsed
     arguments`
   - Finish reason mapping:
     `"stop"` to `"end_turn"`,
     `"tool_calls"` to `"tool_use"`,
     `"length"` to `"max_tokens"`,
     `"content_filter"` to `"end_turn"` (note:
     this is a lossy mapping; the original
     `finish_reason` is preserved in filter
     metadata as `openai.finish_reason` so
     downstream filters can distinguish
     safety-filtered responses from natural
     completions)
   - Usage: `prompt_tokens` to `input_tokens`,
     `completion_tokens` to `output_tokens`,
     `cached_tokens` to `cache_read_input_tokens`
   - Response ID generated as `msg_{uuid}`

4. **Streaming SSE transformation**: a separate
   filter (following the `stream_events` pattern in
   #354) that transforms streaming responses between
   `Anthropic` and `OpenAI` SSE formats. Decoupled
   from request body transformation so operators can
   use SSE event handling independently (e.g. for
   logging or guardrails on passthrough streams).

   **Event mapping (`OpenAI` chunks to `Anthropic` SSE):**
   1. Emit `MessageStartEvent` with empty content
   2. Per text delta: `ContentBlockStartEvent` +
      `ContentBlockDeltaEvent(text_delta)`
   3. Per tool call delta:
      `ContentBlockStartEvent` with empty
      `ToolUseBlock`, then
      `ContentBlockDeltaEvent(input_json_delta)`
   4. `ContentBlockStopEvent` to close each block
   5. `MessageDeltaEvent` with final `stop_reason`
      and usage
   6. `MessageStopEvent`

5. **`Anthropic`-native features**: proxy and preserve
   `Anthropic`-specific capabilities that have no
   `OpenAI` equivalent when routing to `Anthropic`
   backends in pass-through mode:
   - Prompt caching (`cache_control` blocks with
     `ephemeral` type; 5-minute TTL is standard,
     1-hour TTL requires the `extended-cache-ttl`
     beta header)
   - Extended thinking (`thinking` parameter with
     `budget_tokens`)
   - Citations in responses
   - `Anthropic` SSE streaming event protocol
   - `anthropic-version` header preservation
   - Rate-limit headers (`x-ratelimit-limit-tokens`,
     etc.)

Each capability is a separate filter implementing
`HttpFilter`, composable in YAML pipelines. Operators
deploy only what they need.

### Goals

- Validate proxy-needed fields in `Anthropic`
  Messages requests (`messages` non-empty,
  `max_tokens` > 0, `model` present) and reject
  malformed requests with consistent error responses
  before they reach the backend.
- Classify `Anthropic` Messages API requests and
  promote `x-praxis-ai-format: anthropic_messages`
  to headers for routing, extending the existing
  `AiRequestFormat` enum alongside `responses` and
  `chat_completions`.
- Transform requests bidirectionally between
  `Anthropic` Messages and `OpenAI` Chat Completions
  using the mapping rules documented above,
  validated against OGX's production implementation.
- Transform streaming responses between `Anthropic`
  SSE events (`message_start`, `content_block_start`,
  `content_block_delta`, `content_block_stop`,
  `message_delta`, `message_stop`) and `OpenAI` SSE
  chunks (`chat.completion.chunk`).
- Gracefully degrade when transforming `Anthropic`
  requests for `OpenAI` backends: drop unsupported
  features (thinking, server-side tools,
  `cache_control`) with structured log warnings
  rather than rejecting the request.
- Preserve `Anthropic`-specific headers and request
  features end-to-end when routing to backends
  that natively support `/v1/messages` (e.g. vLLM,
  `Anthropic` API).
- Provide a pass-through fast path for backends
  that natively support `/v1/messages` with
  sub-millisecond proxy overhead.
- Support credential injection for `Anthropic`
  backends using the existing `credential_injection`
  filter (inject `x-api-key` and
  `anthropic-version` headers per cluster).
- Enable unified gateway configurations where a
  single Praxis instance routes to vLLM (`OpenAI`),
  llm-d (`OpenAI` via vLLM), KServe/MaaS backends,
  and `Anthropic` API simultaneously, with automatic
  format detection and transformation.

## Why?

### Motivation

Production AI platforms increasingly need to support
multiple inference backends and API formats
simultaneously. The `Anthropic` Messages API is a
first-class inference protocol alongside `OpenAI`'s
Chat Completions and Responses APIs, with
significant adoption in enterprise deployments.

Today, Praxis classifies requests as either
`responses` (`OpenAI` Responses API) or
`chat_completions` (`OpenAI` Chat Completions) in the
`AiRequestFormat` enum. `Anthropic` Messages requests
arrive with `messages` (like Chat Completions) but
are structurally different: `system` is a top-level
parameter, `max_tokens` is required, content uses
typed blocks (`text`, `image`, `tool_use`,
`tool_result`), and streaming uses a distinct SSE
event protocol. The current classifier would
misidentify these as `chat_completions`, leading to
incorrect routing or transformation failures.

The format transformation filters are needed because
real deployments mix backends:

- **vLLM and llm-d** expose `OpenAI`-compatible
  endpoints (`/v1/chat/completions`) and also
  support `/v1/messages` natively, but not all
  deployments enable `Anthropic` compatibility.
  vLLM's `/v1/messages` endpoint supports core
  `Anthropic` features (system, tools, tool_choice,
  thinking blocks, streaming SSE) but does not
  support `cache_control` or `budget_tokens` (these
  are accepted but ignored). llm-d is a
  Kubernetes-native orchestration layer that
  routes to vLLM workers using the Gateway API
  Inference Extension with prefix-cache-aware
  scheduling and prefill/decode disaggregation.
- **KServe and MaaS** (Models as a Service) provide
  model discovery and API key management. MaaS
  returns model URLs that clients call directly;
  the model endpoints may implement either format.
  MaaS uses `OpenAI`-compatible API keys
  (`sk-oai-*`) and `/v1/models` for discovery.
- **`Anthropic` API** is the canonical backend for
  Claude models and uses a distinct wire format
  with features that have no `OpenAI` equivalent:
  prompt caching with `cache_control` blocks
  (5-minute TTL standard; 1-hour TTL requires the
  `extended-cache-ttl` beta header), extended
  thinking with `budget_tokens`, typed content
  blocks, and a block-based SSE streaming protocol.
  `Anthropic` also provides an `OpenAI`
  compatibility endpoint at `/v1/chat/completions`,
  but it lacks prompt caching, extended thinking
  details, and strict tool use, making native
  `/v1/messages` routing necessary for full feature
  access.

The bidirectional format transformation is a
validated pattern. OGX (the open-source agentic API
server) implements the same `Anthropic` to `OpenAI`
mapping in production, with a native-passthrough
fast path when backends support `/v1/messages`
directly. The mapping rules documented in this
proposal are derived from that implementation and
cover the known edge cases: tool result image
promotion, server-side tool filtering, thinking
block handling, and streaming event sequencing.

Without format transformation, operators must either
standardize all clients on one format (impractical)
or run separate gateway instances per format
(operationally expensive). Praxis should handle this
at the filter pipeline level.

`Anthropic`-native features (prompt caching, extended
thinking) represent capabilities that cannot be
expressed in `OpenAI` format. When routing to
`Anthropic` backends, these must be preserved
end-to-end. When routing `Anthropic` requests to
`OpenAI`-compatible backends, the filters must
gracefully degrade: strip unsupported fields, map
what can be mapped, and log what was dropped.

### User Stories

- As a platform engineer, I want to route
  `/v1/messages` requests to vLLM backends that
  only support `/v1/chat/completions` so that
  clients using the `Anthropic` SDK can reach any
  backend in my fleet.
- As an AI gateway operator, I want a single Praxis
  instance to serve clients speaking `OpenAI` Chat
  Completions and `Anthropic` Messages formats,
  routing each to the appropriate backend with
  automatic format detection.
- As a developer, I want to send `Anthropic`-format
  requests with prompt caching to a Claude backend
  through Praxis without losing the `cache_control`
  blocks or `anthropic-version` header.
- As an SRE, I want to use Praxis credential
  injection to manage `x-api-key` headers for
  `Anthropic` backends the same way I manage
  `Authorization: Bearer` headers for `OpenAI`
  backends.
- As a security engineer, I want `Anthropic`-specific
  rate-limit headers (`x-ratelimit-limit-tokens`,
  etc.) to be forwarded to clients so that
  client-side backoff works correctly.
- As a platform engineer using MaaS for model
  discovery, I want Praxis to detect whether a
  discovered model endpoint speaks `Anthropic` or
  `OpenAI` format and apply the appropriate
  transformation filters automatically.

### Translation Decision

The classifier detects the request format (always
`anthropic_messages` for `Anthropic` requests) but
does not determine whether the backend needs
translation. This follows the existing Praxis
classify → route pattern: the classifier promotes
facts to internal headers, and the operator
configures routes that direct traffic to the
appropriate pipeline.

For passthrough backends (vLLM, `Anthropic` API):
the operator configures a route that sends
`/v1/messages` traffic to a passthrough filter
chain. For OpenAI-only backends: the operator
configures a route to a transformation filter
chain. The router selects the cluster; the
listener selects the filter chain.

This is the same pattern used by `openai_responses_format`
for Responses API vs Chat Completions routing. See
`examples/configs/ai/openai/responses/format-routing.yaml`
for the canonical example.
## How?

### Source Material

- `Anthropic` Messages API docs:
  https://platform.claude.com/docs/en/api/messages
- OGX transformation reference:
  `ogx/src/ogx/providers/inline/messages/impl.py`
- Target: `filter/src/builtins/http/ai/anthropic/`
  in praxis

### Architecture

Five filters, each implementing `HttpFilter`.
Filters communicate via `HttpFilterContext`:
- `filter_metadata`: durable key-value state
  persisting across lifecycle phases
- `filter_results`: ephemeral key-value pairs
  consumed by branch conditions
- `extra_request_headers`: headers injected into
  upstream requests
- Request/response body access via
  `on_request_body` / `on_response_body`

The classifier extends the existing
`AiRequestFormat` enum (moved to
`filter/src/builtins/http/ai/classifier/mod.rs` as
a shared module) with an `AnthropicMessages`
variant. The operator configures routes and filter
chains for passthrough vs transformation using the
existing classify → route pattern (see Translation
Decision above).

---

### Filter 0: `anthropic_messages_format`

**Purpose:** Classify requests as `Anthropic` Messages
API and promote routing facts to headers, metadata,
and filter results. Mirrors the pattern of
`openai_responses_format` but detects `/v1/messages`
requests.

**Praxis trait methods:**
- `on_request_body`: parse JSON body, classify
  format, write metadata and headers
- `request_body_mode` → `StreamBuffer` (read-only)

**Classification logic:**

The classifier must distinguish `Anthropic` Messages
from OpenAI Chat Completions. Both have `messages`,
so the classifier uses multiple signals:

1. `anthropic-version` request header (strongest
   signal: only Anthropic clients send this)
2. Top-level `system` field (Anthropic separates
   system from messages; OpenAI puts it in the
   messages array for older models)
3. Required `max_tokens` (Anthropic requires it;
   OpenAI defaults it)
4. Typed content blocks in `messages` (objects with
   `type: "text"` / `type: "image"` / etc.)
5. Path-based: request to `/v1/messages` endpoint

Classification result:
- Extends `AiRequestFormat` with
  `AnthropicMessages` variant
- `as_str()` returns `"anthropic_messages"`

**Promoted facts:**
- `x-praxis-ai-format: anthropic_messages`
- `x-praxis-ai-model: <model>` (extracted from
  body)
- `x-praxis-ai-stream: true|false`
- `filter_metadata`: `anthropic_format.format`,
  `anthropic_format.model`,
  `anthropic_format.stream`,
  `anthropic_format.max_tokens`
- `filter_results`: `anthropic_format.format`,
  `anthropic_format.model`

**Config:**

```yaml
filter: anthropic_messages_format
on_invalid: continue  # continue | reject
max_body_bytes: 1048576  # 1 MiB
headers:
  format: x-praxis-ai-format
  model: x-praxis-ai-model
  stream: x-praxis-ai-stream
```

---

### Filter 1: `anthropic_request_validate`

**Purpose:** Validate proxy-needed fields in
`Anthropic` Messages requests before forwarding.
Unlike #354's `request_validate`, this filter does
not create shared orchestrator state or initialize
persistence: `Anthropic` Messages has no stateful
orchestration.

**Praxis trait methods:**
- `on_request_body`: parse JSON body, validate
  fields, reject with 400 if invalid
- `request_body_mode` → `StreamBuffer` (read-only)

**Validation checks:**
- `messages` array exists and is non-empty
- `max_tokens` is present and > 0
- `model` is present and non-empty
- Content blocks (when arrays) have valid `type`
  fields
- Tool definitions (when present) have `name` and
  `input_schema`

**Validation principle:** Only validate what the
proxy needs for its own operation. Let the inference
server handle parameter ranges, model availability,
and content-level validation. Forward unknown fields
as-is.

**Config:**

```yaml
filter: anthropic_request_validate
max_body_bytes: 1048576  # 1 MiB
```

---

### Filter 2: `anthropic_to_openai`

**Purpose:** Transform an `Anthropic` Messages API
request body into an OpenAI Chat Completions request
body. Runs on the request path. Enables Anthropic
SDK clients to reach OpenAI-compatible backends
(vLLM, llm-d, KServe).

**Praxis trait methods:**
- `on_request_body`: rewrite JSON body
- `request_body_mode` → `StreamBuffer`
  (read-write)
- `on_response_body`: transform response body
  (non-streaming) or SSE chunks (streaming) from
  OpenAI format back to Anthropic format

**Request transformation (Anthropic → OpenAI):**

- Hoist `system` → prepend OpenAI message with
  `role: "system"`. Handles both string and text
  block array forms.
- Flatten content blocks in each message:
  - `type: "text"` → string content or OpenAI
    text content part
  - `type: "image"` with `source.type: "base64"`
    → OpenAI `type: "image_url"` with data URL
  - `type: "image"` with `source.type: "url"`
    → OpenAI `type: "image_url"` with URL
  - `type: "tool_use"` → OpenAI `tool_calls`
    entry with `function.arguments =
    serde_json::to_string(input)`
  - `type: "tool_result"` → separate OpenAI
    message with `role: "tool"`, `tool_call_id`,
    and string content. Images in tool results
    promoted to follow-up user messages.
  - `type: "thinking"` → dropped (logged)
  - `type: "redacted_thinking"` → dropped (logged)
- Map parameters:
  - `max_tokens` → `max_tokens`
  - `stop_sequences` → `stop`
  - `temperature` → `temperature` (strip for
    Opus 4.7+ targeting)
  - `top_p` → `top_p` (same caveat)
  - `top_k` → extra body parameter
- Map `tool_choice`:
  - `"any"` → `"required"`
  - `"none"` → `"none"`
  - `"auto"` → `"auto"`
  - `{"type": "tool", "name": "X"}` →
    `{"type": "function", "function":
    {"name": "X"}}`
- Map `tools`:
  - Custom tools: `input_schema` → `parameters`,
    `name` → `function.name`,
    `description` → `function.description`
  - Server-side tools (`web_search_*`, `bash_*`,
    `text_editor_*`): dropped with
    `tracing::warn!`
- Rewrite `Content-Type` and `Content-Length`
  headers
- Strip `anthropic-version` and `x-api-key`
  headers (credential injection handles upstream
  auth)

**Response transformation (OpenAI → Anthropic):**

Non-streaming:
- `choices[0].message.content` → content block
  with `type: "text"`
- `choices[0].message.tool_calls` → content
  blocks with `type: "tool_use"`, `id`,
  `name`, `input = serde_json::from_str(args)`
- `finish_reason` → `stop_reason`:
  `"stop"` → `"end_turn"`,
  `"tool_calls"` → `"tool_use"`,
  `"length"` → `"max_tokens"`,
  `"content_filter"` → `"end_turn"` (lossy;
     original preserved in filter metadata)
- `usage.prompt_tokens` → `input_tokens`,
  `usage.completion_tokens` → `output_tokens`,
  `usage.prompt_tokens_details.cached_tokens`
  → `cache_read_input_tokens`
- Generate `id` as `msg_{uuid}`, set
  `type: "message"`, `role: "assistant"`

**Config:**

```yaml
filter: anthropic_to_openai
max_body_bytes: 1048576  # 1 MiB
```

---

### Filter 3: `anthropic_stream_events`

**Purpose:** Transform streaming SSE responses
between `OpenAI` Chat Completions chunks and
`Anthropic` Messages events. Separated from request
transformation so operators can use SSE event
handling independently: e.g. for logging, metrics,
or guardrails on passthrough streams without
transforming the request body.

**Praxis trait methods:**
- `on_response_body`: process each TCP chunk as it
  arrives, transform complete SSE events immediately,
  buffer only partial lines across chunk boundaries
- `response_body_mode` → `Stream` (not `StreamBuffer`;
  no full-response buffering)

**Per-chunk processing:**
Each `on_response_body` call:
1. Combines leftover partial data from the previous
   chunk with new bytes
2. Splits on `\n\n` SSE event boundaries
3. Transforms each complete `data:` line immediately
4. Stores any trailing partial data in filter metadata
5. Forwards transformed events to the client

This conforms to the [Inference Proxy Conformance
Guidelines] Sections 4.2 (no streaming-to-non-streaming
conversion) and 4.3 (no full-response buffering).

[Inference Proxy Conformance Guidelines]: https://docs.google.com/document/d/1yDzs9ehHFxqYbufOmY-sEXiEtn9nhXUKHx4uKjasC5Q/edit?tab=t.0

**State machine (per-request, stored in filter metadata):**
- Track: current block index, block type, open
  blocks, finish reason, output tokens
- First chunk → `message_start` with empty
  message envelope
- Text delta → `content_block_start` (first),
  then `content_block_delta(text_delta)`
- Tool call delta → `content_block_start` with
  empty `tool_use` block (first per tool), then
  `content_block_delta(input_json_delta)`
- Block end → `content_block_stop`
- `[DONE]` → `message_delta` with `stop_reason`
  and `usage`, then `message_stop`

**Config:**

```yaml
filter: anthropic_stream_events
```

---

### Filter 4: `anthropic_passthrough`

**Purpose:** Preserve Anthropic-native features
when routing to backends that natively support
`/v1/messages` (`Anthropic` API, vLLM with Anthropic
endpoint). No body transformation: only header
management and credential injection coordination.

**Praxis trait methods:**
- `on_request`: manage headers, set upstream path
- `on_response`: forward rate-limit headers

**Behavior:**

Request:
- Preserve `anthropic-version` header (inject
  default `2023-06-01` if absent)
- Preserve `cache_control` blocks in body as-is
- Preserve `thinking` parameter as-is
- Coordinate with `credential_injection` filter
  for `x-api-key` header injection
- Set upstream path to `/v1/messages`

Response:
- Forward Anthropic rate-limit headers to client:
  `x-ratelimit-limit-requests`,
  `x-ratelimit-limit-tokens`,
  `x-ratelimit-remaining-requests`,
  `x-ratelimit-remaining-tokens`,
  `x-ratelimit-reset-requests`,
  `x-ratelimit-reset-tokens`
- Forward `request-id` header
- Pass through SSE events unchanged (native
  Anthropic streaming)

**Config:**

```yaml
filter: anthropic_passthrough
default_version: "2023-06-01"
forward_rate_limits: true
```

---

### Filter Chain Configuration

#### Anthropic client → OpenAI backend (vLLM/llm-d):

```yaml
filter_chains:
  - name: anthropic-to-openai
    filters:
      - filter: anthropic_messages_format
        name: classify

      - filter: anthropic_request_validate

      - filter: anthropic_to_openai
        name: transform

      - filter: anthropic_stream_events

    cluster: vllm-backend
```

#### Anthropic client → Anthropic backend:

```yaml
filter_chains:
  - name: anthropic-native
    filters:
      - filter: anthropic_messages_format
        name: classify

      - filter: anthropic_request_validate

      - filter: anthropic_passthrough
        name: passthrough

      - filter: credential_injection
        clusters:
          - name: anthropic
            header: x-api-key
            env_var: ANTHROPIC_API_KEY

    cluster: anthropic-backend
```

#### Unified gateway (separate filter chains per format):

Note: branch chains cannot be used for transformation
because body hooks (`on_request_body`, `on_response_body`)
are not executed for filters inside branch chains. Use
separate filter chains with path-based routing instead.

```yaml
listeners:
  - name: gateway
    address: "0.0.0.0:8080"
    filter_chains:
      - anthropic-passthrough
      - openai

filter_chains:
  - name: anthropic-passthrough
    filters:
      - filter: anthropic_messages_format
        on_invalid: continue
      - filter: anthropic_request_validate
      - filter: anthropic_passthrough
        default_version: "2023-06-01"
      - filter: router
        routes:
          - path_prefix: "/v1/messages"
            cluster: anthropic-backend
      - filter: load_balancer
        clusters:
          - name: anthropic-backend
            endpoints:
              - "api.anthropic.com:443"
            tls:
              sni: "api.anthropic.com"

  - name: openai
    filters:
      - filter: openai_responses_format
        on_invalid: continue
      - filter: router
        routes:
          - path_prefix: "/v1/"
            cluster: vllm-backend
      - filter: load_balancer
        clusters:
          - name: vllm-backend
            endpoints:
              - "127.0.0.1:8000"
```

---

### Implementation Tiers

Build order; each tier produces a working system:

| Tier | Filter | What works after |
|------|--------|------------------|
| 0 | `anthropic_messages_format` | Classification and routing. Anthropic requests detected and promoted to headers/metadata for branch-chain routing. |
| 1 | `anthropic_request_validate` | Request validation. Malformed requests rejected at the proxy with consistent error format. |
| 2 | `anthropic_passthrough` | Native Anthropic backend routing. Clients reach `Anthropic` API through Praxis with credential injection and rate-limit forwarding. |
| 3 | `anthropic_to_openai` (request + non-streaming response) | `Anthropic` SDK clients can reach vLLM/llm-d backends. Non-streaming responses translated back. |
| 4 | `anthropic_stream_events` | Per-chunk SSE streaming. `OpenAI` chunks translated to `Anthropic` events incrementally as they arrive. Conformant with [Inference Proxy Conformance Guidelines](https://docs.google.com/document/d/1yDzs9ehHFxqYbufOmY-sEXiEtn9nhXUKHx4uKjasC5Q/edit?tab=t.0). |

---

### File Structure in Praxis

```
filter/src/builtins/http/ai/
  classifier/
    mod.rs                       # shared AiRequestFormat enum
  anthropic/
    mod.rs                       # module exports
    messages_format/
      mod.rs                     # classifier filter
      config.rs                  # YAML config
    request_validate/
      mod.rs                     # validation filter
      config.rs                  # YAML config
    to_openai/
      mod.rs                     # transformation filter
      config.rs                  # YAML config
      request.rs                 # Anthropic → OpenAI request
      response.rs                # OpenAI → Anthropic response
    stream_events/
      mod.rs                     # per-chunk SSE transformation
      config.rs                  # YAML config
    passthrough/
      mod.rs                     # passthrough filter
      config.rs                  # YAML config
```

---

### Open Questions

1. **Classifier placement.** Resolved: the shared
   `AiRequestFormat` enum is moved to
   `ai/classifier/` and extended with
   `AnthropicMessages`. Both `openai_responses_format`
   and `anthropic_messages_format` filters import from
   the same classifier. One enum, one classification
   function.

2. **Path rewriting.** When transforming Anthropic →
   OpenAI, the upstream path must change from
   `/v1/messages` to `/v1/chat/completions`. Should
   this be done in the transformation filter or via
   Praxis route configuration?

3. **Token counting.** Anthropic uses different
   tokenization than OpenAI. When transforming
   responses back, should `usage.input_tokens` /
   `output_tokens` reflect the original Anthropic
   token count or the OpenAI backend's count?

4. **Batches API.** Anthropic supports
   `/v1/messages/batches` for async batch
   processing. Should this be a separate filter or
   part of `anthropic_to_openai`? Deferred for now.

5. **`/v1/messages/count_tokens`.** Anthropic
   supports a token counting endpoint. Should
   Praxis proxy this or implement it locally?
   Deferred for now.
