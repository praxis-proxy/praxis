# AI Inference

Body-aware classification, routing, and enrichment
for AI inference traffic, built on the filter
pipeline and StreamBuffer body access pattern.

## Overview

AI inference filters classify request bodies to
determine the API format (OpenAI Responses, Anthropic
Messages, Chat Completions), extract routing signals
(model, stream mode, store flag), and promote them to
headers, metadata, and filter results for downstream
routing via branch chains.

```text
Request Body
  |
  v
Classifier (pure function)
  |
  v
Format Filter (promotes facts to headers/metadata/results)
  |
  v
Validate Filter (parameter checks, ID generation)
  |
  v
Branch Chains / Router (routing decisions)
  |
  v
Upstream
```

## Classification Pipeline

### Format Detection

The classifier (`classifier/mod.rs`) is a pure
function with no I/O. It parses the request body
JSON once and returns a `ClassifiedRequest` struct
with extracted facts.

Detection precedence:

1. `input` field present or path-based responses
   endpoint: **Responses API**
2. `messages` + `max_tokens` + Anthropic signals
   (`system` or typed content blocks):
   **Anthropic Messages API**
3. `messages` alone: **Chat Completions API**
4. Valid JSON without recognized fields:
   **UnknownJson**
5. Invalid JSON: **InvalidJson**
6. Non-JSON content type: **NonJson**

Path-based classification handles sub-resource
endpoints (`GET /v1/responses/{id}`,
`POST /v1/responses/{id}/cancel`, etc.) that lack
a request body.

### Metadata Propagation

The format filter promotes classified facts using
three channels:

- **Filter metadata**: durable key-value pairs
  (e.g. `openai_responses_format.model`) that
  persist across Pingora phases. Used for
  cross-filter communication.
- **Extra request headers**: added to the upstream
  request (e.g. `X-Praxis-AI-Format`). Used for
  header-based routing in the router filter.
- **Filter results**: written to `FilterResultSet`
  for branch chain condition evaluation.

All promoted values are validated against a 256-byte
length limit and checked for control characters
before propagation.

### Stateful vs Stateless

Responses API requests are classified as "stateful"
when any of these hold:

- `previous_response_id` is present
- `tools` is present
- `store` is not explicitly `false`
- `background` is `true`
- `has_conversation` is true
- `has_prompt_id` is true

Stateful mode influences routing decisions (e.g.
directing to clusters with response store access).

## StreamBuffer Body Access

StreamBuffer is the key enabler for AI inference
filters. It accumulates request body chunks and
defers upstream forwarding until the filter releases
or end-of-stream:

1. Buffer the JSON envelope (model name, parameters,
   prompt prefix).
2. Extract routing signals from the buffered bytes.
3. Select the upstream based on body content.
4. Release the buffered prefix and stream the
   remainder.

This peek-then-stream pattern avoids the latency of
external processor architectures while providing body
visibility where it matters.

Filters declare `BodyAccess::ReadOnly` +
`BodyMode::StreamBuffer { max_bytes }` to opt in.
Only `PromptEnrichFilter` uses `ReadWrite` (it
modifies the messages array).

## Filters

### `model_to_header`

Extracts the `model` field from JSON request bodies
and promotes it to a configurable header (default
`X-Model`). Enables header-based routing to
provider-specific clusters.

### `openai_responses_format`

Classifies AI API request bodies and promotes format,
model, stream, store, background, and mode to
headers, metadata, and filter results.

### `openai_responses_validate`

Validates Responses API parameter combinations
(e.g. stream + background conflicts) and generates
cryptographically random response and conversation
IDs with `resp_` and `conv_` prefixes.

### `anthropic_messages_format`

Classifies Anthropic Messages API requests and
promotes format metadata. Feature-gated behind
`ai-inference`.

### `prompt_enrich`

Injects system or user messages into
OpenAI-compatible chat completion request bodies.
Static configured messages are prepended or appended
to the `messages` array. Uses `BodyAccess::ReadWrite`.

### `credential_injection`

Per-cluster API key injection with client credential
stripping. Supports inline values and environment
variable sources.

### `openai_response_store`

Persists non-streaming Responses API responses. See
[Response Store](response-store.md) for details.

## Feature Flags

AI inference filters are gated behind the
`ai-inference` Cargo feature. The agentic protocol
filters (JSON-RPC, MCP, A2A) are always compiled.

When `ai-inference` is disabled, the classifier,
format, validate, store, prompt enrichment, and
provider-specific filters are excluded from the
build.

## Key Files

- `filter/src/builtins/http/ai/classifier/mod.rs`:
  pure format classifier
- `filter/src/builtins/http/ai/openai/responses/mod.rs`:
  `ResponsesFormatFilter`
- `filter/src/builtins/http/ai/inference/model_to_header.rs`:
  `ModelToHeaderFilter`
- `filter/src/builtins/http/ai/prompt_enrich/`:
  prompt enrichment filter
- `filter/src/builtins/http/ai/anthropic/`:
  Anthropic Messages format filter
- `filter/src/body/mode.rs`:
  `BodyMode::StreamBuffer` definition

## Related

- [Response Store](response-store.md)
- [Agentic Protocols](agentic-protocols.md)
- [Payload Processing](payload-processing.md)
