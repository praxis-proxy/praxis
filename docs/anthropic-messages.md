# Anthropic Messages API

Praxis supports the Anthropic Messages API
(`/v1/messages`) through five composable filters.
Operators can route, validate JSON envelopes, and transform
Anthropic requests to reach any backend.

## Filters

| Filter | Purpose |
| ------ | ------- |
| `anthropic_messages_format` | Classify requests and promote routing facts to headers |
| `anthropic_validate` | Validate the JSON request envelope before forwarding |
| `anthropic_messages_protocol` | Header management for native `/v1/messages` backends |
| `anthropic_to_openai` | Bidirectional body transformation to `OpenAI` Chat Completions |
| `anthropic_stream_events` | SSE event transformation (per-chunk streaming, conformant with Inference Proxy Conformance Guidelines) |

## Passthrough to vLLM

Route Anthropic requests directly to a backend that
supports `/v1/messages` natively (e.g. vLLM with
Anthropic endpoint enabled).

```yaml
listeners:
  - name: gateway
    address: "0.0.0.0:8080"
    filter_chains: [anthropic]

filter_chains:
  - name: anthropic
    filters:
      - filter: anthropic_messages_format
        on_invalid: continue

      - filter: anthropic_validate

      - filter: anthropic_messages_protocol
        default_version: "2023-06-01"

      - filter: router
        routes:
          - path_prefix: "/"
            cluster: vllm

      - filter: load_balancer
        clusters:
          - name: vllm
            endpoints:
              - "127.0.0.1:8000"
```

Test:

```console
curl http://localhost:8080/v1/messages \
  -H "content-type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "openai/gpt-oss-20b",
    "max_tokens": 100,
    "system": "Reply concisely.",
    "messages": [{"role": "user", "content": "Hi"}]
  }'
```

## Passthrough to Anthropic API

Route to `api.anthropic.com` with credential
injection for the `x-api-key` header.

```yaml
listeners:
  - name: gateway
    address: "0.0.0.0:8080"
    filter_chains: [anthropic]

filter_chains:
  - name: anthropic
    filters:
      - filter: anthropic_messages_format
        on_invalid: continue

      - filter: anthropic_validate

      - filter: anthropic_messages_protocol
        default_version: "2023-06-01"

      - filter: headers
        request_set:
          - name: Host
            value: "api.anthropic.com"

      - filter: router
        routes:
          - path_prefix: "/"
            cluster: anthropic

      - filter: credential_injection
        clusters:
          - name: anthropic
            header: x-api-key
            env_var: ANTHROPIC_API_KEY
            strip_client_credential: true

      - filter: load_balancer
        clusters:
          - name: anthropic
            tls:
              sni: "api.anthropic.com"
            endpoints:
              - "api.anthropic.com:443"
```

Test:

```console
curl http://localhost:8080/v1/messages \
  -H "content-type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-haiku-4-5",
    "max_tokens": 100,
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

## Transformation to OpenAI Backend

Transform Anthropic requests to OpenAI Chat
Completions format for backends that only speak
OpenAI (e.g. llm-d with disaggregation, KServe
without Anthropic support).

```yaml
listeners:
  - name: gateway
    address: "0.0.0.0:8080"
    filter_chains: [transform]

filter_chains:
  - name: transform
    filters:
      - filter: anthropic_messages_format
        on_invalid: continue

      - filter: anthropic_validate

      - filter: anthropic_to_openai
        max_body_bytes: 1048576

      - filter: anthropic_stream_events
        response_conditions:
          - when:
              headers:
                content-type: "text/event-stream"

      - filter: path_rewrite
        replace:
          pattern: "^/v1/messages$"
          replacement: "/v1/chat/completions"
        conditions:
          - when:
              path_prefix: "/v1/messages"

      - filter: router
        routes:
          - path_prefix: "/"
            cluster: vllm

      - filter: load_balancer
        clusters:
          - name: vllm
            endpoints:
              - "127.0.0.1:8000"
```

The `anthropic_to_openai` filter:
- Hoists `system` to an OpenAI system message
- Flattens content blocks (text, image, tool_use,
  tool_result)
- Maps `stop_sequences` to `stop`,
  `tool_choice` semantics, tool definitions
- Preserves `top_k` as an extra body parameter
- Drops `thinking` blocks with a log warning
- Transforms the response back to Anthropic format
- Preserves original `finish_reason` in filter
  metadata as `openai.finish_reason`

Add `anthropic_stream_events` with a `text/event-stream`
response condition when the backend may return streaming
Chat Completions SSE. Keep it response-gated so normal
JSON responses stay on the buffered `anthropic_to_openai`
path.

## Filter Configuration Reference

### `anthropic_messages_format`

Classifies requests by body structure, then promotes
ambiguous `/v1/messages` or `anthropic-version`
requests to Anthropic Messages when the body otherwise
looks like Chat Completions.

```yaml
filter: anthropic_messages_format
on_invalid: continue      # continue | reject
max_body_bytes: 1048576    # 1 MiB
headers:
  format: x-praxis-ai-format
  model: x-praxis-ai-model
  stream: x-praxis-ai-stream
```

Body classification precedence:
1. `input` or object-valued `prompt` → OpenAI Responses
2. `messages` + `max_tokens` + Anthropic structural
   signals → Anthropic Messages
3. `messages` alone → OpenAI Chat Completions

`anthropic-version` and `/v1/messages` upgrade only the
ambiguous Chat Completions result to Anthropic Messages;
they do not override Responses-shaped bodies.

### `anthropic_validate`

Validates the proxy-owned JSON envelope before forwarding.
Backend-owned Anthropic semantics such as model availability,
message shape, role ordering, and token limits are deferred
to the backend.

```yaml
filter: anthropic_validate
max_body_bytes: 1048576    # 1 MiB
```

Checks: request body is present, valid JSON, and a JSON object.

### `anthropic_messages_protocol`

Injects `anthropic-version` header if absent.
No body transformation.

```yaml
filter: anthropic_messages_protocol
default_version: "2023-06-01"
```

### `anthropic_to_openai`

Bidirectional request/response transformation.
Non-streaming only; use `anthropic_stream_events`
for SSE responses.

```yaml
filter: anthropic_to_openai
max_body_bytes: 1048576    # 1 MiB
```

### `anthropic_stream_events`

Transforms OpenAI SSE chunks to Anthropic SSE
events. Processes SSE chunks incrementally as they arrive.

```yaml
filter: anthropic_stream_events
response_conditions:
  - when:
      headers:
        content-type: "text/event-stream"
```

## Running with Debug Logging

See filter activity in real time:

```console
RUST_LOG=debug cargo run -p praxis-proxy -- -c config.yaml
```

Filter-specific logging:

```console
RUST_LOG=praxis_filter::builtins::http::ai=debug cargo run -p praxis-proxy -- -c config.yaml
```
