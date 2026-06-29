# Anthropic Messages Recording Fixtures

Curated request/response recordings for Anthropic Messages API
integration tests. Response data is synthetic (no real API calls).

## Format

Each `.json` file contains a single recording:

```json
{
  "source": "Human-readable description",
  "request": { "model": "...", "messages": [...], "max_tokens": 64 },
  "response": { "id": "msg_...", "type": "message", ... }
}
```

Streaming recordings use `response_sse` instead of `response`:

```json
{
  "source": "...",
  "request": { ..., "stream": true },
  "response_sse": "event: message_start\ndata: {...}\n\n..."
}
```

## Adding a recording

1. Create a `.json` file in this directory following the format above.
2. For non-streaming: set `response` to the raw JSON response body.
3. For streaming: set `response_sse` to the raw SSE text with `\n`
   line separators and `\n\n` between events.
4. Load in tests with `Recording::load("anthropic/messages/<name>.json")`.
5. Ensure no API keys, auth headers, or secrets appear in fixtures.

## Files

| Fixture | Description |
|---------|-------------|
| `basic.json` | Simple non-streaming completion |
| `system.json` | Non-streaming with system prompt |
| `multi_turn.json` | Multi-turn conversation |
| `temperature.json` | With temperature parameter |
| `stop_sequences.json` | With stop sequences |
| `tool_defs.json` | Tool use (definitions + invocation) |
| `tool_result.json` | Tool result round-trip |
| `content_block.json` | Content block array input |
| `response_headers.json` | Header passthrough verification |
| `streaming_basic.json` | Basic SSE streaming |
| `to_openai_non_streaming.json` | Chat Completions response for translation |
| `to_openai_streaming.json` | Chat Completions SSE for translation |
