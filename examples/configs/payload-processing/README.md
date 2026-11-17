# Payload Processing Examples

Payload processing filters inspect, validate, and extract data from request and response bodies.

## When to Use

- Promote fields from JSON request bodies to headers for routing/branching
- Validate request structure and reject malformed payloads
- Enforce body size limits
- Extract metadata for logging or metrics
- Inspect bodies conditionally (e.g., per-model guardrails)

## Key Filters

**JSON Body Field**: Promotes a field from a JSON request body to a header during pre-read (before the body is forwarded). Enables routing and filtering on body content without buffering in every filter.

**Body Size Limit**: Enforces maximum request or response body size. Rejects oversized payloads early.

**Conditional Extraction**: Combines body field extraction with filter conditions for selective processing.

## Key Concepts

**StreamBuffer Pre-Read**: The `json_body_field` filter runs during `StreamBuffer` pre-read phase, allowing it to inspect the body before forwarding while still streaming to the upstream.

**Reserved Headers**: Promoted fields must use reserved header names (`x-praxis-*`, `x-ext-*`) so clients cannot spoof them.

## Best Practices

- Use `json_body_field` to promote metadata once, then gate multiple filters on the promoted header
- Set appropriate body size limits to prevent resource exhaustion
- Combine with branching for per-model or per-route body processing
- Validate untrusted body content with guardrails or schema validators

## Related Documentation

- [Payload Processing](../../../docs/architecture/payload-processing.md)
- [JSON Body Field Filter](../../../docs/filters/http/payload_processing/json_body_field.md)
- [Pipeline Concepts](../../../docs/architecture/pipeline-concepts.md)
