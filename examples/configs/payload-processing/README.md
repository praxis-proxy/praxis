# Payload Processing Examples

Payload processing filters inspect, validate, rewrite, and extract data from
request and response bodies.

## When to Use

- Promote fields from JSON request bodies to headers for routing or branching
- Validate request structure and reject malformed payloads
- Enforce body size limits
- Extract metadata for logging or metrics
- Inspect bodies conditionally (for example, per-model guardrails)

## Key Filters

- [`json_body_field`](../../../docs/filters/http/payload_processing/json_body_field.md):
  promotes a JSON request body field to a header. It waits for the full
  request body (StreamBuffer pre-read); the proxy holds the body, then selects
  the upstream and forwards it. Promote a field once and gate several filters
  on the header, instead of having each filter buffer the body.
- [`json_body`](../../../docs/filters/http/payload_processing/json_body.md),
  [`json_rpc`](../../../docs/filters/http/payload_processing/json_rpc.md),
  [`compression`](../../../docs/filters/http/payload_processing/compression.md),
  and [`grpc_web`](../../../docs/filters/http/payload_processing/grpc_web.md)
- **Body size limits** (`body_limits`, not a filter): cap buffered bodies and
  reject oversized payloads early. Combine extraction with filter conditions or branching for per-model
  or per-route processing.

Promote fields that must be client-unspoofable to a reserved header prefix:
`x-praxis-*`, `x-ext-protocol-*`, or `x-ext-agent-*`. Other `x-ext-*` names
are not reserved. Validate untrusted body content with guardrails or schema
validators.

## Related Documentation

- [Payload Processing](../../../docs/architecture/payload-processing.md)
- [JSON Body Field Filter](../../../docs/filters/http/payload_processing/json_body_field.md)
- [Pipeline Concepts](../../../docs/architecture/pipeline-concepts.md)
