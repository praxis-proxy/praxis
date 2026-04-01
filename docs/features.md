# Features

## Core Architecture

- **Extensible proxy framework** - use one of the
  general-purpose provided builds, or extend your own
  custom proxy server using the Praxis framework.
  Implement the `HttpFilter` or `TcpFilter` trait in your
  own crate and compile for native execution of your
  extensions.
- **Filter pipeline** - configurable chains of filters
  applied to requests and responses
- **Conditional filters** - `when`/`unless` gates on both
  request and response phases (path prefix, methods,
  headers, status codes)

## Traffic Management

- **Path and host routing** - prefix-based routing with
  optional `Host` header matching; longest prefix wins
- **Load balancing** - round-robin, least-connections,
  consistent-hash, weighted endpoints
- **Static responses** - return fixed status, headers,
  and body without upstream
- **Rate limiting** - token bucket rate limiter with
  per-IP and global modes, burst allowance, 429
  responses with `Retry-After`, and `X-RateLimit-*`
  headers
- **Active health checks** - HTTP and TCP health check
  probes with configurable thresholds; unhealthy hosts
  are automatically removed from load balancer rotation
- **Timeout enforcement** - 504 rejection when upstream
  response exceeds a configured latency SLA
- **Connection tuning** - per-cluster connection, read,
  write, idle, and total connection (TLS handshake)
  timeouts

## Payload Processing

- **Streaming payload processing**: zero-copy streaming
  by default, opt-in buffered or stream-buffered payload
  access with configurable size limits.
  Stream mode passes chunks through as they arrive
  (lowest latency). Buffer mode accumulates the full
  body. StreamBuffer delivers chunks to filters
  incrementally but defers upstream forwarding until
  release. See [Payload Processing][payload-processing]
  in the architecture docs.
- **StreamBuffer (peek-then-stream)**: a differentiated
  body access pattern that inspects incoming chunks
  while deferring upstream forwarding until content is
  validated. Filters receive chunks incrementally for
  low-latency inspection, then release the accumulated
  buffer to the upstream. This is the enabling primitive
  for AI inference (model routing from the first few
  KB of the request body), agentic protocol parsing
  (JSON-RPC envelope extraction), and security systems
  (guardrails payload scanning, content classification).
  See [architecture.md][payload-processing] for the
  full body access model.
- **Body-based routing**: the built-in `json_body_field`
  filter extracts top-level fields from JSON request
  bodies and promotes values to request headers, enabling
  AI inference model routing, content-based cluster
  selection, and request classification.
- **Response compression**: gzip, brotli, and zstd
  response compression with per-algorithm levels,
  content type filtering, and minimum size thresholds.
- **Payload size limits**: global hard ceilings on
  request and response payload size.

[payload-processing]:./architecture.md#payload-processing

## Security

- **IP ACL** - allow/deny by source IP/CIDR
- **Guardrails** - reject requests matching header or
  body content via string or regex rules; supports
  negated matching
- **Forwarded headers** - X-Forwarded-For/Proto/Host
  injection with trusted proxy CIDR support

## Observability

- **Request ID** - generate or propagate correlation IDs
  (X-Request-ID by default); echoed in responses
- **Access logging** - structured request/response logging
  via `tracing`
- **Admin health endpoints** - `/ready` and `/healthy`
  on a dedicated admin listener. `/ready` returns
  per-cluster health status with healthy/unhealthy/total
  counts when active health checks are configured, and
  returns 503 when any cluster has zero healthy
  endpoints

## Request/Response Transformation

- **Header manipulation** - add, set, and remove headers
  on requests and responses

## Operations

- **Graceful shutdown** - configurable drain timeout
- **Runtime tuning** - thread pool sizing and
  work-stealing toggle

## Protocols

- **HTTP/1.1 and HTTP/2**: standard HTTP proxying and
  HTTP/2 multiplexing; transparent passthrough supports
  SSE streaming and gRPC workloads.
  See [HTTP Connection Lifecycle][http-lifecycle].
- **TLS**:
  - **Termination**: HTTPS on the listener, plain HTTP
    upstream.
  - **Re-encryption**: TLS to upstream with configurable
    SNI.
  - See [TLS documentation][tls-docs].
- **TCP/L4**: bidirectional forwarding with optional TLS
  and idle timeout. See
  [TCP Connection Lifecycle][tcp-lifecycle].
- **Mixed protocols**: HTTP and TCP listeners on a single
  server instance. See
  [Protocol Abstraction][protocol-abstraction].

[http-lifecycle]:./architecture.md#http-connection-lifecycle
[tcp-lifecycle]:./architecture.md#tcp-connection-lifecycle
[protocol-abstraction]:./architecture.md#protocol-abstraction
[tls-docs]:./tls.md

## AI Inference

Praxis is designed as an AI-native proxy. AI inference
capabilities are built on the [filter pipeline][filters]
and [StreamBuffer][payload-processing] body access
pattern, making them composable with all other filters
rather than bolted-on external processors.

### Current

- **Model-based routing** (`model_to_header`): extracts
  the `model` field from JSON request bodies and
  promotes it to an `X-Model` header, enabling
  header-based routing to provider-specific clusters.
  Uses StreamBuffer to inspect the body before upstream
  selection.

### Planned

The following capabilities are on the roadmap as
first-class filters. Each builds on the StreamBuffer
peek-then-stream pattern and the filter pipeline's
body access model.

- **Token counting**: count input tokens from request
  bodies and output tokens from response bodies or SSE
  streams. Token counts are injected into filter context
  for downstream filters and surfaced as response
  headers (`X-Token-Input`, `X-Token-Output`,
  `X-Token-Total`). Provider-specific tokenizer
  selection.
- **Provider routing**: unified routing across LLM
  providers (Anthropic, Mistral, Google, AWS Bedrock,
  Azure). Provider abstraction with API translation
  between formats. Provider-specific endpoint
  configuration per cluster.
- **Provider failover**: ordered failover chains across
  LLM providers with automatic API translation on
  failover. Triggers on 5xx, timeout, or connection
  failure. Circuit breaker integration per provider.
- **Token-based rate limiting**: per-client token quotas
  (input, output, or total) with sliding window or
  token bucket algorithms. 429 responses with
  token-aware `Retry-After` headers.
- **Cost attribution**: token counting mapped to user,
  session, model, and endpoint. Produces data for
  billing and capacity planning.
- **Credential injection**: per-cluster API key
  injection with header-based credential management.
  Strips client-provided credentials before injection.
- **SSE streaming inspection**: per-event filter hooks
  for SSE streaming responses. Token counting
  integration for streaming without breaking the
  stream.
- **Semantic caching**: vector similarity search for
  prompt deduplication using in-process embeddings
  (Candle) and external vector storage (Qdrant).
- **AI guardrails**: integration with NVIDIA NeMo
  Guardrails for prompt validation, content filtering,
  and policy enforcement. Local ML guardrails via
  Candle for low-latency classification (toxicity,
  prompt injection detection).

### StreamBuffer as AI Primitive

StreamBuffer is the key differentiator for AI inference
workloads. Traditional proxies operate on headers only,
requiring external processors for body inspection.
Praxis inspects request bodies inline:

1. Buffer the first N bytes (typically the JSON
   envelope containing the model name, parameters,
   and prompt prefix).
2. Extract routing signals (model, provider, token
   budget, tool name).
3. Select the upstream based on body content.
4. Forward the buffered prefix, then stream the
   remainder with zero additional buffering latency.

This peek-then-stream pattern avoids the latency and
operational complexity of external processor
architectures while providing full body visibility
where it matters.

## AI Agentic

Praxis targets first-class support for AI agent
protocols, positioning MCP and A2A as headline
capabilities alongside HTTP and TCP proxying.

### Planned

The following capabilities are on the roadmap.
None are implemented yet.

### MCP (Model Context Protocol)

MCP is the protocol for AI model interactions with
external tools and resources. Praxis will provide
native MCP-aware proxying:

- **Session management**: stateful MCP connections
  with session-to-upstream binding, ensuring requests
  within a session route to the same backend.
- **Tool discovery and routing**: MCP tool invocation
  routing based on tool name, resource URI, or method
  namespace.
- **Session lifecycle**: creation, timeout, explicit
  close, and cleanup on disconnect.
- **Auth and rate limiting**: MCP-aware authentication
  and per-session rate limiting.

MCP layers on top of a [JSON-RPC 2.0][json-rpc]
foundation that provides envelope parsing, method
routing, error code generation, and observability.

### A2A (Agent-to-Agent)

A2A is the protocol for inter-agent communication.
Praxis will provide native A2A-aware proxying:

- **Agent card discovery**: route and serve agent
  capability advertisements.
- **Task lifecycle management**: proxy `tasks/send`,
  `tasks/get`, and `tasks/cancel` operations with
  task state tracking.
- **SSE streaming**: A2A streaming support for
  long-running agent tasks.

A2A also builds on the JSON-RPC 2.0 foundation.

### Stateful Agent Sessions

Both MCP and A2A require stateful connections. Praxis
will provide a shared session management layer:

- Session storage with configurable backing (in-memory,
  external via Redis).
- Session affinity through the load balancer.
- Session lifecycle hooks for filters.

### JSON-RPC 2.0 Foundation

Both MCP and A2A use JSON-RPC 2.0 as their wire
protocol. A shared `JsonRpcFilter` provides:

- Envelope parsing and validation.
- Method-based routing to different upstreams.
- JSON-RPC error envelope generation with standard
  error codes.
- HTTP-to-JSON-RPC error mapping (502/503/504 to
  JSON-RPC error envelopes).
- Method-level metrics and access log enrichment.

[json-rpc]:https://www.jsonrpc.org/specification

## Build Features

AI filters are controlled via Cargo features (enabled
by default):

- `ai-inference`: model routing, token counting, prompt
  inspection (includes `model_to_header` filter)
- `ai-agentic`: MCP, A2A, agent orchestration (planned)

To disable AI features:

```console
cargo build -p praxis --no-default-features
```

## Extensions

- **Rust extensions**: compile-time custom filters with
  zero overhead via the `HttpFilter`/`TcpFilter` traits
  and `register_filters!` macro.

[filters]:./filters.md
