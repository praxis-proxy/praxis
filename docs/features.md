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

- **Path, host, and header routing** - prefix-based
  routing with optional `Host` header and request header
  matching; longest prefix wins
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
- **Passive health checks** - track upstream failures
  inline; endpoints that exceed a consecutive failure
  threshold are marked unhealthy without dedicated
  probe traffic
- **Circuit breaker** - per-cluster circuit breaker that
  short-circuits requests to failing upstreams with 503,
  then gradually recovers via a half-open probe window
- **Redirect** - return 3xx redirects without upstream;
  supports `${path}` and `${query}` template placeholders
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
  (lowest latency). StreamBuffer delivers chunks to
  filters
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

Security is a primary design constraint. Praxis ships
with secure defaults and fails closed on ambiguous
configuration. See the
[Security Hardening Guide](security-hardening.md) for
deployment guidance.

**Build-level guarantees:**

- `#![deny(unsafe_code)]` in every crate
- Rustls (no OpenSSL, no C FFI in the TLS path)
- Supply chain auditing via `cargo audit` and
  `cargo deny`
- Root execution rejected by default

**Configuration-level protections:**

- Listeners default to localhost binding
- Admin endpoints reject public interfaces
- TLS paths reject directory traversal (`..`)
- Health check targets validated against SSRF
  (loopback and cloud metadata blocked)
- Upstream TLS verification enabled by default
- Insecure overrides require explicit opt-in and
  emit warnings

**Runtime filters:**

- **CORS**: spec-compliant CORS filter with preflight
  handling, origin validation, wildcard subdomain
  matching, credential support, and Private Network
  Access
- **IP ACL**: allow/deny by source IP/CIDR
- **Guardrails**: reject requests matching header or
  body content via string or regex rules; supports
  negated matching
- **Forwarded headers**: X-Forwarded-For/Proto/Host
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
- **Path rewrite** - strip prefix, add prefix, or regex
  replace on request paths; query strings preserved
- **URL rewrite** - regex-based path transformation and
  query string manipulation with ordered operations

## Operations

- **Dynamic configuration reload** - filter pipelines,
  routes, endpoints, health checks, and rate limits
  are swapped atomically at runtime when the config
  file changes. In-flight requests complete on the old
  pipeline; invalid configs are rejected and logged.
  Changes that require a restart (listener topology,
  TLS toggle, protocol type) are detected and logged
  as warnings.
- **Graceful shutdown** - configurable drain timeout
- **Runtime tuning** - thread pool sizing and
  work-stealing toggle

## Protocols

- **HTTP**: standard HTTP proxying with multiplexing;
  transparent passthrough supports SSE streaming and
  gRPC workloads.
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
[protocol-abstraction]:./architecture.md#protocol-adapters
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
- **Credential injection** (`credential_injection`):
  per-cluster API key injection with client credential
  stripping. Supports inline values and environment
  variable sources. Pair with a source discriminator
  (IP ACL, client auth) to control which clients get
  credential upgrades.

### Planned

The following capabilities are on the roadmap. Each
builds on the StreamBuffer body access pattern and the
filter pipeline.

- **Token counting**: input/output token counts from
  request and response bodies
- **Provider routing**: unified routing across LLM
  providers with API translation
- **Provider failover**: ordered failover chains with
  automatic API translation on failure
- **Token-based rate limiting**: per-client token quotas
  with sliding window or token bucket
- **Cost attribution**: token counting mapped to user,
  session, model, and endpoint
- **SSE streaming inspection**: per-event filter hooks
  for streaming responses
- **Semantic caching**: prompt deduplication via vector
  similarity search
- **AI guardrails**: prompt validation, content
  filtering, and policy enforcement

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

### JSON-RPC Support

- **JSON-RPC 2.0 foundation**: request envelope parsing
  and method/id extraction for HTTP POST bodies, enabling
  method-based routing for MCP/A2A-style traffic via the
  `json_rpc` filter

### Planned

The following capabilities are on the roadmap and not
yet implemented:

- **MCP proxying**: session management, tool discovery
  and routing, session lifecycle, auth and rate limiting
  for Model Context Protocol connections
- **A2A proxying**: agent card discovery, task lifecycle
  management, SSE streaming for Agent-to-Agent protocol
- **Stateful agent sessions**: shared session storage,
  affinity, and lifecycle hooks for MCP and A2A

## Build Features

AI filters are controlled via Cargo features (enabled
by default):

- `ai-inference`: model routing (`model_to_header`
  filter)
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
