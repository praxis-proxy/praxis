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
- **Retry with idempotency awareness** - connection
  failures on idempotent requests (GET, HEAD, OPTIONS)
  are retried automatically
- **Static responses** - return fixed status, headers,
  and body without upstream
- **Timeout enforcement** - 504 rejection when upstream
  response exceeds a configured latency SLA
- **Connection tuning** - per-cluster connection, read,
  write, idle, and total connection (TLS handshake)
  timeouts

## Payload Processing

- **Streaming payload processing** - zero-copy streaming
  by default, opt-in buffered or stream-buffered payload
  access with configurable size limits
  > **Note**: Stream mode passes chunks through as they
  > arrive (lowest latency). Buffer mode accumulates the
  > full body. StreamBuffer delivers chunks to filters
  > incrementally but defers upstream forwarding until
  > release. See [architecture.md](architecture.md) for
  > details.
- **Stream-buffered payload inspection** - inspect
  request and response payload chunks as they arrive
  while deferring upstream forwarding until content is
  validated; enables AI inference, Agentic networks,
  and Security systems use cases including content
  scanning, WAF payload inspection, and body-based
  routing without full buffering latency
- **Body-based routing** - the built-in `json_body_field`
  filter extracts top-level fields from JSON request
  bodies and promotes values to request headers, enabling
  AI inference model routing, content-based cluster
  selection, and request classification
- **Payload size limits** - global hard ceilings on
  request and response payload size

## Security

- **IP ACL** - allow/deny by source IP/CIDR
- **Forwarded headers** - X-Forwarded-For/Proto/Host
  injection with trusted proxy CIDR support

## Observability

- **Request ID** - generate or propagate correlation IDs
  (X-Request-ID by default); echoed in responses
- **Access logging** - structured request/response logging
  via `tracing`
- **Admin health endpoints** - `/ready` and `/healthy` on
  a dedicated admin listener

## Request/Response Transformation

- **Header manipulation** - add, set, and remove headers
  on requests and responses

## Operations

- **Graceful shutdown** - configurable drain timeout
- **Runtime tuning** - thread pool sizing and
  work-stealing toggle

## Protocols

- **HTTP/1.1 and HTTP/2** - standard HTTP proxying and
  HTTP/2 multiplexing; transparent passthrough supports
  SSE streaming and gRPC workloads
- **TLS**
  - **Termination** - HTTPS on the listener, plain HTTP upstream
  - **Re-encryption** - TLS to upstream with configurable SNI
- **TCP/L4** - bidirectional forwarding

## Build Features

AI filters are opt-in via Cargo features (not enabled
by default):

- `ai-inference`: model routing, token counting, prompt
  inspection (includes `model_to_header` filter)
- `ai-agentic`: MCP, A2A, agent orchestration (planned)

```console
cargo build -p praxis --features ai-inference
cargo build -p praxis --features ai-inference,ai-agentic
```

## Extensions

- **Rust extensions** - compile-time custom filters with zero
  overhead via the `HttpFilter`/`TcpFilter` traits and
  `register_filters!` macro
