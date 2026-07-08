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
  consistent-hash, power-of-two-choices (P2C),
  weighted endpoints
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
  for protocol parsing (JSON-RPC envelope extraction),
  body-based routing, and security systems (guardrails
  payload scanning, content classification).
  See the [payload processing][payload-processing]
  docs for the full body access model.
- **Body-based routing**: the built-in `json_body_field`
  filter extracts top-level fields from JSON request
  bodies and promotes values to request headers, enabling
  content-based cluster selection and request
  classification.
- **Response compression**: gzip, brotli, and zstd
  response compression with per-algorithm levels,
  content type filtering, and minimum size thresholds.
- **Payload size limits**: global hard ceilings on
  request and response payload size.

[payload-processing]:./architecture/payload-processing.md

## Security

Security is a primary design constraint. Praxis ships
with secure defaults and fails closed on ambiguous
configuration. See the
[Security Hardening Guide](operating/security-hardening.md) for
deployment guidance.

**Build-level guarantees:**

- `unsafe_code = "deny"` in workspace lints
- Rustls (no OpenSSL, no C FFI in the TLS path)
- Supply chain auditing via `cargo audit` and
  `cargo deny`
- Root execution rejected by default

**Configuration-level protections:**

- Listeners default to localhost binding
- Admin endpoints reject public interfaces
- TLS paths reject directory traversal (`..`)
- Health check targets validated against SSRF
  (loopback, link-local, and cloud metadata blocked)
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
- **CSRF protection**: origin-based CSRF validation
  with gradual enforcement rollout, `Sec-Fetch-Site`
  support, wildcard subdomains, and log-only mode
- **Forwarded headers**: X-Forwarded-For/Proto/Host
  injection with trusted proxy CIDR support

## Observability

- **Request ID** - generate or propagate correlation IDs
  (X-Request-ID by default); echoed in responses
- **Access logging** - structured request/response logging
  via `tracing`
- **Prometheus metrics** - `/metrics` on the admin
  listener exposes request counts and duration
  histograms in Prometheus text exposition format
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
- **Max connections** - per-listener connection limit
  via semaphore; HTTP returns 503 with `Retry-After`,
  TCP closes immediately
- **Runtime tuning** - thread pool sizing and
  work-stealing toggle
- **Runtime key-value stores** - in-memory runtime caches
  created dynamically by filters. Admin API
  (GET/PUT/DELETE) and exact/prefix/suffix/regex match
  types. Pluggable `KvBackend` trait for alternative
  backends. Accessible from all filter contexts. Designed
  for operational overrides (routing tables, feature
  flags), not durable storage.

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

[http-lifecycle]:./architecture/connection-lifecycle.md#http-connection-lifecycle
[tcp-lifecycle]:./architecture/connection-lifecycle.md#tcp-connection-lifecycle
[protocol-abstraction]:./architecture/overview.md#protocol-adapters
[tls-docs]:./operating/tls.md

## Extensions

- **Rust extensions**: compile-time custom filters with
  zero overhead via the `HttpFilter`/`TcpFilter` traits
  and `register_filters!` macro.
