# Features

Linked pages hold the configuration and full behavior. Working configs are in
the [example configs](../examples/README.md).

## Core Architecture

- **Extensible proxy framework**: run a provided build, or implement the
  `HttpFilter` or `TcpFilter` trait in your own crate and compile a custom
  proxy. See [extensions](developing/extensions.md).
- **Filter pipeline**: configurable chains of filters applied to requests and
  responses. See [Pipeline Concepts][pipeline-concepts].
- **Conditional filters**: `when`/`unless` gates in request and response
  phases (path prefix, methods, headers, status codes).
- **Branch chains**: branch on filter results, with skip-forward, terminal
  short-circuit, and re-entrance loops. See
  [Branch Chains](filters/branch-chains.md).

## Traffic Management

- **Routing**: prefix routing with optional `Host` and request header
  matching; longest prefix wins. See the
  [router](filters/http/traffic_management/router.md).
- **Load balancing**: round-robin, least-connections, consistent-hash,
  power-of-two-choices (P2C), weighted endpoints. See
  [load balancing](operating/load-balancing.md).
- **Health checks**: active HTTP and TCP probes with thresholds, and passive
  checks that mark an endpoint unhealthy after consecutive failures. Unhealthy
  hosts leave load balancer rotation. See
  [health checking](operating/health-checking.md).
- **Circuit breaker**: per cluster; returns 503 for a failing upstream, then
  recovers through a half-open probe window.
- **Rate limiting**: token bucket, per-IP (IPv6 optionally grouped by prefix)
  or global, with burst, 429 responses with `Retry-After` and `X-RateLimit-*`
  headers, and a `shadow` mode that counts would-be rejections without
  enforcing.
- **Static responses and redirects**: fixed status, headers, and body, or 3xx
  redirects with `${path}` and `${query}` placeholders, without an upstream.
- **Timeouts**: 504 when the upstream response exceeds a latency SLA;
  per-cluster connection, read, write, idle, and total connection (TLS
  handshake) timeouts.
- **gRPC detection**: detects gRPC, gRPC-Web, and sub-protocols by content
  type and writes results for branch conditions.
- **Endpoint selector**: header-based endpoint selection from trusted mutation
  sources.

## Payload Processing

Bodies stream zero-copy by default. Filters opt in to buffered or
StreamBuffer access with size limits. StreamBuffer (peek-then-stream) hands
chunks to filters as they arrive but holds upstream forwarding until release,
which enables JSON-RPC envelope parsing, body-based routing, and guardrails
scanning. See [Payload Processing][payload-processing].

- **JSON body rewrite**: `json_body` applies JSON Pointer add, remove,
  replace, and extract to request bodies, and remove and extract to response
  bodies, without building a DOM. Extract copies values into
  `filter_metadata` or structured metadata. Request `Content-Length` is
  repaired; response remove is padded with trailing spaces. Duplicate keys and
  response limits are covered on the
  [`json_body` page](filters/http/payload_processing/json_body.md).
- **Body-based routing**: `json_body_field` promotes top-level JSON fields to
  request headers for cluster selection and classification.
- **JSON-RPC envelope parsing**: extracts method, id, kind, and batch length
  from JSON-RPC 2.0 payloads into headers and filter results.
- **Response compression**: gzip, brotli, and zstd, with per-algorithm
  levels, content type filtering, and minimum sizes.
- **Payload size limits**: global hard ceilings on request and response
  payload size.

[payload-processing]:./architecture/payload-processing.md
[pipeline-concepts]:./architecture/pipeline-concepts.md

## Security

Praxis ships secure defaults and fails closed on ambiguous configuration. See
the [Security Hardening Guide](operating/security-hardening.md).

Build:

- `unsafe_code = "deny"` in workspace lints
- Rustls for TLS, with the system OpenSSL library as its cryptographic
  provider
- Supply chain auditing with `cargo audit` and `cargo deny`
- Root execution rejected by default

Configuration:

- Listener `address` is required, so a listener binds only where you name it
- The admin API must bind to loopback unless `allow_public_admin` is set
- TLS paths reject directory traversal (`..`)
- Health check targets are checked for SSRF (loopback, link-local, and cloud
  metadata blocked)
- Upstream TLS verification is on by default
- Insecure overrides need explicit opt-in and log warnings

Runtime filters:

- **CORS**: preflight, origin validation, wildcard subdomains, credentials,
  and Private Network Access
- **IP ACL**: allow or deny by source IP/CIDR
- **Guardrails**: reject requests whose headers or body match string or regex
  rules, with negated matching
- **CSRF protection**: origin-based, with `Sec-Fetch-Site` support, wildcard
  subdomains, gradual rollout, and log-only mode
- **Forwarded headers**: X-Forwarded-For/Proto/Host injection with trusted
  proxy CIDRs
- **Credential injection**: per-cluster API keys in upstream request headers,
  from environment variables or inline values; strips client credentials
- **[Praxis Policy Engine (PPE)][policy-guide]** (`policy` filter):
  authorizes API, tool, and model calls using verified user, client, and
  workload identities. Policies can call Cedar, CEL, or OPA, obtain scoped
  upstream credentials, redact tool data, restrict later calls through session
  taint, and require human approval. Auditing is configurable. The standard
  build includes PPE through `policy-builtins`, with its experimental rate
  limiter; add the filter and a policy document to enforce. To select
  individual plugins, see [build features][policy-builds].

[policy-guide]: security/policy-enforcement.md
[policy-builds]: operating/build-features.md#selecting-policy-features

## Observability

- **Request ID**: generates or propagates correlation IDs (X-Request-ID by
  default) and echoes them in responses
- **Access logging**: structured request/response logs via `tracing`
- **Prometheus metrics**: `/metrics` on the health/metrics listener, with
  request counts, duration histograms, and optional per-filter hook duration
  histograms (`metrics.filter_duration`, default off). See
  [observability](operating/observability.md).
- **Admin health endpoints**: `/ready` and `/healthy` on the listener set by
  `admin.metrics_address`. `/ready` reports per-cluster healthy, unhealthy,
  and total counts when active health checks are configured, and returns
  `503` while the replica is initializing, draining, or stopped. With
  `admin.readiness: upstreams` it also returns `503` when any cluster has no
  healthy endpoints.

## Request/Response Transformation

- **Header manipulation**: add, set, and remove request and response headers
- **Path rewrite**: strip prefix, add prefix, or regex replace; query strings
  preserved
- **URL rewrite**: regex path transformation and query string edits as
  ordered operations

## Operations

- **Dynamic configuration reload**: when the config file changes, filter
  pipelines, routes, endpoints, health checks, and rate limits swap
  atomically. In-flight requests finish on the old pipeline; invalid configs
  are rejected and logged. Changes that need a restart (listener topology, TLS
  toggle, protocol type) are logged as warnings.
- **Configuration validation**: `--validate` checks a config without
  starting; `--dump` prints the effective config with defaults applied
- **Graceful shutdown**: configurable drain timeout
- **Max connections**: per-listener limit; HTTP returns 503 with
  `Retry-After`, TCP closes immediately
- **Runtime tuning**: thread pool size and work-stealing toggle
- **FIPS 140-3 build**: all cryptography runs in the system OpenSSL, the
  validated module on a RHEL 9 host in FIPS mode. Published as a `-fips` UBI 9
  image, checked with Red Hat's scanner on every pull request;
  `PRAXIS_REQUIRE_FIPS` refuses to start outside FIPS mode. See
  [FIPS 140-3](operating/fips.md).
- **Runtime key-value stores**: in-memory caches that filters create at
  runtime, with an admin API (GET/PUT/DELETE), exact/prefix/suffix/regex
  matching, and a pluggable `KvBackend` trait. Meant for operational overrides
  (routing tables, feature flags), not durable storage.

## Protocols

- **HTTP**: proxying with multiplexing; transparent passthrough for SSE and
  gRPC. See [HTTP Connection Lifecycle][http-lifecycle].
- **TLS**: termination, re-encryption to upstream with configurable SNI,
  certificate hot-reload (500ms debounce), per-listener cipher suites, and CRL
  checking for mTLS client certificates. See [TLS documentation][tls-docs].
- **TCP/L4**: bidirectional forwarding with optional TLS and idle timeout. See
  [TCP Connection Lifecycle][tcp-lifecycle].
- **Mixed protocols**: HTTP and TCP listeners in one server. See
  [Protocol Abstraction][protocol-abstraction].

[http-lifecycle]:./architecture/connection-lifecycle.md#http-connection-lifecycle
[tcp-lifecycle]:./architecture/connection-lifecycle.md#tcp-connection-lifecycle
[protocol-abstraction]:./architecture/overview.md#protocol-adapters
[tls-docs]:./operating/tls.md

## Extensions

- **Rust extensions**: compile-time custom filters with no runtime overhead,
  through the `HttpFilter`/`TcpFilter` traits and the `register_filters!`
  macro
- **Failure mode**: per-filter `failure_mode: open` lets non-security filters
  pass traffic on runtime errors

## AI gateway

An AI gateway routes, manages, enriches, and parses inference and agent
traffic between workloads and model or agent backends. LLM provider filters,
MCP/A2A, response storage, and token metadata ship in
[praxis-ai](https://github.com/praxis-proxy/ai), not the core `praxis` binary;
see the
[praxis-ai overview](https://github.com/praxis-proxy/ai/blob/main/docs/overview.md).
Core filters such as `json_rpc`, `credential_injection`, and `router` compose
with AI filters in `praxis-ai` pipelines.
