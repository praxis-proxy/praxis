# Security Hardening Guide

Security is a primary motivation of Praxis, not an
afterthought. This guide covers the secure defaults
and operational hardening for production deployments.

## Default Security Posture

Praxis ships secure by default and fails closed on
ambiguous configuration:

- Listeners bind to `127.0.0.1` unless explicitly
  configured otherwise.
- TLS certificate verification is enabled by default
  for upstream connections.
- Admin endpoints are restricted to localhost; public
  binding is a validation error.
- `unsafe_code = "deny"` in workspace lints; no unsafe
  Rust in the Praxis codebase.
- Rustls for TLS (no OpenSSL, no C FFI in the TLS
  path).
- TLS certificate and key paths reject directory
  traversal (`..`).
- Health check targets reject loopback, link-local,
  and cloud metadata addresses (SSRF protection).
- Root execution (UID 0) rejected by default.
- Supply chain audited via `cargo audit` and
  `cargo deny`.
- Reserved internal headers (`x-praxis-*`,
  `x-mcp-*`, `x-a2a-*`) are rejected from client
  requests, stripped before forwarding to backends,
  and stripped from backend responses before reaching
  clients.
- `--dump` redacts credential injection literal
  values as `[REDACTED]` to prevent accidental secret
  exposure in config dumps.

## Network Security

- Bind public-facing listeners to specific interfaces
  rather than `0.0.0.0`.
- Place Praxis behind a firewall. Expose only the
  ports your listeners require.
- Use separate listeners for public traffic and
  internal admin or health-check endpoints.
- Restrict admin and metrics endpoints to internal
  networks or loopback addresses.
- Restrict admin endpoints (including KV store API) to
  internal networks or loopback addresses. The KV admin
  API allows runtime modification of routing and
  transformation data.

## TLS Best Practices

- Set certificate and key file permissions to `0600`,
  owned by the Praxis process user.
- Use `min_version: "1.3"` in TLS configuration.
  TLS 1.2 can be used if required, but TLS 1.0 and 1.1
  are deprecated and Praxis will not negotiate them.
- Rotate certificates before expiration. Single-cert
  listeners hot-reload certificates automatically
  (see [tls.md](tls.md)). Multi-cert listeners require
  a restart.
- Use separate certificate entries with `server_names`
  for multi-domain deployments (SNI routing).
- Enable CRL checking for mTLS listeners by adding
  `crl_paths` to the `client_ca` block. CRL paths
  reject directory traversal (`..`). See
  [tls.md](tls.md) for configuration details.

## Access Control

- **IP ACLs**: Use the `ip_acl` filter to restrict
  access by source IP. Use either `allow` or `deny`,
  not both (mutually exclusive). An allow-list
  implicitly denies all non-matching IPs.
- **Rate Limiting**: Configure `rate_limit` filters
  to bound request volume per client or globally.
  Tune limits based on expected traffic patterns.
- **CORS**: Use the `cors` filter with explicit
  `allow_origins` rather than wildcards. Restrict
  `allow_methods` and `allow_headers` to what
  your application requires.
- **CSRF**: Use the `csrf` filter with explicit
  `trusted_origins`. The `enforce_percentage` field
  enables gradual rollout; enforcement sampling is
  randomized per-request to prevent attackers from
  predicting unenforced windows.
- **Connection limits**: Set `max_connections` on
  listeners to cap concurrent connections. HTTP
  listeners reject excess requests with 503 and
  `Retry-After`; TCP listeners close immediately.

## Resource Limits

- **Memory pressure**: Set `runtime.max_memory_bytes`
  to a process RSS ceiling. When exceeded, the proxy
  rejects new requests with 503 to prevent OOM. See
  [configuration.md](configuration.md) for details.
- **Payload size**: Set `body_limits.max_request_bytes`
  and `body_limits.max_response_bytes` to bound
  buffered payload sizes. Requests exceeding the
  limit receive 413.

## Deployment

### Container Security

- Run the container as a non-root user. The official
  image uses a dedicated `praxis` user.
- Mount the filesystem read-only where possible.
  Configuration and TLS materials can be mounted as
  read-only volumes.
- Drop all Linux capabilities except those required
  for binding to privileged ports (if needed).
- Use a minimal base image to reduce attack surface.

### Kubernetes

- Set `runAsNonRoot: true` and
  `readOnlyRootFilesystem: true` in the pod security
  context.
- Use `NetworkPolicy` to restrict traffic.
- Store TLS certificates in Kubernetes `Secret`
  objects and mount them read-only.
- Set resource limits to prevent resource exhaustion.

## Insecure Configuration Options

The following options weaken security. Use them only
in development:

- **`verify: false`** on upstream TLS: Disables
  certificate verification. Acceptable only for
  local development with self-signed certs.
- **Binding to `0.0.0.0`**: Exposes the listener on
  all interfaces. Use specific addresses in
  production.
- **Wildcard CORS origins (`"*"`)**: Allows any
  origin. Use explicit origin lists in production.
- **Empty IP ACL allowlists**: An empty allowlist
  permits all traffic. When possible, use principle
  of least privilege and only allow access from the
  networks that require it.
