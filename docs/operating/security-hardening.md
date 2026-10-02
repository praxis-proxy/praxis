# Security Hardening Guide

Security is a primary motivation of Praxis, not an
afterthought. This guide covers the secure defaults
and operational hardening for production deployments.

## Default Security Posture

Praxis ships secure by default and fails closed on
ambiguous configuration:

- A listener `address` is required; there is no
  implicit default, so a listener never binds to an
  interface you did not name. Bind to `127.0.0.1`
  rather than `0.0.0.0` when a listener should not be
  externally reachable.
- TLS certificate verification is enabled by default
  for upstream connections.
- The admin API is restricted to loopback; non-loopback
  binding is a validation error unless
  `insecure_options.allow_public_admin` is set. The health/metrics listener
  can bind to non-loopback addresses and should be protected with network
  controls.
- A loopback admin or health/metrics listener rejects requests whose `Host`
  is not a loopback name, blocking DNS rebinding from
  the operator's browser (see
  [Admin DNS Rebinding](#admin-dns-rebinding)).
- `unsafe_code = "deny"` in workspace lints; no unsafe
  Rust in the Praxis codebase.
- Rustls protocol state machine for TLS;
  cryptography via the system OpenSSL
  (rustls-openssl provider).
- TLS certificate and key paths reject directory
  traversal (`..`).
- Health check targets reject loopback, link-local,
  and cloud metadata addresses (SSRF protection).
- Upstream hostnames that resolve to private or
  reserved addresses are refused at connection time on
  both the TCP and HTTP data planes, so a DNS record
  that rebinds after startup cannot steer traffic to
  loopback, RFC 1918, or `169.254.169.254`. When an
  HTTP cluster's endpoint hostname legitimately resolves
  into private space, such as a Kubernetes Service name
  resolving to its ClusterIP, list that host in the
  inline `load_balancer` cluster's
  `trusted_private_endpoints`. It relaxes only
  the listed host, and only to RFC 1918 and IPv6
  unique-local addresses, and skips the load-time
  hostname check that refuses names such as
  `*.cluster.local`. Proxied requests to loopback,
  link-local, and cloud metadata stay refused at
  connect time unless `allow_private_upstreams` is
  set. Health probes do not run this connect-time
  check. Listing a host trusts
  whoever controls its DNS with those ranges. On
  Kubernetes, edit rights on the Service or its
  Endpoints are control of its DNS. Write the endpoint
  address as a fully qualified name with a trailing dot,
  such as `model.tenant.svc.cluster.local.:8000`, so
  resolver search domains cannot substitute another name.
  The list entry needs no dot, since matching ignores
  it, and derived SNI drops it. Without the dot, the
  owner of a namespace named `svc` can answer through
  the search list. An ExternalName Service lets its
  owner point the name at another host. TLS hostname
  verification is what makes listing a tenant-owned
  name safe: keep `verify` on, pin the CA, and let SNI
  be the listed name. Add an egress NetworkPolicy to
  bound what the proxy can reach.
  Prefer this over `insecure_options.allow_private_upstreams`,
  which lifts the check for every upstream.
- Policy engine outbound calls (JWKS, token exchange,
  CIBA backchannel) share the proxy's sub-request
  connector. Private DNS answers (loopback, RFC 1918,
  link-local, cloud metadata, and CGNAT) are skipped;
  calls with no public answer are refused. Resolution
  happens once to prevent rebinding. Use
  `allow_private_idp` for an in-cluster provider.
- Policy engine TLS verifies against the platform
  trust store, including `SSL_CERT_FILE` and
  `SSL_CERT_DIR`; certificate and hostname verification
  are always on. Cluster `tls` settings do not apply,
  so private-CA and mTLS providers are unsupported and
  cannot share cluster-TLS connections.
- Root execution (UID 0) rejected by default.
- Supply chain audited via `cargo audit` and
  `cargo deny`.
- Reserved internal headers (`x-praxis-*` and AI
  extension prefixes `x-ext-protocol-*`, `x-ext-agent-*`) are
  rejected from client requests, stripped before
  forwarding to backends, and stripped from backend
  responses before reaching clients.
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

### Admin DNS Rebinding

The admin API has no authentication; loopback binding is
its access control. A web page the operator visits can
rebind its own DNS name to `127.0.0.1`, after which the
browser treats the admin API as same-origin and can read
`/api/pipelines`, `/api/stats`, and KV values, or send
`PUT`/`DELETE` to `/api/log-level` and `/api/kv/*`.

Every such request still carries the attacker's name in
`Host`. When either `admin.address` or `admin.metrics_address` is a loopback
address, every route on that listener answers `421 Misdirected Request` with
`{"error":"misdirected request"}` unless each `Host`
header (and any absolute-form request authority) is one
of:

- a loopback IP literal: `127.0.0.0/8`, `[::1]`, or
  IPv4-mapped loopback, with or without a port
- `localhost`, in any case, optionally with a trailing
  dot and a port

A request with no `Host` at all (HTTP/1.0) is served:
browsers always send `Host`, so only a client that
already reaches the socket directly can omit it. Use `127.0.0.1`, `[::1]`,
or `localhost` for both listeners; a local DNS alias is rejected.

The check is skipped on a listener bound to a non-loopback
address, because operators may reach it by DNS name. Such a
listener is still reachable through loopback on the same
host, so protect it with network controls rather than
relying on the bind address.

## TLS Best Practices

- Set certificate and key file permissions to `0600`,
  owned by the Praxis process user.
- Use `min_version: tls13` in TLS configuration.
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
- CRL and client CA files reload only on listeners
  with exactly one certificate and `hot_reload` not
  set to `false`. Every other listener needs a
  restart to pick up a new CRL.
- For upstream TLS, set `tls.sni` to the name on the
  backend certificate, especially for a hostname
  behind a load balancer. With
  `authority: { from: endpoint }` and no `tls.sni`,
  each endpoint is verified against its own hostname,
  or an IP endpoint against the certificate's IP SAN.

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
- **Path-based gating is not a boundary against
  normalizing upstreams**: filter conditions
  (`when: { path_prefix: … }`) and `router` route
  matches compare the raw request path. Praxis does
  not resolve dot-segments (`/./`, `/../`), collapse
  duplicate slashes (`//`), or percent-decode the
  path before matching, and it forwards the path to
  the upstream verbatim (this is deliberate — see the
  `%2f`/`//` passthrough behavior). The one exception:
  requests whose path has a `..` segment (including
  `%2e%2e`) are rejected with 400 before any filter
  runs, so `/public/../admin` cannot match a `/public`
  route and reach `/admin` upstream. A request such as
  `//admin` or `/%2e/admin` will therefore *not* match
  a `path_prefix: /admin` gate, yet an upstream that
  normalizes the path may still treat it as `/admin`.
  Do not rely on path-prefix gating of `basic_auth`,
  `ip_acl`, or `csrf` as the sole access control in
  front of a backend that normalizes paths. Prefer
  gating on a classifier-promoted `x-praxis-*` header
  (the "classify → route → branch" pattern), or
  terminate sensitive paths at the proxy.

## Resource Limits

- **Memory pressure**: Set `runtime.max_memory_bytes`
  to a process RSS ceiling. When exceeded, the proxy
  rejects new requests with 503 to prevent OOM. See
  [configuration.md](configuration.md) for details.
- **File descriptors**: Praxis raises its open file
  limit at startup and sheds requests with 503 before
  descriptors run out. Set
  `downstream_keepalive_timeout_ms` on listeners so idle
  clients cannot pin descriptors, and see
  [capacity-planning.md](capacity-planning.md) for
  sizing the limit and raising the hard limit.
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
- **`allow_tls_without_sni`**: Lets a verifying TLS
  cluster run with neither `tls.sni` nor
  `authority: { from: endpoint }`. The certificate is
  then checked against the cluster's fixed
  `authority` if set, else the client's `Host`
  header, so a client picks which name the backend
  must prove. When that is not a hostname, the
  endpoint address is used instead. Set `tls.sni`
  instead of enabling this.
- **Binding to `0.0.0.0`**: Exposes the listener on
  all interfaces. Use specific addresses in
  production.
- **Wildcard CORS origins (`"*"`)**: Allows any
  origin. Use explicit origin lists in production.
- **Empty IP ACL allowlists**: An empty allowlist
  permits all traffic. When possible, use the
  principle of least privilege and only allow access
  from the
  networks that require it.
