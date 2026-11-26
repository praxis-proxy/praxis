# Security Hardening Guide

This guide lists Praxis's secure defaults and the settings to review before a
production deployment. Authentication, authorization, scoped upstream
credentials, and redaction are covered in
[policy enforcement with Praxis Policy Engine (PPE)][policy-guide].

## Default Security Posture

Praxis fails closed on ambiguous configuration:

- A listener `address` is required, so a listener never binds to an
  interface you did not name.
- Upstream TLS certificate verification is on by default.
- The admin API must bind to loopback; a non-loopback address is a
  validation error unless `insecure_options.allow_public_admin` is set. The
  health/metrics listener can bind anywhere, so protect it with network
  controls.
- A loopback admin or health/metrics listener rejects requests whose `Host`
  is not a loopback name (see [Admin DNS Rebinding](#admin-dns-rebinding)).
- `unsafe_code = "deny"` in workspace lints: no unsafe Rust in the Praxis
  codebase.
- TLS uses the rustls protocol state machine, with cryptography from the
  system OpenSSL (rustls-openssl provider).
- TLS certificate, key, and CRL paths reject directory traversal (`..`).
- Health check targets reject loopback, link-local, and cloud metadata
  addresses (SSRF protection). Health probes do not run the connect-time
  check below.
- Upstream hostnames that resolve to private or reserved addresses are
  refused at connection time on both the TCP and HTTP data planes, so a DNS
  record that rebinds after startup cannot steer traffic to loopback,
  RFC 1918, or `169.254.169.254`. See
  [Private upstream endpoints](#private-upstream-endpoints) for the opt-in.
- Policy engine outbound calls (JWKS, token exchange, CIBA backchannel) share
  the proxy's sub-request connector. Private DNS answers (loopback,
  RFC 1918, link-local, cloud metadata, and CGNAT) are skipped, and a call
  with no public answer is refused. Each name resolves once, to prevent
  rebinding. Use `allow_private_idp` for an in-cluster provider.
- Policy engine TLS always verifies certificates and hostnames against the
  platform trust store, including `SSL_CERT_FILE` and `SSL_CERT_DIR`. Cluster
  `tls` settings do not apply, so private-CA and mTLS providers are
  unsupported and cannot share cluster-TLS connections.
- Running as root (UID 0) is rejected by default.
- The supply chain is audited with `cargo audit` and `cargo deny`.
- Reserved internal headers (`x-praxis-*` and the AI extension prefixes
  `x-ext-protocol-*`, `x-ext-agent-*`) are rejected from client requests and
  stripped in both directions between client and backend.
- `--dump` prints credential injection literal values as `[REDACTED]`.

## Network Security

- Bind listeners to specific interfaces, not `0.0.0.0`. Use `127.0.0.1` for
  a listener that should not be reachable from outside the host.
- Put Praxis behind a firewall that exposes only the listener ports.
- Use separate listeners for public traffic and for admin or health checks.
- Keep the admin and metrics endpoints on internal networks or loopback. The
  KV admin API can change routing and transformation data at runtime.

### Private upstream endpoints

When an HTTP cluster's endpoint hostname legitimately resolves into private
space, such as a Kubernetes Service name resolving to its ClusterIP, list the
host in the inline `load_balancer` cluster's `trusted_private_endpoints`.
That relaxes only the listed host, and only to RFC 1918 and IPv6 unique-local
addresses, and skips the load-time hostname check that refuses names such as
`*.cluster.local`. Proxied requests to loopback, link-local, and cloud
metadata stay refused unless `allow_private_upstreams` is set. Prefer this
over `insecure_options.allow_private_upstreams`, which lifts the check for
every upstream.

Listing a host trusts whoever controls its DNS with those ranges. On
Kubernetes, edit rights on the Service or its Endpoints are control of its
DNS, and an ExternalName Service lets its owner point the name at another
host. To keep that safe:

- Write the endpoint as a fully qualified name with a trailing dot, such as
  `model.tenant.svc.cluster.local.:8000`, so resolver search domains cannot
  substitute another name. Without the dot, the owner of a namespace named
  `svc` can answer through the search list. The list entry needs no dot,
  since matching ignores it, and derived SNI drops it.
- Keep TLS `verify` on, pin the CA, and let SNI be the listed name. Hostname
  verification is what makes listing a tenant-owned name safe.
- Add an egress NetworkPolicy to bound what the proxy can reach.

### Admin DNS Rebinding

The admin API has no authentication; loopback binding is its access control.
A web page the operator visits can rebind its own DNS name to `127.0.0.1`,
after which the browser treats the admin API as same-origin and can read
`/api/pipelines`, `/api/stats`, and KV values, or send `PUT`/`DELETE` to
`/api/log-level` and `/api/kv/*`.

Every such request still carries the attacker's name in `Host`. When
`admin.address` or `admin.metrics_address` is a loopback address, every route
on that listener answers `421 Misdirected Request` with
`{"error":"misdirected request"}` unless each `Host` header (and any
absolute-form request authority) is one of:

- a loopback IP literal: `127.0.0.0/8`, `[::1]`, or IPv4-mapped loopback,
  with or without a port
- `localhost`, in any case, optionally with a trailing dot and a port

A request with no `Host` (HTTP/1.0) is served, since browsers always send
one. Use `127.0.0.1`, `[::1]`, or `localhost` for both listeners; a local DNS
alias is rejected.

A listener bound to a non-loopback address skips the check, because
operators may reach it by DNS name. It is still reachable through loopback
on the same host, so protect it with network controls.

## TLS Best Practices

- Give certificate and key files mode `0600`, owned by the Praxis process
  user.
- Set `min_version: tls13`. TLS 1.2 works if required; Praxis never
  negotiates TLS 1.0 or 1.1.
- Rotate certificates before they expire. Single-cert listeners hot-reload
  certificates (see [tls.md](tls.md)); multi-cert listeners need a restart.
- For multi-domain deployments, use separate certificate entries with
  `server_names` (SNI routing).
- On mTLS listeners, enable CRL checking with `crl_paths` in the `client_ca`
  block. [tls.md](tls.md) says when a new CRL needs a restart.
- For upstream TLS, set `tls.sni` to the name on the backend certificate,
  especially for a hostname behind a load balancer. With
  `authority: { from: endpoint }` and no `tls.sni`, each endpoint is verified
  against its own hostname, or an IP endpoint against the certificate's IP
  SAN.

## Access Control

Use the `policy` filter (PPE, built into Core) for authentication and
authorization: JWTs (including OIDC tokens and SPIFFE JWT-SVIDs) or opaque
API keys, with Cedar, CEL, or OPA/Rego rules. The [PPE guide][policy-guide]
covers the use cases and each protocol's requirements;
[identity configuration][policy-identity] covers issuers, audiences, and
claim mapping.

When a policy injects identity into upstream headers (`assertions.request`),
restrict backend access to trusted proxy paths so callers cannot bypass the
assertions ([header assertions][policy-headers]). Basic auth identities are
being added to PPE; check the PPE version in your Core build. The
[basic_auth filter][basic-auth] is deprecated, stores credentials in
plaintext, and is for development and testing only.

### Network controls

- **IP ACLs**: `ip_acl` takes either `allow` or `deny`, not both. An
  allow-list denies every IP that does not match.
- **Rate limiting**: `rate_limit` filters bound request volume per client or
  globally.
- **CORS**: give the `cors` filter explicit `allow_origins`, and restrict
  `allow_methods` and `allow_headers` to what the application needs.
- **CSRF**: give the `csrf` filter explicit `trusted_origins`. For gradual
  rollout, `enforce_percentage` samples randomly per request, so attackers
  cannot predict unenforced windows.
- **Connection limits**: `max_connections` on a listener caps concurrent
  connections. HTTP listeners reject the excess with 503 and `Retry-After`;
  TCP listeners close immediately.
- **Path-based gating is not a boundary against normalizing upstreams.**
  Filter conditions (`when: { path_prefix: … }`) and `router` route matches
  compare the raw request path. Praxis does not resolve dot-segments (`/./`,
  `/../`), collapse duplicate slashes (`//`), or percent-decode before
  matching, and forwards the path verbatim (deliberately, so `%2f` and `//`
  pass through). The one exception: a path with a
  `..` segment (including `%2e%2e`) is rejected with 400 before any filter
  runs, so `/public/../admin` cannot match a `/public` route. A request for
  `//admin` or `/%2e/admin` will *not* match a `path_prefix: /admin` gate,
  yet an upstream that normalizes the path may treat it as `/admin`. Don't
  rely on path-prefix gating of `basic_auth`, `ip_acl`, or `csrf` as the only
  access control in front of such a backend. Gate on a classifier-promoted
  `x-praxis-*` header instead (the "classify → route → branch" pattern), or
  terminate sensitive paths at the proxy.

## Resource Limits

- **Memory pressure**: `runtime.max_memory_bytes` sets a process RSS
  ceiling; above it, new requests get 503 instead of the process hitting OOM
  ([configuration.md](configuration.md)).
- **File descriptors**: Praxis raises its open file limit at startup and
  sheds requests with 503 before descriptors run out. Set
  `downstream_keepalive_timeout_ms` on listeners so idle clients cannot pin
  descriptors. [capacity-planning.md](capacity-planning.md) covers sizing and
  raising the hard limit.
- **Payload size**: `body_limits.max_request_bytes` and
  `body_limits.max_response_bytes` bound buffered payloads; a request over
  the limit gets 413.

## Deployment

### Container Security

- Run as a non-root user. The official image uses a dedicated `praxis` user.
- Mount the filesystem read-only where possible, including configuration
  and TLS material.
- Drop all Linux capabilities except any needed to bind privileged ports.
- Use a minimal base image.

### Kubernetes

- Set `runAsNonRoot: true` and `readOnlyRootFilesystem: true` in the pod
  security context.
- Restrict traffic with `NetworkPolicy`.
- Store TLS certificates in `Secret` objects and mount them read-only.
- Set resource limits.

## Insecure Configuration Options

Use these only in development:

- **`verify: false`** on upstream TLS disables certificate verification.
- **`allow_tls_without_sni`** lets a verifying TLS cluster run with neither
  `tls.sni` nor `authority: { from: endpoint }`, so the client's `Host` header
  can pick which name the backend must prove. Set `tls.sni` instead. Details
  are in [`insecure_options`](../developing/getting-started.md#insecure-options).
- **Binding to `0.0.0.0`** exposes the listener on all interfaces.
- **Wildcard CORS origins (`"*"`)** allow any origin.
- **An empty IP ACL allowlist** permits all traffic.

[policy-guide]: ../security/policy-enforcement.md
[policy-identity]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/apl/identity.md
[basic-auth]: ../filters/http/security/basic_auth.md
[policy-headers]:
  https://github.com/praxis-proxy/policy/blob/main/docs/content/reference/assertions.md
