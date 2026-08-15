---
issue: https://github.com/praxis-proxy/praxis/issues/123
discussion: https://github.com/orgs/praxis-proxy/discussions/961
status: proposed
authors:
  - abdallahsamabd
graduation_criteria:
  - How? section with requirements and design
  - Per-IP concurrent connection limit validated
  - Per-IP new connection rate limit validated
  - Rejection behavior configurable
  - Connection-limit rejection metrics exposed on admin /metrics
stakeholders:
  - shaneutt
---

# Connection Rate Limiting

## What?

Add per-source-IP connection-level rate limiting to
Praxis listeners, independent of the existing
request-level rate limiter.

Today Praxis supports request-level rate limiting
(token bucket per IP or global) and a global
`max_connections` ceiling per listener. However, there
is no mechanism to limit the rate or count of
connections from a single source IP. This means a
single client can exhaust the listener's connection
capacity, starving other clients.

This proposal adds:

- Per-source-IP concurrent connection limit: reject
  new connections from an IP once it exceeds a
  configurable threshold
- Per-source-IP new connection rate limit: limit how
  many new connections a single IP can open per second
  (token bucket)
- Configurable rejection behavior: immediately close
  with TCP RST, send an HTTP 429 response before
  closing, or silently drop

### Goals

- Protect the proxy and backends from connection
  floods originating from a single source IP.
- Limit concurrent connections per source IP so that
  no single client can monopolize listener capacity.
- Rate-limit new connection establishment per source
  IP to prevent rapid reconnection patterns (e.g.
  retry loops, port scans, slow-loris variants).
- Provide configurable rejection behavior so operators
  can choose between silent drop (stealth), TCP RST
  (fast client feedback), or HTTP 429 (application-
  level signal for connections that have completed
  TLS/HTTP negotiation).
- Operate at the connection (L4) layer for RST and
  silent-drop modes, rejecting malicious clients as
  cheaply as possible before any HTTP parsing or TLS
  handshake. The HTTP 429 mode applies only after the
  connection has completed TLS and HTTP framing.
- Integrate with the existing metrics pipeline to
  expose connection-limit rejections as Prometheus
  counters (by listener and reason — low-cardinality
  labels) and source IP in structured logs.
- Support configurable IP prefix aggregation so that
  IPv6 clients with a /64 allocation cannot bypass
  limits by rotating addresses. Defaults: /32 for
  IPv4 (exact IP), /64 for IPv6 (standard allocation
  prefix).

### Non-goals

- Global (non-per-IP) connection rate limiting — the
  existing `max_connections` per listener already
  covers this.
- Request-level rate limiting — already implemented
  via the `rate_limit` filter.
- IP allowlisting/denylisting — separate concern
  (access control).
- Distributed/cross-instance rate limiting — requires
  shared state, out of scope for v1.
- Upstream (cluster) connection rate limiting — this
  proposal targets inbound client connections only.
- PROXY protocol or `X-Forwarded-For`-based client
  identification — at L4 the source IP is the raw TCP
  peer address; there are no HTTP headers available to
  identify the real client. Deployments behind NAT,
  load balancers, or shared-IP gateways should account
  for multiple clients sharing one peer IP when setting
  thresholds. Unlike the L7 request-level rate limiter
  (which could be extended to inspect forwarded
  headers), the L4 connection limiter has no path to
  real-client identification without PROXY protocol
  support — which is out of scope for this proposal.

## Why?

### Motivation

Connection-level abuse is a distinct threat from
request-level abuse. A single client opening thousands
of concurrent connections — even if each connection
sends very few requests — can exhaust file descriptors,
memory, and kernel socket buffers on the proxy. This
is the basis of attacks like:

- **Slow-loris**: open many connections, send data
  very slowly, hold them open to exhaust connection
  slots.
- **Connection floods**: rapidly open/close TCP
  connections to consume CPU in handshake processing
  (SYN floods are handled at the kernel level, but
  completed connections still consume proxy resources).
- **Retry storms from misbehaving clients**: a buggy
  client reconnects in a tight loop after disconnect,
  creating hundreds of connections per second from a
  single IP.

The existing `max_connections` limit is global per
listener — it protects the proxy from total
overload but does not isolate clients from each
other. Without per-IP limits, a single abusive client
can consume the entire connection budget, causing
legitimate clients to receive connection refused
errors.

Competing proxies address this:
- **Envoy**: `connection_limit` filter with per-IP
  tracking
- **NGINX**: `limit_conn_zone` / `limit_conn` for
  per-IP concurrent limits
- **HAProxy**: `maxconn` per source via stick-tables

Praxis currently has no equivalent, leaving operators
to rely on external firewalls or OS-level iptables
rules — which are harder to configure, less
observable, and disconnected from the proxy's metrics.

### User Stories

- As a platform operator, I want to limit each client
  IP to at most 100 concurrent connections so that a
  single misbehaving client cannot exhaust the
  listener's connection capacity and starve other
  tenants.

- As an SRE responding to a slow-loris attack, I want
  to configure a per-IP concurrent connection limit
  that immediately rejects excess connections without
  waiting for HTTP parsing, so the proxy stays
  responsive under attack.

- As a security engineer, I want to rate-limit new
  connections per source IP (e.g. 50 new connections
  per second) so that rapid reconnection patterns
  from buggy or malicious clients are throttled before
  they create resource pressure.

- As an operator of a multi-tenant proxy, I want
  connection-level limits separate from request-level
  limits because a tenant can hold many idle
  connections (HTTP/2 multiplexing, WebSocket, gRPC
  streams) without sending proportionally many
  requests — request rate limiting alone does not
  protect against this.

- As an operator, I want rejected connections to
  appear in Prometheus metrics (counter by listener
  and rejection reason) and in structured logs (with
  source IP) so I can alert on spikes and investigate
  specific offenders.
