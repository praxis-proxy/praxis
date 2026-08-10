---
issue: https://github.com/praxis-proxy/praxis/issues/108
discussion: https://github.com/orgs/praxis-proxy/discussions/905
status: proposed
authors:
  - abdallahsamabd
graduation_criteria:
  - How? section with requirements and design
  - Session mapping data structure validated
  - Cookie injection/extraction logic validated
stakeholders:
  - shaneutt
---

# Sticky Sessions / Session Affinity

## What?

Add cookie-based and header-based session persistence to
pin clients to specific upstream endpoints across
requests.

Today Praxis supports session affinity only through
stateless consistent hashing — a request header value
(or URI path) is hashed to select an endpoint. There is
no server-side session mapping, no proxy-managed session
cookie, and no ability to learn session identifiers from
upstream responses. This proposal adds:

- Cookie-based persistence: proxy sets a session cookie
  mapping to a specific endpoint, reads it on subsequent
  requests to route directly
- Cookie attributes: domain, path, expires/max-age,
  httponly, secure, samesite
- Header-based persistence: use a request header value
  to select and pin to an endpoint with a server-side
  mapping
- Learn mode: extract session identifier from upstream
  response (e.g. Set-Cookie: JSESSIONID) and
  automatically build session-to-endpoint mapping
- Shared session-to-endpoint mapping: thread-safe,
  cross-worker data structure aligned with proposal #99
  (Stateful Proxy State Management), which defines the
  project-wide shared state model and explicitly lists
  sticky sessions as a feature driver
- Graceful failover: re-pin to a healthy endpoint when
  the pinned endpoint fails health checks
- Load balancer integration: session affinity overrides
  normal LB selection on cache hits

### Goals

- Allow operators to configure session persistence per
  cluster without code changes.
- Support cookie-based persistence for browser clients
  and header-based persistence for API clients.
- Automatically learn session identifiers from upstream
  responses so existing applications (Tomcat, Rails,
  Express) work without modification.
- Provide a shared session-to-endpoint mapping visible
  to all proxy workers so routing is consistent
  regardless of which worker handles the request.
- Gracefully failover pinned sessions to healthy
  endpoints when the original endpoint becomes
  unavailable.
- Integrate with the existing load balancer so that
  session affinity overrides LB selection for pinned
  sessions while new sessions still use the configured
  strategy.
- Enforce bounded state for session mappings: TTL-based
  expiry on entries, a configurable entry count cap
  with eviction policy, and visible metrics for mapping
  size and eviction rate to prevent unbounded memory
  growth under high session cardinality.
- Define behavior on pipeline hot-reload: session
  mappings must survive configuration reloads or be
  explicitly documented as ephemeral (the How? section
  will resolve this based on proposal #99's state
  model).
- Align the shared mapping implementation with proposal
  #99 (Stateful Proxy State Management). This proposal
  depends on #99's state model for the storage layer;
  the How? section will adopt #99's typed session
  stores and TTL patterns once accepted.

## Why?

### Motivation

Many production applications store session state in
server memory rather than in an external store: shopping
carts, authentication sessions, multi-turn AI inference
contexts, WebSocket upgrade state, and chunked file
uploads all depend on the same backend handling every
request in a session.

Without true session persistence, operators must either:
1. Require all applications to externalize state (Redis,
   database) — adding complexity and latency.
2. Rely on consistent hashing — which is stateless and
   silently re-routes sessions when endpoints change
   (deploys, scaling events, failures).
3. Push session affinity logic into client applications
   — violating separation of concerns.

The current consistent-hash strategy has specific
limitations:

1. **No cookie support** — browsers cannot participate
   in session affinity without application-level
   workarounds. The proxy cannot inject or read a
   session cookie.
2. **Stateless re-routing** — when an endpoint is added
   or removed, a fraction of sessions are silently
   re-hashed to different endpoints, breaking in-flight
   sessions.
3. **No learn mode** — applications that already issue
   session cookies (JSESSIONID, PHPSESSID, connect.sid)
   cannot have those respected by the proxy for
   routing.
4. **No stable failover** — when the hashed endpoint is
   unhealthy, the ring probes adjacent slots but does
   not persist the new binding, so sessions can bounce
   between endpoints across health transitions and
   topology changes.
5. **No shared state** — each worker independently
   hashes, with no ability to store explicit
   session-to-endpoint bindings.

Competing proxies (Envoy, HAProxy, NGINX Plus, Traefik)
all provide cookie-based sticky sessions as a core
feature. This is a table-stakes capability for any
production proxy handling stateful applications.

### User Stories

- As a platform operator, I want to configure
  cookie-based session persistence per cluster so that
  browser clients are pinned to the same backend
  without requiring application changes.

- As a developer deploying a legacy Java application, I
  want Praxis to learn the JSESSIONID from upstream
  Set-Cookie responses and use it for routing so that
  my application works correctly behind the proxy
  without modification.

- As an SRE, I want graceful failover so that when a
  pinned backend goes down, affected sessions are
  automatically re-pinned to a healthy endpoint rather
  than receiving errors until the cookie expires.

- As a security engineer, I want full control over
  session cookie attributes (HttpOnly, Secure,
  SameSite) so that session cookies meet our security
  policy requirements.

- As an API platform operator, I want header-based
  session persistence for API clients that do not
  support cookies, using a header like X-Session-Id to
  pin requests to the same backend.

- As an operator running a multi-worker proxy, I want
  the session-to-endpoint mapping to be shared across
  all workers so that any worker can correctly route a
  returning session regardless of which worker handled
  the initial request.
