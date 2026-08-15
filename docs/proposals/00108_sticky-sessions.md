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

## How?

### Requirements

- New `sticky_sessions` builtin HTTP filter registered
  in `FilterRegistry`
- Filter runs before (or replaces) load balancer for
  session-pinned requests
- Cookie parsing: extract named cookie value from
  `Cookie` request header
- Cookie injection: append `Set-Cookie` response header
  with configurable attributes
- Header-based persistence: read a configurable request
  header as session key
- Learn mode: extract session identifier from upstream
  `Set-Cookie` response header
- Shared session-to-endpoint mapping with TTL, entry
  cap, and eviction policy
- Health-aware pin validation: verify pinned endpoint
  is healthy before routing
- Graceful failover: re-pin to healthy endpoint and
  update mapping when pin target is unhealthy
- Pipeline hot-reload survival: session mappings stored
  outside filter-owned state (shared via pipeline
  extension or KV store)
- Backward compatibility: clusters without
  `session_persistence` config retain existing
  behavior

### Design

#### Configuration

Session persistence is configured in the
`sticky_sessions` filter's own YAML config block
(not on `Cluster`), keeping the core/filter boundary
clean. The filter references cluster names and carries
persistence settings — same pattern as the
`load_balancer` filter embedding its own `clusters:`
list.

```yaml
filters:
  - type: sticky_sessions
    config:
      clusters:
        - name: app_backend
          type: cookie
          cookie_name: "_praxis_route"
          ttl_secs: 3600
          cookie_attributes:
            path: "/"
            http_only: true
            secure: true
            same_site: "Lax"
          failover: true
          max_entries: 100000
```

Header-based persistence:

```yaml
        - name: api_backend
          type: header
          header_name: "X-Session-Id"
          ttl_secs: 3600
          failover: true
          max_entries: 100000
```

Learn mode:

```yaml
        - name: legacy_backend
          type: learn
          cookie_name: "JSESSIONID"
          ttl_secs: 1800
          failover: true
          max_entries: 100000
```

**Config structs**
(`filter/src/builtins/http/traffic_management/sticky_sessions/config.rs`):

```rust
/// Per-cluster session persistence configuration.
pub struct ClusterSessionConfig {
    pub name: String,
    #[serde(flatten)]
    pub persistence: PersistenceConfig,
    pub ttl_secs: u64,
    pub failover: bool,
    pub max_entries: MaxEntries,
    pub eviction: EvictionPolicy,
}

/// Persistence type — internally tagged enum making
/// invalid states unrepresentable at the type level.
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PersistenceConfig {
    Cookie {
        cookie_name: String,
        #[serde(default)]
        cookie_attributes: CookieAttributes,
    },
    Header {
        header_name: String,
    },
    Learn {
        cookie_name: String,
    },
}

pub struct CookieAttributes {
    pub domain: Option<String>,
    pub path: Option<String>,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<SameSite>,
}

pub enum SameSite {
    Strict,
    Lax,
    None,
}
```

This follows the project's type-design convention:
"Enums over multiple `Option<T>` fields — when
exactly one of N fields must be set, use an N-variant
enum." Invalid combinations (e.g., `Cookie` without
`cookie_name`) cannot compile through serde,
eliminating runtime validation for required fields.

Validation: `max_entries` enforced with upper bound
(200K) via `#[serde(try_from)]` constrained newtype.
`ttl_secs` must be > 0.

#### Session Store

A shared, thread-safe session-to-endpoint mapping
per cluster, stored outside filter-owned state to
survive pipeline hot-reloads.

```rust
pub struct SessionStore {
    map: DashMap<Arc<str>, SessionEntry>,
    max_entries: u64,
    ttl: Duration,
}

struct SessionEntry {
    endpoint: Arc<str>,
    created_at: Instant,
    last_accessed: Instant,
}
```

**Design choices:**

- `DashMap<Arc<str>, SessionEntry>` — low-contention
  concurrent reads/writes via per-shard `RwLock`;
  sharded internally for minimal contention across
  workers.
- **TTL enforcement:** sliding TTL (idle timeout) —
  `last_accessed` is refreshed on every cache hit.
  Lazy eviction on access (check
  `last_accessed + ttl` on lookup; evict if expired)
  plus periodic background sweep (every 30s) for
  entries not accessed.
- **Entry cap:** when `map.len() >= max_entries`,
  new inserts are **rejected** (hard cap). This is
  O(1) on the hot path — no LRU scan required.
  DashMap has no native LRU support, and scanning
  all entries across shards to find the
  least-recently-accessed entry would be O(n) with
  shard locks held — unacceptable at 100K+ entries.
  TTL expiry naturally frees capacity; if workloads
  require LRU-like behavior in the future, consider
  migrating to `moka` (concurrent cache with built-in
  LRU + TTL, O(1) amortized eviction).
- **Metrics:** expose `session_store_size`,
  `session_store_evictions_total`, and
  `session_store_hits/misses` via the existing
  Prometheus metrics surface.

**Lifecycle and ownership:**

The session store registry is stored as a direct field
on `FilterPipeline` — the same pattern used by
`HealthRegistry` and `KvStoreRegistry`. The pipeline
exposes it via a dedicated field on `HttpFilterContext`:

```rust
pub struct SessionStoreRegistry {
    stores: HashMap<Arc<str>, Arc<SessionStore>>,
}

impl SessionStoreRegistry {
    pub fn get(&self, cluster: &str) -> Option<&Arc<SessionStore>> {
        self.stores.get(cluster)
    }
}
```

**Pipeline wiring:**

```rust
// FilterPipeline (filter/src/pipeline/mod.rs)
pub struct FilterPipeline {
    // ... existing fields ...
    session_stores: Option<SessionStoreRegistry>,
}

impl FilterPipeline {
    pub fn set_session_stores(&mut self, stores: SessionStoreRegistry) {
        self.session_stores = Some(stores);
    }

    pub fn session_stores(&self) -> Option<&SessionStoreRegistry> {
        self.session_stores.as_ref()
    }
}
```

```rust
// HttpFilterContext (filter/src/context.rs)
pub struct HttpFilterContext<'a> {
    // ... existing fields ...
    pub session_stores: Option<&'a SessionStoreRegistry>,
}
```

Filters access the store via `ctx.session_stores`.
The session store registry survives hot-reloads
because it is re-attached to the new pipeline during
config reload (same lifecycle as `HealthRegistry`).

**Multi-replica considerations:** For single-replica
deployments, the in-process `DashMap` is sufficient.
For multi-replica, [proposal #99](../proposals/00099_stateful-proxy-state-management.md)'s
shared hot-path state model (Valkey/Redis-backed)
will be adopted when available. The filter abstracts over an
async `SessionStoreBackend` trait to allow pluggable
backends without filter code changes. The trait uses
`async fn` so the in-memory `DashMap` backend returns
ready values trivially, while the future Redis/Valkey
backend can perform real async I/O without a breaking
trait change.

```rust
pub trait SessionStoreBackend: Send + Sync {
    async fn get(&self, key: &str) -> Option<Arc<str>>;
    async fn put(&self, key: Arc<str>, endpoint: Arc<str>);
    async fn remove(&self, key: &str);
}
```

#### Filter Implementation

A new `StickySessionsFilter` registered as builtin:

```rust
register_http(
    filters,
    "sticky_sessions",
    StickySessionsFilter::from_config,
);
```

**Request phase (`on_request`):**

1. Determine session key:
   - `Cookie` type: parse `Cookie` header, extract
     value of configured `cookie_name`
   - `Header` type: read configured `header_name`
   - `Learn` type: parse `Cookie` header for
     configured `cookie_name`

2. If session key found, look up session store:
   - **Hit:** validate endpoint is healthy via
     `ctx.health_registry`
     - Healthy: set `ctx.pinned_endpoint_address` with
       the endpoint address (the load balancer will
       consume this hint and build a full `Upstream`
       with proper TLS and connection options via
       `entry.build_upstream()`), return
       `FilterAction::Continue`
     - Unhealthy + failover enabled: remove stale
       mapping, fall through to load balancer for
       re-selection
     - Unhealthy + failover disabled: route to
       unhealthy endpoint anyway (operator choice)
   - **Miss:** store session key in `filter_metadata`
     for the response phase, then fall through to load
     balancer for endpoint selection

Note: endpoint recording cannot happen in `on_request`
because the sticky sessions filter runs before the load
balancer — at this point in the pipeline, no endpoint
has been selected yet. Recording moves to `on_response`.

**Response phase (`on_response`):**

The response phase runs in **reverse** filter order
(per `filter/src/pipeline/http.rs`). Since
`sticky_sessions` is ordered before the load balancer,
its `on_response` runs **after** the LB's
`on_response`. At this point `ctx.upstream` is
populated by the load balancer (or by the sticky
sessions filter's pinned endpoint via the LB).

1. If a session key is stored in `filter_metadata`
   (cache miss during `on_request`), this is a new
   binding:
   - Read the selected endpoint from `ctx.upstream`
   - Store `session_key → endpoint` in session store

2. **Cookie type:** inject `Set-Cookie` header with
   endpoint identifier and configured attributes:
   ```
   Set-Cookie: _praxis_route=<endpoint_id>;
     Path=/; HttpOnly; Secure; SameSite=Lax;
     Max-Age=3600
   ```
   Use `ctx.response_header.headers.append(SET_COOKIE, value)`
   and set `ctx.response_headers_modified = true`.

3. **Learn mode:** parse upstream `Set-Cookie` for
   configured `cookie_name`. If found, read the
   endpoint from `ctx.upstream` and store
   `session_id → endpoint` in session store.

4. **Header type:** no response modification needed
   (client manages the header).

#### Cookie Parsing

A lightweight cookie parser (no external crate
dependency) that extracts a named value from the
`Cookie` header:

```rust
pub fn extract_cookie_value<'a>(
    cookie_header: &'a str,
    name: &str,
) -> Option<&'a str> {
    cookie_header
        .split(';')
        .map(str::trim)
        .find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k.trim() == name).then_some(v.trim())
        })
}
```

For `Set-Cookie` response parsing (learn mode),
only the first `name=value` pair before `;` is
extracted (attributes are ignored for session ID
extraction).

#### Cookie Injection

Build the `Set-Cookie` value from config:

```rust
fn build_set_cookie(
    name: &str,
    value: &str,
    attrs: &CookieAttributes,
    ttl_secs: u64,
) -> String {
    let mut cookie = format!("{name}={value}");
    if let Some(path) = &attrs.path {
        cookie.push_str(&format!("; Path={path}"));
    }
    if let Some(domain) = &attrs.domain {
        cookie.push_str(&format!("; Domain={domain}"));
    }
    cookie.push_str(&format!("; Max-Age={ttl_secs}"));
    if attrs.http_only {
        cookie.push_str("; HttpOnly");
    }
    if attrs.secure {
        cookie.push_str("; Secure");
    }
    if let Some(ss) = &attrs.same_site {
        cookie.push_str(&format!("; SameSite={}", ss.as_str()));
    }
    cookie
}
```

#### Endpoint Identifier Encoding

The cookie value must encode which endpoint to route
to. Options:

- **Plain address** (`10.0.1.2:8080`): simple but
  exposes internal topology.
- **Hashed identifier** (FNV hash of address): opaque
  to clients; session store maps hash → address.
  Recommended for security.
- **Index-based** (endpoint index in cluster list):
  breaks on topology changes.

**Recommendation:** Use a stable hash of the endpoint
address as the cookie value. The session store maps
`session_key → endpoint_address` regardless of
encoding — the cookie value IS the session key for
cookie-type persistence.

#### Health-Aware Failover

On session store hit, verify endpoint health before
routing:

```rust
fn is_endpoint_healthy(
    registry: Option<&HealthRegistry>,
    cluster: &str,
    endpoint: &str,
) -> bool {
    registry
        .and_then(|r| r.get(cluster))
        .and_then(|state| {
            let idx = state.endpoint_index(endpoint)?;
            Some(state.endpoints()[idx].is_healthy())
        })
        .unwrap_or(true) // no health info = assume healthy
}
```

When unhealthy and `failover: true`:
1. Remove stale entry from session store.
2. Fall through to load balancer for new selection.
3. New selection is stored in session store.
4. Updated cookie is injected in response.

When `failover: false`:
- Route to unhealthy endpoint anyway (operator accepts
  errors until endpoint recovers or cookie expires).

#### Pipeline Integration

**Filter ordering:** `sticky_sessions` must run
after the router (needs `ctx.cluster`) and before
the load balancer. On cache hit, it sets
`ctx.pinned_endpoint_address` with the endpoint
address. The load balancer currently does NOT check
for a pinned endpoint — it unconditionally calls
`select()` and sets `ctx.upstream`.
A prerequisite change is required: add a
pinned-endpoint branch to the load balancer's
`on_request` that consumes `pinned_endpoint_address`
and builds a proper `Upstream` (with TLS and
connection options) without calling `select()`:

```rust
// load_balancer on_request — prerequisite addition:
if let Some(pinned_addr) = ctx.pinned_endpoint_address.take() {
    // Build full Upstream with cluster's TLS/connection options.
    ctx.upstream = Some(entry.build_upstream(pinned_addr, ctx));
    return Ok(FilterAction::Continue);
}
```

This approach avoids the sticky sessions filter
needing access to cluster TLS certificates or
connection options — only the load balancer (which
already has `ClusterEntry`) knows how to construct a
complete `Upstream` value.

Since `select()` is never called for pinned requests,
no in-flight counter is incremented. The load
balancer's `on_response` must not call `release()`
for these requests. A `filter_metadata` flag provides
an unambiguous guard:

**Required companion changes in LB:**

```rust
// load_balancer on_request — after select() runs:
ctx.set_metadata("lb.selected", "true");
```

```rust
// load_balancer on_response — prerequisite addition:
if ctx.get_metadata("lb.selected").is_none() {
    // select() was never called (session-affinity hit
    // or other skip); nothing to release.
    return Ok(());
}
```

This is more reliable than checking
`selected_endpoint_index.is_none()` because
`LeastConnections::select()` increments in-flight
counters via atomic CAS regardless of whether health
state is provided. Without health checks configured,
`selected_endpoint_index` stays `None` even after
`select()` runs — causing the old guard to skip
`release()` and leak counters. The `filter_metadata`
flag is set explicitly after `select()` runs, so it
works regardless of health check configuration.

This guard must be added before the sticky sessions
filter can function correctly.

**Hot-reload:** Session stores live in a
`SessionStoreRegistry` field on `FilterPipeline`.
On reload, the registry is preserved and re-attached
to the new pipeline (same pattern as `HealthRegistry`
and `KvStoreRegistry`).

#### Integration with Existing Code

| Current Code | Change |
|---|---|
| `filter/src/registry.rs` | Register `sticky_sessions` builtin |
| `filter/src/builtins/http/traffic_management/` | New `sticky_sessions/` module |
| `filter/src/pipeline/mod.rs` | Add `session_stores: Option<SessionStoreRegistry>` field |
| `filter/src/context.rs` | Add `session_stores: Option<&SessionStoreRegistry>` and `pinned_endpoint_address: Option<Arc<str>>` fields |
| `filter/src/builtins/http/traffic_management/load_balancer/mod.rs` | Add pinned-endpoint branch in `on_request`; add `filter_metadata` flag (`lb.selected`) in `on_request`/`on_response` |
| `server/src/` (pipeline build) | Initialize session stores from filter configs |

### Implementation

- `filter/src/builtins/http/traffic_management/sticky_sessions/config.rs` —
  config structs, serde, validation
- `filter/src/builtins/http/traffic_management/sticky_sessions/mod.rs` —
  `StickySessionsFilter` (on_request + on_response)
- `filter/src/builtins/http/traffic_management/sticky_sessions/cookie.rs` —
  cookie parsing and injection utilities
- `filter/src/builtins/http/traffic_management/sticky_sessions/store.rs` —
  `SessionStore`, `SessionStoreRegistry` (DashMap, TTL, eviction, metrics)
- `filter/src/builtins/http/traffic_management/sticky_sessions/backend.rs` —
  `SessionStoreBackend` async trait for pluggable backends
- `filter/src/pipeline/mod.rs` —
  Add `session_stores` field and accessors
- `filter/src/context.rs` —
  Add `session_stores` field to `HttpFilterContext`
- `filter/src/builtins/http/traffic_management/load_balancer/mod.rs` —
  Add early-return guard when `ctx.upstream` is set
- `filter/src/registry.rs` — register
  `sticky_sessions` builtin
