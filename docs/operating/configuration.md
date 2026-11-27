# Configuration

Praxis reads one YAML file, passed as a CLI argument or through the
`PRAXIS_CONFIG` environment variable. Working examples are in
`examples/configs/`, and each filter's options are in the
[Filter Reference](../filters/reference.md).

## Structure

```yaml
listeners:             # Required. Named listeners to bind.
filter_chains:         # Named, reusable filter chains.
clusters:              # Optional. Standalone cluster defs (health checks).
admin:                 # Optional. Admin health endpoint.
body_limits:           # Optional. Global body size ceilings.
metrics:               # Optional. Prometheus metric collection toggles.
runtime:               # Optional. Thread pool and logging tuning.
shutdown_timeout_secs: # Optional. Shutdown budget (default: 30 seconds).
shutdown_drain_delay_secs: # Optional. Readiness-first drain delay (default: 0).
insecure_options:      # Optional. Dev/test overrides. See developing/getting-started.md.
```

## Validating Configuration

`--validate` (or `-t`) checks a config without starting the server. It runs
the startup parsing and validation path, including filter pipeline
construction and ordering checks, compiles built-in policies, and validates
access-log sink configuration. It binds no listener ports and starts no policy
plugins or log writers, so startup still checks whether the configured
resources can initialize.

```console
praxis --validate --config praxis.yaml
praxis -t -c praxis.yaml
```

It exits `0` on success, or non-zero with the error on stderr. Warnings
(active `insecure_options`, degraded upstream TLS, likely filter config typos)
go to stderr either way, in the `PRAXIS_LOG_FORMAT` format.

## Dumping Effective Configuration

`--dump` (or `-T`) runs the same validation, then writes the parsed config to
stdout as YAML, with defaults applied and top-level listener chains resolved.

```console
praxis --dump --config praxis.yaml
praxis -T -c praxis.yaml
```

Exit codes and warnings work as with `--validate`. The two flags are mutually
exclusive.

## Dynamic Configuration Reload

Praxis watches the config file. When it changes, the server validates the new
config, rebuilds the filter pipelines, and swaps them atomically, without a
restart. In-flight requests finish on the old pipeline and new requests use
the new one. If the new config is invalid (bad YAML, unknown filter,
validation failure), the server logs the error and keeps the old config.
[Rehearse a reload](reload.md) walks through a reload on a running container.

The watcher compares the file with the exact text the running config was
parsed from, so an edit made while the server is still starting (before the
watch exists) is applied on the watcher's first pass.

**Dynamically reloadable:**

- Filter pipeline configuration
- Metrics collection settings (`metrics.filter_duration`)
- Router routes and path mappings
- Load balancer endpoints and weights
- Rate limit and circuit breaker settings
- Health check configuration
- Log level overrides (`runtime.log_overrides`)

**Requires restart (logged as warning):**

- `runtime.logging` destination or buffering
- Listener add, remove, or address rebind
- Listener `max_connections`, `downstream_read_timeout_ms`, and
  `downstream_keepalive_timeout_ms`
- Compression module addition
- TLS enable/disable, and any change inside a listener's `tls` block
  (the certificate watcher hot-reloads certificate *file contents*, not
  config-level TLS changes)
- Startup-only `runtime` settings (`threads`, `work_stealing`,
  `global_queue_interval`, `max_connections`, `max_memory_bytes`,
  `max_open_files`, `overload_gauges`, `overload_actions`, `overload_purge`,
  `overload_thresholds`, `shed_on_fd_pressure`,
  `subrequest_pool_size`, `subrequest_max_connections`,
  `subrequest_circuit_breaker`, `upstream_ca_file`,
  `upstream_keepalive_pool_size`)
- The `admin` section (both listener addresses bind at startup)

**Rejected (reload fails, nothing changes):**

- A protocol change (HTTP to TCP or back) on an existing listener. Its
  handler runs only filters of the protocol it started with, so the reload is
  refused until the change is reverted or the process restarts.
- Grouped TCP listeners (same upstream, cluster and timeouts) whose
  `filter_chains` or `max_connections` disagree.
- A change to a bound TCP listener's `upstream`, `cluster`,
  `tcp_session_timeout_ms` or `tcp_max_duration_secs`, removal of a bound TCP
  listener, or a change to `insecure_options.allow_private_upstreams` while
  TCP listeners exist. The TCP service captures these at startup.
- A change to a bound HTTP listener's `forward_proxy` block (`forward-proxy`
  builds; including adding or removing the block), removal of a bound
  listener that has one, or a change to
  `insecure_options.allow_private_upstreams` while a bound listener has an
  enabled block. The CONNECT runtime captures the CONNECT gate, destination
  rules, tunnel timeouts, and the private-address setting when the handler
  starts. Applying only the new pipeline could leave CONNECT open with the
  egress filters removed.

Stateful filters reset on reload: expect a brief burst window for rate
limiters and a closed circuit for circuit breakers right after.

Three kinds of state survive a reload:

- key-value store entries;
- sticky-session bindings for a cluster whose `max_entries`, `ttl` and
  eviction policy did not change (changing any of them starts that cluster's
  sessions afresh);
- endpoint health for a cluster whose `health_check` did not change. Only the
  unhealthy flag carries over, not the failure count, so new probes must
  confirm recovery before such an endpoint rejoins rotation.

When a reload changes what key-value entries mean, clear or rewrite them
through the admin API. See [hot-reload.yaml] for an example.

[hot-reload.yaml]: ../../examples/configs/operations/hot-reload.yaml

## Admin

`admin.address` binds the management API, and `admin.metrics_address` binds
the health and metrics listener. Either can be set without the other. Validation
rejects either address when it overlaps the other or a proxy listener. Paths
not listed here return `404 NOT FOUND`. Neither listener has authentication.

| Listener | Serves |
| -------- | ------ |
| `admin.metrics_address` | `/healthy`, `/ready`, `/metrics` |
| `admin.address` | `/api/kv/*`, `/api/pipelines`, `/api/log-level`, `/api/stats` |

- `/healthy` returns `200 OK` with `{"status":"ok"}` once the server is
  accepting connections (liveness).
- `/ready` returns per-cluster health counts when active health checks are
  configured. With the default `readiness: serving` it returns `200 OK` once
  the replica is serving, even when an upstream cluster is degraded.
  `readiness: upstreams` returns `503 SERVICE UNAVAILABLE` when any checked
  cluster has zero healthy endpoints. Response bodies, including the `503`
  states while initializing, draining, or stopped, are in
  [Health Checking](health-checking.md#ready-readiness).
- `/metrics` returns Prometheus text exposition format; see the
  [Metrics Reference](observability.md#metrics-reference).
- `/api/kv/{store}/{key}` reads and writes entries in configured
  [key-value stores](#key-value-stores).
- `/api/pipelines` (GET) returns a JSON snapshot of every listener's resolved
  filter pipeline, including branch chains and rejoin targets. Known sensitive
  header matcher values, including session identifiers, are redacted. Filter
  it with `?listener=NAME`.

```yaml
admin:
  address: "127.0.0.1:9901"
  metrics_address: "127.0.0.1:9902"
  readiness: serving # or upstreams for upstream-dependent readiness
  verbose: true
```

- `admin.readiness` defaults to `serving`. It is a startup setting: changing
  it in a watched file logs a restart warning and leaves the running listener
  unchanged.
- `admin.verbose: true` adds per-cluster detail (cluster names, health counts)
  to `/ready`. It defaults to `false` to avoid leaking internal topology.
- The admin API must bind to a loopback address (`127.0.0.1` or `[::1]`). Any
  other address, including `0.0.0.0` / `[::]` or a LAN IP, is a validation
  error unless `insecure_options.allow_public_admin: true` is set. The health
  and metrics listener has no loopback check: when it is not on loopback,
  bind it to a specific interface and limit access with network controls.

## Annotated Example

```yaml
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains:
      - observability
      - routing

filter_chains:
  - name: observability
    filters:
      - filter: request_id
      - filter: access_log

  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: api
          - path_prefix: "/"
            cluster: web
      - filter: load_balancer
        clusters:
          - name: api
            endpoints: ["127.0.0.1:4000"]
          - name: web
            endpoints:              # multi-line form
              - "127.0.0.1:3000"   # (equivalent to inline
              - "127.0.0.1:3001"   #  array above)
```

## Listeners

Each listener has a required, unique `name` (used to resolve its pipeline at
startup), an `address`, an optional `tls` block ([TLS](tls.md)), an optional
`protocol` (default `http`), and a list of `filter_chains`. HTTP listeners
need at least one filter chain; only `protocol: tcp` listeners that route via
`upstream` or `cluster` may omit it. HTTP and TCP listeners can run in the
same server.

```yaml
listeners:
  - name: public
    address: "0.0.0.0:80"
    filter_chains: [main]

  - name: secure
    address: "0.0.0.0:443"
    filter_chains: [main]
    tls:
      certificates:
        - cert_path: /etc/praxis/tls/cert.pem
          key_path: /etc/praxis/tls/key.pem
```

### Network Binding

`0.0.0.0` or `[::]` exposes the listener on all network interfaces. Use
`127.0.0.1` for local development, and specific internal IPs with firewall
rules in production. The default configuration binds to `127.0.0.1:8080`.

### TCP Listeners

TCP listeners set `protocol: tcp` and exactly one of `upstream` (a static
address) or `cluster` (load-balanced). Filter chains are optional.

- `tcp_session_timeout_ms` is a hard deadline after which active connections
  are terminated, regardless of activity.
- `tcp_max_duration_secs` caps the total session duration, regardless of
  activity.

[TCP Proxy](../architecture/tcp-proxy.md) explains when each clock starts.

```yaml
listeners:
  - name: postgres
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
    tcp_session_timeout_ms: 300000   # 5 minutes
    tcp_max_duration_secs: 3600      # 1 hour
```

### Downstream Read Timeout

`downstream_read_timeout_ms` sets how long the proxy waits for data from a
downstream client during body reads, which mitigates slow-body attacks on HTTP
listeners. Initial request header reads on fresh connections use Pingora's own
60s default.

```yaml
listeners:
  - name: web
    address: "0.0.0.0:8080"
    downstream_read_timeout_ms: 10000   # 10 seconds
    filter_chains: [main]
```

### Downstream Keep-Alive Timeout

`downstream_keepalive_timeout_ms` closes an idle HTTP/1.x keep-alive client
connection once it has waited that long for its next request. Without it,
idle keep-alive connections stay open until the client closes them, each
holding a file descriptor, so many idle or half-dead clients can exhaust the
process limit.

```yaml
listeners:
  - name: web
    address: "0.0.0.0:8080"
    downstream_keepalive_timeout_ms: 60000   # 60 seconds
    filter_chains: [main]
```

The value (1 to 3600000 ms) is applied in whole seconds, rounded up, and
replaces any `Keep-Alive: timeout` hint a client sends. It never turns
keep-alive on: `Connection: close` and HTTP/1.0 clients without
`Connection: keep-alive` are still closed after their response. It does not affect HTTP/2
connections or TCP listeners.

### Max Connections

`max_connections` caps concurrent requests on an HTTP listener and
concurrent connections on a TCP listener. HTTP listeners
reject excess requests with `503 Service Unavailable` and a `Retry-After: 1`
header; TCP listeners close the socket immediately. A slot is held for the
request (HTTP) or connection (TCP) and freed on completion, error, or timeout.
Each HTTP listener has its own limit. TCP listeners with the same upstream,
cluster, and timeouts form a group that shares one limit, and must set the
same `max_connections`.

```yaml
listeners:
  - name: public
    address: "0.0.0.0:8080"
    max_connections: 10000
    filter_chains: [main]
```

See [max-connections.yaml] for an example.

[max-connections.yaml]: ../../examples/configs/operations/max-connections.yaml

## Filter Chains

Filter chains are defined at the top level, each with a `name` and an ordered
list of `filters`. Listeners reference chains by name in `filter_chains:`.
The [annotated example](#annotated-example) shows two chain definitions.

### Chain Composition

A listener's pipeline is its chains' filters concatenated in order. Here the
public listener runs security, observability, and routing, and the internal
listener reuses observability and routing without security:

```yaml
listeners:
  - name: public
    address: "0.0.0.0:8080"
    filter_chains:
      - security
      - observability
      - routing

  - name: internal
    address: "0.0.0.0:9090"
    filter_chains:
      - observability
      - routing
```

### Protocol Compatibility

HTTP filters (e.g. `router`, `load_balancer`) only work on HTTP listeners.
TCP filters (e.g. `tcp_access_log`) work on both, because an HTTP listener's
protocol stack includes TCP.

## Payload Size Limits

`body_limits` sets global hard ceilings on request and response payload size,
across all body modes (Stream, StreamBuffer). When a filter also declares a
per-filter `max_bytes`, the smaller limit applies. Requests over the limit
get 413 (Payload Too Large), subject to the gRPC mapping below.

```yaml
body_limits:
  max_buffer_bytes: 67108864    # 64 MiB, per accumulated body
  max_request_bytes: 10485760    # 10 MiB, cumulative request bytes
  max_response_bytes: 5242880    # 5 MiB, cumulative response bytes
```

- `max_request_bytes` and `max_response_bytes` default to 10 MiB (10,485,760
  bytes). Setting either to `null` removes the ceiling but requires
  `insecure_options.allow_unbounded_body: true`; without it, startup fails
  with a validation error.
- `max_buffer_bytes` defaults to 64 MiB and takes a positive integer byte
  count. Zero, null, and values beyond an addressable allocation are
  rejected. It caps static and runtime-selected buffering, nested pipelines,
  buffered subrequest responses, and iterative-router state. Incremental
  streams use only their cumulative transfer limits.

When a pipeline statically buffers requests (`StreamBuffer`), a finite
`body_limits.max_request_bytes` must not exceed `body_limits.max_buffer_bytes`.
Startup, config validation, and reload reject that combination with an error
naming both fields and values, and a rejected reload leaves the running
configuration intact. Lower the request limit or raise the buffer cap. The
rule also covers nested pipelines and filters that can release their buffer
early. Streaming request pipelines may keep higher transfer limits, including
when only responses buffer.

For a 128 MiB buffered request, set `max_buffer_bytes: 134217728`,
`max_request_bytes: 134217728`, and raise the relevant filter's inspection
limit (for example `json_body_field.max_body_bytes`), plus
`max_response_bytes` if responses need the room too. The smallest applicable
limit wins, and `allow_unbounded_body` does not remove the buffering cap.
Reloads apply to new requests; in-flight requests keep their pinned limits.
These limits bound accumulated bytes, not parsed-object memory or aggregate
memory across concurrent requests.

For a final body-bearing response, Praxis compares a validated, unambiguous
upstream `Content-Length` with the effective cumulative response limit before
committing the final response. A larger length returns a complete proxy error
(HTTP 502, or the configured gRPC trailers-only mapping) without forwarding
upstream body bytes; a length exactly at the limit is accepted. Custom error
formatters receive the stable code `response_body_too_large`. The comparison
uses the upstream length before response filters can replace or remove it.
`HEAD`, 204, 304, informational and 101 responses, and successful CONNECT
tunnels carry no response body for this check. Missing, transfer-encoded, or
ambiguous lengths are not used for preflight. Protocol validation still
rejects malformed framing; unknown or under-reported bodies keep the
incremental response limit, which may abort after headers are committed. A
`StreamBuffer` threshold is not a cumulative response limit after `Release`.
An unknown-length overflow detected after commit can still count as a
passive-health failure for a tracked endpoint; the pre-commit declared-length
rejection does not, unless the upstream response itself was a 5xx.

### Rejections and Unread Uploads

A request-body limit failure logs a warning with the limit,
bytes seen, and rejection phase. Body-phase failures return a JSON 413, or a
gRPC Trailers-Only response when the `grpc_status` filter has armed the
request. A declared `Content-Length` above the effective input limit,
including matching comma-separated lengths the HTTP parser accepts, is
rejected with JSON 413 before the body is read or 100 Continue is sent.

When a local HTTP/1 response closes the connection with an
unread upload (this includes early responses such as 401, 403, and 429), the
Pingora backend sends the response, records request completion, shuts down
the write side, and discards the remaining body. Streaming body rejections
release the upstream connection before sending the response. Access logs and
request duration metrics exclude the cleanup time. Cleanup has a 30-second
deadline and a 128 MiB discard budget, checked between native body reads, so
the last chunk can cross it; downstream read timeouts still apply. HTTP/2 uses
its native stream cleanup, and overload admission failures still close
promptly. Clients should stop uploading after a rejection.

Rejected uploads keep their listener and runtime connection permits until
cleanup finishes, so stalled rejected uploads can hold `max_connections`
slots for up to 30 seconds; size for that. A configured
`downstream_read_timeout_ms` can end a stalled read sooner.

## Metrics

HTTP request metrics are recorded when either admin listener is configured,
but `/metrics` is exposed only on `admin.metrics_address`. Per-filter hook
duration histograms are opt-in:

```yaml
metrics:
  filter_duration: true
```

`filter_duration` defaults to `false`. When enabled, it records wall-clock
duration for each HTTP filter hook as
[`praxis_filter_duration_seconds`](observability.md#praxis_filter_duration_seconds-histogram),
which lists its `filter`, `phase`, and `stream` labels. Enabling it without `admin.metrics_address` logs a
startup warning: metrics are recorded but not exposed.

### Label Dimensions

`metrics.labels` selects which label dimensions metrics
carry, bounding total time-series cardinality. Each
dimension takes its own `true`/`false` setting.

```yaml
metrics:
  labels:
    route: false        # drop a dimension that defaults on
    endpoint: false
    status_code: true   # add a dimension that defaults off
```

A dimension you leave out keeps its default. Six default
to on (`cluster`, `endpoint`, `listener`, `method`,
`route`, `status_class`) and one defaults to off
(`status_code`), so an empty `labels` block emits exactly
the series Praxis emitted before this setting existed.

Setting a dimension to `false` drops it from every metric
that carries it. The metric stays available, with the
series that differed only by that dimension collapsed
into one. Setting one to the value it already has changes
nothing.

Each dimension may appear at most once. YAML keeps the
last value for a repeated key, so a second
`status_code:` line further down would silently override
the first; Praxis rejects the config instead, naming the
repeated dimension.

The exception is `cluster` on the two per-cluster health
gauges (`praxis_upstream_healthy_endpoints` and
`praxis_upstream_total_endpoints`), which keep the label
either way: those gauges are set rather than summed, so
dropping it would collapse every cluster onto one
last-writer series instead of lowering cardinality.

Label selection installs once at startup and is not
hot-reloadable. A reload that changes it is ignored and
logs a warning; the new set takes effect on restart. For
the per-dimension table and what enabling `status_code`
costs, see
[Metric Label Sets](observability.md#metric-label-sets).

> **Changed:** this setting used to take a `disabled`
> list, which could only remove a dimension. It was
> replaced by the per-dimension form above. A config
> still using `disabled` is rejected at startup with a
> message naming the replacement.

## Header and Request Limits

Header and request limits come from Pingora's HTTP/1.x parser. They are
compile-time constants in Pingora and not configurable in Praxis.

| Limit | Value | Notes |
| ------- | ------- | ------- |
| Max total header size | 1,048,575 B (~1 MiB) | Includes request line |
| Max number of headers | 256 | HTTP/1.x only |
| Request-URI max size | shared with header limit | No separate cap |
| Header read timeout | 60 s | Pingora default |
| Body buffer chunk | 65,536 B (64 KiB) | Per-read buffer |

HTTP/2 header limits come from the `h2` crate's HPACK and frame-level settings
(typically 16 KiB for HEADERS frames, negotiated via SETTINGS). Requests over
the header size or count limits get a 400 Bad Request from Pingora before
reaching the filter pipeline.

## Runtime

Worker thread pool, scheduling, and process limits.

```yaml
runtime:
  threads: 4
  work_stealing: true
  upstream_keepalive_pool_size: 64
  max_connections: 10000         # process-wide limit
  max_memory_bytes: 1073741824   # 1 GiB
  max_open_files: 65536          # default: the hard limit
  subrequest_circuit_breaker:
    consecutive_failures: 5
    recovery_window_secs: 30
```

- `threads`: worker threads per service. `0` (the default) auto-detects from
  available CPUs.
- `work_stealing`: allow work-stealing between worker threads of the same
  service. Default `true`.
- `global_queue_interval`: Tokio scheduler global queue check interval, in
  ticks. `Option<u32>`, default `null` (unset); zero is rejected by config
  validation. Positive values apply with the Hyper backend; Pingora warns and
  ignores them because it manages its own runtime.
- `upstream_keepalive_pool_size`: maximum idle upstream connections kept per
  thread. `Option<usize>`, default `Some(64)`. `null` uses Pingora's default
  of 128 per thread.
- `max_connections`: process-wide limit on concurrent HTTP requests and TCP
  connections across all listeners, distinct from per-listener
  `max_connections`. Requests and connections beyond it are rejected.
  `Option<u32>`, default `None` (disabled).
- `max_memory_bytes`: process-wide RSS limit for load shedding. Above it, new
  requests get `503 Service Unavailable`. `Option<usize>`, default `None`
  (disabled).
- `max_open_files`: soft limit on open file descriptors (`RLIMIT_NOFILE`) the
  process sets for itself at startup. Every connection, pooled connection,
  and DNS lookup holds one. `Option<u64>` (128 to 2^30). The default `None`
  raises the soft limit to the hard limit, which needs no privileges and lifts
  the 1024 soft limit containers commonly start with. A value above the hard
  limit is clamped with a warning. Startup logs the limit in effect and warns
  when it is below 4096, or below what `max_connections` implies. See
  [Capacity Planning](capacity-planning.md).
- `overload_gauges`: publish `praxis_overload_pressure` for cgroup memory,
  anonymous resident memory, CPU stall time, connections, and file
  descriptors. `bool`, default `false`. It does not refuse work or change
  timeouts. The gauges are served at `/metrics` on `admin.metrics_address`,
  not `admin.address`. Heap pressure needs `max_memory_bytes`, and connection
  pressure needs `max_connections`. How cgroup pressure is computed is in
  [Observability](observability.md#praxis_overload_pressure-gauge).
- `overload_purge`: defaults to `true`. With overload actions enabled, set
  `false` to disable only explicit jemalloc purge calls. Other overload actions
  and allocator-managed background decay continue independently. Requires a
  restart; filter reload does not change this setting.
- `overload_actions`: **experimental.** Requires a binary built with
  `--features overload-actions` and `overload_gauges: true`.
  Purges unused jemalloc pages under memory pressure, disables HTTP/1
  keep-alive above 50% pressure (restoring it at 40%), and fails
  `/ready` after three consecutive raw saturated samples. Three clear
  samples restore readiness for that resource. Cgroup memory takes
  precedence over heap for actions. Saturation refuses new connections
  before TLS and new HTTP requests with 503; admitted streams complete.
  Connect, idle, and downstream HTTP/1 header timeouts scale from 100%
  to 10% of their configured values as effective pressure rises. Body
  reads/writes and stream/session deadlines are preserved. Returned idle
  upstream connections expire sooner; an unset upstream idle timeout has
  a 60-second baseline when actions are enabled. Previously idle entries
  keep their current expiry. `bool`, defaults to `false`. Changes
  require a restart. See [Observability](observability.md).
- `overload_thresholds`: optional per-resource bands under `runtime`.
  Each pair requires finite `0 <= scaling < saturation <= 1`.
  Resources are `cgroup_memory` and `heap` (default 0.80/0.95),
  `cpu` (0.10/0.50), and `connections` and `file_descriptors`
  (0.70/0.95). For example:
  `connections: { scaling: 0.60, saturation: 0.85 }`.
  Omitted resources retain their defaults. Bands require a restart and
  apply to gauges even when actions are off.
- `shed_on_fd_pressure`: when open file descriptors near the process limit,
  reject new requests with `503 Service Unavailable` and close new TCP
  connections, keeping a reserve of 5% or 64 descriptors, whichever is
  larger, for health probes, DNS, and logs. Counted as
  `praxis_overload_rejects_total{reason="file_descriptors"}`. `bool`, default
  `true`; set `false` to let requests run into the limit.
- `subrequest_circuit_breaker`: per-peer circuit breaker for the shared
  sub-request connector used by `iterative_request_router`. It tracks
  consecutive transport failures per upstream `SocketAddr` and rejects
  sub-requests while a peer's circuit is open. Its state survives config
  reloads. Match circuit-open rejections with the
  `transport_error: circuit_open` transition in `iterative_request_router` step rules. Fields:
  - `consecutive_failures`: failure threshold before the circuit opens
    (required, must be > 0).
  - `recovery_window_secs`: seconds the circuit stays open before allowing a
    probe (required, 1..=3600).
  - `half_open_timeout_secs`: seconds a half-open probe may stay in flight
    before the circuit resets to open (default 30, 1..=3600).

### Upstream CA

`upstream_ca_file` sets a PEM CA file as the root certificate store for all
upstream TLS connections. It replaces the system trust store instead of
adding to it. Per-cluster `tls.ca` overrides it. See [tls.md](tls.md) for CA
trust precedence and combined bundles.

```yaml
runtime:
  upstream_ca_file: /etc/praxis/tls/internal-ca.pem
```

### Logging

`PRAXIS_LOG_FORMAT=json` switches log output from the default human-readable
format to structured JSON. `runtime.log_overrides` sets per-module log levels:

```yaml
runtime:
  log_overrides:
    praxis_filter::pipeline: trace
    praxis_protocol: debug
```

## Key-Value Stores

Key-value stores hold runtime-updatable mappings. Stores are created in code:
`KvStoreRegistry::get_or_create_memory` creates an in-memory store, and
`KvStoreRegistry::register` adds a caller-supplied `KvBackend` under a new
name, for example one that stores data outside the process. No built-in
filter or configuration section creates a store yet, so in a standard
deployment the registry is empty and the admin key-value endpoints answer 404
for every store name.

Filters access stores by name through `HttpFilterContext` and
`TcpFilterContext`.

### Match Types

| Type | Behavior |
| ---- | -------- |
| `exact` | Key must equal the lookup key |
| `prefix` | Stored key starts with the pattern |
| `suffix` | Stored key ends with the pattern |
| `regex` | Stored key matches a regex pattern |

### Admin API

When `admin.address` is configured, these endpoints read and update existing
stores (they do not create stores):

| Method | Path | Description |
| ------ | ---- | ----------- |
| `GET` | `/api/kv/{store}` | List all entries |
| `GET` | `/api/kv/{store}/{key}` | Get a value |
| `PUT` | `/api/kv/{store}/{key}` | Set a value (body) |
| `DELETE` | `/api/kv/{store}/{key}` | Delete a key |

Writes are immediately visible to all filters on all threads. Unknown store
names return 404.

### Runtime Cache Semantics

Key-value stores are runtime caches, not durable storage. Every store
survives config reloads. With `InMemoryKvBackend` (the default), entries live
in process memory and are lost on exit; a backend added with
`KvStoreRegistry::register` keeps them wherever it stores them. Use stores for
operational overrides (routing tables, feature flags, config knobs) that can
be rebuilt from an external source of truth, not as a primary data store.

### Pluggable Backends

The `KvBackend` trait allows other implementations (e.g. Redis). The trait is
defined in the `praxis_core::kv` module docs.

## Graceful Shutdown

With the default Pingora backend, `shutdown_timeout_secs` is the total
SIGTERM-to-exit budget, including the readiness-first drain delay:

```yaml
shutdown_timeout_secs: 60    # default: 30
shutdown_drain_delay_secs: 2 # optional readiness-first handoff delay
```

On SIGTERM, listeners become unready immediately but keep accepting new
connections during `shutdown_drain_delay_secs`. Eligible HTTP/1 responses on
connections accepted during this handoff carry `Connection: close`; HTTP/2 and
upgraded connections do not use that header. The delay must not exceed
`shutdown_timeout_secs` and consumes that budget; zero keeps the immediate
handoff.

After the delay, listeners stop accepting and graceful connection shutdown
begins. In-flight requests get
`min(shutdown_timeout_secs - shutdown_drain_delay_secs, 5)` seconds. Runtime
shutdown then cancels remaining async tasks, and the rest of the budget
bounds the wait for blocking work. So a setting of `60` still gives requests
at most five seconds, and the full grace period is spent even when nothing is
in flight.

The requests cut at the end of the grace period are the long-running ones:
streaming and SSE responses, slow uploads and downloads, and WebSocket or
other upgraded connections. Their clients see the connection or stream close
early and should reconnect, retrying only idempotent requests. When requests
need longer, drain traffic before SIGTERM; see
[Diagnostics](diagnostics.md#draining-before-shutdown).

On Kubernetes, `terminationGracePeriodSeconds` must cover
`shutdown_timeout_secs` (which already includes `shutdown_drain_delay_secs`),
any `preStop` hook, and time for final cleanup, or the kubelet kills the
container before the shutdown budget completes. Streams still open when the
window ends are closed on every pod deletion, rolling update, and node drain.

On the experimental hyper backend, HTTP listeners let in-flight connections
finish for up to `shutdown_timeout_secs` minus `shutdown_drain_delay_secs`
and a 1 s reserve, so `shutdown_timeout_secs: 1` leaves them no drain time.
Active TCP forwarding may continue during a nonzero
`shutdown_drain_delay_secs`, stops when the runtime signals services to shut
down, and can stop earlier if SIGINT ends the delay. See
[Hyper Backend](../architecture/hyper-backend.md#runtime-and-shutdown).

The overload housekeeping runtime stops its periodic loops on shutdown
and clears its server's action state. After the network runtime's shutdown
budget, server-owned watcher, housekeeping, and health tasks
share a two-second cleanup budget. An active jemalloc purge is joined while
that budget remains. If it expires, cleanup warns and detaches the runtime;
allocator work is never forcibly interrupted. Returning from an embedded
server therefore does not guarantee purge completion. Process exit can end
any remaining background work.

Once runtime shutdown completes, Praxis flushes queued log lines, attempts to
export pending OTLP spans, and exits `0`. OTLP shutdown errors go to stderr
and do not change the exit status. Errors while building filters or
registering listeners are logged and flushed, and Praxis exits `1`.

## Default Configuration

With no configuration file, Praxis starts with a built-in config that listens
on `127.0.0.1:8080` (localhost only, so a first run is not exposed) and
responds with `{"status": "ok", "server": "praxis"}` on `/` (exact match) and
404 elsewhere. The source is [default.yaml]. For a realistic starting point,
see [basic-reverse-proxy.yaml]. The [examples index](../../examples/README.md)
lists every example config by category.

[default.yaml]: ../../crates/core/src/config/default.yaml
[basic-reverse-proxy.yaml]: ../../examples/configs/traffic-management/basic-reverse-proxy.yaml

## Branch Chains

Branch chains are conditional sub-pipelines based on filter results:
short-circuit responses, skipped filters, retry loops, and cross-chain
routing. See [Branch Chains](../filters/branch-chains.md) and
[Pipeline Concepts](../architecture/pipeline-concepts.md).

## Health Checks

Per-cluster active HTTP, TCP, gRPC and optional TLS probes, plus passive
inline failure tracking, remove unhealthy endpoints from rotation. See
[Health Checking](health-checking.md) and
[health-checks.yaml](../../examples/configs/traffic-management/health-checks.yaml).

The top-level `clusters:` section feeds health checks (and the `/api/stats`
admin view and startup key-permission checks), never proxied traffic: the
data path builds its upstreams from the clusters defined inline in the
`load_balancer` or `tcp_load_balancer` filter. A probe uses a cluster's
`endpoints` and `health_check` block. With the experimental
`tls-health-check` build feature, TLS and HTTPS probes also use its `tls` and
`http.authority` settings, and handshake probes honor `http.version` for ALPN
(see [health checking](health-checking.md#tls-and-https-probes)); without it,
HTTP probes stay plaintext. Top-level data-path settings such as
`retry_policy`, connection timeouts, `load_balancer_strategy` and
`trusted_private_endpoints` do not affect proxied traffic; set them on the
inline load-balancer cluster.

An inline cluster with the same name as a top-level declaration can omit its
endpoints, and validation fills them in from the declaration, so routed and
health-checked addresses stay together. An inline list that is present stays
the routing truth, and validation warns when it diverges from the
declaration: a diverged endpoint is routed but never health-gated, or probed
but never routed. An inline `health_check` is rejected; probes are configured
only at top level.

Filled endpoints are copied per reference, so the copies are capped at 16 MiB
of endpoint string data (addresses, zones, and metadata). Config validation
applies the cap across all filter chains, and pipeline construction applies
it again across the inline outbound chains it binds. A config over either cap
is rejected.

## Slow Start

A cluster's `slow_start` ramps new and recovering endpoints up to full weight.
It needs the experimental `slow-start` Cargo feature (off by default); without
it, the key is rejected as an unknown field. The ramp also applies inside
subset, priority, and zone-aware selection. Fields, baseline rules, and
strategy support are in [Slow Start](load-balancing.md#slow-start); see also
[slow-start.yaml](../../examples/configs/traffic-management/slow-start.yaml).

## Hedged Requests

A route's `hedge_policy` races one idempotent client request across healthy
endpoints in its cluster. It needs the `hedged-requests` build feature. The
[router filter](../filters/http/traffic_management/router.md) page lists the
fields and how `budget_percent` caps copies.

- GET, HEAD, OPTIONS, and QUERY are eligible. `max_attempts: 1`, `CONNECT`,
  `Upgrade`, non-idempotent methods (`POST`, `PUT`, `PATCH`, `DELETE`),
  `application/grpc` requests, and requests that accept `text/event-stream`
  stay on one upstream. The policy is parsed with the route.
- `initial_requests` start at once. Each later copy waits
  `per_try_timeout_ms`, unless nothing is left in flight; then the next copy
  starts immediately while `max_attempts` and the budget allow it. The
  per-request `max_attempts` cap applies even when the shared budget would
  allow another copy.
- A 2xx, 3xx, or 4xx response wins: it is returned and the other attempts
  stop. A 5xx, or an attempt that fails before an HTTP response, does not
  win, and the race starts another available attempt. If no attempt produces
  a 2xx to 4xx response, the proxy returns the retained failure status and body
  when there is one; otherwise a timeout is 504 and a connect or read failure
  is 502, as for a single upstream.
- A copy reserves budget before an endpoint is chosen, holds it while in
  flight, and returns it when no endpoint can take the copy or when the
  attempt finishes.
- A hedged response is buffered up to the response ceiling, so the policy is
  a poor fit for any other response that must stream.
- When the cluster has no `tls.ca`, a hedged attempt uses
  `runtime.upstream_ca_file`.

## Failure Mode

Filters declare `failure_mode: open` (continue on error) or `closed` (reject
the request). Security-critical filters reject open mode by default. See
[failure-mode.yaml](../../examples/configs/pipeline/failure-mode.yaml).

## Validation and Errors

Praxis validates configuration at startup and fails closed: ambiguous or
risky settings are errors, not warnings. Validation covers listener name
uniqueness, filter chain reference resolution, TLS path traversal, admin
endpoint binding, health check SSRF protection, upstream TLS SNI
requirements, and payload size enforcement.

The process exits before serving on:

- **Invalid YAML or missing required fields**: a descriptive error before any
  listener binds.
- **Unknown filter chain reference**: a listener names a chain not defined in
  `filter_chains:`.
- **TLS certificate load failure**: a certificate's `cert_path` or `key_path`
  cannot be read or parsed.
- **Address bind failure**: the listen address is in use or invalid.

At runtime:

- **Unreachable upstream**: 502 (Bad Gateway). Connection timeouts are
  configurable per cluster.
- **Filter error**: an `Err` from a filter returns 500 and is logged.
- **Payload too large**: exceeding `body_limits.max_request_bytes` or a
  filter's `max_bytes` returns 413.

## Overrides

Some validations and features can be overridden for development and testing
with `insecure_options`. They need explicit opt-in and log warnings at
startup; see
[getting-started.md](../developing/getting-started.md#insecure-options).
