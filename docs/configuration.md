# Configuration

Single YAML file, passed as CLI argument or set via the
`PRAXIS_CONFIG` environment variable. See
`examples/configs/` for working examples.

## Structure

```yaml
listeners:             # Required. Named listeners to bind.
filter_chains:         # Named, reusable filter chains.
clusters:              # Optional. Standalone cluster defs (health checks).
admin:                 # Optional. Admin health endpoint.
body_limits:           # Optional. Global body size ceilings.
runtime:               # Optional. Thread pool and logging tuning.
shutdown_timeout_secs: # Optional. Graceful drain time (default: 30).
insecure_options:      # Optional. Dev/test overrides. See development.md.
```

## Dynamic Configuration Reload

Praxis watches the config file for changes and
automatically reloads filter pipelines without restart
or disruption. When the file is modified, the server
validates the new config, rebuilds pipelines, and swaps
them atomically. In-flight requests complete on the old
pipeline; new requests pick up the new config.

If the new config is invalid (bad YAML, unknown filter,
validation failure), the server logs the error and
continues serving with the old config.

**Dynamically reloadable:**

- Filter pipeline configuration
- Router routes and path mappings
- Load balancer endpoints and weights
- Rate limit and circuit breaker settings
- Health check configuration

**Requires restart (logged as warning):**

- Listener add, remove, or address rebind
- Protocol changes (HTTP to TCP)
- Compression module addition
- TLS enable/disable

Stateful filters (rate limiter, circuit breaker) reset
their state on reload. Operators should expect a brief
burst window for rate limiters and a closed circuit for
circuit breakers immediately after reload.

See [hot-reload.yaml] for an example.

[hot-reload.yaml]: ../examples/configs/operations/hot-reload.yaml

## Admin

`admin.address` binds a separate HTTP listener that serves
`/ready` and `/healthy`. `/healthy` returns `200 OK` with
`{"status":"ok"}` once the server is accepting
connections (liveness). `/ready` returns per-cluster
health status with healthy/unhealthy/total counts when
active health checks are configured; it returns 503
when any cluster has zero healthy endpoints. Without
health checks, `/ready` returns `{"status":"ok"}`. Any
other path returns 404. Useful for orchestrator health
checks without exposing them on the main listeners.

```yaml
admin:
  address: "127.0.0.1:9901"
```

When `admin.verbose: true`, the `/ready` response
includes per-cluster detail (cluster names, health
counts). Default is `false` to avoid leaking internal
topology.

```yaml
admin:
  address: "127.0.0.1:9901"
  verbose: true
```

By default, binding admin to a public interface
(`0.0.0.0` / `[::]`) is a validation error.

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

Each listener has a required `name`, an `address`, optional
`tls`, optional `protocol` (defaults to `http`), and an
optional list of `filter_chains` to apply. When
`filter_chains` is omitted it defaults to empty (no filters
applied).

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

The `name` field uniquely identifies the listener and is
used to resolve its pipeline at startup.

### Network Binding

Binding to `0.0.0.0` or `[::]` exposes the listener
on all network interfaces. For local development,
prefer `127.0.0.1`. In production, bind to specific
internal IPs and use firewall rules to restrict
access. The default configuration binds to
`127.0.0.1:8080` as a security precaution.

### TCP Listeners

TCP listeners set `protocol: tcp` and require an `upstream`
address. Filter chains are optional for TCP listeners.

```yaml
listeners:
  - name: postgres
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
```

Optional `tcp_idle_timeout_ms` closes connections that have
been idle longer than the specified duration:

```yaml
listeners:
  - name: postgres
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
    tcp_idle_timeout_ms: 300000   # 5 minutes
```

Optional `tcp_max_duration_secs` caps the total session
duration regardless of activity:

```yaml
listeners:
  - name: postgres
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
    tcp_max_duration_secs: 3600   # 1 hour
```

### Downstream Read Timeout

Optional `downstream_read_timeout_ms` sets how long the
proxy waits for data from downstream clients during body
reads. Mitigates slow-body attacks on HTTP listeners.

```yaml
listeners:
  - name: web
    address: "0.0.0.0:8080"
    downstream_read_timeout_ms: 10000   # 10 seconds
    filter_chains: [main]
```

Pingora applies its own 60s default for initial request
header reads on fresh connections. This setting controls
body read timeouts within an active request.

### Mixed Protocols

HTTP and TCP listeners can run on a single server instance.
Each listener gets its own filter chains appropriate to its
protocol.

```yaml
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [routing]

  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
```

See [tls.md](tls.md) for TLS details.

## Filter Chains

Named filter chains are defined at the top level. Each chain
has a `name` and an ordered list of `filters`. Listeners
reference chains by name via `filter_chains:`.

```yaml
filter_chains:
  - name: security
    filters:
      - filter: headers
        response_set:
          - name: "X-Content-Type-Options"
            value: "nosniff"

  - name: observability
    filters:
      - filter: request_id
      - filter: access_log

  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["10.0.0.1:8080"]
```

### Chain Composition

A listener can reference multiple chains. The filters from
each chain are concatenated in order to form the listener's
complete pipeline. This enables reuse without duplication.

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

The public listener runs security + observability + routing.
The internal listener skips security but shares the same
observability and routing chains.

### Protocol Compatibility

Filters are protocol-aware. HTTP filters (e.g. `router`,
`load_balancer`) only work on HTTP listeners. TCP filters
(e.g. `tcp_access_log`) work on both HTTP and TCP listeners.
An HTTP listener's protocol stack includes TCP, so it
supports TCP-level filters too.

## Built-in Filters

| Filter | Category | Protocol |
| --- | --- | --- |
| `router` | Traffic Management | HTTP |
| `load_balancer` | Traffic Management | HTTP |
| `timeout` | Traffic Management | HTTP |
| `static_response` | Traffic Management | HTTP |
| `rate_limit` | Traffic Management | HTTP |
| `circuit_breaker` | Traffic Management | HTTP |
| `headers` | Transformation | HTTP |
| `request_id` | Observability | HTTP |
| `access_log` | Observability | HTTP |
| `tcp_access_log` | Observability | TCP |
| `forwarded_headers` | Security | HTTP |
| `guardrails` | Security | HTTP |
| `ip_acl` | Security | HTTP |
| `credential_injection` | Security | HTTP |
| `json_body_field` | Payload Processing | HTTP |
| `compression` | Payload Processing | HTTP |
| `cors` | Security | HTTP |
| `redirect` | Traffic Management | HTTP |
| `path_rewrite` | Transformation | HTTP |
| `url_rewrite` | Transformation | HTTP |
| `model_to_header` | AI / Inference | HTTP (requires `ai-inference` feature) |

### Router

Routes requests to clusters by path prefix. Longest prefix
wins. Optional `host` restricts matching to a specific
`Host` header. Optional `headers` restricts matching to
requests with all specified header values present (AND
semantics, case-sensitive). Routes without `host` match
any host.

Example configs: [path-based-routing.yaml],
[hosts.yaml], [canary-routing.yaml].

[path-based-routing.yaml]: ../examples/configs/traffic-management/path-based-routing.yaml
[hosts.yaml]: ../examples/configs/traffic-management/hosts.yaml
[canary-routing.yaml]: ../examples/configs/traffic-management/canary-routing.yaml

### Load Balancing

Strategies:

- `round_robin` (default): cycles through endpoints
- `least_connections`: picks endpoint with fewest active
  requests
- `consistent_hash`: hashes a request header (or URI path
  as fallback) to pin requests to stable endpoints

Example configs: [weighted-load-balancing.yaml],
[least-connections.yaml], [session-affinity.yaml].

[weighted-load-balancing.yaml]: ../examples/configs/traffic-management/weighted-load-balancing.yaml
[least-connections.yaml]: ../examples/configs/traffic-management/least-connections.yaml
[session-affinity.yaml]: ../examples/configs/traffic-management/session-affinity.yaml

Cluster-level options: `connection_timeout_ms`,
`total_connection_timeout_ms`, `idle_timeout_ms`,
`read_timeout_ms`, `write_timeout_ms`, `tls`.

`total_connection_timeout_ms` sets the combined budget for
TCP connect and TLS handshake. When used alongside
`connection_timeout_ms`, the difference is effectively the
TLS handshake budget. It must be >= `connection_timeout_ms`.

Cluster `tls` enables TLS to the upstream. See
[tls.md](tls.md) for full details on upstream TLS, mTLS,
CA trust, and certificate verification.

#### Health Checks

Clusters support active health checks via the
`health_check` field. Endpoints that fail consecutive
probes are removed from load balancer rotation until they
recover. See [health-checks.yaml].

[health-checks.yaml]: ../examples/configs/traffic-management/health-checks.yaml

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `type` | string | required | `"http"` or `"tcp"` (`"grpc"` parses but is not yet supported) |
| `path` | string | `"/"` | HTTP path to probe (HTTP only) |
| `expected_status` | integer | 200 | Expected HTTP status code |
| `interval_ms` | integer | 5000 | Probe interval in ms |
| `timeout_ms` | integer | 2000 | Per-probe timeout in ms |
| `healthy_threshold` | integer | 2 | Consecutive successes to mark healthy |
| `unhealthy_threshold` | integer | 3 | Consecutive failures to mark unhealthy |
| `passive_unhealthy_threshold` | integer | none | Consecutive upstream failures (5xx or connect error) to mark unhealthy without probes |
| `passive_healthy_threshold` | integer | none | Consecutive upstream successes to recover a passively-marked endpoint |

TCP health checks only verify a TCP connection can be
established; `path` and `expected_status` are ignored.
When active health checks are configured, the admin
`/ready` endpoint reports per-cluster health counts.

Passive health checking tracks upstream request
outcomes inline. When `passive_unhealthy_threshold` is
set, endpoints that return consecutive 5xx responses or
connect errors are marked unhealthy without dedicated
probe traffic. Set `passive_healthy_threshold` to
control how many consecutive successes are required to
recover. Passive and active checks can be used together;
either mechanism can mark an endpoint unhealthy, and
either can recover it.

By default, health check endpoints that resolve to
loopback or cloud metadata addresses are rejected
(SSRF protection).

### Headers

Add headers to requests; add, set, or remove headers on
responses:

```yaml
- filter: headers
  request_add:
    - name: "X-Forwarded-Proto"
      value: "https"
  response_add:
    - name: "X-Served-By"
      value: "praxis"
  response_set:
    - name: "Server"
      value: "praxis"
  response_remove:
    - "X-Powered-By"
```

`add` appends (preserves existing), `set` replaces,
`remove` deletes. Request headers support `add` only.
Response headers support all three operations.

### Timeout

Returns 504 if upstream response exceeds configured duration:

```yaml
- filter: timeout
  timeout_ms: 5000
```

### Request ID

Propagates an existing request ID header or generates a
new one:

```yaml
- filter: request_id
  header_name: "X-Request-Id"   # optional, this is the default
```

### Access Log

Structured JSON logging of method, path, status, and
timing:

```yaml
- filter: access_log
```

Optional sampling to reduce log volume:

```yaml
- filter: access_log
  sample_rate: 0.1    # log ~10% of requests
```

### Forwarded Headers

Injects `X-Forwarded-For`, `X-Forwarded-Proto`, and
`X-Forwarded-Host` into upstream requests:

```yaml
- filter: forwarded_headers
  trusted_proxies:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
```

When the client IP is from a trusted proxy, existing
`X-Forwarded-For` values are preserved. Otherwise, the
header is overwritten to prevent spoofing.

### IP ACL

Allow or deny requests by source IP/CIDR:

```yaml
- filter: ip_acl
  allow:
    - "10.0.0.0/8"
  deny:
    - "0.0.0.0/0"
```

When `allow` is set, only matching IPs are permitted.
`allow` takes precedence over `deny`. Denied requests
receive a `403 Forbidden` response.

### Credential Injection

Injects per-cluster API credentials into upstream
requests and strips client-provided credentials to
prevent forwarding. Pair with a source discriminator
(IP ACL, client authentication) to control which
clients receive credential upgrades. See
[credential-injection.yaml].

```yaml
- filter: credential_injection
  clusters:
    - name: openai
      header: Authorization
      value: "sk-example-key"
      header_prefix: "Bearer "
      strip_client_credential: true
```

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `clusters[].name` | string | yes | Cluster to inject credentials for |
| `clusters[].header` | string | yes | Header name to set |
| `clusters[].value` | string | one of | Inline credential value |
| `clusters[].env_var` | string | one of | Environment variable containing the credential |
| `clusters[].header_prefix` | string | no | Prefix prepended to the value (e.g. `"Bearer "`) |
| `clusters[].strip_client_credential` | bool | no | Remove client-sent value before injection (default: true) |

[credential-injection.yaml]: ../examples/configs/ai/credential-injection.yaml

### TCP Access Log

Structured JSON logging of TCP connections. Works on both
TCP and HTTP listeners:

```yaml
- filter: tcp_access_log
```

### JSON Body Field

Extracts a top-level field from a JSON request body and
promotes its value to a request header. Uses StreamBuffer
mode to inspect the body before upstream selection,
enabling body-based routing.

```yaml
- filter: json_body_field
  field: model
  header: X-Model
```

`field` is the JSON key to extract. `header` is the
request header name to promote the value into. If the
field is missing or the body is not valid JSON, the
filter passes through without modification.

### Static Response

Returns a fixed response without contacting any upstream.
Useful for health checks, status endpoints, or stub routes:

```yaml
- filter: static_response
  status: 200
  headers:
    - name: Content-Type
      value: application/json
  body: '{"status": "ok", "server": "praxis"}'
```

`status` is required. `headers` and `body` are optional.
Combine with conditions to serve static responses on
specific paths.

### Rate Limit

Token bucket rate limiter. Supports `per_ip` (one bucket
per source IP) and `global` (one shared bucket) modes.
Rejects excess traffic with 429 and `Retry-After` header.
Injects `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and
`X-RateLimit-Reset` headers into both rejections and
successful responses.

```yaml
- filter: rate_limit
  mode: per_ip        # "per_ip" or "global"
  rate: 100           # tokens replenished per second
  burst: 200          # maximum bucket capacity
```

| Field | Type | Required | Description |
| ------- | ------ | ---------- | ------------- |
| `mode` | string | yes | `"per_ip"` or `"global"` |
| `rate` | float | yes | Tokens per second (must be > 0) |
| `burst` | integer | yes | Max bucket capacity (must be >= rate) |

### Circuit Breaker

Per-cluster circuit breaker that prevents cascading
failures. When consecutive upstream failures reach the
threshold, the circuit opens and subsequent requests
receive 503 immediately. After the recovery window, a
single probe request is forwarded; if it succeeds the
circuit closes. See [circuit-breaker.yaml].

```yaml
- filter: circuit_breaker
  clusters:
    - name: backend
      consecutive_failures: 5
      recovery_window_secs: 30
```

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `clusters[].name` | string | yes | Cluster name to protect |
| `clusters[].consecutive_failures` | integer | yes | Failures before opening |
| `clusters[].recovery_window_secs` | integer | yes | Seconds before half-open probe |

[circuit-breaker.yaml]: ../examples/configs/traffic-management/circuit-breaker.yaml

### Guardrails

Rejects requests matching string or regex rules against
headers and/or body content. Rejected requests receive
401 Unauthorized.

```yaml
- filter: guardrails
  rules:
    - target: header
      name: "User-Agent"
      pattern: "bad-bot.*"
    - target: body
      contains: "DROP TABLE"
    - target: body
      pattern: "^\\{.*\\}$"
      negate: true
```

Each rule has:

| Field | Type | Required | Description |
| ------- | ------ | ---------- | ------------- |
| `target` | string | yes | `"header"` or `"body"` |
| `name` | string | header only | Header name to inspect |
| `contains` | string | one of | Literal substring match |
| `pattern` | string | one of | Regex pattern match |
| `negate` | bool | no | Invert match (default: false) |

Each rule must have either `contains` or `pattern`, not
both. Body rules use StreamBuffer mode (up to 1 MiB by
default) to inspect the full request body.

### CORS

Spec-compliant CORS filter with preflight handling, origin
validation, and credential support. See [cors.yaml].

[cors.yaml]: ../examples/configs/security/cors.yaml

| Field | Type | Default | Description |
| ------- | ------ | --------- | ------------- |
| `allow_origins` | list | required | Origins to allow; `["*"]` for any |
| `allow_methods` | list | GET, HEAD, POST | Allowed HTTP methods |
| `allow_headers` | list | none | Allowed request headers |
| `expose_headers` | list | none | Response headers exposed to client |
| `allow_credentials` | bool | false | Include credentials header |
| `max_age` | integer | 86400 | Preflight cache duration (seconds) |
| `allow_private_network` | bool | false | Private Network Access support |
| `disallowed_origin_mode` | string | "omit" | `"omit"` or `"reject"` for non-matching origins |
| `allow_null_origin` | bool | false | Allow `Origin: null` |

Wildcard subdomain patterns (e.g. `https://*.example.com`)
are supported. `allow_credentials: true` is incompatible
with wildcard origins, methods, or headers per the Fetch
spec.

### Redirect

Returns a 3xx redirect without contacting any upstream:

```yaml
- filter: redirect
  status: 301
  location: "https://example.com${path}"
```

| Field | Type | Default | Description |
| ------- | ------ | --------- | ------------- |
| `status` | integer | 301 | Redirect status (301, 302, 307, or 308) |
| `location` | string | required | URL template; `${path}` and `${query}` are substituted |

### Path Rewrite

Rewrites the request path before forwarding to upstream.
Exactly one of `strip_prefix`, `add_prefix`, or `replace`
per filter instance. Query strings are preserved. See
[path-rewriting.yaml].

[path-rewriting.yaml]: ../examples/configs/transformation/path-rewriting.yaml

| Field | Type | Description |
| ------- | ------ | ------------- |
| `strip_prefix` | string | Remove this prefix from the path |
| `add_prefix` | string | Prepend this prefix to the path |
| `replace.pattern` | string | Regex pattern to match |
| `replace.replacement` | string | Replacement string (`$1`, `$name` captures) |

### URL Rewrite

Regex-based path transformation and query string
manipulation. Operations applied in order:
`regex_replace`, `strip_query_params`,
`add_query_params`. See [url-rewriting.yaml].

[url-rewriting.yaml]: ../examples/configs/transformation/url-rewriting.yaml

### Compression

Gzip, brotli, and zstd response compression. All three
enabled by default. See [compression.yaml].

[compression.yaml]: ../examples/configs/payload-processing/compression.yaml

| Field | Type | Default | Description |
| ------- | ------ | --------- | ------------- |
| `level` | integer | 6 | Default compression level (1-12) |
| `min_size_bytes` | integer | 256 | Skip responses smaller than this |
| `gzip` | object | enabled | Per-algorithm `enabled` and `level` |
| `brotli` | object | enabled | Per-algorithm `enabled` and `level` |
| `zstd` | object | enabled | Per-algorithm `enabled` and `level` |
| `content_types` | list | see above | MIME type prefixes that qualify |

At least one algorithm must be enabled.

### Conditions

`when`/`unless` gates on any filter chain entry. Request
predicates: `path` (exact match), `path_prefix`,
`methods`, `headers`. All fields within a condition are
ANDed. Use `response_conditions` with `status` or
`headers` predicates to gate response hooks. See
[conditional-filters.yaml].

[conditional-filters.yaml]: ../examples/configs/pipeline/conditional-filters.yaml

Request conditions gate both request and body hooks.
Response conditions gate only `on_response` and response
body hooks. A filter can have both `conditions` and
`response_conditions`.

## Payload Size Limits

Global hard ceilings on request and response payload
size. These apply across all body modes (Stream,
StreamBuffer). When a filter also declares a per-filter
`max_bytes`, the smaller of the two limits is enforced.
Requests exceeding the limit receive 413 (Payload Too
Large).

```yaml
body_limits:
  max_request_bytes: 10485760    # 10 MB
  max_response_bytes: 5242880    # 5 MB
```

Both default to unlimited when omitted.

## Header and Request Limits

Praxis inherits header and request limits from Pingora's
HTTP/1.x parser. These are compile-time constants in
Pingora and are not currently configurable in Praxis.

| Limit | Value | Notes |
| ------- | ------- | ------- |
| Max total header size | 1,048,575 B (~1 MiB) | Includes request line |
| Max number of headers | 256 | HTTP/1.x only |
| Request-URI max size | shared with header limit | No separate cap |
| Header read timeout | 60 s | Pingora default |
| Body buffer chunk | 65,536 B (64 KiB) | Per-read buffer |

HTTP/2 header limits are governed by the `h2` crate's
HPACK and frame-level settings (typically 16 KiB for
HEADERS frames by default, negotiated via SETTINGS).

Requests that exceed header size or count limits receive
a 400 Bad Request from Pingora before reaching the filter
pipeline.

## Runtime

Worker thread pool and scheduling configuration.

```yaml
runtime:
  threads: 8             # 0 = auto-detect (default)
  work_stealing: true    # default: true
```

- `threads`: number of worker threads per service.
  When set to 0 (the default), the thread count is
  auto-detected from available CPUs.
- `work_stealing`: allow work-stealing between worker
  threads of the same service. Enabled by default.
- `global_queue_interval`: fixed global queue interval
  for the tokio scheduler. `Option<u32>`, defaults to
  `Some(61)`. Set to `null` to use tokio's default.
- `upstream_keepalive_pool_size`: maximum number of idle
  upstream connections kept per thread. `Option<usize>`,
  defaults to `Some(64)`. Set to `null` to disable
  keepalive pooling.

```yaml
runtime:
  threads: 4
  work_stealing: true
  global_queue_interval: 61
  upstream_keepalive_pool_size: 64
```

### Upstream CA

`upstream_ca_file` sets a PEM CA file used as the root
certificate store for all upstream TLS connections.
Per-cluster `tls.ca` overrides this for individual
clusters.

```yaml
runtime:
  upstream_ca_file: /etc/praxis/tls/internal-ca.pem
```

This **replaces** the system trust store (not additive).
See [tls.md](tls.md) for details on CA trust
precedence and combined bundles.

### Logging

Set `PRAXIS_LOG_FORMAT=json` to emit structured JSON log
output instead of the default human-readable format.

Per-module log level overrides can be configured under
`runtime.log_overrides`:

```yaml
runtime:
  log_overrides:
    praxis_filter::pipeline: trace
    praxis_protocol: debug
```

This is useful for debugging a specific subsystem without
flooding output from every module.

## Graceful Shutdown

The `shutdown_timeout_secs` field controls how long the
server drains in-flight connections before forcing
shutdown:

```yaml
shutdown_timeout_secs: 60    # default: 30
```

## Default Configuration

When no configuration file is provided, Praxis starts with
a built-in default config that listens on `127.0.0.1:8080`
and responds with `{"status": "ok", "server": "praxis"}`
on `/` (exact match) and 404 elsewhere. The default binds
to localhost only, preventing accidental exposure to
public networks during initial setup. This allows zero
config startup for testing. The source lives in
[default.yaml]. For a realistic starting point, see
[basic-reverse-proxy.yaml].

[default.yaml]: ../core/src/config/default.yaml
[basic-reverse-proxy.yaml]: ../examples/configs/traffic-management/basic-reverse-proxy.yaml

## Example Configs

Working examples live under `examples/configs/`, organized
by category:

| Directory | Contents |
| ----------- | ---------- |
| `ai` | AI inference model-to-header routing |
| `traffic-management` | Router, load balancer, timeouts, static responses, redirects, rate limiting, health checks |
| `payload-processing` | Body processing: compression, field extraction, stream buffering, size limits |
| `security` | Forwarded headers, IP ACL, guardrails, CORS, downstream read timeout |
| `observability` | Access logs, request IDs |
| `transformation` | Header manipulation, path rewriting, URL rewriting |
| `protocols` | TCP, TLS, mixed protocol configs |
| `pipeline` | Filter chain composition and conditions |
| `operations` | Production gateway, multi-listener |

## Validation and Security

Praxis validates configuration at startup and fails
closed. Ambiguous or risky settings are errors, not
warnings. Insecure overrides (see [development.md])
require explicit opt-in and emit warnings at startup.

Key validations: listener name uniqueness, filter chain
reference resolution, TLS path traversal rejection,
admin endpoint binding restrictions, health check SSRF
protection, upstream TLS SNI requirements, and payload
size enforcement.

## Error Behavior

Praxis fails fast at startup for configuration problems.
Common failure modes:

- **Invalid YAML or missing required fields**: the process
  exits with a descriptive error before any listener binds.
- **Unknown filter chain reference**: a listener references
  a chain name not defined in `filter_chains:`; caught at
  config validation.
- **TLS certificate load failure**: the process exits if
  a certificate's `cert_path` or `key_path` cannot be
  read or parsed.
- **Address bind failure**: if the listen address is already
  in use or invalid, the server fails to start.

At runtime:

- **Unreachable upstream**: the request returns 502 (Bad
  Gateway). Connection timeouts are configurable per
  cluster.
- **Filter error**: an `Err` from a filter results in a
  500 response to the client. The error is logged.
- **Payload too large**: exceeding
  `body_limits.max_request_bytes` or a filter's
  `max_bytes` returns 413.

## Overrides

Some validations and features can be overridden for development
and testing purposes. See `insecure_options` in [development.md].

[development.md]:./development.md#insecure-options
