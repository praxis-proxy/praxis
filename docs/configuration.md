# Configuration

Single YAML file, passed as CLI argument or set via the
`PRAXIS_CONFIG` environment variable. See
`examples/configs/` for working examples.

## Structure

```yaml
listeners:        # Required. Named listeners to bind.
filter_chains:    # Named, reusable filter chains.
admin_address:    # Optional. Admin health endpoint.
```

`admin_address` binds a separate HTTP listener that serves
`/ready` and `/healthy`. Both return `200 OK` with a JSON
body (`{"status":"ok"}`) once the server is accepting
connections. They reflect server liveness only; they do
not probe upstream backends. Any other path returns 404.
Useful for orchestrator health checks without exposing
them on the main listeners.

```yaml
admin_address: "0.0.0.0:9901"
```

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
      cert_path: /etc/praxis/tls/cert.pem
      key_path: /etc/praxis/tls/key.pem
```

The `name` field uniquely identifies the listener and is
used to resolve its pipeline at startup.

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
| `headers` | Transformation | HTTP |
| `request_id` | Observability | HTTP |
| `access_log` | Observability | HTTP |
| `tcp_access_log` | Observability | TCP |
| `forwarded_headers` | Security | HTTP |
| `ip_acl` | Security | HTTP |
| `json_body_field` | Payload Processing | HTTP |

### Router

Routes requests to clusters by path prefix. Longest prefix
wins. Optional `host` field restricts matching to a specific
`Host` header value.

```yaml
- filter: router
  routes:
    - path_prefix: "/api/"
      cluster: api
    - path_prefix: "/static/"
      host: "cdn.example.com"
      cluster: cdn
    - path_prefix: "/"
      cluster: default
```

Routes without `host` match any host.

### Load Balancing

Strategies:

- `round_robin` (default): cycles through endpoints
- `least_connections`: picks endpoint with fewest active
  requests
- `consistent_hash`: hashes a request header (or URI path
  as fallback) to pin requests to stable endpoints

```yaml
- filter: load_balancer
  clusters:
    - name: backend
      load_balancer_strategy: least_connections
      endpoints: ["10.0.0.1:8080", "10.0.0.2:8080"]
```

Weighted endpoints:

```yaml
endpoints:
  - address: "10.0.0.1:8080"
    weight: 3
  - address: "10.0.0.2:8080"
    weight: 1
```

Consistent hash with a specific header:

```yaml
load_balancer_strategy:
  consistent_hash:
    header: "X-User-Id"
```

Cluster-level options: `connection_timeout_ms`,
`total_connection_timeout_ms`, `idle_timeout_ms`,
`read_timeout_ms`, `write_timeout_ms`, `upstream_tls`,
`upstream_sni`.

`total_connection_timeout_ms` sets the combined budget for
TCP connect and TLS handshake. When used alongside
`connection_timeout_ms`, the difference is effectively the
TLS handshake budget. It must be >= `connection_timeout_ms`.

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

### Conditions

`when`/`unless` gates on any filter chain entry:

```yaml
- filter: headers
  conditions:
    - when:
        path_prefix: "/api/"
    - unless:
        headers:
          x-internal: "true"
  request_add:
    - name: "X-Api-Version"
      value: "v2"
```

Request predicates: `path` (exact match), `path_prefix`,
`methods`, `headers`. All fields within a condition are
ANDed.

```yaml
conditions:
  - when:
      path: "/"           # exact match
```

```yaml
conditions:
  - when:
      path_prefix: "/api" # prefix match
```

#### Response Conditions

Use `response_conditions` to gate `on_response` execution
based on response attributes. Response predicates support
`status` (list of status codes) and `headers`.

```yaml
- filter: headers
  response_conditions:
    - when:
        status: [200]
  response_set:
    - name: "Cache-Control"
      value: "public, max-age=60"
```

Request conditions gate both request and body hooks.
Response conditions gate only `on_response` and response
body hooks. A filter can have both `conditions` and
`response_conditions`.

## Payload Size Limits

Global hard ceilings on request and response payload
size. These apply across all body modes (Stream, Buffer,
StreamBuffer). When a filter also declares a per-filter
`max_bytes`, the smaller of the two limits is enforced.
Requests exceeding the limit receive 413 (Payload Too
Large).

```yaml
max_request_body_bytes: 10485760    # 10 MB
max_response_body_bytes: 5242880    # 5 MB
```

Both default to unlimited when omitted.

## Header and Request Limits

Praxis inherits header and request limits from Pingora's
HTTP/1.x parser. These are compile-time constants in
Pingora and are not currently configurable in Praxis.

| Limit | Value | Notes |
|-------|-------|-------|
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

## Legacy Format

For backward compatibility, configs using the old `pipeline:`
and `routes:` format are auto-converted at startup via
`apply_defaults()`. The legacy format uses a single shared
pipeline across all listeners:

```yaml
# Legacy format (still works)
listeners:
  - address: "0.0.0.0:8080"

pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: backend
  - filter: load_balancer
    clusters:
      - name: backend
        endpoints: ["127.0.0.1:3000"]
```

New configs should use named listeners with `filter_chains:`.

## Default Configuration

When no configuration file is provided, Praxis starts with
a built-in default config that listens on `127.0.0.1:8080`
and responds with `{"status": "ok", "server": "praxis"}`
on `/` (exact match) and 404 elsewhere. This allows zero
config startup for testing. The source lives in
[default.yaml]. For a realistic starting point, see
[basic-reverse-proxy.yaml].

[default.yaml]: ../examples/configs/pipeline/default.yaml
[basic-reverse-proxy.yaml]: ../examples/configs/traffic-management/basic-reverse-proxy.yaml

## Example Configs

Working examples live under `examples/configs/`, organized
by category:

| Directory | Contents |
|-----------|----------|
| `traffic-management` | Router, load balancer, timeouts, static responses |
| `payload-processing` | JSON body field extraction |
| `security` | Forwarded headers, IP ACL |
| `observability` | Access logs, request IDs |
| `transformation` | Header manipulation |
| `protocols` | TCP, TLS, mixed protocol configs |
| `pipeline` | Filter chain composition and conditions |
| `operations` | Production gateway, multi-listener |

## Error Behavior

Praxis fails fast at startup for configuration problems.
Common failure modes:

- **Invalid YAML or missing required fields**: the process
  exits with a descriptive error before any listener binds.
- **Unknown filter chain reference**: a listener references
  a chain name not defined in `filter_chains:`; caught at
  config validation.
- **TLS certificate load failure**: the process exits if
  `cert_path` or `key_path` cannot be read or parsed.
- **Address bind failure**: if the listen address is already
  in use or invalid, the server fails to start.

At runtime:

- **Unreachable upstream**: the request returns 502 (Bad
  Gateway). Connection timeouts are configurable per
  cluster.
- **Filter error**: an `Err` from a filter results in a
  500 response to the client. The error is logged.
- **Payload too large**: exceeding `max_request_body_bytes`
  or a filter's `max_bytes` returns 413.
