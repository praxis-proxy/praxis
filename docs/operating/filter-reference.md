# Filter Reference

Configuration reference for all built-in filters. For
filter system architecture and custom filter development,
see the [filter system documentation](../filters/README.md)
and the [extensions guide](../filters/extensions.md).

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
| `a2a` | Payload Processing | HTTP |
| `json_body_field` | Payload Processing | HTTP |
| `json_rpc` | Payload Processing | HTTP |
| `mcp` | Payload Processing | HTTP |
| `compression` | Payload Processing | HTTP |
| `cors` | Security | HTTP |
| `csrf` | Security | HTTP |
| `redirect` | Traffic Management | HTTP |
| `path_rewrite` | Transformation | HTTP |
| `url_rewrite` | Transformation | HTTP |
| `sni_router` | Traffic Management | TCP |
| `tcp_load_balancer` | Traffic Management | TCP |
| `model_to_header` | AI / Inference | HTTP (requires `ai-inference` feature) |
| `prompt_enrich` | AI / Inference | HTTP (requires `ai-inference` feature) |

## Router

Routes requests to clusters by path prefix. Longest prefix
wins. Optional `host` restricts matching to a specific
`Host` header. Optional `headers` restricts matching to
requests with all specified header values present (AND
semantics, case-sensitive). Routes without `host` match
any host.

Example configs: [path-based-routing.yaml],
[hosts.yaml], [canary-routing.yaml].

[path-based-routing.yaml]: ../../examples/configs/traffic-management/path-based-routing.yaml
[hosts.yaml]: ../../examples/configs/traffic-management/hosts.yaml
[canary-routing.yaml]: ../../examples/configs/traffic-management/canary-routing.yaml

## Load Balancing

Strategies:

- `round_robin` (default): cycles through endpoints
- `least_connections`: picks endpoint with fewest active
  requests (O(N) scan)
- `p2c`: samples two random endpoints, picks the less
  loaded one (O(1), near-optimal distribution)
- `consistent_hash`: hashes a request header (or URI path
  as fallback) to pin requests to stable endpoints

Example configs: [weighted-load-balancing.yaml],
[least-connections.yaml], [p2c.yaml],
[session-affinity.yaml].

[weighted-load-balancing.yaml]: ../../examples/configs/traffic-management/weighted-load-balancing.yaml
[least-connections.yaml]: ../../examples/configs/traffic-management/least-connections.yaml
[p2c.yaml]: ../../examples/configs/traffic-management/p2c.yaml
[session-affinity.yaml]: ../../examples/configs/traffic-management/session-affinity.yaml

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

### Health Checks

Clusters support active health checks via the
`health_check` field. Endpoints that fail consecutive
probes are removed from load balancer rotation until they
recover. See [health-checks.yaml].

[health-checks.yaml]: ../../examples/configs/traffic-management/health-checks.yaml

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
loopback, link-local, or cloud metadata addresses are
rejected (SSRF protection).

## Headers

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

## Timeout

Returns 504 if upstream response exceeds configured duration:

```yaml
- filter: timeout
  timeout_ms: 5000
```

## Request ID

Propagates an existing request ID header or generates a
new one:

```yaml
- filter: request_id
  header_name: "X-Request-Id"   # optional, this is the default
```

## Access Log

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

## Forwarded Headers

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

## IP ACL

Allow or deny requests by source IP/CIDR:

```yaml
- filter: ip_acl
  allow:
    - "10.0.0.0/8"
```

Use either `allow` or `deny`, not both (mutually
exclusive). When `allow` is set, only matching IPs are
permitted (implicit deny-all). Denied requests receive
a `403 Forbidden` response.

## Credential Injection

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

[credential-injection.yaml]: ../../examples/configs/ai/credential-injection.yaml

## TCP Access Log

Structured JSON logging of TCP connections. Works on both
TCP and HTTP listeners:

```yaml
- filter: tcp_access_log
```

## SNI Router

Routes TLS connections to upstream addresses based on
the SNI hostname from the TLS ClientHello. Supports
exact matches and wildcard patterns (e.g.
`*.example.com`). Performs exact-match lookup first,
then longest-suffix wildcard match. Matching is
case-insensitive per RFC 4343.

```yaml
- filter: sni_router
  routes:
    - server_names: ["api.example.com"]
      upstream: "10.0.0.1:443"
    - server_names: ["*.example.com"]
      upstream: "10.0.0.2:443"
  default_upstream: "10.0.0.3:443"
```

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `routes` | list | yes | SNI route entries |
| `routes[].server_names` | list | yes | Exact or wildcard hostnames |
| `routes[].upstream` | string | yes | Upstream address for matches |
| `default_upstream` | string | no | Fallback when no route matches |

Connections without SNI or with no matching route use
`default_upstream` if configured, otherwise receive a
421 rejection. Bare wildcards (`*`), IP addresses as
server names, and duplicate server names across routes
are rejected at config validation.

## TCP Load Balancer

Selects an upstream TCP endpoint from a cluster using
the configured load-balancing strategy. Reads
`ctx.cluster` to find the target cluster, selects an
endpoint, and writes `ctx.upstream_addr`. Supports
round-robin (default), least-connections, and
consistent-hash strategies.

```yaml
- filter: tcp_load_balancer
  clusters:
    - name: db_pool
      endpoints:
        - "10.0.0.1:5432"
        - "10.0.0.2:5432"
```

Weighted endpoints and strategy selection follow the
same syntax as the HTTP `load_balancer` filter. Health
check integration is supported; if all endpoints are
unhealthy, the filter enters panic mode and routes to
all endpoints.

## JSON Body Field

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

## JSON-RPC

Parses JSON-RPC 2.0 request bodies and promotes
method, id, and message kind to request headers for
routing. Uses StreamBuffer mode to inspect the body
before upstream selection.

```yaml
- filter: json_rpc
  max_body_bytes: 1048576
  batch_policy: reject
  on_invalid: continue
```

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `max_body_bytes` | integer | 1048576 | Maximum body size to buffer (1 MiB) |
| `batch_policy` | string | `"reject"` | `"reject"` returns 400 for batch arrays; `"first"` uses first valid request |
| `on_invalid` | string | `"continue"` | `"continue"` passes non-JSON through; `"reject"` returns 400; `"error"` raises a filter error |
| `headers.method` | string | `"X-Json-Rpc-Method"` | Header name for the JSON-RPC method |
| `headers.id` | string | `"X-Json-Rpc-Id"` | Header name for the JSON-RPC id |
| `headers.kind` | string | `"X-Json-Rpc-Kind"` | Header name for the message kind |

Message kinds: `request`, `notification`, `response`,
`batch`. The filter also writes `json_rpc.*` entries
to the filter result set for branch chain conditions.

## MCP

Extracts Model Context Protocol metadata from JSON-RPC
request bodies and promotes method, tool/resource/prompt
name, session ID, and protocol version to request
headers and filter results for routing. Validates MCP
headers against body-derived values when
`header_validation` is configured.

```yaml
- filter: mcp
  max_body_bytes: 65536
  on_invalid: reject
```

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `max_body_bytes` | integer | 65536 | Maximum body size to buffer (64 KiB) |
| `on_invalid` | string | `"reject"` | `"reject"` returns 400 for non-MCP; `"continue"` passes through |
| `header_validation.mismatch` | string | `"reject"` | `"reject"` or `"ignore"` when MCP headers conflict with body values |
| `header_validation.missing` | string | `"ignore"` | `"ignore"`, `"synthesize"` (inject from body), or `"reject"` |
| `headers.method` | string | `"x-praxis-mcp-method"` | Header name for MCP method |
| `headers.name` | string | `"x-praxis-mcp-name"` | Header name for tool/resource/prompt name |
| `headers.kind` | string | `"x-praxis-mcp-kind"` | Header name for JSON-RPC kind |
| `headers.session_present` | string | `"x-praxis-mcp-session-present"` | Header name for session presence |

Recognized MCP methods include `initialize`,
`tools/call`, `tools/list`, `resources/read`,
`resources/list`, `prompts/get`, `prompts/list`,
`ping`, and others. Methods requiring a name selector
(`tools/call`, `resources/read`, `prompts/get`) return
a JSON-RPC error if the selector is missing and
`on_invalid` is `"reject"`. The filter writes `mcp.*`
and `json_rpc.*` entries to the filter result set for
branch chain conditions.

### MCP Broker Mode

When the `mcp` filter config includes a `servers`
block, broker mode activates. The broker aggregates
tool catalogs from configured backends and handles
`initialize`, `tools/list`, `ping`, and notifications
directly as synthetic responses.

```yaml
- filter: mcp
  path: /mcp
  max_body_bytes: 65536
  protocol_profile: current
  default_version: "2025-03-26"
  supported_versions: ["2025-03-26"]
  servers:
    - name: weather
      cluster: weather-mcp
      path: /mcp
      tool_prefix: "weather_"
      tools:
        - name: get_weather
          description: Get current weather
```

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `path` | string | `"/mcp"` | Public endpoint path |
| `max_body_bytes` | integer | 65536 | Maximum body size to buffer (64 KiB) |
| `protocol_profile` | string | `"current"` | Protocol profile governing session semantics |
| `default_version` | string | `"2025-03-26"` | Protocol version used in `initialize` responses when the client's requested version is not supported |
| `supported_versions` | list | `["2025-03-26"]` | Protocol versions accepted during `initialize` negotiation; every entry must be implemented by this build |
| `invalid_tool_policy` | string | `"reject_server"` | `"reject_server"` or `"filter_out"` for tools with invalid schemas |
| `servers` | list | `[]` | Backend MCP server definitions |

Each server entry supports `name`, `cluster`, `path`
(default `"/mcp"`), `tool_prefix`, and `tools`. Tool
definitions include `name`, optional `description`,
optional `inputSchema`, and optional `annotations`.

## Static Response

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

## Rate Limit

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

## Circuit Breaker

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

[circuit-breaker.yaml]: ../../examples/configs/traffic-management/circuit-breaker.yaml

## Guardrails

Rejects requests matching string or regex rules against
headers and/or body content. Rejected requests receive
403 Forbidden.

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

## CORS

Spec-compliant CORS filter with preflight handling, origin
validation, and credential support. See [cors.yaml].

[cors.yaml]: ../../examples/configs/security/cors.yaml

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

## CSRF

Cross-site request forgery protection via origin
validation. Safe methods (GET, HEAD, OPTIONS by default)
bypass the check. State-changing methods require an
`Origin` or `Referer` header matching the trusted
origins. Rejected requests receive 403 Forbidden.
See [csrf.yaml].

[csrf.yaml]: ../../examples/configs/security/csrf.yaml

```yaml
- filter: csrf
  trusted_origins:
    - "https://app.example.com"
    - "https://*.example.com"
  enforce_percentage: 100
  enable_sec_fetch_site: true
```

| Field | Type | Default | Description |
| ------- | ------ | --------- | ------------- |
| `trusted_origins` | list | required | Origins to allow; `["*"]` for any |
| `safe_methods` | list | GET, HEAD, OPTIONS | Methods that bypass CSRF checks |
| `enforce_percentage` | integer | 100 | Percentage of requests to enforce (0..=100); enables gradual rollout |
| `enable_sec_fetch_site` | bool | false | Reject requests with `Sec-Fetch-Site: cross-site` |

Wildcard subdomain patterns (e.g.
`https://*.example.com`) are supported. A bare wildcard
(`"*"`) cannot be mixed with other origins. Set
`insecure_options.csrf_log_only: true` to log violations
without rejecting requests during initial rollout.

## Redirect

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

## Path Rewrite

Rewrites the request path before forwarding to upstream.
Exactly one of `strip_prefix`, `add_prefix`, or `replace`
per filter instance. Query strings are preserved. See
[path-rewriting.yaml].

[path-rewriting.yaml]: ../../examples/configs/transformation/path-rewriting.yaml

| Field | Type | Description |
| ------- | ------ | ------------- |
| `strip_prefix` | string | Remove this prefix from the path |
| `add_prefix` | string | Prepend this prefix to the path |
| `replace.pattern` | string | Regex pattern to match |
| `replace.replacement` | string | Replacement string (`$1`, `$name` captures) |

## URL Rewrite

Regex-based path transformation and query string
manipulation. Operations applied in order:
`regex_replace`, `strip_query_params`,
`add_query_params`. See [url-rewriting.yaml].

[url-rewriting.yaml]: ../../examples/configs/transformation/url-rewriting.yaml

## Compression

Gzip, brotli, and zstd response compression. All three
enabled by default. See [compression.yaml].

[compression.yaml]: ../../examples/configs/payload-processing/compression.yaml

| Field | Type | Default | Description |
| ------- | ------ | --------- | ------------- |
| `level` | integer | 6 | Default compression level (1-12) |
| `min_size_bytes` | integer | 256 | Skip responses smaller than this |
| `gzip` | object | enabled | Per-algorithm `enabled` and `level` |
| `brotli` | object | enabled | Per-algorithm `enabled` and `level` |
| `zstd` | object | enabled | Per-algorithm `enabled` and `level` |
| `content_types` | list | see above | MIME type prefixes that qualify |

At least one algorithm must be enabled.

## Prompt Enrich

Injects statically configured messages into
OpenAI-compatible chat completion request bodies. The
filter parses the JSON body, splices configured messages
into the `messages` array, re-serializes, and updates
`Content-Length`. Requires the `ai-inference` feature.
See [prompt-enrichment.yaml].

[prompt-enrichment.yaml]: ../../examples/configs/ai/prompt-enrichment.yaml

```yaml
- filter: prompt_enrich
  prepend:
    - role: system
      content: "You are a helpful assistant."
  append:
    - role: user
      content: "Cite your sources."
```

| Field | Type | Default | Description |
| ------- | ------ | --------- | ------------- |
| `prepend` | list | `[]` | Messages inserted at the beginning of `messages` (system role only) |
| `append` | list | `[]` | Messages added at the end of `messages` (system or user role) |
| `on_invalid` | string | `"continue"` | `"continue"` passes non-JSON through; `"reject"` returns 400 |
| `max_body_bytes` | integer | 10485760 | Maximum body size to buffer (10 MiB) |

At least one of `prepend` or `append` must be non-empty.
Each message has a `role` (system or user) and a
non-empty `content` string. JSON is re-serialized, so
byte-for-byte body identity is not preserved. In chains
that also use `json_body_field` or `model_to_header`,
place `prompt_enrich` first.

## Conditions

`when`/`unless` gates on any filter chain entry. Request
predicates: `path` (exact match), `path_prefix`,
`methods`, `headers`. All fields within a condition are
ANDed. Use `response_conditions` with `status` or
`headers` predicates to gate response hooks. See
[conditional-filters.yaml].

[conditional-filters.yaml]: ../../examples/configs/pipeline/conditional-filters.yaml

Request conditions gate both request and body hooks.
Response conditions gate only `on_response` and response
body hooks. A filter can have both `conditions` and
`response_conditions`.
