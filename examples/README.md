# Examples

Configuration examples organized by category.

## Running an Example

```console
cargo run -p praxis -- -c examples/configs/traffic-management/basic-reverse-proxy.yaml
curl http://localhost:8080/
```

Configs use local ports (`3000`, `3001`, ...) for
upstreams. For quick experiments without a real backend,
use `static_response` (see
[static-response.yaml](configs/traffic-management/static-response.yaml))
or run Praxis with no config file for a built-in welcome
page.

## Configs

### Traffic Management

| File | Description |
| ------ | ------------- |
| [basic-reverse-proxy.yaml](configs/traffic-management/basic-reverse-proxy.yaml) | Minimal single-listener, single-cluster proxy |
| [path-based-routing.yaml](configs/traffic-management/path-based-routing.yaml) | Route by URL path prefix to separate clusters |
| [hosts.yaml](configs/traffic-management/hosts.yaml) | Route by Host header; one listener, multiple domains |
| [canary-routing.yaml](configs/traffic-management/canary-routing.yaml) | Weighted traffic split for canary deployments |
| [round-robin.yaml](configs/traffic-management/round-robin.yaml) | Default strategy: even distribution across backends |
| [weighted-load-balancing.yaml](configs/traffic-management/weighted-load-balancing.yaml) | Proportional traffic split via per-endpoint weights |
| [least-connections.yaml](configs/traffic-management/least-connections.yaml) | Route to backend with fewest in-flight requests |
| [session-affinity.yaml](configs/traffic-management/session-affinity.yaml) | consistent_hash to pin a user to one backend |
| [health-checks.yaml](configs/traffic-management/health-checks.yaml) | Active HTTP and TCP health check probes per cluster |
| [timeout.yaml](configs/traffic-management/timeout.yaml) | 504 when upstream exceeds a latency SLA |
| [rate-limiting.yaml](configs/traffic-management/rate-limiting.yaml) | Token bucket rate limiter with per-IP and global modes |
| [static-response.yaml](configs/traffic-management/static-response.yaml) | Fixed response without upstream |
| [redirect.yaml](configs/traffic-management/redirect.yaml) | 3xx redirects with path/query template substitution |
| [hostname-upstream.yaml](configs/traffic-management/hostname-upstream.yaml) | Resolve hostname upstream endpoints such as `localhost:9000` |

### Payload Processing

| File | Description |
| ------ | ------------- |
| [ai-inference-body-based-routing.yaml](configs/payload-processing/ai-inference-body-based-routing.yaml) | Route LLM requests by model field in JSON body |
| [json-rpc-routing.yaml](configs/payload-processing/json-rpc-routing.yaml) | Route JSON-RPC 2.0 requests by method for MCP and A2A protocols |
| [stream-buffer.yaml](configs/payload-processing/stream-buffer.yaml) | Stream-buffered body inspection before forwarding |
| [compression.yaml](configs/payload-processing/compression.yaml) | Gzip, brotli, and zstd response compression |
| [multi-field-extraction.yaml](configs/payload-processing/multi-field-extraction.yaml) | Extract multiple JSON fields into headers in one pass |
| [conditional-field-extraction.yaml](configs/payload-processing/conditional-field-extraction.yaml) | Apply json_body_field only on matching request paths |
| [field-extraction-access-control.yaml](configs/payload-processing/field-extraction-access-control.yaml) | Extract tenant_id from body for header-based routing |
| [body-size-limit-with-extraction.yaml](configs/payload-processing/body-size-limit-with-extraction.yaml) | Global body size ceiling with json_body_field extraction |
| [multi-listener-body-pipeline.yaml](configs/payload-processing/multi-listener-body-pipeline.yaml) | Three listeners with different body processing strategies |

### Security

| File | Description |
| ------ | ------------- |
| [forwarded-headers.yaml](configs/security/forwarded-headers.yaml) | X-Forwarded-For/Proto/Host with trusted proxies |
| [guardrails.yaml](configs/security/guardrails.yaml) | Reject requests matching header or body string/regex rules |
| [ip-acl.yaml](configs/security/ip-acl.yaml) | Allow/deny by source IP/CIDR |
| [downstream-read-timeout.yaml](configs/security/downstream-read-timeout.yaml) | Protect against slow client attacks with read timeouts |
| [cors.yaml](configs/security/cors.yaml) | CORS preflight handling with origin validation |

### Observability

| File | Description |
| ------ | ------------- |
| [access-logging.yaml](configs/observability/access-logging.yaml) | Access log with sampling |
| [logging.yaml](configs/observability/logging.yaml) | request_id + access_log: correlation IDs and structured logs |
| [tcp-access-log.yaml](configs/observability/tcp-access-log.yaml) | Structured JSON TCP connection logging |

### Transformation

| File | Description |
| ------ | ------------- |
| [header-manipulation.yaml](configs/transformation/header-manipulation.yaml) | Add, overwrite, and remove request/response headers |
| [path-rewriting.yaml](configs/transformation/path-rewriting.yaml) | Strip prefix, add prefix, or regex replace on request paths |
| [url-rewriting.yaml](configs/transformation/url-rewriting.yaml) | Regex path transformation and query string manipulation |

### Protocols

| File | Description |
| ------ | ------------- |
| [tcp-proxy.yaml](configs/protocols/tcp-proxy.yaml) | L4 bidirectional TCP forwarding |
| [tcp-timeouts.yaml](configs/protocols/tcp-timeouts.yaml) | TCP proxy with idle and max duration timeouts |
| [tcp-consistent-hash.yaml](configs/protocols/tcp-consistent-hash.yaml) | TCP load balancing with consistent-hash client IP affinity |
| [tcp-least-connections.yaml](configs/protocols/tcp-least-connections.yaml) | TCP load balancing via least-connections strategy |
| [tcp-round-robin.yaml](configs/protocols/tcp-round-robin.yaml) | TCP round-robin load balancing across replicas |
| [mixed-protocol.yaml](configs/protocols/mixed-protocol.yaml) | HTTP + TCP listeners on one server |
| [tls-termination.yaml](configs/protocols/tls-termination.yaml) | HTTPS listener; plain HTTP to backends |
| [tls-cipher-suites.yaml](configs/protocols/tls-cipher-suites.yaml) | Restrict accepted TLS cipher suites per listener |
| [tls-sni-routing.yaml](configs/protocols/tls-sni-routing.yaml) | Route TLS connections by SNI hostname without termination |
| [tcp-tls-mtls.yaml](configs/protocols/tcp-tls-mtls.yaml) | TCP proxy with mutual TLS |
| [tcp-tls-termination.yaml](configs/protocols/tcp-tls-termination.yaml) | TCP proxy with TLS termination |
| [tls-http-reencrypt.yaml](configs/protocols/tls-http-reencrypt.yaml) | TLS termination with re-encryption to upstream |
| [tls-mtls-both.yaml](configs/protocols/tls-mtls-both.yaml) | mTLS on both listener and upstream |
| [tls-mtls-listener.yaml](configs/protocols/tls-mtls-listener.yaml) | mTLS on listener (require client cert) |
| [tls-mtls-listener-request.yaml](configs/protocols/tls-mtls-listener-request.yaml) | mTLS on listener (request client cert) |
| [tls-mtls-upstream.yaml](configs/protocols/tls-mtls-upstream.yaml) | mTLS to upstream (client cert) |
| [tls-multi-cert.yaml](configs/protocols/tls-multi-cert.yaml) | SNI-based multi-certificate selection |
| [tls-verify-disabled.yaml](configs/protocols/tls-verify-disabled.yaml) | Upstream TLS with verification disabled |
| [tls-version-constraint.yaml](configs/protocols/tls-version-constraint.yaml) | Minimum TLS version constraint |
| [upstream-ca-file.yaml](configs/protocols/upstream-ca-file.yaml) | Global upstream CA file reference |
| [upstream-tls.yaml](configs/protocols/upstream-tls.yaml) | Plain HTTP listener; TLS to upstream with SNI |
| [websocket.yaml](configs/protocols/websocket.yaml) | Transparent WebSocket upgrade proxying over HTTP |

### Pipeline

| File | Description |
| ------ | ------------- |
| [default.yaml](../core/src/config/default.yaml) | Built-in default config (static JSON on /) |
| [composed-chains.yaml](configs/pipeline/composed-chains.yaml) | Multiple named chains composed per listener |
| [conditional-filters.yaml](configs/pipeline/conditional-filters.yaml) | when/unless conditions on request and response phase |
| [branch-chains.yaml](configs/pipeline/branch-chains.yaml) | All branch chain scenarios in one config (six patterns) |

### AI / Inference

| File | Description |
| ------ | ------------- |
| [model-to-header-routing.yaml](configs/ai/model-to-header-routing.yaml) | Route by model field in JSON body via X-Model header |

### Branching

| File | Description |
| ------ | ------------- |
| [unconditional-branch.yaml](configs/branching/unconditional-branch.yaml) | Always-fire branch for injecting side-effect chains |
| [conditional-terminal.yaml](configs/branching/conditional-terminal.yaml) | Short-circuit the pipeline with a static response on result match |
| [conditional-skip-to.yaml](configs/branching/conditional-skip-to.yaml) | Skip filters by jumping to a named rejoin point on result match |
| [multiple-branches.yaml](configs/branching/multiple-branches.yaml) | Multiple branches on one filter with first-match-wins evaluation |
| [named-chain-ref.yaml](configs/branching/named-chain-ref.yaml) | Reference a top-level chain by name instead of inline definition |
| [nested-branches.yaml](configs/branching/nested-branches.yaml) | Multi-level decision tree with branches inside branches |
| [reentrance.yaml](configs/branching/reentrance.yaml) | Loop back to a named filter with max_iterations cap |
| [cross-chain-flat.yaml](configs/branching/cross-chain-flat.yaml) | Branch across concatenated chains via flat pipeline name index |

### Operations

| File | Description |
| ------ | ------------- |
| [production-gateway.yaml](configs/operations/production-gateway.yaml) | Full production setup with composed chains |
| [multi-listener.yaml](configs/operations/multi-listener.yaml) | Multiple listeners sharing a filter chain |
| [admin-interface.yaml](configs/operations/admin-interface.yaml) | Admin interface with health endpoints |
| [container-default.yaml](configs/operations/container-default.yaml) | Default containerized deployment with public binding |
| [max-connections.yaml](configs/operations/max-connections.yaml) | Per-listener connection limit with 503 rejection |
| [log-overrides.yaml](configs/operations/log-overrides.yaml) | Per-module log level tuning via runtime config |
