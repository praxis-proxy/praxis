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

### AI / Inference

| File | Description |
| ------ | ------------- |
| [a2a-classifier-routing.yaml](configs/ai/a2a-classifier-routing.yaml) | Routes A2A requests by body-derived method, family, task ID, and streaming detection |
| [a2a-task-routing.yaml](configs/ai/a2a-task-routing.yaml) | Captures task ownership from SendMessage JSON responses and SendStreamingMessage / SubscribeToTask SSE responses, then routes follow-up task operations back to the backend cluster that created the task |
| [ai-inference-body-based-routing.yaml](configs/ai/ai-inference-body-based-routing.yaml) | Routes LLM API requests to different backends based on the `model` field in the JSON request body |
| [messages-protocol.yaml](configs/ai/anthropic/messages-protocol.yaml) | Routes Anthropic Messages API requests to a native `/v1/messages` backend |
| [messages-to-openai.yaml](configs/ai/anthropic/messages-to-openai.yaml) | Transforms Anthropic Messages API requests and responses for Chat Completions-compatible inference backends |
| [request-validate.yaml](configs/ai/anthropic/request-validate.yaml) | Rejects empty, malformed, or non-object JSON request bodies |
| [unified-gateway.yaml](configs/ai/anthropic/unified-gateway.yaml) | Routes traffic by classifier-promoted headers so a single listener handles Anthropic Messages, OpenAI Chat Completions, and OpenAI Responses requests |
| [credential-injection.yaml](configs/ai/credential-injection.yaml) | Injects per-cluster API credentials into upstream requests and strips client-provided credentials to prevent forwarding |
| [json-rpc-routing.yaml](configs/ai/json-rpc-routing.yaml) | Routes JSON-RPC 2.0 requests to different backends based on the "method" field in the JSON request body |
| [mcp-classifier-routing.yaml](configs/ai/mcp-classifier-routing.yaml) | Routes MCP requests by body-derived method and tool name |
| [model-to-header-routing.yaml](configs/ai/model-to-header-routing.yaml) | Routes LLM API requests to different backends based on the "model" field in the JSON request body |
| [format-routing.yaml](configs/ai/openai/responses/format-routing.yaml) | Routes AI API traffic by detected body format |
| [full-flow.yaml](configs/ai/openai/responses/full-flow.yaml) | Combines format classification, request validation, and backend routing into a single pipeline |
| [model-rewrite.yaml](configs/ai/openai/responses/model-rewrite.yaml) | Rewrites or injects the top-level `model` field in Responses API request bodies before forwarding to the inference backend |
| [rehydrate.yaml](configs/ai/openai/responses/rehydrate.yaml) | Validates `previous_response_id` by fetching the stored response, confirming its status is completed, and promoting the ID to filter metadata |
| [request-validate.yaml](configs/ai/openai/responses/request-validate.yaml) | Validates Responses API requests and rejects invalid parameter combinations |
| [response-store.yaml](configs/ai/openai/responses/response-store.yaml) | Persists non-streaming Responses API responses to a database and serves stored data via GET endpoints and handles DELETE /v1/responses/{id} locally |
| [responses-routing.yaml](configs/ai/openai/responses/responses-routing.yaml) | Routes Responses API traffic by detected mode |
| [prompt-enrichment.yaml](configs/ai/prompt-enrichment.yaml) | Injects system messages into OpenAI-compatible chat completion requests before forwarding to the upstream provider |
| [token-usage-headers.yaml](configs/ai/token-usage-headers.yaml) | Inject Praxis-Token-Input, Praxis-Token-Output, and Praxis-Token-Total headers into downstream responses when token counts are available in filter metadata |

### Branching

| File | Description |
| ------ | ------------- |
| [conditional-skip-to.yaml](configs/branching/conditional-skip-to.yaml) | Skips browser-facing middleware for clean requests |
| [conditional-terminal.yaml](configs/branching/conditional-terminal.yaml) | Short-circuits the pipeline when guardrails detects a dangerous request header |
| [cross-chain-flat.yaml](configs/branching/cross-chain-flat.yaml) | A listener references two chains: preprocessing and routing |
| [multiple-branches.yaml](configs/branching/multiple-branches.yaml) | Multiple branches on a single filter, evaluated in order |
| [named-chain-ref.yaml](configs/branching/named-chain-ref.yaml) | A branch references a top-level chain by name instead of defining filters inline |
| [nested-branches.yaml](configs/branching/nested-branches.yaml) | Branch filters that themselves contain branches, forming a multi-level decision tree |
| [reentrance.yaml](configs/branching/reentrance.yaml) | Loops back to a named filter up to N times |
| [unconditional-branch.yaml](configs/branching/unconditional-branch.yaml) | Always runs a utility chain before continuing the main pipeline |

### Observability

| File | Description |
| ------ | ------------- |
| [access-logging.yaml](configs/observability/access-logging.yaml) | Structured JSON logging with sampling; logs ~10% of requests. request_id ensures each log line has a correlation ID. access_log emits method, path, status, and timing |
| [logging.yaml](configs/observability/logging.yaml) | request_id — ensures every request has a correlation ID |
| [tcp-access-log.yaml](configs/observability/tcp-access-log.yaml) | Structured JSON logging of TCP connection events (connect and disconnect) |

### Operations

| File | Description |
| ------ | ------------- |
| [admin-interface.yaml](configs/operations/admin-interface.yaml) | Exposes an admin endpoint for operational health checks, readiness probes, and Prometheus metrics |
| [container-default.yaml](configs/operations/container-default.yaml) | Default config for containerized deployments |
| [hot-reload.yaml](configs/operations/hot-reload.yaml) | Filter pipelines are swapped atomically at runtime when the config file changes |
| [log-overrides.yaml](configs/operations/log-overrides.yaml) | Use `runtime.log_overrides` to raise or lower log verbosity for specific modules without flooding output from every subsystem |
| [max-connections.yaml](configs/operations/max-connections.yaml) | HTTP listeners return 503 with Retry-After: 1. TCP listeners close the socket immediately |
| [multi-listener.yaml](configs/operations/multi-listener.yaml) | Demonstrates multiple HTTP listeners, each with its own filter pipeline |
| [production-gateway.yaml](configs/operations/production-gateway.yaml) | Combines TLS, logging, timeouts, security headers, path routing, and load balancing |

### Payload Processing

| File | Description |
| ------ | ------------- |
| [body-size-limit-with-extraction.yaml](configs/payload-processing/body-size-limit-with-extraction.yaml) | Combines body_limits.max_request_bytes with json_body_field to enforce a global body ceiling while still performing body-based routing |
| [compression.yaml](configs/payload-processing/compression.yaml) | Enables transparent response compression using Pingora's built-in compression module |
| [conditional-field-extraction.yaml](configs/payload-processing/conditional-field-extraction.yaml) | Uses the condition system to apply json_body_field only on specific request paths |
| [field-extraction-access-control.yaml](configs/payload-processing/field-extraction-access-control.yaml) | Extracts the "tenant_id" field from the JSON request body and promotes it to an X-Tenant-Id header |
| [mcp-static-catalog.yaml](configs/payload-processing/mcp-static-catalog.yaml) | Provides a static MCP catalog and broker for initialize, tools/list, ping, and notifications/initialized requests |
| [multi-field-extraction.yaml](configs/payload-processing/multi-field-extraction.yaml) | A single json_body_field filter extracts multiple top-level JSON fields into separate request headers in one pass |
| [multi-listener-body-pipeline.yaml](configs/payload-processing/multi-listener-body-pipeline.yaml) | Three listeners, each with a different body processing strategy |
| [stream-buffer.yaml](configs/payload-processing/stream-buffer.yaml) | json_body_field inspects request body chunks as they arrive and defers upstream forwarding until the field is extracted (or end-of-stream) |

### Pipeline

| File | Description |
| ------ | ------------- |
| [default.yaml](../core/src/config/default.yaml) | Built-in default config (static JSON on /) |
| [branch-chains.yaml](configs/pipeline/branch-chains.yaml) | Filters write structured results to FilterResultSet |
| [composed-chains.yaml](configs/pipeline/composed-chains.yaml) | Multiple named chains are composed per listener |
| [conditional-filters.yaml](configs/pipeline/conditional-filters.yaml) | Filters support `conditions` (request phase) and `response_conditions` (response phase) to gate execution |
| [failure-mode.yaml](configs/pipeline/failure-mode.yaml) | Demonstrates open and closed failure handling for filters |

### Protocols

| File | Description |
| ------ | ------------- |
| [mixed-protocol.yaml](configs/protocols/mixed-protocol.yaml) | HTTP and TCP listeners run on a single server instance |
| [tcp-consistent-hash.yaml](configs/protocols/tcp-consistent-hash.yaml) | TCP consistent-hash load balancing (client IP affinity) |
| [tcp-least-connections.yaml](configs/protocols/tcp-least-connections.yaml) | TCP least-connections load balancing |
| [tcp-proxy.yaml](configs/protocols/tcp-proxy.yaml) | Bidirectional TCP forwarding |
| [tcp-round-robin.yaml](configs/protocols/tcp-round-robin.yaml) | TCP round-robin load balancing across database replicas |
| [tcp-timeouts.yaml](configs/protocols/tcp-timeouts.yaml) | TCP proxy with session and max duration timeouts. `tcp_session_timeout_ms` wraps the entire TCP forwarding session in a hard deadline, terminating connections after the threshold regardless of activity. `tcp_max_duration_secs` caps the total session duration in seconds |
| [tcp-tls-mtls.yaml](configs/protocols/tcp-tls-mtls.yaml) | The proxy requires TCP clients to present a valid TLS certificate signed by the trusted CA |
| [tcp-tls-termination.yaml](configs/protocols/tcp-tls-termination.yaml) | TLS on the listener; plain TCP to the upstream backend |
| [tls-cipher-suites.yaml](configs/protocols/tls-cipher-suites.yaml) | Restrict accepted cipher suites per listener |
| [tls-http-reencrypt.yaml](configs/protocols/tls-http-reencrypt.yaml) | HTTPS on the listener; TLS to the upstream backend |
| [tls-mtls-both.yaml](configs/protocols/tls-mtls-both.yaml) | Client mTLS to the proxy (client cert required), and proxy mTLS to the upstream backend (proxy presents its own client certificate) |
| [tls-mtls-listener-request.yaml](configs/protocols/tls-mtls-listener-request.yaml) | The proxy requests a client certificate but does not require one |
| [tls-mtls-listener.yaml](configs/protocols/tls-mtls-listener.yaml) | The proxy requires clients to present a valid TLS certificate signed by the trusted CA |
| [tls-mtls-upstream.yaml](configs/protocols/tls-mtls-upstream.yaml) | Plain HTTP from clients; the proxy presents a client certificate to the upstream backend, which requires mutual TLS authentication |
| [tls-multi-cert.yaml](configs/protocols/tls-multi-cert.yaml) | Multiple certificates on one listener; Praxis selects the certificate matching the client's SNI hostname |
| [tls-sni-routing.yaml](configs/protocols/tls-sni-routing.yaml) | Routes TLS connections to different upstreams based on the Server Name Indication (SNI) hostname in the ClientHello |
| [tls-termination.yaml](configs/protocols/tls-termination.yaml) | HTTPS on the listener; plain HTTP to the backend |
| [tls-verify-disabled.yaml](configs/protocols/tls-verify-disabled.yaml) | Plain HTTP listener; TLS to the upstream with certificate verification disabled |
| [tls-version-constraint.yaml](configs/protocols/tls-version-constraint.yaml) | Restrict accepted TLS versions via `min_version` |
| [upstream-ca-file.yaml](configs/protocols/upstream-ca-file.yaml) | Sets a trusted CA bundle for all upstream TLS connections via `runtime.upstream_ca_file` |
| [upstream-tls.yaml](configs/protocols/upstream-tls.yaml) | Plain HTTP on the listener; TLS to the upstream |
| [websocket.yaml](configs/protocols/websocket.yaml) | HTTP listener that transparently proxies WebSocket upgrade requests |

### Security

| File | Description |
| ------ | ------------- |
| [cors.yaml](configs/security/cors.yaml) | Spec-compliant CORS filter with preflight handling, origin validation, and credential support |
| [csrf.yaml](configs/security/csrf.yaml) | Cross-site request forgery protection via origin validation |
| [downstream-read-timeout.yaml](configs/security/downstream-read-timeout.yaml) | Protects against slow client attacks by limiting how long the proxy waits for data from downstream clients |
| [forwarded-headers.yaml](configs/security/forwarded-headers.yaml) | Injects X-Forwarded-For, X-Forwarded-Proto, and X-Forwarded-Host into upstream requests |
| [guardrails.yaml](configs/security/guardrails.yaml) | Reject requests that match header or body inspection rules |
| [ip-acl.yaml](configs/security/ip-acl.yaml) | Allow or deny requests by source IP/CIDR |

### Traffic Management

| File | Description |
| ------ | ------------- |
| [basic-reverse-proxy.yaml](configs/traffic-management/basic-reverse-proxy.yaml) | Minimal config: one listener, one upstream, default filter chain |
| [canary-routing.yaml](configs/traffic-management/canary-routing.yaml) | Sends ~10% of traffic to a canary backend while the stable backend handles the remaining ~90% |
| [circuit-breaker.yaml](configs/traffic-management/circuit-breaker.yaml) | Prevents cascading failures by tracking consecutive upstream errors per cluster |
| [grpc-detection.yaml](configs/traffic-management/grpc-detection.yaml) | Detects gRPC requests from the content-type header and promotes the variant to filter metadata and results |
| [health-checks.yaml](configs/traffic-management/health-checks.yaml) | Per-cluster health checks probe endpoints on a timer and remove unhealthy backends from the load balancer rotation |
| [hostname-upstream.yaml](configs/traffic-management/hostname-upstream.yaml) | Demonstrates using DNS hostnames instead of IP addresses for upstream endpoints |
| [hosts.yaml](configs/traffic-management/hosts.yaml) | One listener serves multiple domains |
| [least-connections.yaml](configs/traffic-management/least-connections.yaml) | Routes each request to the backend with the fewest in-flight requests |
| [p2c.yaml](configs/traffic-management/p2c.yaml) | Samples two random endpoints and picks the one with fewer in-flight requests |
| [path-based-routing.yaml](configs/traffic-management/path-based-routing.yaml) | Routes by URL path prefix |
| [rate-limiting.yaml](configs/traffic-management/rate-limiting.yaml) | Token bucket rate limiter with per-IP or global modes |
| [redirect.yaml](configs/traffic-management/redirect.yaml) | Returns a 3xx redirect without contacting any upstream |
| [round-robin.yaml](configs/traffic-management/round-robin.yaml) | Default strategy |
| [session-affinity.yaml](configs/traffic-management/session-affinity.yaml) | Hashes a request header to pin a user's requests to one backend |
| [static-response.yaml](configs/traffic-management/static-response.yaml) | Returns a fixed response without contacting any upstream |
| [timeout.yaml](configs/traffic-management/timeout.yaml) | Returns 504 if the upstream takes longer than timeout_ms to respond |
| [weighted-load-balancing.yaml](configs/traffic-management/weighted-load-balancing.yaml) | Traffic split proportional to per-endpoint weights |

### Transformation

| File | Description |
| ------ | ------------- |
| [header-manipulation.yaml](configs/transformation/header-manipulation.yaml) | Add, overwrite, and remove headers on requests and responses |
| [path-rewriting.yaml](configs/transformation/path-rewriting.yaml) | Rewrite request paths before forwarding to upstream |
| [url-rewriting.yaml](configs/transformation/url-rewriting.yaml) | Regex-based path transformation and query string manipulation |
