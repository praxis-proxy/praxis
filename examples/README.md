# Examples

Configuration examples organized by category.

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
| [timeout.yaml](configs/traffic-management/timeout.yaml) | 504 when upstream exceeds a latency SLA |
| [static-response.yaml](configs/traffic-management/static-response.yaml) | Fixed response without upstream |

### Payload Processing

| File | Description |
| ------ | ------------- |
| [ai-inference-body-based-routing.yaml](configs/payload-processing/ai-inference-body-based-routing.yaml) | Route LLM requests by model field in JSON body |
| [stream-buffer.yaml](configs/payload-processing/stream-buffer.yaml) | Stream-buffered body inspection before forwarding |

### Security

| File | Description |
| ------ | ------------- |
| [forwarded-headers.yaml](configs/security/forwarded-headers.yaml) | X-Forwarded-For/Proto/Host with trusted proxies |
| [ip-acl.yaml](configs/security/ip-acl.yaml) | Allow/deny by source IP/CIDR |

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

### Protocols

| File | Description |
| ------ | ------------- |
| [tcp-proxy.yaml](configs/protocols/tcp-proxy.yaml) | L4 bidirectional TCP forwarding |
| [mixed-protocol.yaml](configs/protocols/mixed-protocol.yaml) | HTTP + TCP listeners on one server |
| [tls-termination.yaml](configs/protocols/tls-termination.yaml) | HTTPS listener; plain HTTP to backends |
| [upstream-tls.yaml](configs/protocols/upstream-tls.yaml) | Plain HTTP listener; TLS to upstream with SNI |

### Pipeline

| File | Description |
| ------ | ------------- |
| [default.yaml](configs/pipeline/default.yaml) | Built-in default config (static JSON on /) |
| [composed-chains.yaml](configs/pipeline/composed-chains.yaml) | Multiple named chains composed per listener |
| [conditional-filters.yaml](configs/pipeline/conditional-filters.yaml) | when/unless conditions on request and response phase |

### Operations

| File | Description |
| ------ | ------------- |
| [production-gateway.yaml](configs/operations/production-gateway.yaml) | Full production setup with composed chains |
| [multi-listener.yaml](configs/operations/multi-listener.yaml) | Multiple listeners sharing a filter chain |

### Running an Example

```console
cargo run -p praxis -- -c examples/configs/traffic-management/basic-reverse-proxy.yaml
curl http://localhost:8080/
```

Configs use local ports (`3000`, `3001`, ...) for upstreams.
For quick experiments without a real backend, use
`static_response` (see
[static-response.yaml](configs/traffic-management/static-response.yaml))
or run Praxis with no config file for a built-in welcome
page.
