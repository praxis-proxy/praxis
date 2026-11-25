# Health Checking

Praxis finds unhealthy upstream endpoints with active probes and with passive
observation of real traffic. Unhealthy endpoints leave load balancer rotation
and return when they recover. When every endpoint in a cluster is unhealthy,
the load balancer routes to all of them; see
[Panic Mode](load-balancing.md#panic-mode).

## Active Health Checks

Active checks are configured per cluster in the top-level `clusters` section.
A background task per cluster probes all of its endpoints in parallel on each
interval. Only clusters with a `health_check` block are monitored; clusters
without one are always healthy. [health-checks.yaml] is a complete config
with HTTP and TCP probes.

```yaml
clusters:
  - name: backend
    endpoints:
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"
    health_check:
      type: http
      path: "/healthz"
      expected_status: 200
      interval_ms: 5000
      timeout_ms: 2000
      healthy_threshold: 2
      unhealthy_threshold: 3
      passive_unhealthy_threshold: 5
      passive_healthy_threshold: 3

  - name: database
    endpoints:
      - "10.0.0.1:5432"
      - "10.0.0.2:5432"
    health_check:
      type: tcp
      interval_ms: 10000
      timeout_ms: 3000
      healthy_threshold: 1
      unhealthy_threshold: 2
```

| Field | Default | Description |
| ----- | ------- | ----------- |
| `type` | (required) | `http`, `tcp`, `grpc`, or feature-gated `tls` |
| `path` | `/` | HTTP path to probe |
| `expected_status` | `200` | Status code that indicates healthy |
| `interval_ms` | `5000` | Milliseconds between probe rounds |
| `timeout_ms` | `2000` | Per-probe timeout in milliseconds |
| `healthy_threshold` | `2` | Consecutive successes to mark healthy |
| `unhealthy_threshold` | `3` | Consecutive failures to mark unhealthy |
| `passive_unhealthy_threshold` | (disabled) | See [Passive Health Checks](#passive-health-checks) |
| `passive_healthy_threshold` | (disabled) | See [Passive Health Checks](#passive-health-checks) |

[health-checks.yaml]: ../../examples/configs/traffic-management/health-checks.yaml

### HTTP Probes

An HTTP probe sends a raw `HTTP/1.1 GET` to `path` with a
`Host: health-check` header and `Connection: close`. Any status other than
`expected_status` is a failure.

Without `tls-health-check`, HTTP probes connect in plaintext. A TLS cluster
with an HTTP probe logs a startup warning; use a TCP probe or enable the
feature described below. Plain HTTP keeps `Host: health-check` in either
build.

### TLS and HTTPS Probes

Build with `--features tls-health-check` to enable experimental TLS probes.
The transport uses the Pingora backend, so this feature also selects
`pingora` in the protocol crate.

```yaml
clusters:
  - name: secure
    endpoints: ["backend.example.com:443"]
    tls:
      sni: backend.example.com
      ca:
        ca_path: /etc/praxis/upstream-ca.pem
      # client_cert:
      #   cert_path: /etc/praxis/client.pem
      #   key_path: /etc/praxis/client-key.pem
    health_check:
      type: tls
```

There are two modes:

- `type: tls` requires cluster `tls` settings and only completes a TLS
  handshake. It ignores `path` and `expected_status`, and honors
  `http.version` during ALPN negotiation, so it can check an h2-only TLS
  endpoint.
- `type: http` on a TLS cluster checks an HTTPS application endpoint, with
  `path` (default `/`) and `expected_status` (default `200`). HTTPS probes
  use HTTP/1.1 even when `http.version` selects HTTP/2 for proxied traffic.

Probes use the cluster's CA, client certificate, and `verify`
settings. Disabling verification still requires the existing insecure opt-in.
Without a cluster CA, `runtime.upstream_ca_file` replaces system trust when
configured; otherwise system trust applies. Runtime trust is captured at
startup and needs a restart to change, even when probe tasks reload. Cluster
TLS material reloads with the config. If certificate loading fails, probes
fail; they never fall back to another trust source or to plaintext.

The verification name comes from explicit `tls.sni`, then a fixed
DNS `http.authority`, then the endpoint hostname or IP address. An IP
authority keeps endpoint certificate verification when no explicit SNI is
set. A background probe has no downstream Host to inherit. Existing SNI
validation and opt-in rules still apply. The HTTPS Host header uses the
configured `http.authority`, including IP literals and `{ from: endpoint }`;
otherwise it uses explicit SNI or the endpoint. IPv6 Hosts use brackets;
endpoint-derived Hosts omit port 443 and keep other ports.

Each probe opens a new connection with session resumption
disabled, so a resumed session cannot hide a changed server certificate. One
timeout covers DNS, connection, handshake, HTTP exchange, and close.
Successful probes send `close_notify`. HTTPS probes read only a bounded HTTP
status line, not the whole body, and do not wait for a reciprocal close
alert.

After `close_notify`, a handshake-only probe waits for a fatal TLS alert that
rejects the client credentials. The grace period is the greater of 100 ms and
the time spent resolving, connecting, and handshaking, capped by the remaining
probe timeout. The probe succeeds on silence at that deadline (if the
handshake completed), a normal `close_notify` (returned as EOF), application
data, or EOF without `close_notify` (`UnexpectedEof`). A handshake that times
out still fails, as do other read errors and fatal TLS alerts.

TLS closure and error alerts are defined in [RFC 8446 Section 6] (TLS 1.3)
and [RFC 5246 Section 7.2] (TLS 1.2). The grace period and accepting
transport EOF are Praxis policy. HTTP/1.1 status-line syntax is in
[RFC 9112 Section 4]; the bounded read follows the resource-limit guidance in
[RFC 9110 Section 17.5]. The [TLS conformance tests] cover protocol versions
and client authentication; [HTTP correctness] covers the proxy's protocol
responsibilities.

A verified handshake proves server identity. Client credentials are sent only
when the server requests client authentication ([RFC 8446 Section 4.4.2],
[RFC 5246 Section 7.4.6]). In TLS 1.3 a completed client handshake does not
prove the server accepted those credentials, and a rejection that arrives
after the grace period can be missed. Use an HTTPS response check to verify
client authorization and application health. Upstream revocation checking is
not supported, so these probes make no revocation guarantee.

The [TLS health-check example][tls-health-check] shows both modes. TCP probes
stay connect-only, and gRPC probes stay plaintext.

[tls-health-check]: ../../examples/configs/observability/tls-health-check.yaml
[RFC 8446 Section 6]: https://datatracker.ietf.org/doc/html/rfc8446#section-6
[RFC 5246 Section 7.2]:
  https://datatracker.ietf.org/doc/html/rfc5246#section-7.2
[RFC 9112 Section 4]: https://datatracker.ietf.org/doc/html/rfc9112#section-4
[RFC 9110 Section 17.5]:
  https://datatracker.ietf.org/doc/html/rfc9110#section-17.5
[RFC 8446 Section 4.4.2]:
  https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
[RFC 5246 Section 7.4.6]:
  https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.6
[TLS conformance tests]: ../../tests/conformance/tests/suite/tls.rs
[HTTP correctness]: ../architecture/http-correctness.md

### TCP Probes

A TCP probe counts an endpoint healthy when a TCP handshake completes within
the timeout, then closes the connection. It ignores `path` and
`expected_status`. Use it for non-HTTP services (databases, caches, message
brokers) where a connection implies availability.

### gRPC Probes

A gRPC probe calls `grpc.health.v1.Health/Check`. Use it for gRPC upstreams:
a gRPC server does not serve `/healthz`, and one that has stopped serving
still completes an HTTP/2 handshake, so HTTP and TCP probes report it healthy.

```yaml
clusters:
  - name: grpc-backend
    endpoints:
      - "10.0.0.1:50051"
    http:
      version: h2
    health_check:
      type: grpc
      grpc_service: "" # empty: the server's overall status
      interval_ms: 2000
      timeout_ms: 1000
      healthy_threshold: 1
      unhealthy_threshold: 2
```

`grpc_service` names one registered service. Empty (the default) asks for the
server's overall status, as the health protocol defines.

An endpoint is healthy only with HTTP 200, `grpc-status: 0`, and a decoded
`SERVING`. A server that answers `NOT_SERVING`, or does not implement the
health service, is unhealthy. gRPC probes ignore `path` and
`expected_status`. They speak plaintext h2c on their own connection, so
config load rejects them on a cluster with TLS.

## Passive Health Checks

Passive checks watch real requests instead of sending probes. A request fails
when the upstream connection fails (connect error, timeout, reset) or the
response status is >= 500. Every other completed response is a success.

- `passive_unhealthy_threshold`: consecutive failures that mark an endpoint
  unhealthy.
- `passive_healthy_threshold`: consecutive successes that recover an
  unhealthy endpoint.

Set only `passive_unhealthy_threshold` to let real traffic mark endpoints
down quickly while only active probes recover them. Omit both to disable
passive checking; active probes run either way.

## Health State Transitions

Endpoints start healthy:

```text
                  unhealthy_threshold
                  consecutive failures
    [Healthy] --------------------------> [Unhealthy]
        ^                                      |
        |    healthy_threshold                 |
        |    consecutive successes             |
        +--------------------------------------+
```

A success resets the failure counter and a failure resets the success
counter, so an endpoint that alternates never transitions. Active and passive
checks share the same counters and state.

## Admin Health Endpoints

The health and metrics listener (`admin.metrics_address`) serves two
endpoints for orchestrators, load balancers, and monitoring.

### /healthy (Liveness)

Returns `200 OK` with `{"status":"ok"}` once the server accepts connections.
It does not check upstreams.

```console
curl http://127.0.0.1:9902/healthy
```

### /ready (Readiness)

```console
curl http://127.0.0.1:9902/ready
```

Without health checks, it returns `{"status":"ok"}`. With active health
checks, it adds per-cluster counts. A cluster is degraded when all of its
endpoints are unhealthy; one healthy endpoint keeps it healthy.

The default `readiness: serving` returns `200` once the replica is serving,
even when a cluster has zero healthy endpoints. The body still reports the
degraded cluster:

```json
{
  "status": "ok",
  "clusters": {
    "total": 2,
    "healthy": 1,
    "degraded": 1
  }
}
```

Set `admin.readiness: upstreams` to return `503` in that state, with
`"status": "degraded"` and the same `clusters` object:

```yaml
admin:
  metrics_address: "127.0.0.1:9902"
  readiness: upstreams
```

In both modes, `/ready` returns `503` while the replica is initializing,
draining, or stopped, with `{"status":"initializing"}`,
`{"status":"draining"}`, or `{"status":"stopped"}`. Draining starts on
`SIGTERM`; see [Graceful Shutdown](configuration.md#graceful-shutdown) for
`shutdown_drain_delay_secs`.

When an embedding distribution registers runtime services, HTTP and TCP proxy
listeners wait for all required services before accepting traffic. The metrics
listener can answer `/ready` during initialization. A service that abandons
readiness before startup causes the server to shut down with an error naming the
service. If a service exits after startup, `/ready` returns `503` with
`{"status":"unavailable","runtime_services":"not_ready"}`. Already-running
listeners continue to serve.

### Verbose Mode

`/ready` omits cluster names by default so it does not leak internal
topology. `admin.verbose: true` adds per-cluster detail:

```yaml
admin:
  metrics_address: "127.0.0.1:9902"
  verbose: true
```

```json
{
  "status": "ok",
  "clusters": {
    "total": 2,
    "healthy": 2,
    "degraded": 0,
    "detail": {
      "backend": {
        "healthy": 3,
        "unhealthy": 0,
        "total": 3
      },
      "database": {
        "healthy": 2,
        "unhealthy": 0,
        "total": 2
      }
    }
  }
}
```

Verbose mode exposes cluster names and endpoint counts, so keep it off in
production unless the health/metrics listener is network-isolated.

## Configuration Validation

Startup rejects a health check config unless:

- `interval_ms` and `timeout_ms` are greater than zero, and `timeout_ms` is
  less than `interval_ms`
- `healthy_threshold` and `unhealthy_threshold` are >= 1, and so are
  `passive_unhealthy_threshold` and `passive_healthy_threshold` when set
- `expected_status` is in the range 100-599
- `path` starts with `/` and has no query string, fragment, CR/LF, or encoded
  control characters
- `grpc_service` is at most 255 bytes of printable ASCII without spaces
- `type: grpc` is not combined with cluster TLS

### SSRF Prevention

Health check endpoints may not be loopback (`127.0.0.0/8`, `::1`),
link-local (`169.254.0.0/16`, `fe80::/10`), or cloud metadata addresses
(`169.254.169.254`). For local development only, set
`insecure_options.allow_private_health_checks: true` to probe loopback and
private addresses. Probed endpoints also carry data-plane traffic and must
pass the endpoint check, so set `allow_private_endpoints: true` too:

```yaml
insecure_options:
  allow_private_endpoints: true
  allow_private_health_checks: true
```

Never use these in production.

## Threshold Tuning

- `unhealthy_threshold` of 1-2 removes failing endpoints fast but reacts to
  transient errors; 3-5 tolerates them but removes a dead endpoint later.
- `healthy_threshold` of at least 2 confirms an endpoint responds
  consistently before it rejoins rotation.
- Passive checks see every request, so set `passive_unhealthy_threshold`
  above `unhealthy_threshold` and allow for your normal error rate.
- Shorter intervals detect failures sooner but send more probe traffic, which
  adds up on large clusters.

## Dynamic Reload

Changing health check settings rebuilds the health registry and probe tasks
without a restart; in-flight requests finish on the previous config. See
[Dynamic Configuration Reload](configuration.md#dynamic-configuration-reload)
for which endpoint health state survives.

## Monitoring

Active probe transitions log at `info`, passive failures at `warn`:

```text
INFO endpoint transitioned to healthy
  cluster=api endpoint=10.0.0.1:8080

INFO endpoint transitioned to unhealthy
  cluster=api endpoint=10.0.0.2:8080

WARN passive health: endpoint marked unhealthy
  cluster=api endpoint_index=1 threshold=5
```

Individual probe results log at `trace`. To see them without raising other
modules' log level:

```yaml
runtime:
  log_overrides:
    praxis_protocol::http::pingora::health: trace
```
