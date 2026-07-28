# TCP Proxy

Design of the raw TCP/L4 bidirectional forwarding
protocol adapter.

## Overview

The TCP proxy forwards opaque byte streams between
clients and upstreams without interpreting application
protocols. It operates at L4 and supports two upstream
resolution modes:

- **Static upstream**: the listener config provides a
  fixed `upstream` address (e.g. `10.0.0.1:5432`).
- **Filter-routed**: no upstream is configured; TCP
  filters (e.g. `sni_router`, `tcp_load_balancer`)
  set the upstream during `on_connect`.

TCP listeners sharing the same
`(upstream, cluster, timeout, max_duration)` tuple
are grouped into a single Pingora `Service`. The
grouping logic validates that listeners in the same
group use identical `filter_chains` and
`max_connections`, rejecting mismatches at startup.

## Connection Lifecycle

```text
accept -> admission -> SNI peek -> filters -> connect -> forward -> disconnect
```

1. **Accept**: Pingora accepts the TCP connection.
   The proxy extracts remote and local socket
   addresses from the session digest.

2. **Admission gates**: two checks run before any
   work begins:
   - Memory pressure: if the process exceeds its
     memory threshold, the connection is dropped.
   - Connection limits: a global semaphore
     (`runtime.max_connections`) and a per-listener
     semaphore (`max_connections`) must both have
     available permits.

3. **SNI peek** (filter-routed mode only): reads the
   initial bytes to extract the TLS `ClientHello`
   SNI. See [SNI Peek-and-Forward](#sni-peek-and-forward).

4. **Connect filters**: the filter pipeline runs
   `on_connect` in declared order. Filters may set
   `ctx.upstream_addr` or reject the connection.

5. **SSRF check**: before connecting to the resolved
   upstream, DNS resolution runs and every resolved
   IP is checked against private/reserved ranges.
   See [SSRF Protection](#ssrf-protection).

6. **Peeked byte replay**: if SNI peeking consumed
   bytes, they are written to the upstream before
   bidirectional forwarding begins.

7. **Bidirectional forwarding**: `copy_bidirectional`
   streams bytes in both directions, governed by
   timeout layering.

8. **Disconnect filters**: `on_disconnect` runs in
   reverse order with final byte counts.

Connections are not pooled. Each TCP session uses a
dedicated upstream socket that is closed when the
session ends.

## SNI Peek-and-Forward

When no static upstream is configured, the proxy
must inspect the initial TLS `ClientHello` to
extract the SNI hostname before filters run. The
challenge: the peeked bytes are part of the TLS
handshake and must reach the upstream intact.

### Peek Strategy

The proxy reads (not peeks) from the downstream
`Stream` into a growing buffer:

```text
1024 B initial -> double on NeedMore -> cap at 16 KiB
```

Each read attempt is parsed through the SNI parser
in `praxis-tls`. Three outcomes:

| Result     | Action                              |
|------------|-------------------------------------|
| `Parsed`   | Truncate buffer, return SNI + bytes |
| `NeedMore` | Grow buffer, read again             |
| `NotTls`   | Truncate buffer, return None + bytes|

The parser is zero-copy: it walks the TLS record
header, handshake header, `ClientHello` fixed
fields, skips variable-length fields (session ID,
cipher suites, compression), and iterates extensions
looking for type `0x0000` (SNI). It validates the
hostname per RFC 6066 (rejects IP literals, empty
hostnames, non-DNS characters).

### Replay

The peeked bytes are written to the upstream socket
with `write_all` before `copy_bidirectional` starts.
From the upstream's perspective, the connection
begins with a complete `ClientHello` - the peek is
invisible.

Static-upstream mode skips SNI peeking entirely.
The `ClientHello` flows through `copy_bidirectional`
without interception.

## Timeout Layering

Three independent timeouts protect different phases:

```text
|-- SNI peek --|-------- session timeout ---------|
               |---- max duration (hard cap) -----|
```

### SNI Peek Timeout (5 seconds)

Bounds the time a client can hold a connection
during the initial `ClientHello` read. Without this,
a slow-drip client could hold a connection and
semaphore permit indefinitely. Only applies in
filter-routed mode. If exceeded, the connection is
closed without running filters.

### Session Timeout (`tcp_session_timeout_ms`)

A hard deadline on the `copy_bidirectional` phase.
Active connections are terminated after this
duration regardless of whether data is in flight.
Configured per-listener. The forwarding loop uses
`tokio::select!` with biased polling so that a
graceful shutdown signal takes priority over data
transfer.

### Max Duration (`tcp_max_duration_secs`)

A hard cap on total session lifetime regardless of
activity. Wraps the entire forwarding phase in
`tokio::time::timeout`. Useful for preventing
indefinite connections to services like databases
or message brokers.

### Upstream Connect Timeout (10 seconds)

A fixed timeout on DNS resolution and TCP connect
to the upstream. Not configurable. Applied via
`tokio::time::timeout` around the resolve-and-connect
sequence.

### Graceful Shutdown

All forwarding variants monitor a `ShutdownWatch`
receiver. When the server initiates shutdown, the
`tokio::select!` biased branch fires first, ending
the session cleanly.

## TLS Setup

TCP listeners support optional TLS termination.
The TLS configuration is shared with HTTP listeners
through `build_tls_settings` (context label `"TCP"`).
Certificate hot-reload is supported: watcher tasks
return shutdown senders that the caller must keep
alive.

Listeners are registered as either plain TCP or TLS:

```text
listener.tls: Some(_) -> service.add_tls_with_settings()
listener.tls: None    -> service.add_tcp()
```

TLS termination and SNI peeking serve different
purposes. TLS termination decrypts traffic at the
proxy. SNI peeking reads the `ClientHello` from an
encrypted stream that will be forwarded as-is to the
upstream (the proxy does not terminate TLS in this
case).

## SSRF Protection

Before connecting to any upstream, the proxy resolves
DNS and checks every returned IP against
private/reserved ranges:

- IPv4 loopback (`127.0.0.0/8`)
- RFC 1918 (`10/8`, `172.16/12`, `192.168/16`)
- Link-local (`169.254.0.0/16`)
- Current network (`0.0.0.0/8`)
- CGNAT (`100.64.0.0/10`, RFC 6598)
- IPv6 loopback (`::1`)
- IPv6 link-local (`fe80::/10`)
- IPv6 unique local (`fc00::/7`)

IPv4-mapped IPv6 addresses (`::ffff:A.B.C.D`) are
normalized before checking, preventing bypass via
mixed-family resolution.

This protects against DNS rebinding attacks where a
hostname resolves to a public IP at config time but a
private IP at connection time. The check runs at
connection time, not config time.

The check is skipped when
`insecure_options.allow_private_upstreams` is set.

## TCP Filter Pipeline

TCP filters implement a two-phase model:

```rust
#[async_trait]
trait TcpFilter: Send + Sync {
    fn name(&self) -> &'static str;
    async fn on_connect(&self, ctx: &mut TcpFilterContext<'_>)
        -> Result<FilterAction, FilterError>;
    async fn on_disconnect(&self, ctx: &mut TcpFilterContext<'_>)
        -> Result<(), FilterError>;
}
```

Compared to HTTP's multi-phase model (request,
request body, response, response body), TCP filters
are simpler:

- `on_connect` runs in forward order at connection
  acceptance, before upstream connect.
- `on_disconnect` runs in reverse order after the
  session ends, with final byte counts.
- No conditions, branch chains, or body processing.
  Those features are HTTP-only.
- HTTP filters in a mixed pipeline are skipped
  during TCP execution.

`FilterAction::Reject` in `on_connect` stops the
pipeline and closes the connection. The
`failure_mode` setting (open/closed) controls
whether filter errors are fatal.

### TcpFilterContext

The context carries per-connection state:

| Field              | Purpose                          |
|--------------------|----------------------------------|
| `remote_addr`      | Client socket address            |
| `local_addr`       | Listener socket address          |
| `sni`              | Extracted SNI hostname           |
| `upstream_addr`    | Target upstream (writable)       |
| `cluster`          | Cluster name for load balancing  |
| `health_registry`  | Endpoint health state            |
| `kv_stores`        | Named key-value stores           |
| `connect_time`     | Connection acceptance timestamp  |
| `bytes_in`         | Client bytes (post-forward)      |
| `bytes_out`        | Upstream bytes (post-forward)    |

The pipeline is held behind `ArcSwap` for atomic
hot-reload without disrupting in-flight connections.

## Built-in TCP Filters

### sni_router

Routes TLS connections by SNI hostname. Performs
exact-match lookup first, then longest-suffix
wildcard match (e.g. `*.example.com`). Matching is
case-insensitive per RFC 4343. Falls back to
`default_upstream` or rejects with 421.

### tcp_load_balancer

Selects an upstream endpoint from a named cluster
using the configured strategy (round-robin,
least-connections, consistent-hash, random,
weighted). Reads `ctx.cluster` (set by listener
config), writes `ctx.upstream_addr`. Releases
least-connections counters on disconnect. Enters
panic mode (routes to all) when every endpoint is
unhealthy.

### tcp_access_log

Logs connection and disconnection events via
`tracing::info` with remote address, upstream, SNI,
duration, and byte counts.

## Related

- [Architecture Overview](overview.md)
- [Connection Lifecycle](connection-lifecycle.md)
- [Filter System](../filters/README.md)
- [Security Hardening](../operating/security-hardening.md)
