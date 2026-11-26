# TCP Proxy

The TCP proxy forwards opaque byte streams between clients and upstreams at
L4. The upstream comes from one of two places:

- **Static upstream**: the listener sets a fixed `upstream` address (e.g.
  `10.0.0.1:5432`).
- **Filter-routed**: no upstream is configured, and TCP filters (e.g.
  `sni_router`, `tcp_load_balancer`) set it during `on_connect`.

TCP listeners with the same `(upstream, cluster, timeout, max_duration)` tuple
share one Pingora `Service`. Listeners in a group must use identical
`filter_chains` and `max_connections`; a mismatch fails startup.

## Connection Lifecycle

```text
accept -> admission -> TLS (if configured) -> SNI peek -> filters -> connect -> forward -> disconnect
```

1. **Accept**: Hyper admits the connection before spawning its connection
   task. Pingora admits in its pre-TLS callback, after its accept task and L4
   buffers exist.
2. **Admission gates**: the shared token is acquired before a TLS handshake,
   or at plain TCP entry:
   - Memory pressure: over the process memory threshold, the connection is
     dropped.
   - Connection limits: the global semaphore (`runtime.max_connections`) and
     the TCP-group semaphore (`max_connections`) must both have a permit.
   - File descriptor pressure: a forecast claim is held until an upstream
     connection opens or the session ends.
3. **SNI peek** (filter-routed mode only): reads the TLS `ClientHello` to
   extract the SNI. See [SNI Peek-and-Forward](#sni-peek-and-forward).
4. **Connect filters**: `on_connect` runs in declared order. Filters may set
   `ctx.upstream_addr` or reject the connection.
5. **SSRF check**: DNS resolution runs and every resolved IP is checked. See
   [SSRF Protection](#ssrf-protection).
6. **Peeked byte replay**: bytes consumed by the SNI peek are written to the
   upstream first.
7. **Bidirectional forwarding**: `copy_bidirectional` streams bytes both ways,
   bounded by the [timeouts](#timeout-layering).
8. **Disconnect filters**: `on_disconnect` runs in reverse order with final
   byte counts.

Connections are not pooled. Each session gets its own upstream socket, closed
when the session ends.

## SNI Peek-and-Forward

Without a static upstream, the proxy reads the client's first bytes before
filters run and takes the SNI hostname from them when they are a TLS
`ClientHello`. Non-TLS bytes yield no SNI. Either way, the bytes read must
still reach the upstream intact.

### Peek Strategy

The proxy reads (not peeks) from the downstream `Stream` into a growing
buffer:

```text
1024 B initial -> double on NeedMore -> cap at 16 KiB
```

After each read the buffer goes through the SNI parser in `praxis-tls`:

| Result     | Action                              |
|------------|-------------------------------------|
| `Parsed`   | Truncate buffer, return SNI + bytes |
| `NeedMore` | Grow buffer, read again             |
| `NotTls`   | Truncate buffer, return None + bytes|

The parser walks the TLS record header, the handshake header and the
`ClientHello` fixed fields, skips the variable-length fields (session ID,
cipher suites, compression), and looks for extension type `0x0000` (SNI). It
validates the hostname per RFC 6066, rejecting IP literals, empty hostnames,
and non-DNS characters.

### Replay

The peeked bytes are written to the upstream with `write_all` before
`copy_bidirectional` starts, so the upstream sees a complete `ClientHello`.
Static-upstream mode skips the peek and the `ClientHello` flows through
`copy_bidirectional` untouched.

## Timeout Layering

```text
|-- TLS --|-- SNI peek --|-- filters --|-- connect --|-- forward --|
|--------------------- max duration -----------------------------|
                                           |-- session timeout --|
```

| Timeout | Value | Covers |
| ------- | ----- | ------ |
| SNI peek | 5 seconds, fixed | The `ClientHello` read, filter-routed mode only. On expiry the connection closes without running filters. It stops a slow-drip client from holding a connection and semaphore permit. |
| Session (`tcp_session_timeout_ms`) | per listener | The `copy_bidirectional` phase. Active connections end at the deadline even with data in flight. |
| Max duration (`tcp_max_duration_secs`) | per listener | Everything from admission: shared setup, forwarding, and Hyper's TLS handshake. |
| Upstream connect | 10 seconds, fixed | DNS resolution and TCP connect, wrapped in `tokio::time::timeout`. |

Pingora's pre-TLS callback starts the max-duration budget before its
handshake, but Pingora fixes that handshake's own timeout at 60 seconds. A
stalled Pingora handshake can overrun the configured maximum until Pingora
returns, and the proxy then rejects the expired token.

### Graceful Shutdown

Every forwarding variant watches a `ShutdownWatch` receiver in a
`tokio::select!` with biased polling, so a shutdown signal wins over data
transfer and ends the session cleanly.

## TLS Setup

TCP listeners can terminate TLS. They share TLS configuration with HTTP
listeners through `build_tls_settings` (context label `"TCP"`). Certificates
hot-reload; the watcher tasks return shutdown senders that the caller must
keep alive.

```text
listener.tls: Some(_) -> service.add_tls_with_settings()
listener.tls: None    -> service.add_tcp()
```

TLS termination decrypts traffic at the proxy. SNI peeking reads the
`ClientHello` of an encrypted stream that is forwarded as-is, without
termination.

## SSRF Protection

Before connecting to any upstream, the proxy resolves DNS and refuses the
connection if any returned IP is in a private or reserved range:

- IPv4 loopback (`127.0.0.0/8`)
- RFC 1918 (`10/8`, `172.16/12`, `192.168/16`)
- Link-local (`169.254.0.0/16`)
- Current network (`0.0.0.0/8`)
- CGNAT (`100.64.0.0/10`, RFC 6598)
- IPv6 loopback (`::1`)
- IPv6 unspecified (`::`)
- IPv6 link-local (`fe80::/10`)
- IPv6 unique local (`fc00::/7`)

IPv4-mapped IPv6 addresses (`::ffff:A.B.C.D`) are normalized first, so
mixed-family resolution can't bypass the check. The check runs at connection
time, which defeats DNS rebinding (a name that resolves publicly at config
time and privately later). `insecure_options.allow_private_upstreams` turns it
off.

## TCP Filter Pipeline

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

- `on_connect` runs in forward order when the connection is accepted, before
  the upstream connect. `FilterAction::Reject` stops the pipeline and closes
  the connection.
- `on_disconnect` runs in reverse order after the session ends, with final
  byte counts.
- `failure_mode` (open/closed) decides whether filter errors are fatal.
- Conditions, branch chains, and body processing are HTTP-only. HTTP filters
  in a mixed pipeline are skipped during TCP execution.

The pipeline sits behind `ArcSwap`, so hot-reload swaps it without disturbing
in-flight connections.

### TcpFilterContext

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

## Built-in TCP Filters

- [`sni_router`](../filters/tcp/traffic_management/sni_router.md): routes by
  SNI hostname. With no match and no `default_upstream`, it rejects with 421.
- [`tcp_load_balancer`](../filters/tcp/traffic_management/tcp_load_balancer.md):
  picks an endpoint from `ctx.cluster` and writes `ctx.upstream_addr`.
- [`tcp_access_log`](../filters/tcp/observability/tcp_access_log.md): logs
  connect and disconnect events via `tracing::info` with remote address,
  upstream, SNI, duration, and byte counts.

## Related

- [Architecture Overview](overview.md)
- [Connection Lifecycle](connection-lifecycle.md)
- [Filter System](../filters/README.md)
- [Security Hardening](../operating/security-hardening.md)
