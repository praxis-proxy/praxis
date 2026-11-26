# Hyper Backend

The hyper backend is an experimental network backend for Praxis. It runs the
same filter pipeline, admin surface, health checking and sub-request client as
the default Pingora backend, on [hyper] 1.x, [tokio-rustls] and a tokio
runtime that Praxis owns. It lets Praxis carry its own data path (connection
pool, retry replay, response commit point, drain sequence) without depending
on Pingora internals, and measure those pieces against the existing suites
before any default changes.

It is off by default, selected at build time, and not at parity with Pingora
yet; see [What is not at parity](#what-is-not-at-parity).

## Selecting the backend

Backends are Cargo features of `praxis-proxy`, `praxis-proxy-protocol` and
`praxis-proxy-core`: `pingora` (on by default) and `hyper` (off,
experimental). A build with both refuses to compile, so the hyper build starts
from no defaults and names what it wants:

```console
cargo build -p praxis-proxy --release --no-default-features \
    --features hyper,config-reload,admin-api,policy-builtins
```

`make lint`, `make doc` and the test targets therefore name every feature
except `hyper`. `cargo xtask features` derives that list from the manifests,
so a new feature needs no Makefile edit. `make check-features` type-checks the
hyper code, and the `*-hyper` targets build, lint and test it.
`praxis_core::backend::NAME` names the compiled-in backend, and the
`initializing server` log line carries it. `hyper` implies `experimental`, so
a hyper build logs the experimental-features warning at startup.

## Build, test and CI

The Makefile mirrors the FIPS targets, building into `target/hyper` so a hyper
build never overwrites the standard one:

| Target | What it does |
| ------ | ------------ |
| `make build-hyper` | Debug build of the hyper feature set. |
| `make check-hyper` | `cargo check` of the hyper feature set, all targets. |
| `make lint-hyper` | Clippy over the hyper binary and over the core and protocol crates with only the hyper backend, plus the rustfmt check. |
| `make test-hyper` | Unit tests of the server, protocol and core crates resolved as the hyper build. |
| `make test-integration-hyper` | The schema, security, resilience and integration suites on hyper. |
| `make test-conformance-hyper` | The conformance suite (including h2spec) on hyper. |

`BACKEND=hyper` routes the standard test targets to these, so
`make test-integration BACKEND=hyper` runs the same suites on hyper. The
suites build the proxy through the backend contract and run unchanged on
either backend; the few tests that reach into Pingora directly are gated on
`pingora`. The harness crate forwards the backend feature, and tests that
spawn the `praxis` binary get the hyper binary through `PRAXIS_BIN`.

The `Hyper backend` workflow (`.github/workflows/hyper.yaml`) runs the lint,
unit, integration and conformance targets on every pull request and push to
`main`.

## How a request flows

The hyper adapter (`crates/protocol/src/http/hyper.rs` and its children)
drives the pipeline at the same points, in the same order, as the
[Pingora handler](pingora-handler-lifecycle.md). It calls the same
backend-neutral functions (per-request context, body-mode handling, retry
decisions, error-response body, passive health) and has its own code only for
the transport: reading and writing hyper requests and responses, the attempt
loop, the replay buffer, and error classification.

1. **Accept.** Each HTTP listener is a service on the runtime, made of:
   - a socket bound at registration (a bind error fails startup) that listens
     with Pingora's backlog once the runtime starts;
   - a `tokio-rustls` acceptor built from the same `rustls::ServerConfig` the
     Pingora listener uses (SNI resolver, mTLS, hot reload);
   - `hyper-util`'s automatic HTTP/1 and HTTP/2 connection builder, with the
     Pingora handler's HTTP/2 limits (64 KiB header list, 128 concurrent
     streams) and the 256 header lines Pingora's HTTP/1 parser allows.

   Plaintext listeners accept HTTP/2 prior knowledge. The listener's
   keep-alive timeout (one minute when unset) bounds the wait for a request
   head on an idle connection; the read timeout bounds every body frame on
   HTTP/1 and HTTP/2. An authenticated client certificate gives every request
   on the connection, HTTP/2 streams included, one immutable peer identity
   (SHA-256 leaf digest, organization, and hexadecimal serial). Without a
   client certificate there is no identity. If the parser can't decode a
   subject organization, the digest and serial remain and organization
   matching sees no value.
2. **Admission and validation.** Memory, file-descriptor, global and
   per-listener limits, then the request-validation rules (Host, duplicate
   framing headers, obs-fold, reserved headers, `..` paths, `Max-Forwards`).
3. **Request pipeline** in the configured body mode: a `StreamBuffer` filter
   pre-reads the whole body before upstream selection, `SizeLimit` counts and
   rejects, `Stream` forwards chunk by chunk.
4. **Upstream.** The selected `Upstream` becomes a `PeerSpec` and is dialled
   through the same connector type the sub-request client uses. The adapter
   has its own pool for now; sharing one with the sub-request client is a
   follow-up. The connect budget is the cluster's total connection timeout,
   else the larger of its connection timeout and ten seconds. Connect
   failures and retriable statuses go through the shared retry decision with
   the cluster's retry policy and budget, capped at Pingora's default of
   sixteen attempts. Request body and response head proceed concurrently, so
   an upstream that answers before the upload ends isn't stalled.
5. **Response pipeline and commit.** Nothing is written downstream until the
   response pipeline has run on the upstream head, so a rejection there
   becomes the client's response. Body chunks go through the response body
   filters in the same modes, and trailers through the trailer filters.
6. **Completion.** Metrics, passive health, the retry budget release, the
   response-phase cleanup that feeds the circuit breaker, and the access log
   fallback run on every path, including a client that leaves mid-body.

## Connection pool

`praxis_core::egress::hyper::HyperConnector` is a Praxis-owned pool over
`hyper::client::conn` HTTP/1 and HTTP/2 handshakes. Its key is resolved
address, server name, TLS on or off, pool partition, HTTP version and the
identity of the cluster's TLS material, so connections never move between
clusters with different trust settings. The pool:

- is bounded by `runtime.upstream_keepalive_pool_size` (64 idle connections in
  the stock config), evicting the longest-unused first;
- honours the cluster's idle timeout;
- discards HTTP/1 connections the peer closed instead of handing them out;
- shares one HTTP/2 connection per key between streams.

A session reports whether its connection served a request before, for
connection accounting and tracing.

Upstream TLS is a `rustls::ClientConfig` built from the cluster's cached
material: the cluster CA, else the runtime `upstream_ca_file`, else the
system trust store; the client certificate; and the verification toggle. The
provider is the one `praxis-tls` installs at startup. Two behaviors differ
from Pingora's OpenSSL connector; see "Upstream TLS strictness" under
[What is not at parity](#what-is-not-at-parity).

## Replay and retries

A request body forwarded upstream is also kept in a bounded replay buffer
(64 KiB, Pingora's limit) with a flag set when the body outgrew it. A failed
attempt is replayed only when the buffer is intact, no response byte has
reached the client, and the retry policy allows it. That includes failures on
reused connections, since reuse and an EOF don't prove the upstream processed
nothing. Non-idempotent requests need `allow_non_idempotent`, and every retry
consumes the policy budget.

Client trailers with reserved `x-praxis-*`, `x-ext-protocol-*`, or
`x-ext-agent-*` names are rejected before they can be forwarded or kept for
replay, for streamed and pre-read bodies alike. Before response commitment the
client gets 400; after it, the response is aborted. Ordinary trailers,
including other `x-ext-*` names, are preserved for HTTP/2 upstreams and
retries.

## Runtime and shutdown

`praxis_core::server::hyper::HyperRuntime` builds a multi-thread tokio
runtime from `runtime.threads` and `runtime.global_queue_interval` (a logged
no-op on Pingora that takes effect here) and runs the registered services.
Signal handlers are installed before any listener accepts, so a signal during
startup is honoured.

HTTP, TCP and management listeners are required services: an unexpected exit
stops the other services within the fast shutdown bound and fails the
runtime. A failed socket in a TCP listener group stops the whole group.

`SIGTERM` starts a readiness-first graceful shutdown. `/ready` becomes
unavailable at once, listeners keep accepting during the optional
`shutdown_drain_delay_secs` handoff, then stop accepting so in-flight
connections finish through hyper's graceful shutdown, bounded by
`shutdown_timeout_secs`. Existing HTTP/2 connections get GOAWAY when the drain
begins. `SIGHUP` is ignored because configuration reload owns it. `SIGINT`
stops quickly, and so does the harness path (`run_with_shutdown`), as on
Pingora.

## What is not at parity

Known gaps of the experimental backend. Each is a follow-up behind the same
feature. Promotion out of `experimental` requires the security, conformance,
integration and resilience suites to pass on hyper.

- **Request trailers to HTTP/1 upstreams.** The hyper egress doesn't encode
  HTTP/1 chunked trailers, so such requests get 400 when a trailer arrives, or
  the exchange is aborted if the response is already streaming. HTTP/2
  upstreams receive trailers from streaming, pre-read and replayed bodies.
- **Response compression.** Pingora's compression module has no hyper
  equivalent yet; a hyper build does not compress responses.
- **Upgrades.** WebSocket and other `Upgrade` tunnels are not supported: the
  request is forwarded with its upgrade headers stripped, and an upstream
  `101` is answered with a 502.
- **Hedged requests.** The `hedged-requests` feature compiles, but the hyper
  data path does not race hedges.
- **TLS health probes.** The `tls-health-check` feature selects Pingora's TLS
  transport, so it can't be combined with `hyper`. TLS and HTTPS probe tests
  run only in the Pingora suite.
- **Drain sequence.** Shutdown is one phase here; Pingora's grace period
  before the runtime drain is not mirrored.
- **`Expect: 100-continue`.** hyper's server answers `100 Continue` itself as
  soon as the body is read. Pingora sends none of its own: it forwards the
  body and relays an upstream's 100 if one comes. On hyper, interim `1xx`
  responses from an upstream are not relayed to the client (hyper's server
  cannot send them); on HTTP/1 the egress still sees them.
- **Header name case.** hyper writes every response header name in lowercase;
  Pingora keeps the spelling a filter wrote. Clients are unaffected, since
  header names are case-insensitive, but raw-byte comparisons differ.
- **HTTP/1 parsing differences.** hyper's parser serves pipelined requests,
  accepts a chunk size of `u64::MAX` and answers an over-long request target
  with 414. Pingora drops a pipelined second request after the first response
  and refuses the other two with 400. Praxis sits above the parser on both
  backends.
- **Upstream TLS strictness.** A TLS 1.2 upstream without extended master
  secret support (RFC 7627) fails the handshake on hyper and works on
  Pingora. For an IP-literal server name rustls sends no SNI where OpenSSL
  sends the literal, so an upstream that selects its certificate by SNI
  answers with its default certificate.
- **`runtime.work_stealing: false`** has no effect; the runtime always
  work-steals.
- **FIPS.** The hyper build is not verified under the FIPS tooling.
- **Suite parity.** Tests that don't pass on hyper yet are listed in
  `tests/hyper-skip.txt` with their bucket; `make test-integration-hyper` and
  the CI workflow skip exactly that list. Pingora-only features such as TLS
  health probes are omitted, and tests that reach into Pingora directly are
  compiled out under hyper instead of listed.

## Related

- [Adding a Network Backend](../developing/adding-backends.md): the
  contract this backend implements.
- [Build features](../operating/build-features.md): the feature table.
- [Pingora Handler Lifecycle](pingora-handler-lifecycle.md): the lifecycle
  this backend mirrors.

[hyper]: https://github.com/hyperium/hyper
[tokio-rustls]: https://github.com/rustls/tokio-rustls
