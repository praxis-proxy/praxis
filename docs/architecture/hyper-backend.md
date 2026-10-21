# Hyper Backend

The hyper backend is an experimental network backend for Praxis: the same
filter pipeline, admin surface, health checking and sub-request client as
the default Pingora backend, running on [hyper] 1.x, [tokio-rustls] and a
tokio runtime that Praxis owns. It exists so Praxis can carry its own data
path (connection pool, retry replay, response commit point, drain
sequence) without depending on Pingora internals, and so those pieces can
be developed and measured against the existing suites before any default
changes.

It is off by default, selected at build time, and not at parity with
Pingora yet; see [What is not at parity](#what-is-not-at-parity).

## Selecting the backend

Backends are Cargo features of `praxis-proxy`, `praxis-proxy-protocol` and
`praxis-proxy-core`: `pingora` (on by default) and `hyper` (off,
experimental). They are mutually exclusive: a build with both refuses to
compile. Features are additive, so the hyper build starts from no defaults
and names what it wants:

```console
cargo build -p praxis-proxy --release --no-default-features \
    --features hyper,config-reload,admin-api,policy-engine
```

Because the two cannot be combined, `make lint`, `make doc` and the test
targets name every feature except `hyper`; `cargo xtask features` derives
that list from the manifests, so a new feature is picked up without editing
the Makefile. The hyper code is type-checked by `make check-features` and
built, linted and tested by the `*-hyper` targets. `praxis_core::backend::NAME`
names the backend compiled in, and the `initializing server` log line
carries it.

The `hyper` feature implies `experimental`, so a hyper build logs the
experimental-features warning at startup like any other experimental build.

## Build, test and CI

The Makefile mirrors the FIPS targets, into `target/hyper` so a hyper build
never overwrites the standard one:

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
suites build the proxy under test through the backend contract, so they run
unchanged on either backend; the few tests that reach into Pingora directly
are gated on `pingora`. The harness crate forwards the backend feature, and
tests that spawn the `praxis` binary get the hyper binary through
`PRAXIS_BIN`.

The `Hyper backend` workflow (`.github/workflows/hyper.yaml`) runs the lint,
unit, integration and conformance targets on every pull request and push
to `main`.

## How a request flows

The hyper adapter (`crates/protocol/src/http/hyper.rs` and its children)
drives the pipeline at the same points, in the same order, as the Pingora
handler described in [Pingora Handler Lifecycle](pingora-handler-lifecycle.md).
Where the Pingora handler's logic is backend-neutral (the per-request
context, body-mode handling, retry decisions, the error-response body,
passive health) the hyper adapter calls the same functions; only the
transport-facing parts (reading and writing hyper requests and responses,
the attempt loop, the replay buffer, error classification) are its own.

1. **Accept.** Each HTTP listener is a service on the runtime: a socket
   bound at registration (so a bind error fails startup) and listening with
   Pingora's backlog once the runtime starts, a `tokio-rustls` acceptor
   built from the same `rustls::ServerConfig` the Pingora listener uses
   (SNI resolver, mTLS, hot reload), and `hyper-util`'s automatic HTTP/1
   and HTTP/2 connection builder with the HTTP/2 limits the Pingora handler
   sets (64 KiB header list, 128 concurrent streams) and the 256 header
   lines Pingora's HTTP/1 parser allows. Plaintext listeners accept HTTP/2
   prior knowledge. The listener's keep-alive timeout (one minute when
   unset) bounds the wait for a request head on an idle connection; the
   read timeout bounds every body frame on HTTP/1 and HTTP/2 alike.
2. **Admission and validation.** Memory, file-descriptor, global and
   per-listener limits, then the request-validation rules (Host, duplicate
   framing headers, obs-fold, reserved headers, `..` paths,
   `Max-Forwards`).
3. **Request pipeline** with the configured body mode: a `StreamBuffer`
   filter pre-reads the whole body before upstream selection; `SizeLimit`
   counts and rejects; `Stream` forwards chunk by chunk.
4. **Upstream.** The selected `Upstream` becomes a `PeerSpec` and is dialled
   through a connector of the same type the sub-request client uses; the
   adapter owns its own pool for now, and sharing one between the two is a
   follow-up. The connect budget is the cluster's total connection timeout,
   else the larger of its connection timeout and ten seconds. Connect
   failures and retriable statuses go through the shared retry decision
   with the cluster's retry policy and budget, capped at Pingora's default
   of sixteen attempts. Request body and response head proceed
   concurrently, so an upstream that answers before the upload ends is not
   stalled.
5. **Response pipeline and commit.** Nothing is written downstream before
   the response pipeline has run on the upstream head; a rejection at that
   point becomes the client's response instead. Body chunks run through the
   response body filters with the same modes, and trailers through the
   trailer filters.
6. **Completion.** Metrics, passive health, the retry budget release, the
   response-phase cleanup that feeds the circuit breaker, and the access
   log fallback run on every path, including a client that goes away
   mid-body.

## Connection pool

`praxis_core::egress::hyper::HyperConnector` is a Praxis-owned pool over
`hyper::client::conn` HTTP/1 and HTTP/2 handshakes. It is keyed by resolved
address, server name, TLS on or off, pool partition, HTTP version and the
identity of the cluster's TLS material, so connections never move between
clusters with different trust settings. The pool is bounded by
`runtime.upstream_keepalive_pool_size` (64 idle connections in the stock
config, the one unused longest evicted first), honours the cluster's idle
timeout, discards HTTP/1 connections the peer closed instead of handing them
out, and shares one HTTP/2 connection per key between streams. A session
reports whether its connection served a request before, which the
`ReusedOnly` retry rule needs.

Upstream TLS is a `rustls::ClientConfig` built from the cluster's cached
material: the cluster CA, else the runtime `upstream_ca_file`, else the
system trust store; the client certificate; and the verification toggle.
The provider is the one `praxis-tls` installs at startup. Two choices
differ from Pingora's OpenSSL connector and are listed under parity: the
extended master secret is required on TLS 1.2, and an IP-literal server
name sends no SNI.

## Replay and retries

A request body forwarded upstream is also kept in a bounded replay buffer
(64 KiB, the same limit Pingora applies) with a flag that records when the
body outgrew it. A failed attempt is replayed only when the buffer is
intact, no response byte has reached the client, and the retry policy
allows it; a failure on a reused connection additionally requires
`praxis_core::retry::reused_only_replay_safe`.

## Runtime and shutdown

`praxis_core::server::hyper::HyperRuntime` builds a multi-thread tokio
runtime from `runtime.threads` and `runtime.global_queue_interval` (a knob
that is a logged no-op on Pingora and takes effect here) and runs the
registered services. The signal handlers are installed before any
listener accepts, so a signal that lands during startup is honoured.
HTTP, TCP and management listeners are required services: an unexpected exit
stops the other services within the fast shutdown bound and fails the runtime.
A failed socket in a TCP listener group stops the whole group.
`SIGTERM` and `SIGHUP` start a graceful shutdown: listeners stop accepting,
in-flight connections finish through hyper's graceful shutdown, bounded by
`shutdown_timeout_secs`; `SIGINT` stops quickly. The harness path
(`run_with_shutdown`) stops quickly too, like Pingora's.

## What is not at parity

These are known gaps of the experimental backend. Each is a follow-up
change behind the same feature; promotion out of `experimental` requires
the security, conformance, integration and resilience suites green on
hyper.

- **Response compression.** Pingora's compression module has no hyper
  equivalent yet; a hyper build does not compress responses.
- **Upgrades.** WebSocket and other `Upgrade` tunnels are not supported:
  the request is forwarded with its upgrade headers stripped, and an
  upstream `101` is answered with a 502.
- **Hedged requests.** The `hedged-requests` feature compiles, but the
  hyper data path does not race hedges.
- **Drain sequence.** Shutdown is one phase here; Pingora's grace period
  before the runtime drain is not mirrored.
- **`Expect: 100-continue`.** hyper's server answers `100 Continue`
  itself as soon as the body is read. Pingora sends no `100 Continue` of
  its own: it forwards the body and relays an upstream's 100 if one comes.
  On hyper, interim `1xx` responses from an upstream are not relayed to
  the client (hyper's server cannot send them); on HTTP/1 the egress still
  sees them.
- **Header name case.** hyper writes every response header name in
  lowercase; Pingora keeps the spelling a filter wrote. Header names are
  case-insensitive, so clients are unaffected, but raw-byte comparisons
  differ.
- **mTLS peer identity.** `TlsPeerIdentity` (certificate digest,
  organization, serial) is not computed from the client certificate, so
  filters that authorize by peer identity see none. The protocol crate has
  no X.509 parser; the one in `praxis-tls` sits behind its `spiffe` feature.
- **HTTP/1 parsing differences.** hyper's parser serves pipelined
  requests, accepts a chunk size of `u64::MAX` and answers an over-long
  request target with 414 rather than 400. Pingora drops a pipelined
  second request after the first response and refuses the other two with a
  400. Praxis sits above the parser on both backends.
- **Upstream TLS strictness.** A TLS 1.2 upstream that does not support
  the extended master secret (RFC 7627) fails the handshake on hyper and
  works on Pingora; and for an IP-literal server name rustls sends no SNI
  where OpenSSL sends the literal, so an upstream that selects its
  certificate by that SNI answers with its default certificate.
- **`runtime.work_stealing: false`** has no effect; the runtime always
  work-steals.
- **FIPS.** The hyper build is not verified under the FIPS tooling.
- **Suite parity.** Tests that do not pass on hyper yet are listed in
  `tests/hyper-skip.txt`, with the bucket each belongs to;
  `make test-integration-hyper` and the CI workflow skip exactly that list
  and run everything else. The tests that reach into Pingora directly are
  compiled out under hyper instead of listed.

## Related

- [Adding a Network Backend](../developing/adding-backends.md): the
  contract this backend implements.
- [Build features](../operating/build-features.md): the feature table.
- [Pingora Handler Lifecycle](pingora-handler-lifecycle.md): the lifecycle
  this backend mirrors.

[hyper]: https://github.com/hyperium/hyper
[tokio-rustls]: https://github.com/rustls/tokio-rustls
