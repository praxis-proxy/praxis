# Adding a Network Backend

## Overview

A network backend is the layer that owns sockets, TLS acceptors, HTTP
framing, connection pooling and the async runtime. Praxis runs on one
backend per binary, selected at build time with a Cargo feature. Pingora
is the only backend today and is on by default.

Everything above the backend is backend-neutral and stays untouched when a
backend is added: configuration, validation, the filter engine, routing,
load balancing, health checking, retry policy, hop-by-hop handling, the
admin and metrics handlers, and the sub-request client. A backend plugs
into a small contract and drives the filter pipeline at the right points
of a request's life.

## The contract

| Piece | Where | What a backend provides |
| ----- | ----- | ----------------------- |
| Runtime | `praxis_core::server::ServerRuntime` | A type that owns the async runtime, binds listeners, and runs until a shutdown signal or a supplied shutdown future resolves. |
| Egress | `praxis_core::egress::{Connector, Session}` | A pooled connector that turns a [`PeerSpec`] into a live session: send a request head and body, read the response head and body, report reuse and completion, release or shut down. |
| Protocol adapters | `praxis_protocol::Protocol` | An `Http` and a `Tcp` adapter that bind the configured listeners onto the runtime and drive the pipeline. |
| Admin surface | `praxis_protocol::http::health::AdminRequest` and `praxis_protocol::backend::admin` | An `AdminRequest` view of the backend's parsed request, one listener each for the admin API and the health and metrics endpoints, and the recorder upkeep task. |
| Selection | `praxis_core::backend`, `praxis_protocol::backend` | The feature-gated arms that resolve `Runtime`, `Connector`, `Http`, `Tcp` and `admin::*` to the backend's types. |

The server bootstrap (`crates/server/src/server.rs`) and the test harness
(`tests/utils/src/proxy.rs`) use only these names, so neither changes when a
backend is added.

[`PeerSpec`]: ../../crates/core/src/egress/peer.rs

## Steps

### 1. Wire the feature

Add a feature named after the backend in three manifests. Cargo's `dep:`
syntax lets the feature share a dependency's name.

```toml
# crates/core/Cargo.toml
[features]
default = ["pingora"]
pingora = ["dep:pingora-core", "dep:pingora-http"]
hyper = ["dep:hyper", "dep:hyper-util", "dep:tokio-rustls"]

# crates/protocol/Cargo.toml
pingora = ["dep:pingora-core", "dep:pingora-http", "dep:pingora-proxy", "praxis-core/pingora"]
hyper = ["dep:hyper", "dep:hyper-util", "praxis-core/hyper"]

# crates/server/Cargo.toml
pingora = ["praxis-core/pingora", "praxis-protocol/pingora"]
hyper = ["praxis-core/hyper", "praxis-protocol/hyper", "experimental"]
```

Keep the backend's dependencies `optional = true`. A backend that is not yet
supported implies `experimental`, which turns on the startup warning.

Then add the arms to the `backend` module at the end of
`crates/core/src/lib.rs` and of `crates/protocol/src/lib.rs`, and extend
the guards in `crates/server/src/lib.rs`: the existing `compile_error!`
refuses a build with no backend; with two backends, add one that refuses
both at once.

```rust
#[cfg(all(feature = "pingora", feature = "hyper"))]
compile_error!("praxis-proxy takes exactly one network backend feature");
```

### 2. Implement `ServerRuntime`

Create `crates/core/src/server/<name>.rs`. `from_config` builds the runtime
from `Config` (thread count via `resolve_thread_count`, shutdown timing
from `shutdown_timeout_secs`) and binds nothing. `run_until_shutdown`
installs signal handling and serves; `run_with_shutdown` serves until the
given future resolves, which is how the harness stops a proxy. The signal
path returns once graceful shutdown completes. Pingora uses immediate
shutdown for the supplied future and may drop active work.

### 3. Implement `Connector` and `Session`

Create `crates/core/src/egress/<name>.rs`. The connector keeps the pool,
keyed however the transport needs; a `PeerSpec` carries the resolved
address, the TLS flag and server name, a pool partition, connection options
(timeouts and HTTP version) and the cluster's cached TLS material plus any
runtime trust anchors. `connect` receives the exchange timeout and must
bound its own connection-setup timers to it; the caller applies any
tighter per-attempt cap with its own timer, so a cap that runs out is
reported as such rather than as a transport timeout. `release(session,
false)` is the abnormal path: shut the connection down, except that a
stream of a multiplexed connection only gives up its share.

`Session::read_response_head` asynchronously reads one head into the
session. `response_head` then borrows its status, version and headers in a
backend-neutral `ResponseHead` view. Keep the transport's headers intact
for body framing and connection reuse: the caller sanitizes the borrowed
headers directly into its result map. Each new read replaces that view;
interim `1xx` heads are skipped, while `101` is final. The borrow ends
before the session moves into the response body handle.

The sub-request client is generic over the connector and needs nothing
else. Under a backend that also routes the proxy data path through its
connector, pool, limits and metrics are one thing for both.

### 4. Implement `Protocol` for HTTP and TCP

Create `crates/protocol/src/http/<name>/` and the TCP counterpart. Each
adapter filters the configured listeners by `ProtocolKind`, resolves the
listener's pipeline from `ListenerPipelines`, binds the socket (through
`praxis_protocol::tls_setup::build_listener_tls` for TLS listeners) and
registers a service on the runtime. Return the cert-watcher shutdown
senders as the trait documents.

The HTTP adapter drives the pipeline at these points of a request's life.
The Pingora handler under `crates/protocol/src/http/pingora/handler/` is
the worked example, and `docs/architecture/pingora-handler-lifecycle.md`
walks through it.

| Point | Pipeline call | Notes |
| ----- | ------------- | ----- |
| Admission, before any read | `inbound_admission` | Memory pressure, global and per-listener connection limits, read timeout. Backend-neutral code in the Pingora handler module. |
| Request head received | `execute_http_request` | After validation and hop-by-hop stripping. Pin the pipeline `Arc` for the whole request. |
| Request body chunks | `execute_http_request_body` | Honour `BodyMode` (stream, size-limited buffer, pre-read before upstream selection). |
| Upstream selected | `execute_http_selected_upstream_request_body` | Only when a filter asked for the bound-upstream body hook. |
| Response head received | `execute_http_response` | Nothing is written downstream before this returns. |
| Response body chunks | `execute_http_response_body` and `execute_http_response_body_with_response_header` | Trailers and gRPC completion are captured here. |
| TCP connect and disconnect | `execute_tcp_connect`, `execute_tcp_disconnect` | The TCP adapter's two hooks. |

Per-request state lives in the adapter's own context type; the Pingora
one is `PingoraRequestCtx` in `crates/protocol/src/http/pingora/context.rs`
and its `filter_context!` macro shows how a context becomes an
`HttpFilterContext`.

Two rules the backend must keep because the suites check them:

- **Replay.** Retry a stale reused-connection failure only when
  `praxis_core::retry::reused_only_replay_safe` says so: the connection
  was reused and the replay buffer is intact.
- **Framing.** Praxis owns hop-by-hop stripping, Host validation,
  `X-Forwarded-*` and Via; the backend owns request-smuggling prevention,
  HTTP/2 flow control and connection-pool safety. See
  `docs/operating/security-hardening.md`.

### 5. Serve the admin surface

Implement `AdminRequest` for the backend's request type (method, target,
headers, bounded body read), then serve `PingoraHealthService::respond` on
the metrics listener and `PingoraAdminService::respond` on the admin
listener. The handlers are backend-neutral despite their names; only the
glue is yours. Provide `add_admin_api`, `add_health_endpoint`,
`add_health_endpoint_with_pipelines` and `add_prometheus_upkeep` taking
`&mut Runtime`, and re-export them from `praxis_protocol::backend::admin`.
`run_prometheus_upkeep` is the upkeep loop; run it as a background task
with your shutdown watch. It and the recorder's exporter handle are
crate-visible, so the glue can live anywhere under `crates/protocol/src`.

The Pingora glue is `crates/protocol/src/http/pingora/health/pingora_glue.rs`.

### 6. Build and CI

- Add a separate invocation to `check-features` in the `Makefile` that uses
  `--no-default-features --features <name> --all-targets`. The existing
  optional-feature loop always enables `pingora`, so adding another backend
  to that loop would enable mutually exclusive backends together.
- Add the feature to the `not(...)` list of the dead-code expectation at
  the top of `crates/protocol/src/http/pingora/metrics.rs`: with your
  backend compiled in, the recording helpers have a caller again.
- Add a nightly job that runs the integration, conformance and `h2spec`
  suites on the backend. The harness builds every proxy through the
  contract, so no suite file changes:

  ```console
  cargo test --no-default-features --features <name>,config-reload,admin-api,policy-engine
  ```

- Promotion out of `experimental` requires the security, conformance,
  integration and resilience suites green on the backend; see
  `docs/developing/project-management.md` and the enhancements process.

### 7. Document

- Add the feature to the table in `docs/operating/build-features.md` and
  describe it under the backends section.
- Add `docs/architecture/<name>-backend.md` describing the lifecycle
  mapping, the pool, replay and what is not yet at parity.

## Building without a backend

The library crates compile with no backend feature so lean builds can be
checked: `praxis_core::backend::Connector` is then `egress::Unavailable`,
which refuses every connection, and `Runtime` is
`server::UnavailableRuntime`, which has nothing to serve. The `praxis-proxy`
binary refuses to build in that state, so every `--no-default-features`
invocation names a backend:

```console
cargo build -p praxis-proxy --no-default-features --features pingora,config-reload,admin-api
```

Library consumers that depend on `praxis-proxy` with
`default-features = false` name the backend the same way.
