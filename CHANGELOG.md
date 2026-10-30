# Changelog

<!-- markdownlint-disable MD013 -->

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

> **Types of changes:**
>
> - **Added**: for new features.
> - **Changed**: for changes in existing functionality.
> - **Deprecated**: for soon-to-be removed features.
> - **Removed**: for now removed features.
> - **Fixed**: for any bug fixes.
> - **Security**: in case of vulnerabilities.

## [Unreleased]

### Added

- A [support diagnostics reference](docs/operating/diagnostics.md) covering
  config checks, live state, logging, reloads and draining before shutdown.
- An experimental network backend behind the `hyper` feature, off by
  default: the proxy data path, TCP forwarder, admin surface and sub-request
  client on hyper 1.x. See `docs/architecture/hyper-backend.md`.
- Experimental `tls-health-check` feature for TLS handshake probes and HTTPS
  health endpoints using cluster certificates and startup runtime trust.
  Handshake probes detect client-certificate rejection alerts after sending
  `close_notify`, allowing the greater of 100 ms and the connection and
  handshake duration, capped by the remaining probe timeout. Completed
  handshakes remain healthy when that deadline expires without a response.
  Rust consumers matching `HealthCheckType` exhaustively must handle the new
  `Tls` variant even when the feature is disabled.

### Fixed

- The FIPS runtime probe selects the Pingora backend when compiling its
  listener tests with default features disabled.
- The Hyper backend rejects reserved client trailer names before forwarding
  or retaining them for replay, including streamed and pre-read uploads.
- The Hyper backend applies the retry policy to failures on pooled
  connections, preventing POST replays without opt-in and enforcing the
  configured retry limit.
- The Hyper backend stops the runtime if a required listener exits during
  startup or serving, including a failed socket in a TCP listener group.
- The Hyper backend preserves request trailers through pre-read and retries
  to HTTP/2 upstreams, and rejects unsupported HTTP/1 uploads with trailers.
- The Hyper backend rejects strict HTTP/2 TLS upstreams that do not negotiate
  `h2` through ALPN. Automatic HTTP version selection still allows HTTP/1.1.

## [0.7.5] - 2026-10-21

### Added

- `policy` filter accepts `context_headers` and `context_meta` configuration.
  `context_headers` maps reserved-prefix HTTP headers to typed `agent.*` /
  `framework.*` extension fields (via a closed `ContextField` enum) so APL
  rules can reference host-injected values. `context_meta` stamps operator-
  defined `scope`, `tags`, and `properties` onto every policy evaluation;
  `scope` feeds the PPE's scoped route resolver for both authentication and
  authorization. ([#1388](https://github.com/praxis-proxy/praxis/pull/1388))
- A network backend contract, so an alternative to Pingora can be dropped
  in behind a Cargo feature: `praxis_core::server::ServerRuntime`,
  `praxis_core::egress::{PeerSpec, Connector, Session}`,
  `praxis_protocol::http::health::AdminRequest`, and the `backend` modules
  in `praxis-proxy-core` and `praxis-proxy-protocol` that resolve to the
  selected backend. `docs/developing/adding-backends.md` describes what a
  backend implements. ([#1407](https://github.com/praxis-proxy/praxis/pull/1407))
- With the `hedged-requests` feature, an eligible idempotent request is raced
  across healthy endpoints and the first 2xx, 3xx, or 4xx response is
  returned. The feature is off by default; when it is off, a configured
  `hedge_policy` is still parsed and every request stays on one upstream.
  ([#1372](https://github.com/praxis-proxy/praxis/pull/1372))
- Clusters accept an optional `slow_start` (`window_ms`, `aggression`) when
  built with the `slow-start` feature. Round robin, random, least-connections,
  and power-of-two-choices apply the ramp, including inside subset, priority,
  and zone-aware selection. Hash strategies keep the configured weight.
  ([#1364](https://github.com/praxis-proxy/praxis/pull/1364),
  [#1406](https://github.com/praxis-proxy/praxis/pull/1406),
  [#110](https://github.com/praxis-proxy/praxis/issues/110))
- FIPS crypto-readiness settings that let an operator require and verify
  FIPS-mode cryptography, with tests covering the readiness checks.
  ([#1365](https://github.com/praxis-proxy/praxis/pull/1365))
- A request-head filter lifecycle phase and a `head_classifier` filter that
  run on the request head before the body phase.
  ([#1380](https://github.com/praxis-proxy/praxis/pull/1380))

### Changed

- **Breaking:** the Pingora backend is now the `pingora` Cargo feature of
  `praxis-proxy`, `praxis-proxy-protocol` and `praxis-proxy-core`, on by
  default. A `--no-default-features` build (the FIPS build included) names
  it: `--features pingora,config-reload,admin-api`. A build with no backend
  feature refuses to compile the binary.
  ([#1407](https://github.com/praxis-proxy/praxis/pull/1407))
- **Breaking:** sub-request peers are `praxis_core::egress::PeerSpec` instead
  of Pingora's `HttpPeer`: `SubRequestClient::execute`, `send_streaming`,
  `HttpFilterContext::execute_subrequest`, `send_streaming_subrequest` and
  `PreparedSubrequest::{peers, peer_at}` take or return it, and
  `SubRequestClient::with_upstream_ca` takes the cached CA certificates
  rather than Pingora's parsed form. `praxis-proxy-filter` no longer depends
  on Pingora. ([#1407](https://github.com/praxis-proxy/praxis/pull/1407))
- **Breaking:** `Protocol::register` takes `&mut praxis_core::backend::Runtime`
  (the same type as before under the default feature). The admin, health and
  metrics listeners are registered through `praxis_protocol::backend::admin`;
  the `*_to_pingora_server` functions remain for callers holding a raw
  Pingora `Server`. The Praxis-owned health, metrics and KV modules are
  reachable as `praxis_protocol::http::{health, metrics, kv}`.
  ([#1407](https://github.com/praxis-proxy/praxis/pull/1407))
- **Breaking:** Rust API: `SubResponse` has a new public `version` field, so
  struct literals need `version`.
  ([#1372](https://github.com/praxis-proxy/praxis/pull/1372))

### Fixed

- `praxis-proxy-filter` exposes the streaming body mode after a buffered body
  is released. ([#1382](https://github.com/praxis-proxy/praxis/pull/1382))
- A stalled per-call DNS lookup is bounded so it no longer holds its admission
  slot indefinitely. ([#1383](https://github.com/praxis-proxy/praxis/pull/1383))
- The `policy` filter dispatches prompt and resource post hooks on the
  response. ([#1356](https://github.com/praxis-proxy/praxis/pull/1356))

### Security

- Updated `rustls-webpki` to 0.103.16 to reject certificate paths containing
  distrusted emSign intermediate public keys (`RUSTSEC-2026-0382`).
- `rustls` is 0.23.46, which fixes buffered application data sent after ECH
  rejection, Brotli certificate decompression allocating before
  authentication, an unauthenticated ServerHello downgrading later
  connections, and `Debug` impls exposing TLS secrets
  (`RUSTSEC-2026-0347`, `RUSTSEC-2026-0348`, `RUSTSEC-2026-0349`,
  `RUSTSEC-2026-0346`).
- URL-mode sub-requests no longer include their path in debug connection
  events. Paths supplied by clients can contain bearer tokens or signed
  download identifiers; the actual outbound request target is unchanged.
  ([#1419](https://github.com/praxis-proxy/praxis/pull/1419))

## [0.7.4] - 2026-10-12

### Added

- Named filter chains take a `conditions:` list that every filter in the chain
  inherits, ANDed with the filter's own conditions, wherever the chain is used
  (listeners, branch chains, outbound bindings).
  ([#1286](https://github.com/praxis-proxy/praxis/pull/1286))
- `access_log` takes an optional `template` that renders each record as one
  text line from `{field}` placeholders, such as
  `'{method} {path} {status} {duration_ms}ms'`. It can't be combined with
  `fields`. ([#1323](https://github.com/praxis-proxy/praxis/pull/1323))
- `access_log` takes an optional `sink` that writes records to stdout or to a
  file opened for append, as NDJSON (or the `template` line, if one is set),
  bypassing the tracing subscriber. Delivery is best effort: if the writer
  falls behind, records are dropped rather than blocking requests.
  ([#1324](https://github.com/praxis-proxy/praxis/pull/1324))
- `url_rewrite` has a `preserve_query_params_only` operation that keeps only
  the listed query parameters and drops the rest.
  ([#1339](https://github.com/praxis-proxy/praxis/pull/1339))
- With the `otel` feature and an OTLP exporter, Praxis continues a valid
  inbound W3C `traceparent` and exports a client span for each upstream
  attempt, so traces link across Praxis hops. The forwarded `traceparent` now
  names that client span instead of a synthetic hop ID.
  ([#1347](https://github.com/praxis-proxy/praxis/pull/1347))
- Filter conditions take `headers_present`, a list of header names that must
  all be present (any value), in both request and response conditions.
  ([#1348](https://github.com/praxis-proxy/praxis/pull/1348))
- Rust API: `praxis-proxy-filter` adds the `ClientResponseHeadersCommitted` and
  `StreamBodySuppressed` request extension markers, a typed
  `CalloutResponseTooLarge` error, and
  `FilteredSubrequestExecutor::for_callout_with_limits` for separate buffered
  and streaming callout limits.
  ([#1349](https://github.com/praxis-proxy/praxis/pull/1349))
- `router` routes accept an optional `hedge_policy` (`initial_requests`,
  `max_attempts`, `per_try_timeout_ms`, `budget_percent`), validated at load.
  The policy is parsed but, without the `hedged-requests` feature, every
  request still stays on one upstream.
  ([#1361](https://github.com/praxis-proxy/praxis/pull/1361))

### Changed

- **Breaking:** `/healthy`, `/ready` and `/metrics` moved off `admin.address`
  to their own listener, `admin.metrics_address`, which may bind a non-loopback
  address without `insecure_options.allow_public_admin`. Set it and move probes
  and scrapes there. The container image now exposes and health-checks port
  9902 instead of 9901.
  ([#1342](https://github.com/praxis-proxy/praxis/pull/1342))
- Config validation rejects an `admin.address` or `admin.metrics_address` that
  overlaps the other or a proxy listener.
  ([#1342](https://github.com/praxis-proxy/praxis/pull/1342))
- **Breaking:** Rust API: `ConditionMatch` and `ResponseConditionMatch` have a
  new public `headers_present` field, so struct literals need
  `headers_present: None`.
  ([#1348](https://github.com/praxis-proxy/praxis/pull/1348))

### Removed

- **Breaking:** Rust API: `praxis-proxy-protocol` drops
  `add_admin_endpoints_to_pingora_server` and
  `add_admin_endpoints_to_pingora_server_with_recorder`. Use
  `add_admin_api_to_pingora_server`,
  `add_health_endpoint_to_pingora_server_with_pipelines` and
  `add_prometheus_upkeep_to_pingora_server`.
  ([#1342](https://github.com/praxis-proxy/praxis/pull/1342))
- **Breaking:** Rust API: `praxis-proxy-filter` drops
  `set_policy_subrequest_connector` and
  `registered_policy_subrequest_connector`. Call
  `FilterRegistry::set_policy_connector` on the registry you build pipelines
  from. ([#1344](https://github.com/praxis-proxy/praxis/pull/1344))

### Fixed

- HTTP/1.1 responses with a body go out chunked when a response filter removes
  the upstream `Content-Length`. Before, they were delimited by closing the
  connection, so clients couldn't reuse it.
  ([#1284](https://github.com/praxis-proxy/praxis/pull/1284))
- A retry that moves to another endpoint keeps the SNI the first attempt took
  from the cluster authority or the client `Host`, instead of using the new
  endpoint's address (or no SNI at all for an IP endpoint).
  ([#1343](https://github.com/praxis-proxy/praxis/pull/1343))
- Policy filters built for two runtimes in one process no longer end up on
  each other's sub-request pool, admission limit and circuit breaker.
  ([#1344](https://github.com/praxis-proxy/praxis/pull/1344))
- A TLS cluster that reaches an IP endpoint without `tls.sni` now verifies it
  against the certificate's IP SAN; before, every request failed with a 502,
  verify on or off. `authority: { from: endpoint }` with IP endpoints no
  longer needs `allow_tls_without_sni`.
  ([#1345](https://github.com/praxis-proxy/praxis/pull/1345))
- Rust API: `Config::from_yaml` and `Config::validate` reject a bad
  `runtime.log_overrides` entry. Before, such a config loaded fine and failed
  later unless the caller ran the logging validators itself.
  ([#1346](https://github.com/praxis-proxy/praxis/pull/1346))
- Bodies buffered in `StreamBuffer` mode now hold memory in proportion to the
  payload. Before, lots of tiny chunks (small HTTP/2 DATA frames, say) could
  keep far more memory alive than the body limit allowed.
  ([#1351](https://github.com/praxis-proxy/praxis/pull/1351))

### Security

- `--dump` and the admin `/api/pipelines` view now redact credential-looking
  header matcher values (`authorization`, `x-session-id` and the like) in
  filter and chain conditions, and `--dump` redacts `credential_injection`
  values nested in `iterative_request_router` steps. Both used to print them
  as configured. ([#1286](https://github.com/praxis-proxy/praxis/pull/1286))

Releases 0.1.0 through 0.7.3 came out before this file existed; their notes
are on [GitHub Releases](https://github.com/praxis-proxy/praxis/releases).

[Unreleased]: https://github.com/praxis-proxy/praxis/compare/v0.7.5...HEAD
[0.7.5]: https://github.com/praxis-proxy/praxis/compare/v0.7.4...v0.7.5
[0.7.4]: https://github.com/praxis-proxy/praxis/compare/v0.7.3...v0.7.4
