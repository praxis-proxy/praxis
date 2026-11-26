# Build features

Praxis is composed at build time with Cargo features, so a build can carry
only what a deployment needs. Most features are on by default. The standard
binary includes hot-reload, the admin surface, and the `policy` filter with
all supported builtins:

```console
cargo build -p praxis-proxy --release
```

The leanest binary turns every optional subsystem off; add features back as
needed:

```console
cargo build -p praxis-proxy --release --no-default-features --features pingora
cargo build -p praxis-proxy --release --no-default-features --features pingora,admin-api
```

A policy-free build that keeps everything else names those features:

```console
cargo build -p praxis-proxy --release --no-default-features \
    --features pingora,config-reload,admin-api
```

A `--no-default-features` build always names its network backend (`pingora`
today; see [Network backends](#network-backends)). Every Praxis crate depends
on `praxis-proxy-filter` without dependency defaults, so leaving out the
policy features leaves the policy engine's dependency tree out of the build.
`make release-fips` is this build with the feature list kept in one place;
see [FIPS 140-3](fips.md).

### Selecting policy features

The standard build uses `policy-builtins`: the policy engine, every Policy
builtin, the RustCrypto crypto backend and the experimental rate limiter
(`ratelimit/limitador`). Because the limiter is experimental, a default build
logs the experimental-features warning at startup. Compiling the limiter in
adds no counting: it runs only for a policy that declares a
`kind: ratelimit/limitador` plugin and lists it under `rate_limits:`, and
Praxis warns at startup and on every reload when a loaded policy does.

A narrower build starts from `--no-default-features` and names its Policy
features. Policy's builtins share one crypto backend, and a granular build
selects exactly one: `policy-crypto-default` (RustCrypto) or
`policy-crypto-fips` (system OpenSSL). The engine refuses to compile with
neither or both, so `policy-engine` or `policy-jwt` alone does not build.

| Profile | Policy features |
| ------- | --------------- |
| Standard (default) | `policy-builtins` |
| Engine only | `policy-engine,policy-crypto-default` |
| API-key identity | `policy-api-key,policy-crypto-default` |
| JWT identity | `policy-jwt,policy-crypto-default` |
| Limiter without an identity builtin | `policy-experimental-ratelimit,policy-crypto-default` |
| Limiter with JWT | `policy-experimental-ratelimit,policy-jwt,policy-crypto-default` |

For example, an API-key-only proxy:

```console
cargo build -p praxis-proxy --no-default-features \
    --features pingora,config-reload,admin-api,policy-api-key,policy-crypto-default
```

An engine-only build registers no builtin plugin kinds. Its policies can use
inline rules and host-registered plugins; a policy naming a `kind:` the build
did not compile in (for example `identity/jwt`) fails to load with an error
naming the kind, at startup or on reload.

`policy-jwt` verifies tokens on aws-lc-rs. `policy-jwt-openssl-fips` is the
same plugin on the system OpenSSL; it requires `policy-crypto-fips` and
cannot be combined with `policy-jwt`. `policy-api-key-fips`
(`policy-api-key` + `policy-crypto-fips`) and `policy-jwt-fips`
(`policy-jwt-openssl-fips` + `policy-crypto-fips`) are convenience aliases.
The default FIPS build carries no Policy feature.

### Selecting policy features as a library consumer

Each crate that reaches the filter (`praxis-proxy`, `praxis-proxy-protocol`)
depends on it without defaults and exposes the same `policy-*` features,
forwarding them to the filter's:

- `praxis-proxy` with `default-features = false` and only the features you
  name is policy-free; with defaults on, it has the complete builtin set.
- `praxis-proxy-protocol` or `praxis-proxy-filter` has no policy engine
  unless you enable `policy-engine`, `policy-builtins`, or an individual
  `policy-*` feature on that edge. Set `default-features = false` on a filter
  dependency to choose features explicitly. `praxis-proxy-core` and
  `praxis-proxy-tls` never pull it.

Cargo unions features across the whole dependency graph, so one crate that
depends on `praxis-proxy-filter` with its defaults turns `policy-builtins`
back on for everyone, and the `policy` filter becomes nameable in config in a
build believed to be policy-free. Verify with
`cargo tree -e normal -i praxis-policy`: no output means the policy engine is
out of the build.

## Network backends

The *backend* owns sockets, TLS acceptors, HTTP framing, connection pooling
and the async runtime, and a build runs on exactly one. Pingora is the
production backend (`pingora`, on by default); `hyper` is an experimental
second backend, off by default (see [hyper backend](../architecture/hyper-backend.md)
for what is not at parity yet). Everything above the backend (configuration,
filters, routing, health checks, retries, the admin handlers, the sub-request
client) is the same on both.

The two backends are mutually exclusive, and a build with both refuses to
compile, so a hyper build starts from `--no-default-features`:

```console
cargo build -p praxis-proxy --release --no-default-features \
    --features hyper,config-reload,admin-api,policy-builtins
```

`make build-hyper` is the same build without `--release`, into
`target/hyper`, and `make test-integration BACKEND=hyper` runs the suites on
it. With no backend feature the `praxis-proxy` binary refuses to compile; the
library crates still compile, with a stand-in connector that refuses every
connection, so lean-build checks work. Library consumers that depend on
`praxis-proxy`, `praxis-proxy-protocol` or `praxis-proxy-core` with
`default-features = false` name the backend feature on that edge too. See
[Adding a Network Backend](../developing/adding-backends.md).

## Feature summary

| Feature | Default | Enables | Turn it off / on when |
| ------- | ------- | ------- | --------------------- |
| `pingora` | on | The Pingora network backend: listeners, HTTP/1 and HTTP/2 framing, connection pooling and the async runtime, from the [Pingora fork](https://github.com/praxis-proxy/pingora). | Never off on its own: a build needs a backend. Mutually exclusive with `hyper`. |
| `hyper` | off (experimental) | The hyper network backend on [hyper](https://github.com/hyperium/hyper) 1.x with `tokio-rustls`, a Praxis-owned connection pool and a tokio runtime. | On, from `--no-default-features`, for testing and evaluation. |
| `config-reload` | on | Config-file and TLS-certificate hot-reload (filesystem watching). | Off for a static-config deployment: drops both watchers and the `notify`, `arc-swap`, and `tokio` dependencies they pull into the TLS crate. |
| `admin-api` | on | The admin HTTP services: management API (`/api/*`) on `admin.address`, and `/healthy`, `/ready`, `/metrics` on `admin.metrics_address`. | Off when the proxy exposes no monitoring or management surface. The data path and background health checks are unaffected. |
| `otel` | off | OpenTelemetry / OTLP span export for traces. | On for distributed tracing. Pulls in a heavy `opentelemetry` + `tonic` dependency graph. |
| `policy-builtins` | on | The `policy` filter with every Policy builtin, the RustCrypto backend and the experimental rate limiter. | Off when the deployment does no policy-based authorization: the largest single saving in build time and binary size. Name granular features to keep only the plugin kinds a policy uses. |
| `policy-engine` | via `policy-builtins` | The policy engine with no builtin plugin. Needs a crypto backend. | With `policy-crypto-default` for policies that use only inline rules and host-registered plugins. |
| `policy-crypto-default` | via `policy-builtins` | Policy's RustCrypto backend, shared by every builtin. | Exactly one backend per build; the ordinary choice. |
| `policy-crypto-fips` | off | Policy's system OpenSSL backend. | Exactly one backend per build; for FIPS builds. |
| `policy-api-key` | via `policy-builtins` | The `identity/api-key` plugin. | With a crypto backend for API-key authentication. |
| `policy-jwt` | via `policy-builtins` | The `identity/jwt` plugin on aws-lc-rs. | With a crypto backend for JWT authentication. Not FIPS. |
| `policy-jwt-openssl-fips` | off | The `identity/jwt` plugin on system OpenSSL. | With `policy-crypto-fips`; excludes `policy-jwt`. |
| `policy-experimental-ratelimit` | via `policy-builtins` (experimental) | The `ratelimit/limitador` plugin. Outside Policy's semver guarantees. | Name it in a granular build that needs the limiter. |
| Other `policy-*` features | via `policy-builtins` | One builtin each: `policy-oauth`, `policy-delegator-vault`, `policy-elicitation-ciba`, `policy-cedar`, `policy-cel`, `policy-opa`, `policy-valkey`, `policy-secrets-vault`. | Combine only the builtins the policy documents reference. `policy-secrets-vault` compiles Policy's Vault secret backend, but the `policy` filter registers only the `env` secret provider, so a `kind: vault` secret still fails to load. |
| `basic-auth-filter` | off (experimental) | The `basic_auth` filter. | Dev and testing only. |
| `bandwidth` | off (experimental library support) | Shared byte budgets and the `bandwidth_limit` filter. | Enable `praxis-proxy-filter/bandwidth`; server and listener adapters are in part 2. |
| `cloud-events-filter` | off (experimental) | The `cloud_events` filter. | On for event export. Adds `chrono` and `url`. |
| `upstream-binding` | off (experimental) | Logical upstream binding. | On when a pipeline gates filters on the bound cluster's application metadata or dispatches from the binding. Implied by `iterative-request-router` and `bound-upstream-request-body`. |
| `iterative-request-router` | off (experimental) | The `iterative_request_router` filter. | On for callout and failover pipelines (the AI gateway relies on it). No extra dependencies; pulls in `upstream-binding`. |
| `router-json-aliases` | off (experimental) | The `router` filter's JSON-alias body-routing groundwork. | Groundwork only, not wired into routing. |
| `slow-start` | off (experimental) | Per-cluster `slow_start` config. | The key is rejected unless the feature is on. |
| `forward-proxy` | off (experimental) | The listener `forward_proxy` block, the HTTP CONNECT runtime, and absolute-form forwarding of plain `http://` requests. | On for an egress gateway in front of `HTTP_PROXY`/`HTTPS_PROXY` clients. The key is rejected unless the feature is on. |
| `bound-upstream-request-body` | off (experimental) | The `HttpFilter::on_bound_upstream_request_body` hook. | For out-of-tree filters that inspect or rewrite the request body against the bound upstream. Pulls in `upstream-binding`. |
| `chain-binding` | off (experimental) | The `register_chain_binding` outbound-callout API, deferred credentials, and cluster-staged callouts. | For out-of-tree callout filters. |
| `spiffe` | off (experimental) | SPIFFE X.509-SVID mTLS peer identity and the `peer_identity_trust` filter. | On for mTLS peer-identity authorization. Adds `spiffe` and `x509-parser`. |
| `access-log-syslog` | off (experimental) | The `access_log` filter's syslog sink. | On to ship access logs to a syslog collector. Adds the optional `syslog` crate. |
| `managed-websocket` (protocol crate) | off (experimental) | Local HTTP/1.1 WebSocket transport. Enables the protocol crate’s `pingora` feature. | For library integration. Listener configuration support is planned separately. |
| `tls-health-check` | off (experimental) | TLS handshakes and HTTPS active health probes. Selects Pingora. | Enables `health_check.type: tls`; HTTP probes on TLS clusters use HTTPS. See [health checking](health-checking.md#tls-and-https-probes). |
| `hedged-requests` | off (experimental) | Races one idempotent request across healthy endpoints and returns the first successful response. | On when a route sets `hedge_policy` with `max_attempts` greater than 1. Off, the policy is still parsed and every request stays on one upstream. |
| `dev` | off | Developer convenience bundle (currently enables `basic-auth-filter`). | Local development builds. |
| `experimental` | off | Marker feature set transitively by experimental features; drives a startup warning. | Not selected directly. |

## Experimental features

Each experimental feature turns on the `experimental` marker feature, which
makes the server log `experimental features are enabled that should not be used in production`
at startup. All are off by default except `policy-experimental-ratelimit`,
which the default `policy-builtins` bundle enables. Do not run an
experimental build in production. Details beyond the table:

- **`hyper`**: runs the same filter pipeline, admin surface and sub-request
  client as Pingora, but several data-path behaviours are not at parity yet;
  see [hyper backend](../architecture/hyper-backend.md).
- **`basic-auth-filter`** (deprecated): credentials live in plaintext config.
  Praxis warns when a config uses the filter. It is slated for removal in
  favor of the policy engine ([praxis-proxy/policy]); use that for
  authentication.
- **`cloud-events-filter`**: serializes a request into a CloudEvent and ships
  it to a configured HTTP receiver. Delivery is best-effort and never changes
  the client response.
- **`upstream-binding`**: a `router` in a pipeline that reads the binding
  publishes the matched cluster once per request, `bound_upstream`
  conditions match on that cluster's application metadata, and a
  `load_balancer` with `cluster_source: bound_upstream` picks an endpoint
  from it. Without the feature those two config forms fail validation and
  the router never touches request extensions. See
  [Upstream Binding](../architecture/upstream-binding.md).
- **`iterative-request-router`**: a bounded loop of sequential sub-requests
  through named step pipelines, for provider failover and LLM agentic/tool
  loops. Its streaming multi-step machine is still stabilizing.
- **`router-json-aliases`**: the matching primitives exist but are not wired
  into request routing, so a route that sets `json_aliases` is rejected at
  build even with the feature on. Default builds do not accept the
  `json_aliases` keys at all.
- **`slow-start`**: with the feature on, round robin, random,
  least-connections, and power-of-two-choices apply the ramp; hash
  strategies keep the configured weight.
- **`forward-proxy`**: turns a `protocol: http` listener into an HTTP CONNECT
  egress gateway. CONNECT requests run the filter pipeline, then the
  destination allowlist and the private-IP guard decide the dial, and the
  tunnel relays raw bytes under the configured timeouts. An empty
  `allow_destinations` list admits every destination through the allowlist;
  the filters and the private-IP guard still apply, and validation then
  requires an `ip_acl` or `policy` filter. Tunneled payloads are opaque to
  body-inspecting filters, which see only the end of the CONNECT's own,
  empty body.
- **`bound-upstream-request-body`**: the hook
  (`bound_upstream_request_body_access` and `on_bound_upstream_request_body`
  on `HttpFilter`) runs once per request, right after the binding `router`
  freezes the request's
  [logical upstream binding](../architecture/upstream-binding.md), over the
  fully buffered body. A read-write participant's output becomes the body
  forwarded, retried, and handed to the IRR. Logical binding needs
  `upstream-binding`, which this feature pulls in; this feature gates only
  the hook. No in-tree filter uses it yet.
- **`chain-binding`**: `register_chain_binding` and
  `ChainBindingContext::bind_chain`, the authority-bound deferred-credential
  channel (`PendingCredentials` / `DeferredCredential`), which injects a
  secret into an outbound sub-request only when the resolved destination
  matches the authority the credential was issued for, and the
  `ChainBindingContext::cluster` / `StagedCluster` pair, which sends a
  callout to a named top-level cluster. No in-tree consumer yet.
- **`spiffe`**: includes the `require_named` listener client-cert mode.
  `peer_identity_trust` works with any mTLS client certificate, not only
  SPIFFE, so a non-SPIFFE mTLS deployment still needs `spiffe` to use it.
- **`access-log-syslog`**: `sink: {type: syslog}` sends each record as an
  RFC 3164 message over a Unix socket, UDP, or TCP. Each message is capped at
  1024 bytes (RFC 3164 §4.1), so a longer record is truncated and a
  structured (e.g. JSON) payload may not stay valid. The `syslog` crate is
  crypto-free and kept out of the default and FIPS builds.

## Notes

- **Runtime still gates behavior.** Building with `admin-api` does not start
  the admin endpoints; they bind only when `admin.address` or
  `admin.metrics_address` is configured. A listener's `hot_reload: true` key
  takes effect only in a binary built with `config-reload`; otherwise the
  certificate is served statically and a startup warning is logged.
- **The memory allocator is not a feature.** Praxis targets Linux and always
  uses `tikv-jemallocator`.
- **Where the savings are.** Dropping `policy-engine`, `config-reload`,
  `admin-api`, and `otel` trims the dependency tree and binary size,
  `policy-engine` by the widest margin. Most filters are always compiled in
  and share dependencies with the core proxy, so gating them would not
  remove a crate. The experimental filter gates (`upstream-binding`,
  `iterative-request-router`, `chain-binding`, `router-json-aliases`,
  `slow-start`, `bound-upstream-request-body`) keep unfinished surface out of
  default builds rather than save a crate; `spiffe`, `cloud-events-filter`,
  and `access-log-syslog` also drop the dependencies listed in the table.

## See also

- [Filter Reference][filter-reference]: the per-filter `Feature` column shows
  which filters require a cargo feature.
- [Observability][observability]: metrics and tracing, gated by `admin-api`
  and `otel`.
- [TLS][tls]: the runtime `hot_reload` listener key, gated by `config-reload`.
- [Getting Started][getting-started]: the build and test workflow.

[praxis-proxy/policy]: https://github.com/praxis-proxy/policy
[filter-reference]: ../filters/reference.md
[observability]: observability.md
[tls]: tls.md
[getting-started]: ../developing/getting-started.md
