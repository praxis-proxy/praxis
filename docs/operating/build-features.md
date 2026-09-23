# Build features

Praxis is composed at build time with Cargo *features*. Several subsystems
are optional so you can build a proxy that carries only what a deployment
needs: a smaller binary, a leaner dependency tree, or no external
observability and admin surface at all.

Most features are on by default. Build the standard binary with:

```console
cargo build -p praxis-proxy --release
```

which includes hot-reload, the admin surface, and the `policy` filter.

Build the leanest possible binary (every optional subsystem off) with:

```console
cargo build -p praxis-proxy --release --no-default-features
```

and add back individual features as needed:

```console
cargo build -p praxis-proxy --release --no-default-features --features admin-api
```

For a policy-free build that keeps everything else, name the features you want
instead:

```console
cargo build -p praxis-proxy --release --no-default-features \
    --features config-reload,admin-api
```

For that exact invocation the guarantee holds: every Praxis crate depends on
`praxis-proxy-filter` without dependency defaults, so dropping the server's
`policy-engine` feature leaves the filter's `policy-engine` off and the policy
engine's dependency tree out of the build. `make release-fips` is this build
with the feature list kept in one place; see [FIPS 140-3](fips.md) for what
that build is for and how to deploy it.

### Disabling the policy engine as a library consumer

The same holds when Praxis crates are embedded. Each crate that reaches the
filter (`praxis-proxy`, `praxis-proxy-protocol`) depends on it without
defaults and exposes its own `policy-engine` feature, forwarding to the
filter's. So:

- Depending on `praxis-proxy` (the server as a library) with
  `default-features = false` and naming the features you want gives a
  policy-free build; leaving defaults on gives the policy engine.
- Depending on `praxis-proxy-protocol` or `praxis-proxy-filter` directly gives
  no policy engine unless you enable `policy-engine` on them (the filter's own
  default is on, so set `default-features = false` on that edge to keep it
  off). `praxis-proxy-core` and `praxis-proxy-tls` never pull it.

Cargo unions features across the whole dependency graph, so one crate anywhere
in your graph that depends on `praxis-proxy-filter` with its defaults turns
`policy-engine` back on for everyone, and the `policy` filter then becomes
nameable in config in a build believed to be policy-free. Verify with
`cargo tree -e normal -i praxis-policy`: no output means the policy engine
really is out of the build.

## Feature summary

| Feature | Default | Enables | Turn it off / on when |
| ------- | ------- | ------- | --------------------- |
| `config-reload` | on | Config-file and TLS-certificate hot-reload (filesystem watching). | Off for a static-config deployment: drops both watchers and the `notify`, `arc-swap`, and `tokio` dependencies they pull into the TLS crate. |
| `admin-api` | on | The admin HTTP service: management API (`/api/*`), Prometheus `/metrics`, and `/healthy` + `/ready`. | Off when the proxy exposes no monitoring or management surface. The data path and background health checks are unaffected; only the HTTP endpoints go away. |
| `otel` | off | OpenTelemetry / OTLP span export for traces. | On for distributed tracing. Pulls in a heavy `opentelemetry` + `tonic` dependency graph. |
| `policy-engine` | on | The `policy` filter (Praxis Policy Engine: OPA-style route policy, JWT identity, token exchange). | Off for a deployment that does no policy-based authorization: it is the heaviest optional dependency, so dropping it is the largest single saving in build time and binary size. |
| `basic-auth-filter` | off (experimental) | The `basic_auth` filter. | Dev and testing only. Slated for removal in favor of the policy engine ([praxis-proxy/policy]); prefer that for authentication. |
| `cloud-events-filter` | off (experimental) | The `cloud_events` filter (serialize requests into CloudEvents and ship them to an HTTP receiver). | On for event export; delivery is best-effort. Adds `chrono` and `url`. |
| `iterative-request-router` | off (experimental) | The `iterative_request_router` filter: a bounded loop of sub-requests for provider failover and agentic/tool loops. | On for callout and failover pipelines (the AI gateway relies on it). No extra dependencies. |
| `router-json-aliases` | off (experimental) | The `router` filter's JSON-alias body-routing groundwork. | Groundwork only: it is not wired into routing, and a route that sets `json_aliases` is rejected at build even with the feature on. Default builds do not accept the keys. |
| `chain-binding` | off (experimental) | The `register_chain_binding` outbound-callout API (`ChainBindingContext::bind_chain`) and its authority-bound deferred credentials (`PendingCredentials`, `DeferredCredential`). | For out-of-tree callout filters; no in-tree consumer yet. |
| `spiffe` | off (experimental) | SPIFFE X.509-SVID mTLS peer identity (the `require_named` listener mode) and the `peer_identity_trust` filter. | On for mTLS peer-identity authorization. Adds `spiffe` and `x509-parser`. |
| `dev` | off | Developer convenience bundle (currently enables `basic-auth-filter`). | Local development builds. |
| `experimental` | off | Marker feature set transitively by experimental features; drives a startup warning. | Not selected directly; it lights up when an experimental feature is enabled. |

## Experimental features

Several features are *experimental*: each is off by default, each turns on the
`experimental` marker feature transitively, and enabling any of them makes the
server log `experimental features are enabled that should not be used in
production` at startup. Do not run an experimental build in production.

- **`basic-auth-filter`** (deprecated): the `basic_auth` filter. Credentials
  live in plaintext config, so it is for development and testing only. Prefer
  the policy engine for authentication.
- **`cloud-events-filter`**: the `cloud_events` filter, which serializes a
  request into a CloudEvent and ships it to a configured HTTP receiver.
  Delivery is best-effort and never changes the client response; review its
  limitations before relying on it.
- **`iterative-request-router`**: the `iterative_request_router` filter, a
  bounded loop of sequential sub-requests through named step pipelines. It
  powers provider failover and LLM agentic/tool loops and is the flagship
  consumer path for the AI gateway. Its streaming multi-step machine is
  high-complexity code that is still stabilizing.
- **`router-json-aliases`**: groundwork for routing on a JSON request-body
  field through the `router` filter. The matching primitives exist but are not
  wired into request routing, so a route that sets `json_aliases` is rejected
  at build even with the feature on. It is kept behind the flag for a future
  implementation; default builds do not carry the `json_aliases` keys at all.
- **`chain-binding`**: the `register_chain_binding` extension API and
  `ChainBindingContext::bind_chain`, together with the authority-bound
  deferred-credential channel (`PendingCredentials` / `DeferredCredential`)
  that injects a secret into an outbound sub-request only when the resolved
  destination matches the authority the credential was issued for. This is the
  outbound-callout mechanism; it has no in-tree consumer yet and exists for
  out-of-tree callout filters.
- **`spiffe`**: SPIFFE X.509-SVID mutual-TLS peer identity, including the
  `require_named` listener client-cert mode, plus the `peer_identity_trust`
  filter that authorizes clients by mTLS peer identity. Note that
  `peer_identity_trust` works with any mTLS client certificate, not only
  SPIFFE, so a non-SPIFFE mTLS deployment must still build with `spiffe` to use
  it.

## Notes

- **Runtime still gates behavior.** Building with `admin-api` does not start
  the admin endpoints; they bind only when `admin.address` is configured. A
  listener's `hot_reload: true` key takes effect only when the binary was
  built with `config-reload`; otherwise the certificate is served statically
  and a startup warning is logged.
- **The memory allocator is not a feature.** Praxis targets Linux and always
  uses `tikv-jemallocator`; there is no build toggle for it.
- **Where the savings are.** Dropping `policy-engine`, `config-reload`,
  `admin-api`, and `otel` is what trims the dependency tree and binary size,
  `policy-engine` by the widest margin. Most filters are always compiled in and
  share dependencies with the core proxy, so gating them individually would not
  remove a crate. The experimental filter gates (`iterative-request-router`,
  `chain-binding`, `router-json-aliases`) exist to keep unfinished or
  not-for-production surface out of default builds rather than to save a crate;
  `spiffe` and `cloud-events-filter` do additionally drop dependencies
  (`spiffe` + `x509-parser`, and `chrono` + `url` respectively).

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
