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

For that exact invocation in this workspace, the guarantee holds: the server
depends on `praxis-proxy-filter` without dependency defaults, so dropping the
server's `policy-engine` feature leaves the filter and the policy engine's
dependency tree out of the build.

Library embedders need more than one `default-features = false`. Cargo unions
features across the whole dependency graph, so a single crate anywhere in that
graph that depends on `praxis-proxy-filter` with its defaults turns
`policy-engine` back on for everyone, and the `policy` filter registers itself
on the filter crate's own feature rather than the server's — it becomes
nameable in config in a build believed to be policy-free. Every edge reaching
`praxis-proxy-filter` must therefore set `default-features = false`. Verify with
`cargo tree -i praxis-policy`: no output means the policy engine really is out
of the build.

## Feature summary

| Feature | Default | Enables | Turn it off / on when |
| ------- | ------- | ------- | --------------------- |
| `config-reload` | on | Config-file and TLS-certificate hot-reload (filesystem watching). | Off for a static-config deployment: drops both watchers and the `notify`, `arc-swap`, and `tokio` dependencies they pull into the TLS crate. |
| `admin-api` | on | The admin HTTP service: management API (`/api/*`), Prometheus `/metrics`, and `/healthy` + `/ready`. | Off when the proxy exposes no monitoring or management surface. The data path and background health checks are unaffected; only the HTTP endpoints go away. |
| `otel` | off | OpenTelemetry / OTLP span export for traces. | On for distributed tracing. Pulls in a heavy `opentelemetry` + `tonic` dependency graph. |
| `policy-engine` | on | The `policy` filter (Praxis Policy Engine: OPA-style route policy, JWT identity, token exchange). | Off for a deployment that does no policy-based authorization: it is the heaviest optional dependency, so dropping it is the largest single saving in build time and binary size. |
| `basic-auth-filter` | off | The experimental `basic_auth` filter. | Dev and testing only. Slated for removal in favor of the policy engine ([praxis-proxy/policy]); prefer that for authentication. |
| `dev` | off | Developer convenience bundle (currently enables `basic-auth-filter`). | Local development builds. |
| `experimental` | off | Marker feature set transitively by experimental features; drives a startup warning. | Not selected directly; it lights up when an experimental feature is enabled. |

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
  remove a crate.

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
