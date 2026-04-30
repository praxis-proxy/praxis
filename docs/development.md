# Development

## Requirements

- Rust stable 1.94+
- Rust nightly
- CMake 3.31+
- Docker 29.3.0+

## Conventions

**All contributors must read and understand
[conventions.md] before contributing.** The conventions
cover code style, testing requirements, file
organization, and security practices. Submissions
that do not follow these conventions will be rejected.

[conventions.md]:./conventions.md

## Build

```console
make build
make release
make check
```

### Test

```console
make test
```

```console
make test-integration
```

### Supply Chain Safety

Security is enforced at every stage of development.
`cargo audit` and `cargo deny check` are run as part of
the `make audit` target. The `deny.toml` config bans
wildcard version requirements, unknown registries, and
unknown git sources. Multiple versions of the same crate
produce a warning. All crates enforce
`#![deny(unsafe_code)]` and Clippy runs with
`-D warnings` (zero tolerance).

See [architecture.md](architecture.md) for workspace layout
and crate dependencies.
See [security-hardening.md](security-hardening.md) for
deployment guidance.

## Adding a new Built-in Filter

Review [extensions.md] first.

1. Create the filter module under
   `filter/src/builtins/<protocol>/<category>/`.
2. Implement `HttpFilter` (or `TcpFilter` for TCP-level
   filters). Add a `from_config` factory that deserializes
   a `serde_yaml::Value` into your config struct.
3. Register it in `filter/src/registry.rs`
   alongside the existing built-ins.
4. Add unit tests and doctests.
5. Add an example config in the appropriate category under
   `examples/configs/`.
6. Add an integration test in `tests/integration/`.

[extensions.md]:./extensions.md

## Adding a Protocol

1. Implement the `Protocol` trait in a new module under
   `protocol/src/`.
2. Add a variant to `ProtocolKind` in
   `core/src/config/listener.rs`.
3. Wire it up in `server/src/server.rs` where the protocol
   is selected.

## Security: Binding Low Ports

Praxis refuses to start when running as root (UID 0)
on Unix systems. This check runs before any port
binding or protocol registration. If you need to
bind ports below 1024, prefer one of these approaches:

- Grant `CAP_NET_BIND_SERVICE` to the binary:
  `sudo setcap cap_net_bind_service=+ep ./target/release/praxis`
- Run behind a reverse proxy or load balancer that
  handles port 80/443.
- Use socket activation (systemd) to pass pre-bound
  sockets.

## Insecure Options

> **Warning.** These flags are intended for development and
> testing only. Never enable them in production. Each flag demotes
> a security check from an error to a warning.

All flags live under `insecure_options` in the YAML config and default to `false`.

```yaml
insecure_options:
  allow_open_security_filters: false
  allow_private_health_checks: false
  allow_public_admin: false
  allow_root: false
  allow_tls_without_sni: false
  allow_unbounded_body: false
  skip_pipeline_validation: false
```

| Flag | Effect |
| ------ | -------- |
| `allow_open_security_filters` | Allow security-critical filters (`ip_acl`, `forwarded_headers`) to use `failure_mode: open`. Without this flag, open security filters are rejected because a runtime error would bypass security enforcement. |
| `allow_private_health_checks` | Allow health check endpoints that resolve to loopback (`127.0.0.0/8`) or cloud metadata addresses. Blocked by default as SSRF protection. |
| `allow_public_admin` | Allow the admin health endpoint to bind to a public interface (`0.0.0.0` / `[::]`). By default this is a validation error. |
| `allow_root` | Allow starting as root (UID 0). Praxis refuses to run as root by default. |
| `allow_tls_without_sni` | Allow upstream TLS connections without an explicit SNI hostname. Most TLS servers require SNI; without this flag, missing SNI is a validation error. |
| `allow_unbounded_body` | Allow `StreamBuffer` body mode without a size limit (`max_bytes: None`). Without this flag, unbounded stream buffering is rejected. |
| `skip_pipeline_validation` | Demote pipeline ordering errors (e.g. filter placement issues) to warnings instead of failing startup. |

Example overriding two flags for local development:

```yaml
admin:
  address: "0.0.0.0:9901"

insecure_options:
  allow_public_admin: true
  allow_private_health_checks: true
```

## Performance & Benchmarking

See [benchmarks.md](./benchmarks.md).
