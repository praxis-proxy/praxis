# Getting Started

## Requirements

- Rust stable 1.96+
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

See the [crate layout](../architecture/crate-layout.md) for workspace
structure and crate dependencies.
See [security-hardening.md](../operating/security-hardening.md) for
deployment guidance.

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
  allow_private_endpoints: false
  allow_private_health_checks: false
  allow_public_admin: false
  allow_root: false
  allow_tls_without_sni: false
  allow_unbounded_body: false
  csrf_log_only: false
  skip_pipeline_validation: false
```

| Flag | Effect |
| ------ | -------- |
| `allow_open_security_filters` | Allow security-critical filters (`ip_acl`, `forwarded_headers`) to use `failure_mode: open`. Without this flag, open security filters are rejected because a runtime error would bypass security enforcement. With this flag enabled, the error is demoted to a warning. |
| `allow_private_endpoints` | Allow cluster endpoints to resolve to loopback, link-local, or cloud metadata addresses. Blocked by default as SSRF protection for upstream targets. |
| `allow_private_health_checks` | Allow health check endpoints that resolve to loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), or cloud metadata addresses. Blocked by default as SSRF protection. |
| `allow_public_admin` | Allow the admin health endpoint to bind to a public interface (`0.0.0.0` / `[::]`). By default this is a validation error. |
| `allow_root` | Allow starting as root (UID 0). Praxis refuses to run as root by default. |
| `allow_tls_without_sni` | Allow upstream TLS connections without an explicit SNI hostname. Most TLS servers require SNI; without this flag, missing SNI is a validation error. |
| `allow_unbounded_body` | Allow unbounded body processing. This covers two checks: (1) `body_limits.max_request_bytes` or `max_response_bytes` set to `null`, and (2) `StreamBuffer` body mode without a `max_bytes` limit. Without this flag, both are rejected at startup. |
| `csrf_log_only` | Run the CSRF filter in log-only mode: evaluate all rules but log violations as warnings instead of rejecting requests. Useful for initial rollout monitoring. |
| `skip_pipeline_validation` | Demote pipeline ordering errors (e.g. filter placement issues) to warnings instead of failing startup. |

Example overriding two flags for local development:

```yaml
admin:
  address: "0.0.0.0:9901"

insecure_options:
  allow_public_admin: true
  allow_private_health_checks: true
```

## Shared Build Cache with sccache

[sccache] caches compiled artifacts so that switching
branches, cleaning `target/`, or working across
multiple git worktrees does not require rebuilding
every dependency from scratch.

### Setup

[Install sccache][sccache-install], then add the
following to your shell profile (`~/.bashrc`,
`~/.zshrc`, etc.):

```sh
export RUSTC_WRAPPER=sccache
```

### Warming the cache

After setting up sccache, run a full clippy pass in any
worktree to populate the cache:

```console
cargo clippy --workspace --all-targets
```

Subsequent builds reuse the cached artifacts
automatically. Cargo still prints `Compiling` /
`Checking` for every crate, but cache-hit compilations
complete in milliseconds instead of seconds.

Check hit rates with `sccache --show-stats`. See
[sccache usage][sccache-usage] for more configuration
options.

[sccache]: https://github.com/mozilla/sccache
[sccache-install]: https://github.com/mozilla/sccache#installation
[sccache-usage]: https://github.com/mozilla/sccache#usage

## Performance & Benchmarking

See [benchmarks.md](../benchmarks.md).
