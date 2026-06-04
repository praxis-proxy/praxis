---
sidebar_position: 2
title: Testing
---

# Development

## Requirements

- Rust stable 1.94+
- Rust nightly
- CMake 3.31+
- Docker 29.3.0+

## Conventions

**All contributors must read and understand
[Contributing](/docs/development/contributing) before contributing.** The conventions
cover code style, testing requirements, file
organization, and security practices. Submissions
that do not follow these conventions will be rejected.

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
`unsafe_code = "deny"` in workspace lints and Clippy runs with
`-D warnings` (zero tolerance).

See [System Design](/docs/architecture/system-design) for workspace layout
and crate dependencies.
See [Hardening Guide](/docs/security/hardening) for
deployment guidance.

## Adding a new Built-in Filter

Review [Custom Filters](/docs/filters/custom-filters) first.

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
6. Add a functional integration test in
   `tests/integration/tests/suite/examples/`.
7. Update `examples/README.md` to list any new or renamed
   example configs.

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
  csrf_log_only: false
  skip_pipeline_validation: false
```

| Flag | Effect |
| ------ | -------- |
| `allow_open_security_filters` | Allow security-critical filters (`ip_acl`, `forwarded_headers`) to use `failure_mode: open`. Without this flag, open security filters are rejected because a runtime error would bypass security enforcement. With this flag enabled, the error is demoted to a warning. |
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

## Project Management

All repositories in the `praxis-proxy` organization
use a consistent workflow for planning, prioritizing,
and tracking work.

### Milestones

Milestones represent a body of work toward a shared
goal (e.g. a release, a feature area, or a hardening
pass). Every issue and pull request should belong to
a milestone. Milestones provide scope boundaries and
help answer "what ships together?"

### Priority

Every issue should have a priority set via the
built-in Priority issue field (not labels). Address
work in priority order:

| Priority | Description |
| --- | --- |
| Urgent | Must be worked on immediately before anything else |
| High | Needs to be worked on immediately, defer to urgents |
| Medium | Resolve after high and urgent |
| Low | Resolve after all other priority levels |

### Size

Every issue should have a size set via the built-in
Size issue field. Size is a rough effort estimate:

| Size | Rough Estimate |
| --- | --- |
| Large | 1 week or more |
| Medium | Roughly 3 days |
| Small | Roughly 1 day |
| Tiny | Less than a day |

### Project Boards

GitHub project boards visualize the state of work
across milestones. Use boards to track issues through
their lifecycle (backlog, in progress, in review,
done). Boards are the primary tool for stand-ups and
status checks.

## Performance & Benchmarking

See [Benchmarks](benchmarks).
