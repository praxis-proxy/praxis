# Getting Started

## Requirements

- Rust stable 1.92+
- Rust nightly (for `rustfmt`)
- CMake 3.31+
- Docker 29.3.0+ or Podman (for container builds; the FIPS image, its
  signature verification and Red Hat's scanner need Podman on Linux)
- Go 1.26+ (`make fips-scanner`, optional)
- `cargo-machete` (unused dependency detection, `make lint`)
- `cargo-audit`, `cargo-deny` (supply chain safety, `make audit`)
- `cargo-llvm-cov` (coverage, `make coverage-check`)
- `cargo-semver-checks` (SemVer compliance, optional)
- `cargo-mutants` (mutation testing, optional)
- `cargo-hack` (feature matrix checks, optional)
- `typos`, `taplo`, `shellcheck`, `actionlint`
  (non-Rust lint, `make lint-extra`)

## Conventions

**All contributors must read and understand
[conventions.md] before contributing.** The conventions
cover code style, testing requirements, file
organization, and security practices. Submissions
that do not follow these conventions will be rejected.

[conventions.md]:./conventions.md

## Lint

```console
make fmt
make lint
```

It is recommended you run `make setup-hooks` to set
up pre-commit hooks that ensure linting is always
done before committing code.

## Dev Utilities

For rapid development and testing:

**Echo server** (quick HTTP test backend):

```console
cargo xtask echo
cargo xtask echo --status 201 --body '{"created": true}'
```

**Debug server** (run with dev settings):

```console
cargo xtask debug
cargo xtask debug path/to/config.yaml
```

See the [Quickstart](../quickstart.md#quick-test-servers) for full usage.

## Build

```console
make build
make release
make check
```

### Test

```console
make test
make test-integration
```

Integration tests wait for the proxy to start accepting connections
before issuing requests. On slow or heavily loaded runners (notably
under coverage instrumentation), the default readiness deadlines can
expire before startup finishes, producing spurious failures. Set
`PRAXIS_TEST_READY_TIMEOUT_MS` to a larger value (in milliseconds) to
raise the deadline for every readiness utility; `make coverage` and
`make coverage-check` already set it. When unset, the defaults apply
(2s for TCP, 5s for HTTP, HTTP/2, and TLS).

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

### FIPS Build and Compliance Check

Praxis targets FIPS 140-3 on Red Hat Enterprise Linux by performing all
cryptography in the RHEL OpenSSL FIPS provider. The standard build
(`make build`, `make release`, `make container`) enables everything by
default. The FIPS build turns off what is known not to be compliant yet,
currently the policy engine, so nobody has to know which features to
pick. The feature set is defined once, as `FIPS_FEATURES` in the
`Makefile`:

```console
make release-fips    # FIPS build, release profile, into target/fips
make build-fips      # same, debug profile, without the crate manifest
make container-fips  # FIPS runtime image on UBI 9, tagged praxis:<version>-fips
```

Three targets check a build against the rules Red Hat's release scanner
(`openshift/check-payload`) applies to Rust binaries, and explain every
finding with a reason and a pointer:

```console
make fips-deps     # dependency graph vs the crypto denylist (seconds, no build)
make fips-report   # full report against target/fips/release/praxis
make fips-check    # build on UBI 9 with Red Hat's toolchain, then report
make fips-scanner  # build Red Hat's scanner (check-payload) at its pinned revision
make fips-scan     # run that scanner on the FIPS image, warnings fatal: the gate
```

The report and the image verification are `cargo xtask fips` commands; the
Makefile targets wrap them. `make container-fips`, `make fips-check`,
`make fips-smoke` and `make fips-scan` need a Linux podman (rootless or
root): the UBI 9 base images are pinned by digest and their Red Hat
signatures are verified before every build (`cargo xtask fips
verify-image`), and the scanner reads podman's image store. On Debian
and Ubuntu, whose podman packaging ships no `registries.d` entry for Red
Hat's registry, run `make fips-signature-store` once first. The FIPS
image is built with Red Hat's `rust-toolset` and links the system
OpenSSL; nothing is installed into the runtime image beyond the binary
and its config. The report's exit status is non-zero while findings
remain. See [FIPS Tooling](fips.md) for what is checked, the provenance
of the pinned images and signing key, and why the build uses cargo's SBOM
precursor.

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
  allow_private_upstreams: false
  allow_public_admin: false
  allow_root: false
  allow_tls_no_verify: false
  allow_tls_without_sni: false
  allow_unbounded_body: false
  csrf_log_only: false
  skip_pipeline_checks: {}
  skip_pipeline_validation: false
```

| Flag | Effect |
| ------ | -------- |
| `allow_open_security_filters` | Allow filters registered as `SecurityClass::Security` (built-in examples: `ip_acl`, `forwarded_headers`; also custom filters registered as Security) to use `failure_mode: open`. Without this flag, open security filters are rejected because a runtime error would bypass security enforcement. With this flag enabled, the error is demoted to a warning. |
| `allow_private_endpoints` | Allow cluster endpoints to resolve to loopback, link-local, or cloud metadata addresses. Blocked by default as SSRF protection for upstream targets. |
| `allow_private_health_checks` | Allow health check endpoints that resolve to loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), or cloud metadata addresses. Blocked by default as SSRF protection. |
| `allow_private_upstreams` | Allow upstream connections that resolve to private or reserved IP addresses at runtime. Without this flag, DNS-resolved upstream addresses in RFC 1918, loopback, link-local, CGNAT, and IPv6 unique-local ranges are rejected to prevent DNS rebinding and SSRF attacks, on both the TCP and HTTP data planes (including `iterative_request_router` sub-requests). Literal `host:port` upstreams are unaffected; those are gated at config time by `allow_private_endpoints`. |
| `allow_public_admin` | Allow the admin health endpoint to bind to a non-loopback address (`0.0.0.0`, a LAN IP, etc.). By default admin must bind to loopback (`127.0.0.1` or `[::1]`). |
| `allow_root` | Allow starting as root (UID 0). Praxis refuses to run as root by default. |
| `allow_tls_no_verify` | Allow disabling upstream TLS certificate verification (`tls.verify: false` on a cluster). Without this flag, `verify: false` is a hard validation error. |
| `allow_tls_without_sni` | Allow upstream TLS connections without an explicit SNI hostname. Most TLS servers require SNI; without this flag, missing SNI is a validation error. |
| `allow_unbounded_body` | Allow unbounded body processing. This covers two checks: (1) `body_limits.max_request_bytes` or `max_response_bytes` set to `null`, and (2) `StreamBuffer` body mode without a `max_bytes` limit. Without this flag, both are rejected at startup. |
| `csrf_log_only` | Run the CSRF filter in log-only mode: evaluate all rules but log violations as warnings instead of rejecting requests. Useful for initial rollout monitoring. |
| `skip_pipeline_checks` | Granular per-check pipeline validation bypass flags (`conditional_security`, `conflicting_cluster_selectors`, `duplicate_load_balancers`, `duplicate_rewrite_filters`, `duplicate_routers`, `lb_without_router`, `misaligned_clusters`, `unreachable_filters`). Prefer these over the blanket `skip_pipeline_validation` flag. |
| `skip_pipeline_validation` | **Deprecated.** Demote ALL pipeline ordering errors (e.g. filter placement issues) to warnings instead of failing startup. Prefer the granular `skip_pipeline_checks` flags. |

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
