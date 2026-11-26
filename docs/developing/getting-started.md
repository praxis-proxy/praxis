# Getting Started

For contributors building and changing Praxis. To configure and run a local
proxy, use the [operator quickstart](../getting-started/quickstart.md).

## Requirements

For a local build and targeted tests, install:

- Git and Make
- Rust stable pinned by [`rust-toolchain.toml`](../../rust-toolchain.toml)
  (rustup selects it automatically in the checkout)
- CMake 3.31+
- System OpenSSL development libraries and `pkg-config`

Clone the repository and build from its root:

```console
git clone https://github.com/praxis-proxy/praxis.git
cd praxis
cargo build -p praxis-proxy
```

While making changes, run focused tests, for example the core unit tests:

```console
cargo test -p praxis-proxy-core --lib
```

## Tools for linting and specialist workflows

Install the tools for the targets you plan to run:

- Rust nightly for `rustfmt`, at `NIGHTLY_VERSION` in the Makefile
- Docker 29.3.0+ or Podman (for container builds; the FIPS image, its
  signature verification and Red Hat's scanner need Podman on Linux)
- Go 1.26+ (`make fips-scanner`, optional)
- OpenShift CLI `oc` (`make fips-scan`, optional)
- `cargo-machete` (unused dependency detection, `make lint`)
- `cargo-audit`, `cargo-deny` (supply chain safety, `make audit`)
- `cargo-llvm-cov` (coverage, `make coverage-check`)
- `cargo-semver-checks` (SemVer compliance, optional)
- `cargo-mutants` (mutation testing, optional)
- `cargo-hack` (feature matrix checks, optional)
- `typos`, `taplo`, `shellcheck`, `actionlint`
  (non-Rust lint, `make lint-extra`)

## Conventions and Lint

Read [conventions.md](conventions.md) before contributing. It covers code
style, testing requirements, file organization, and security practices, and
submissions that don't follow it are rejected.

```console
make fmt
make lint
```

`make setup-hooks` installs a pre-commit hook that runs the linters before
every commit.

## Dev Utilities

`cargo xtask echo` starts a quick HTTP test backend:

```console
cargo xtask echo
cargo xtask echo --status 201 --body '{"created": true}'
```

`cargo xtask debug` runs the proxy with dev settings:

```console
cargo xtask debug
cargo xtask debug path/to/config.yaml
```

See [Build from source](../getting-started/build-from-source.md#quick-test-servers)
for full usage.

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
make test-rollout # temporarily disabled; prints SKIPPED
```

KIND rollout acceptance is disabled in CI and in both `make test-rollout`
and `cargo xtask rollout`: the four-node rootless cluster exhausts the host's
shared inotify instance budget before Praxis starts. Move the suite to
[gateway-controller](https://github.com/praxis-proxy/gateway-controller)
before re-enabling it. The harness and its assertions stay in
`tests/rollout` for the migration; a skipped run validates nothing.

Integration tests wait for the proxy to accept connections before sending
requests. The default readiness deadlines are 2s for TCP and 5s for HTTP,
HTTP/2, and TLS. On slow runners, notably under coverage instrumentation,
they can expire and cause spurious failures; set
`PRAXIS_TEST_READY_TIMEOUT_MS` (milliseconds) to raise the deadline for
every readiness utility. `make coverage` and `make coverage-check` already
set it.

### Supply Chain Safety

`make audit` runs `cargo audit` and `cargo deny check`. `deny.toml` bans
wildcard version requirements, unknown registries, and unknown git sources,
and warns on multiple versions of one crate. All crates enforce
`#![deny(unsafe_code)]`, and Clippy runs with `-D warnings`.

See the [crate layout](../architecture/crate-layout.md) for workspace
structure and [security-hardening.md](../operating/security-hardening.md)
for deployment guidance.

### FIPS Build and Compliance Check

The FIPS build does all cryptography in the system OpenSSL, which on a Red
Hat Enterprise Linux host in FIPS mode is the validated FIPS provider. It
leaves out features that are not FIPS compliant yet, currently the policy
engine. Its feature set is `FIPS_FEATURES` in the `Makefile`; the standard
build (`make build`, `make release`, `make container`) uses the default
features.

```console
make release-fips    # FIPS build, release profile, into target/fips
make build-fips      # same, debug profile, without the crate manifest
make container-fips  # FIPS runtime image on UBI 9, tagged praxis:<version>-fips
make lint-fips       # clippy and rustfmt for the FIPS feature set (CI runs it)
make test-fips       # unit tests for the FIPS feature set (CI runs it)
make test-integration-fips  # the integration suites against the FIPS feature set
make test-fips-host  # the whole suite as the FIPS build, inside the UBI 9 toolchain image, on a FIPS host
```

The compliance targets (`fips-deps`, `fips-report`, `fips-check`,
`fips-scanner`, `fips-scan`), the FIPS-host targets (`fips-host-check`,
`fips-runtime-probe`), and the base-image signature checks are in
[FIPS Tooling](fips.md), with what the report checks and the provenance of
the pinned images and signing key. `make container-fips`, `make fips-check`,
`make fips-smoke` and `make fips-scan` need a Linux podman, rootless or root.

### Hyper Backend (experimental)

The proxy can build on the experimental hyper backend instead of Pingora.
Its feature set is `HYPER_FEATURES` in the `Makefile`, and its builds go to
`target/hyper`. `BACKEND=hyper` points the standard test targets at it, so
`make test-integration BACKEND=hyper` runs the same suites on hyper. CI runs
the lint and test targets below.

```console
make build-hyper              # hyper build, debug profile, into target/hyper
make check-hyper              # cargo check of the hyper feature set, all targets
make lint-hyper               # clippy and rustfmt for the hyper feature set
make test-hyper               # unit tests resolved as the hyper build
make test-integration-hyper   # the integration suites on hyper
make test-conformance-hyper   # the conformance suite on hyper
```

See [hyper backend](../architecture/hyper-backend.md) for what the backend
covers and what is not at parity with Pingora yet.

## Security: Binding Low Ports

On Unix, Praxis refuses to start as root (UID 0), checked before any port
binding or protocol registration. To bind ports below 1024:

- Grant `CAP_NET_BIND_SERVICE` to the binary:
  `sudo setcap cap_net_bind_service=+ep ./target/release/praxis`
- Run behind a reverse proxy or load balancer that handles port 80/443.

## Insecure Options

> **Warning.** For development and testing only; never enable these in
> production. Each flag demotes a security check from an error to a warning.

All flags live under `insecure_options` in the YAML config and default to
`false`.

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
| `allow_open_security_filters` | Allow filters registered as `SecurityClass::Security` (built-ins such as `ip_acl` and `forwarded_headers`, and custom filters registered that way) to use `failure_mode: open`. Without it they are rejected, because a runtime error would bypass security enforcement. |
| `allow_private_endpoints` | Allow cluster endpoints to resolve to loopback, link-local, or cloud metadata addresses. Blocked by default as SSRF protection for upstream targets. |
| `allow_private_health_checks` | Allow health check endpoints that resolve to loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), or cloud metadata addresses. Blocked by default as SSRF protection. The probed endpoints are also cluster endpoints, so they additionally need `allow_private_endpoints`. |
| `allow_private_upstreams` | Allow upstream connections that resolve to private or reserved IP addresses at runtime. Without this flag, DNS-resolved upstream addresses in RFC 1918, loopback, link-local, CGNAT, and IPv6 unique-local ranges are rejected to prevent DNS rebinding and SSRF attacks, on both the TCP and HTTP data planes (including `iterative_request_router` sub-requests). Literal `host:port` upstreams are unaffected; those are gated at config time by `allow_private_endpoints`. |
| `allow_public_admin` | Allow the admin API listener to bind to a non-loopback address (`0.0.0.0`, a LAN IP, etc.). The health/metrics listener is not restricted to loopback by this flag. |
| `allow_root` | Allow starting as root (UID 0). Praxis refuses to run as root by default. |
| `allow_tls_no_verify` | Allow disabling upstream TLS certificate verification (`tls.verify: false` on a cluster), otherwise a validation error. |
| `allow_tls_without_sni` | Allow upstream TLS verification on a cluster with neither `tls.sni` nor `authority: { from: endpoint }`. The certificate is then verified against the cluster's fixed `authority` if set, else the client's `Host` header, which the client chooses. When that is not a hostname, the endpoint address is used instead. Without this flag, such a cluster is a validation error. IP endpoints don't need it: with `authority: { from: endpoint }` they are verified against the certificate's IP SAN. |
| `allow_unbounded_body` | Allow unbounded body processing: `body_limits.max_request_bytes` or `max_response_bytes` set to `null`, and `StreamBuffer` body mode without a `max_bytes` limit. Both are otherwise rejected at startup. |
| `csrf_log_only` | Run the CSRF filter in log-only mode: evaluate all rules but log violations as warnings instead of rejecting, for example during an initial rollout. |
| `skip_pipeline_checks` | Granular per-check pipeline validation bypass flags (`conditional_security`, `conflicting_cluster_selectors`, `duplicate_load_balancers`, `duplicate_rewrite_filters`, `duplicate_routers`, `lb_without_router`, `misaligned_clusters`, `unreachable_filters`). Prefer these over the blanket `skip_pipeline_validation` flag. |
| `skip_pipeline_validation` | **Deprecated.** Demote all pipeline ordering errors (such as filter placement) to warnings instead of failing startup. Use `skip_pipeline_checks`. |

Example overriding two flags for local development:

```yaml
admin:
  address: "0.0.0.0:9901"

insecure_options:
  allow_public_admin: true
  allow_private_health_checks: true
```

## Shared Build Cache with sccache

[sccache] caches compiled artifacts, so switching branches, cleaning
`target/`, or working across git worktrees doesn't rebuild every dependency.
[Install sccache][sccache-install] and add this to your shell profile
(`~/.bashrc`, `~/.zshrc`):

```sh
export RUSTC_WRAPPER=sccache
```

Warm the cache with one full clippy pass in any worktree:

```console
cargo clippy --workspace --all-targets
```

Later builds reuse the cache. Cargo still prints `Compiling` / `Checking` for
every crate, but cache hits finish in milliseconds. Check hit rates with
`sccache --show-stats`; see [sccache usage][sccache-usage] for configuration.

[sccache]: https://github.com/mozilla/sccache
[sccache-install]: https://github.com/mozilla/sccache#installation
[sccache-usage]: https://github.com/mozilla/sccache#usage

## Performance & Benchmarking

See [benchmarks.md](../benchmarks.md).
