# Dependency Policy & Review

Praxis keeps its dependency tree small, pinned, and
auditable. This page documents the policy, the
enforcement tooling, and a provenance review of every
direct workspace dependency.

## Policy

- Keep dependencies light. Avoid new dependencies
  when feasible.
- Only add dependencies with a well-established
  reputation: a canonical ecosystem crate, a crate
  from a known organization, or a crate maintained
  by this project's own organization.
- Declare versions in `[workspace.dependencies]`
  only, with full three-component semver
  (`1.2.3`, never `1.2` or `1`). `cargo xtask
  lint-deps` enforces this mechanically.
- Crates must come from the crates.io registry.
  Git and unknown-registry sources are denied via
  `deny.toml` (`unknown-registry = "deny"`,
  `unknown-git = "deny"`, empty `allow-git`).

## Enforcement Tooling

`make audit` runs both supply-chain checks; CI runs
them on every pull request.

- **cargo-audit**: scans `Cargo.lock` against the
  [RustSec advisory database] for vulnerable or
  unsound crates.
- **cargo-deny**: enforces the advisory,
  license-allowlist, duplicate-version, and source
  policies in [deny.toml].
- **cargo-machete** (via `make lint`): detects
  declared-but-unused dependencies.
- **cargo xtask lint-deps** (via `make lint`):
  requires three-component semver on every
  workspace dependency.

Accepted, documented exceptions live in
[deny.toml] with a reason each:

- `RUSTSEC-2024-0388` (`derivative`, unmaintained):
  transitive via the Pingora fork.
- `RUSTSEC-2025-0134` (`rustls-pemfile`,
  unmaintained): transitive via the Pingora fork's
  `pingora-rustls` only; `praxis-tls` migrated to
  the `rustls::pki_types` PEM iterators.
- `RUSTSEC-2026-0253` (`lru`, unsound `pop()` panic
  safety): transitive; tracked until a fixed
  release is available.

[RustSec advisory database]: https://rustsec.org/
[deny.toml]: ../../deny.toml

## Direct Dependency Review

Provenance of every `[workspace.dependencies]`
entry, grouped by origin. "Canonical ecosystem
crate" means the crate is the de-facto standard for
its niche, with an established maintainer or
organization behind it.

### Project-owned (praxis-proxy organization)

| Crate | Notes |
| ----- | ----- |
| `quixotic-plecostomus-core` / `-http` / `-proxy` | Temporary fork of Cloudflare's [Pingora] published by this project's maintainers from <https://github.com/praxis-proxy/pingora>; tracked for retirement on each upstream sync. |
| `praxis-policy` (`ppe`) | Policy engine facade from <https://github.com/praxis-proxy/policy>. |

### Rust project / rust-lang adjacent

| Crate | Notes |
| ----- | ----- |
| `futures` | rust-lang maintained async foundation. |
| `regex` | rust-lang maintained. |
| `rand` | rust-random organization. |

### Tokio / Tower ecosystem

`tokio`, `tokio-stream`, `tokio-util`,
`tokio-rustls`, `bytes`, `tracing`,
`tracing-subscriber`, `async-trait`, `h2`, `http` —
all maintained under the tokio / hyperium
organizations that underpin most of async Rust.

### TLS and cryptography (rustls / RustCrypto)

`rustls`, `rcgen`, `sha2`, `subtle`, `zeroize` —
maintained by the rustls project and the RustCrypto
organization.

### Observability

`metrics`, `metrics-exporter-prometheus`
(metrics-rs organization); `opentelemetry`,
`opentelemetry_sdk`, `opentelemetry-otlp`,
`tracing-opentelemetry` (OpenTelemetry project);
`tonic`, `tonic-prost` (hyperium).

### Serialization

| Crate | Notes |
| ----- | ----- |
| `serde`, `serde_json` | dtolnay-maintained ecosystem standards. |
| `yaml_serde` | Drop-in continuation of the deprecated `serde_yaml`, maintained by The YAML Organization (<https://github.com/yaml/yaml-serde>, published by a YAML language co-creator). |

### Other canonical ecosystem crates

`arc-swap`, `base64`, `chrono`, `clap`, `dashmap`,
`nix`, `notify`, `percent-encoding`, `smallvec`,
`thiserror`, `tikv-jemallocator` (TiKV project),
`tokio-tungstenite` (tests), `quote` / `syn`
(dtolnay, dev tooling), `criterion` / `plotters`
(benchmarks), `tempfile`.

## Review Cadence

- Every new dependency goes through this policy at
  review time and gets added to the table above.
- `cargo audit` / `cargo deny` run in CI, so new
  advisories surface on the next pull request.
- The Pingora fork subtree and the `deny.toml`
  exceptions are re-evaluated on each fork sync
  (see the `skip-tree` note in [deny.toml]).
