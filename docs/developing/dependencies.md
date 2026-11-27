# Dependency Policy & Review

The dependency policy, the tools that enforce it, and the provenance of every
direct workspace dependency.

## Policy

- Keep dependencies light. Avoid new dependencies when feasible.
- Only add dependencies with a well-established reputation: a canonical
  ecosystem crate, a crate from a known organization, or a crate maintained by
  this project's own organization.
- Declare versions in `[workspace.dependencies]` only, with full
  three-component semver (`1.2.3`, never `1.2` or `1`).
- Crates come from the crates.io registry. `deny.toml` denies git and
  unknown-registry sources (`unknown-registry = "deny"`,
  `unknown-git = "deny"`, empty `allow-git`).

## Enforcement Tooling

`make audit` runs cargo-audit and cargo-deny; CI runs them on every pull
request. `make lint` runs the other two.

- **cargo-audit**: scans `Cargo.lock` against the [RustSec advisory database]
  for vulnerable or unsound crates.
- **cargo-deny**: enforces the advisory, license-allowlist, duplicate-version,
  and source policies in [deny.toml].
- **cargo-machete**: detects declared-but-unused dependencies.
- **cargo xtask lint-deps**: requires three-component semver on every
  workspace dependency, and requires every member crate's dependencies to
  inherit from the workspace (`workspace = true`) or use a `path`. A
  dependency marked `# workspace:ignore` (inline or on the line before) is
  exempt.

### Advisory exceptions

Each accepted exception carries a reason. cargo-deny ignores live in
[deny.toml] and cargo-audit ignores in [.cargo/audit.toml], with the same list
in both. `deny.toml` gates both unmaintained and unsound advisories. Only
these IDs are excepted; vulnerability and unsoundness checks stay enabled.

- `RUSTSEC-2025-0134` (`rustls-pemfile` 2.2.0, unmaintained): transitive via
  the Pingora fork's `pingora-rustls` and `rustls-native-certs` 0.7.
- `RUSTSEC-2024-0436` (`paste` 1.0.15, unmaintained): a compile-time macro
  dependency of `cel` 0.12, pulled in by `limitador` for the Policy rate
  limiter.
- [RUSTSEC-2026-0543] (`chrono` 0.4.45, unmaintained): used directly for
  timestamps and transitively by Policy, the Pingora fork, and benchmark
  tooling.
- [RUSTSEC-2026-0555] (`chrono-tz` 0.10.4, unmaintained): transitive through
  Policy's CEL and OPA engines (`cel` and `regorus`).

The chrono advisories cover every version and have no patched release; the
exceptions accept the maintenance risk without resolving it. Migrate direct
chrono users to a maintained crate such as `jiff` or `time`, and remove the
exceptions once the transitive dependencies have migrated too.

[RUSTSEC-2026-0543]: https://rustsec.org/advisories/RUSTSEC-2026-0543
[RUSTSEC-2026-0555]: https://rustsec.org/advisories/RUSTSEC-2026-0555
[RustSec advisory database]: https://rustsec.org/
[deny.toml]: ../../deny.toml
[.cargo/audit.toml]: ../../.cargo/audit.toml

## Direct Dependency Review

Every `[workspace.dependencies]` entry, grouped by origin. A "canonical
ecosystem crate" is the de-facto standard for its niche, with an established
maintainer or organization behind it.

| Origin | Crates |
| ------ | ------ |
| Project-owned (praxis-proxy organization) | `quixotic-plecostomus-core` / `-http` / `-proxy`: temporary fork of Cloudflare's [Pingora] published by this project's maintainers from <https://github.com/praxis-proxy/pingora>, tracked for retirement on each upstream sync. `praxis-policy` (`ppe`): policy engine facade from <https://github.com/praxis-proxy/policy>. |
| rust-lang and adjacent | `futures`, `regex` (rust-lang); `rand` (rust-random) |
| tokio / hyperium | `tokio`, `tokio-stream`, `tokio-util`, `tokio-rustls`, `bytes`, `tracing`, `tracing-subscriber`, `async-trait`, `h2`, `http` |
| rustls project / RustCrypto | `rustls`, `rcgen`, `sha2`, `subtle`, `zeroize`; `secrecy` (below) |
| Observability | `metrics`, `metrics-exporter-prometheus` (metrics-rs); `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`, `tracing-opentelemetry` (OpenTelemetry project); `tonic`, `tonic-prost` (hyperium) |
| Serialization | `serde`, `serde_json` (dtolnay). `yaml_serde`: drop-in continuation of the deprecated `serde_yaml`, maintained by The YAML Organization (<https://github.com/yaml/yaml-serde>, published by a YAML language co-creator). |
| Other canonical ecosystem crates | `arc-swap`, `base64`, `chrono`, `clap`, `dashmap`, `nix`, `notify`, `percent-encoding`, `smallvec`, `thiserror`, `tikv-jemallocator` (TiKV project), `tokio-tungstenite` (tests), `quote` / `syn` (dtolnay, dev tooling), `criterion` / `plotters` (benchmarks), `tempfile`; `syslog` (below) |

**`secrecy`** wraps the credentials held by the `credential_injection` filter
so they are not accidentally logged and are zeroized on drop. It is the
ecosystem's de-facto secret wrapper (~37M recent downloads), maintained by Tony
Arcieri (iqlusion), author of `zeroize` and much of the RustCrypto stack, and
dual-licensed Apache-2.0 OR MIT. It has a single maintainer and its last
release was 2024-10-09, which is low risk for a small, feature-complete
primitive. If it goes dormant, vendor its narrow surface: it is a thin wrapper
over `zeroize`, already a direct dependency.

`tikv-jemalloc-sys` is included transitively in Unix default builds through
the non-optional `tikv-jemallocator`. The optional `overload-actions` feature
enables a direct dependency and uses it to purge unused pages from the binary's
jemalloc arenas. Only that direct dependency and explicit purge callback are
feature-gated; the allocator's transitive FFI dependency is already present.
It adds no cryptography.

`tikv-jemalloc-ctl` is the matching TiKV typed control API, enabled only by
`overload-actions`. Safe epoch and allocation-stat readers avoid raw FFI for
the allocator wiring check. Purging still needs a narrow raw command because
the crate has no typed arena-purge API. Both crates use the same jemalloc-sys
version and introduce no cryptography.

Every allocator upgrade requires manually re-auditing the version-specific
initialization and locking assumptions in `crates/server/src/allocator.rs`.
Run its `purge_contract_matches_locked_allocator` test with `overload-actions`;
update the version tripwire only after reviewing the new vendored source.

**`syslog`** backs the `access_log` filter's RFC 3164 sink. It is optional,
pulled in only by the off-by-default experimental `access-log-syslog` feature.
It is the de-facto Rust syslog client, maintained by Geoffroy Couprie (author
of `nom`) at <https://github.com/Geal/rust-syslog>, MIT-licensed. It has no
cryptography of its own (message framing is plain formatting, transport is
`std` sockets); it stays out of the default and FIPS builds only to keep those
trees minimal. If it goes dormant, vendor its narrow surface: RFC 3164
formatting over the `std::net` / `std::os::unix::net` sockets Praxis already
constructs directly.

## Review Cadence

- Every new dependency goes through this policy at review time and is added
  to the table above.
- `cargo audit` / `cargo deny` run in CI, so new advisories surface on the next
  pull request.
- The Pingora fork subtree and the `deny.toml` exceptions are re-evaluated on
  each fork sync (see the `skip-tree` note in [deny.toml]).
