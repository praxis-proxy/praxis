# FIPS Tooling

Local, reproducible checks that a praxis build is on the path to FIPS 140-3
compliance on Red Hat Enterprise Linux. The checks mirror what Red Hat's
release scanner (`openshift/check-payload`, Rust support in its PR #360) looks
at, so a clean local report is a strong predictor of a clean scan. The build
targets themselves (`make release-fips`, `make container-fips`) are described
in [Getting Started](getting-started.md#fips-build-and-compliance-check).

Everything here is a `cargo xtask fips` command (`xtask/src/fips/`), wrapped
by a Makefile target. The Makefile builds xtask without its default features
for these targets (`XTASK_FIPS`), so they never compile the standard proxy
build to run; the same invocation runs inside the report stage of
`Containerfile.fips`.

| Command | Makefile | Purpose |
|---|---|---|
| `cargo xtask fips report [--deps-only] [--features LIST] [--offline] [--out FILE] [BINARY]` | `fips-deps`, `fips-report`, `fips-check` | The compliance report: environment, dependency graph, binary structure, source guards, with a reason and a pointer for every finding. Exit status 1 while findings remain. |
| `cargo xtask fips verify-image REFERENCE` | `fips-verify-image` (run by `container-fips` and `fips-check` first) | Refuses any base image that is not digest-pinned, from `registry.access.redhat.com`, and signed by Red Hat's release key. |
| `check-payload scan image ...` | `fips-scanner`, `fips-scan` | Red Hat's own scanner at a pinned revision, run against the FIPS image with warnings fatal: the actual gate. |

## What the report checks

1. **Dependency graph**: no crate on the scanner's `rust_denied_crypto` list
   (`ring`, `aws-lc-rs`, `sha2`, `hmac`, ...) in the shipped binary's normal
   dependency graph, resolved for the assessed feature set. `--deps-only`
   stops here; this is what `make lint` runs.
2. **Binary**: links the system `libcrypto.so.3` dynamically, defines no
   symbol of a bundled crypto backend (`ring_core_`, `aws_lc_`, `BORINGSSL_`,
   `OPENSSL_`), imports OpenSSL, carries the cargo-auditable manifest
   (`.dep-v0`, built from cargo's SBOM precursor, listing no denied crate)
   and the rustc producer string.
3. **Source guards**: the application never enables a FIPS provider itself,
   never uses OpenSSL's legacy (non-provider) digest API, never vendors or
   statically links OpenSSL.

Every finding comes with why the scanner cares, where in the tree to look and
what to do about it.

## Data compiled into xtask

From `xtask/assets/fips/`:

| File | Purpose |
|---|---|
| `redhat-release-key-2.asc` | Red Hat, Inc. (release key 2), the GPG key Red Hat signs its container images with. See provenance below. |
| `registry.access.redhat.com.yaml` | The `registries.d` entry that tells podman where Red Hat's signature store is. podman reads only its own `registries.d` (`~/.config/containers/registries.d` or `/etc/containers/registries.d`; containers-common installs the same entry), so `verify-image` checks the host has one and prints this file to install when it does not. |
| `fips-provider.cnf` | An `OPENSSL_CONF` that activates the RHEL FIPS provider for one process, used by the report to probe FIPS behaviour on hosts that are not in FIPS mode. Test infrastructure only; the application never enables FIPS itself. |

### Provenance of the signing key

`redhat-release-key-2.asc` was downloaded on 2026-09-22 from Red Hat's key
distribution URL, `https://access.redhat.com/security/data/fd431d51.txt`. Its
fingerprint,

    567E 347A D004 4ADE 55BA 8A5F 199E 2F91 FD43 1D51

matches the fingerprint Red Hat publishes for "Red Hat, Inc. (release key 2)"
at `https://access.redhat.com/security/team/key`. `verify-image` recomputes
the fingerprint on every run (RFC 4880 v4: SHA-1 over the public key packet,
in Rust) and refuses to proceed if it differs; `cargo test -p xtask fips`
checks the same. podman's own signature check still needs gnupg installed
(it verifies `signedBy` policies through gpgme), which `verify-image`
checks for up front.

The copy of this key shipped inside the UBI image itself is an older export
that lacks the binding for the subkey Red Hat currently signs with; that is why
the published file, not the in-image file, is used.

## cargo-auditable

Red Hat's scanner finds pure-Rust cryptography through the crate list that
`cargo auditable build` embeds in the binary (the `.dep-v0` section); a binary
without it is graded inconclusive. The UBI builder installs `cargo-auditable`
from crates.io at the version pinned in `Containerfile.fips`
(`CARGO_AUDITABLE_VERSION`), and `make release-fips` uses it when it is
installed locally (`cargo install cargo-auditable --version 0.7.6 --locked`).
It is maintained by the Rust Secure Code Working Group and embeds data only,
never code. The report decodes the section itself (zlib-compressed JSON).

### Why the build uses cargo's SBOM precursor

The manifest has to list exactly the crates compiled into the binary: the
scanner fails on a denied crate's name alone, whether or not its code was
linked. On a stable toolchain cargo-auditable derives the list from
`cargo metadata`, and that resolve is not the build's:

- it unifies features across every workspace member, dev-dependencies
  included (rcgen in the tls and protocol crates pulls `ring`; the test
  utilities enable the policy engine, which pulls `aws-lc-rs`, `sha2` and
  `hmac`), and
- it activates weak features (`dep?/feature`) that the real build never turns
  on: rustls always enables rustls-webpki's `alloc`, whose `ring?/alloc`
  entry puts `ring` in the resolve of a binary that never compiled it. That
  one cannot be avoided by any rustls user.

Cargo's SBOM precursor (`build.sbom`, still unstable behind `-Zsbom`) is
written by cargo's own unit graph and is exact; cargo-auditable 0.7 reads
it when present. `make release-fips` and `Containerfile.fips` therefore run

```console
RUSTC_BOOTSTRAP=1 CARGO_BUILD_SBOM=true cargo auditable -Zsbom \
    --config 'env.RUSTC_BOOTSTRAP.value="-1"' \
    --config 'env.RUSTC_BOOTSTRAP.force=true' \
    build --release -p praxis-proxy ...
```

`RUSTC_BOOTSTRAP=1` lets a stable cargo accept the `-Z` flag (it also relaxes
cargo's guard against a build script setting `RUSTC_BOOTSTRAP` through
`cargo:rustc-env` from an error to a warning; the value is never forwarded
to rustc). The two `env` overrides replace it with `RUSTC_BOOTSTRAP=-1` for
rustc and every build script, and rustc treats `-1` as "no unstable
features", so the code compiled is exactly the stable code (the build scripts
of proc-macro2 and thiserror probe for unstable APIs when the variable is
set; with `-1` the probes fail, as they do without it). The report checks
the manifest's `format` field, which is 8 when it came from the precursor,
so a build that silently fell back to `cargo metadata` is a finding.

Cargo before 1.99 does not relink a binary when only the SBOM setting
changed (rust-lang/cargo#15695, fixed by #17216), so both recipes remove the
old binary first; drop that once the toolchains in use are 1.99 or newer.
Drop the whole workaround once `build.sbom` is stable
(rust-lang/cargo#13709).

## Red Hat's scanner

`make fips-scanner` fetches the pinned commit of `openshift/check-payload`
(`CHECK_PAYLOAD_REV` in the Makefile, the head of its PR #360, fetched by
commit so a rewrite of the PR cannot break the build) and builds it the way
upstream does (`CGO_ENABLED=0 go build`, vendored modules) into
`target/fips/check-payload/`; it needs Go 1.26 or newer. `make fips-scan`
runs it against the FIPS image from podman's image store (under
`podman unshare` when podman is rootless) with `--fail-on-warnings`, so an
inconclusive verdict such as a missing manifest fails, as it does in Red
Hat's gated scans. Both need a Linux podman, rootless or root, not a podman
machine. Point `CHECK_PAYLOAD` at another build to use it instead. Move
`CHECK_PAYLOAD_REV` forward once the PR merges or a release carries Rust
support.

## Updating the pinned base image

The digests live in the `Makefile` (`FIPS_UBI9_DIGEST`,
`FIPS_UBI9_MINIMAL_DIGEST`) and, as defaults, in `Containerfile.fips`. To move
to a newer UBI 9:

```console
curl -sI -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
  https://registry.access.redhat.com/v2/ubi9/ubi/manifests/latest | grep -i docker-content-digest
cargo xtask fips verify-image registry.access.redhat.com/ubi9/ubi@sha256:<new digest>
```

Only update both places once the verification passes.
