# FIPS Tooling

Local checks that a praxis build is on track for FIPS 140-3 on Red Hat
Enterprise Linux. They mirror what Red Hat's release scanner
(`openshift/check-payload`, Rust support in its PR #360) looks at, so a clean
local report predicts a clean scan. The build targets (`make release-fips`,
`make container-fips`) are in
[Getting Started](getting-started.md#fips-build-and-compliance-check), and
the operator guide is [FIPS 140-3](../operating/fips.md).

The report, the image verification and the signature-store setup are
`cargo xtask fips` commands (`xtask/src/fips/`) with Makefile wrappers. The
Makefile builds xtask without its default features (`XTASK_FIPS`), so these
targets never compile the standard proxy build; the report stage of
`Containerfile.fips` runs the same invocation.

| Command | Makefile | Purpose |
|---|---|---|
| `cargo xtask fips report [--deps-only] [--features LIST] [--offline] [--out FILE] [BINARY]` | `fips-deps`, `fips-report`, `fips-check` | The compliance report (below). Exits 1 while findings remain. |
| `cargo xtask fips verify-image [--pinned-in CONTAINERFILE] REFERENCE` | `fips-verify-image`, run first by `container-fips` and `fips-check` | Refuses a base image that is not digest-pinned, not from `registry.access.redhat.com`, or not signed by Red Hat's release key; with `--pinned-in`, also one the Containerfile does not pin by that digest. |
| `cargo xtask fips signature-store [--install]` | `fips-signature-store` | Checks that podman's `registries.d` names Red Hat's signature store, without which every Red Hat image looks unsigned. `--install` adds the bundled entry for the current user where the podman packaging ships none (Debian, Ubuntu, GitHub's runners). CI runs it before `fips-verify-image`. |
| `check-payload scan image ...` | `fips-scanner`, `fips-scan` | Red Hat's own scanner at a pinned revision, run on the FIPS image with warnings fatal. This is the actual gate. |

## What the report checks

1. **Dependency graph**: no crate from the scanner's `rust_denied_crypto`
   list (`ring`, `aws-lc-rs`, `sha2`, `hmac`, ...) in the shipped binary's
   normal dependency graph, resolved for the assessed feature set.
2. **Binary**: links the system `libcrypto.so.3` dynamically, defines no
   symbol of a bundled crypto backend (`ring_core_`, `aws_lc_`, `BORINGSSL_`,
   `OPENSSL_`), imports OpenSSL, and carries the rustc producer string and
   the cargo-auditable manifest (`.dep-v0`, built from cargo's SBOM
   precursor, listing no denied crate).
3. **Source guards**: the application never enables a FIPS provider itself,
   never uses OpenSSL's legacy (non-provider) digest API, and never vendors or
   statically links OpenSSL.

Each finding says why the scanner cares, where to look and what to do.

`--deps-only` skips the binary checks. `make fips-deps` runs the report that
way, after checking that the `CARGO_FEATURES` default in `Containerfile.fips`
matches `FIPS_FEATURES`, and `make lint` runs `make fips-deps`.

## Data compiled into xtask

From `xtask/assets/fips/`:

| File | Purpose |
|---|---|
| `redhat-release-key-2.asc` | Red Hat, Inc. (release key 2), the GPG key Red Hat signs its container images with. See provenance below. |
| `registry.access.redhat.com.yaml` | The `registries.d` entry that tells podman where Red Hat's signature store is. podman reads one `registries.d`: `~/.config/containers/registries.d` when it exists, else `/etc/containers/registries.d`. `verify-image` checks that this directory names the store, and `signature-store --install` writes the file into the user's directory when it does not. Fedora and RHEL ship the same entry in containers-common; Debian and Ubuntu ship no `registries.d` at all. |
| `fips-provider.cnf` | An `OPENSSL_CONF` that activates the RHEL FIPS provider for one process, so the report can probe FIPS behavior on hosts that are not in FIPS mode. Test infrastructure only; the application never enables FIPS itself. |

### Provenance of the signing key

`redhat-release-key-2.asc` was downloaded on 2026-09-22 from
`https://access.redhat.com/security/data/fd431d51.txt`. Its fingerprint,
`567E 347A D004 4ADE 55BA 8A5F 199E 2F91 FD43 1D51`, matches the one Red Hat
publishes for "Red Hat, Inc. (release key 2)" at
`https://access.redhat.com/security/team/key`. `verify-image` recomputes the
fingerprint on every run (RFC 4880 v4: SHA-1 over the public key packet, in
Rust) and stops if it differs; `cargo test -p xtask fips` checks the same.
podman's signature check needs gnupg (it verifies `signedBy` policies through
gpgme), and `verify-image` checks for it first.

The copy of this key inside the UBI image is an older export that lacks the
binding for the subkey Red Hat now signs with, so the published file is used
instead.

## cargo-auditable

Red Hat's scanner finds pure-Rust cryptography through the crate list that
`cargo auditable build` embeds in the binary (the `.dep-v0` section), and
grades a binary without one inconclusive. The UBI builder installs
`cargo-auditable` from crates.io at the version pinned in `Containerfile.fips`
(`CARGO_AUDITABLE_VERSION`). `make release-fips` uses it when it is installed
locally (`cargo install cargo-auditable --version 0.7.6 --locked`) and warns
when it is not. The Rust Secure Code Working Group maintains it; it embeds
data only, never code. The report decodes the section itself (zlib-compressed
JSON).

### Why the build uses cargo's SBOM precursor

The manifest must list exactly the crates compiled into the binary: the
scanner fails on a denied crate's name alone, whether or not its code was
linked. On a stable toolchain cargo-auditable derives the list from
`cargo metadata`, whose resolve is not the build's:

- It unifies features across every workspace member, dev-dependencies
  included. rcgen in the tls and protocol crates pulls `ring`; the test
  utilities enable the policy engine, which pulls `aws-lc-rs`, `sha2` and
  `hmac`.
- It activates weak features (`dep?/feature`) the real build never turns on.
  rustls always enables rustls-webpki's `alloc`, whose `ring?/alloc` entry
  puts `ring` in the resolve of a binary that never compiled it. No rustls
  user can avoid that one.

Cargo's SBOM precursor (`build.sbom`, unstable behind `-Zsbom`) comes from
cargo's own unit graph and is exact; cargo-auditable 0.7 reads it when
present. So `make release-fips` and `Containerfile.fips` run:

```console
RUSTC_BOOTSTRAP=1 CARGO_BUILD_SBOM=true cargo auditable -Zsbom \
    --config 'env.RUSTC_BOOTSTRAP.value="-1"' \
    --config 'env.RUSTC_BOOTSTRAP.force=true' \
    build --release -p praxis-proxy ...
```

`RUSTC_BOOTSTRAP=1` lets a stable cargo accept the `-Z` flag. It also turns
cargo's guard against a build script setting `RUSTC_BOOTSTRAP` through
`cargo:rustc-env` from an error into a warning; that value never reaches
rustc. The two `env` overrides give rustc and every build script
`RUSTC_BOOTSTRAP=-1`, which rustc treats as "no unstable features", so the
compiled code is exactly the stable code. The build scripts of proc-macro2
and thiserror probe for unstable APIs when the variable is set; with `-1` the
probes fail, as they do without it. The report checks the manifest's `format`
field, which is 8 when it came from the precursor, so a build that silently
fell back to `cargo metadata` is a finding.

Cargo before 1.99 does not relink a binary when only the SBOM setting
changed (rust-lang/cargo#15695, fixed by #17216), so both recipes remove the
old binary first; drop that once the toolchains in use are 1.99 or newer.
Drop the whole workaround once `build.sbom` is stable
(rust-lang/cargo#13709).

## Red Hat's scanner

`make fips-scanner` fetches `openshift/check-payload` at `CHECK_PAYLOAD_REV`
in the Makefile (the head of its PR #360, fetched by commit so a rewrite of
the PR cannot break the build) and builds it as upstream does
(`CGO_ENABLED=0 go build`, vendored modules) into `target/fips/check-payload/`.
It needs Go 1.26 or newer. Point `CHECK_PAYLOAD` at another build to use that
one instead.

`make fips-scan` runs the scanner on the FIPS image in podman's image store
(under `podman unshare` when podman is rootless) with `--fail-on-warnings`,
so an inconclusive verdict such as a missing manifest fails, as in Red Hat's
gated scans. It needs a Linux podman, rootless or root, not a podman machine.
It also needs the OpenShift CLI (`oc`) on `PATH`: the scanner refuses to
start without it, although an image scan never runs it.

Move `CHECK_PAYLOAD_REV` forward once the PR merges or a release carries Rust
support.

## Updating the pinned base images

The digests live in the `Makefile` (`FIPS_UBI9_DIGEST`,
`FIPS_UBI9_MINIMAL_DIGEST`) and, as defaults, in `Containerfile.fips`. For
each of `ubi9/ubi` and `ubi9/ubi-minimal`, look up the new digest and verify
it:

```console
curl -sI -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
  https://registry.access.redhat.com/v2/ubi9/ubi/manifests/latest | grep -i docker-content-digest
cargo xtask fips verify-image registry.access.redhat.com/ubi9/ubi@sha256:<new digest>
```

Update both files only once verification passes. `make fips-verify-image`
fails while they disagree.
