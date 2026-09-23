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

## What the report checks

1. **Dependency graph**: no crate on the scanner's `rust_denied_crypto` list
   (`ring`, `aws-lc-rs`, `sha2`, `hmac`, ...) in the shipped binary's normal
   dependency graph, resolved for the assessed feature set. `--deps-only`
   stops here; this is what `make lint` runs.
2. **Binary**: links the system `libcrypto.so.3` dynamically, defines no
   symbol of a bundled crypto backend (`ring_core_`, `aws_lc_`, `BORINGSSL_`,
   `OPENSSL_`), imports OpenSSL, carries the cargo-auditable manifest
   (`.dep-v0`, listing no denied crate) and the rustc producer string.
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
