# FIPS Tooling

Local checks that a praxis build is on track for FIPS 140-3 on Red Hat
Enterprise Linux. They mirror what Red Hat's release scanner
(`openshift/check-payload`, Rust support in its PR #360) looks at, so a clean
local report predicts a clean scan. The build targets (`make release-fips`,
`make container-fips`) are in
[Getting Started](getting-started.md#fips-build-and-compliance-check), and
the operator guide is [FIPS 140-3](../operating/fips.md).

The report, image verification, signature-store setup and host attestation
are [`cargo fips-check`](https://github.com/praxis-proxy/cargo-fips-check)
commands with Makefile wrappers. It is a separate tool shared with other Rust
projects; [`fips-check.toml`](../../fips-check.toml) at the workspace root
tells it what is specific to this tree (the shipped package, the paths the
source guards scan, where a denied crate usually comes from, what the unit
tests may link). The Makefile installs it at a pinned commit
(`FIPS_CHECK_REV`) under `target/fips/tools` on first use; set `FIPS_CHECK`
to use another build. The toolchain stage of `Containerfile.fips` installs
the same commit, and `make fips-deps` fails while the two differ.

Only the runtime probe is Praxis-specific and stays in `cargo xtask fips`
(`xtask/src/fips/`). The Makefile builds xtask without its default features
(`XTASK_FIPS`), so it never compiles the standard proxy build.

| Command | Makefile | Purpose |
|---|---|---|
| `cargo fips-check report [--deps-only] [--features LIST] [--offline] [--out FILE] [BINARY]` | `fips-deps`, `fips-report`, `fips-check` | The compliance report (below). Exits 1 while findings remain. |
| `cargo fips-check verify-image [--pinned-in CONTAINERFILE] REFERENCE` | `fips-verify-image`, run first by `container-fips` and `fips-check` | Refuses a base image that is not digest-pinned, not from `registry.access.redhat.com`, or not signed by Red Hat's release key; with `--pinned-in`, also checks that the supported UBI base stage consumes the matching named digest argument and its default matches the verified reference. This checks the recipe and defaults, not arbitrary build-argument overrides or adversarial source changes. |
| `cargo fips-check signature-store [--install]` | `fips-signature-store` | Checks that podman's `registries.d` names Red Hat's signature store, without which every Red Hat image looks unsigned. `--install` adds the bundled entry for the current user where the podman packaging ships none (Debian, Ubuntu, GitHub's runners). CI runs it before `fips-verify-image`. |
| `check-payload scan image ...` | `fips-scanner`, `fips-scan` | Red Hat's own scanner at a pinned revision, run on the FIPS image with warnings fatal. This is the actual gate for what is in the image. |
| `cargo fips-check host-check [--image IMAGE] [--require-certified] [--out FILE] [--json FILE]` | `fips-host-check` | On a FIPS host: attest the kernel flag, `fips=1`, the crypto policy, `fips-mode-setup --check` and the module the host's OpenSSL loads; with `--image`, the crypto policy podman propagated into the container and the build of `fips.so` the image carries, looked up in the list of module builds the tool carries. Exit 1 on any unmet requirement. |
| `cargo xtask fips runtime-probe IMAGE [--toolchain-image IMAGE] [--host-cargo] [--log FILE]` | `fips-runtime-probe` | On a FIPS host: start the image under `PRAXIS_REQUIRE_FIPS=1` with a TLS listener, run the listener probes of the integration suite against it (inside the toolchain image, or with the host's cargo), and check the startup status line. |

## The FIPS host run

The hosted checks prove what is in the image. What the image does in FIPS
mode can only be proven on a RHEL 9 host in FIPS mode, and these pieces make
that proof a Make target.

**The suites as the FIPS build.** `make test-integration-fips` runs the
schema, security, integration and resilience suites (and
`test-conformance-fips` the conformance suite) with `--no-default-features`,
so the proxy each suite starts in process is built exactly as the FIPS binary
is: the workspace declares the binary crate without its defaults, and every
test crate opts into `policy-builtins` through its own default feature. Tests
that spawn the binary get the FIPS build through `PRAXIS_BIN`
(`make build-fips` produces it first). `cargo tree -e normal,dev --no-default-features
-p praxis-tests-integration -i aws-lc-rs` prints nothing for that graph; only
`ring` remains, for rcgen's test certificates.

**Both branches, always.** The FIPS behavior tests
(`crates/tls/tests/fips_mode.rs`, `tests/integration/tests/suite/fips.rs`)
key their expectations on what the installed provider reports
(`praxis_tls::provider::status().provider_fips`): on a host whose OpenSSL is
in approved mode they prove the refusals, anywhere else they prove the same
offers are accepted, so they mean something on every machine and in hosted
CI. `PRAXIS_FIPS_HOST=1` declares the host to be in FIPS mode: the harness
then fails closed the first time it installs the provider on a host that is
not (all three signals: provider, kernel flag and crypto policy), and every
behavior test insists on its approved-mode branch. A green run on the FIPS
runner therefore cannot have happened on OpenSSL's default provider.

**Inside the toolchain image.** `make test-fips-host` builds the `toolchain`
stage of `Containerfile.fips` (Red Hat's `rust-toolset` and OpenSSL, no
sources) and runs `test-fips`, `test-integration-fips` and
`test-conformance-fips` in it against the bind-mounted checkout, with
`PRAXIS_FIPS_HOST=1` and `PRAXIS_REQUIRE_FIPS=1`. OpenSSL and the module
under test are the image's, the same packages the FIPS image is built with;
the kernel flag and FIPS crypto policy are the host's, passed in by podman.

- The container runs as the invoking user (rootless podman's
  `--userns=keep-id`), since praxis refuses to start as root.
- The cargo home and target directory live in named volumes
  (`praxis-fips-host-cargo`, mounted with `:U` so it belongs to that user,
  and `praxis-fips-host-target`), so later runs are incremental.
- The run opens with `make fips-host-facts`, which logs what the test process
  sees (kernel flag, crypto policy, the providers OpenSSL loads, whether MD5
  is refused) and fails right there when `PRAXIS_FIPS_HOST` is declared on a
  container that is not in FIPS mode.
- The resilience suite's throughput floors, sized for GitHub's hosted
  runners, are scaled down (`PRAXIS_TEST_THROUGHPUT_SCALE`, from the
  Makefile's `FIPS_HOST_THROUGHPUT_SCALE`, 0.5 by default).

**The raw TLS probes.** `tests/utils/src/tls_probe.rs` builds `ClientHello`
records that offer exactly what a test names (ChaCha20 only, X25519 only,
TLS 1.2 without Extended Master Secret) and reads the listener's first record
back: a `ServerHello` means accepted, an alert means refused. A rogue server
does the reverse for the upstream client: it records what praxis offered,
answers with a chosen `ServerHello` or alert, and watches for the client's
alert. No cryptography is involved, so the probes work against any listener,
including the shipped image, on any host.

**Policy FIPS construction.** Every run executes four startup scenarios in
isolated child processes with their own `OPENSSL_CONF`, each with an explicit
expected result checked against the kernel flag:

| Scenario | Configurable provider, non-FIPS kernel | RHEL FIPS kernel |
|---|---|---|
| Base-only config | SHA-256 is unavailable; construction fails with `policy.crypto_failed` | FIPS SHA-256 remains available, MD5 is refused, construction succeeds |
| JWT config without FIPS defaults | FIPS SHA-256 and MD5 are available; JWT construction rejects non-FIPS defaults | MD5 remains refused; FIPS JWT construction succeeds |
| Rival `jsonwebtoken` provider | Construction refuses the rival provider | Construction refuses the rival provider |
| Three JWT loads in one process | All succeed | All succeed |

RHEL activates its FIPS provider and default properties when the kernel
requires FIPS, even if the supplied config omits them, so the tests assert
the effective crypto state before checking Policy construction.

`make test-fips-policy-provider` runs all four in the UBI toolchain image on a
non-FIPS kernel; the hosted `FIPS` job requires it on every PR and push.
`make test-fips-host` runs them on the FIPS runner with the unit,
integration and conformance suites, and `make test-fips-provider` also
includes the configurable-provider startup checks. The general `test-fips`
unit target excludes these scenarios, so it does not require
`FIPS_POLICY_STARTUP_MODE`; both container entrypoints run the dedicated
startup target separately, including with a Policy profile. For a direct run
inside the toolchain image:

```console
make test-fips-policy-startup FIPS_POLICY_STARTUP_MODE=configurable-provider \
    FIPS_POLICY_PROVIDER_CONF=xtask/assets/fips/fips-provider.cnf
```

Use mode `kernel-fips` on the FIPS host. A missing mode, wrong kernel mode,
missing provider config, ignored test or missing scenario fails the gate;
there are no successful skips. The tests exercise Policy's existing crypto
validation; Praxis adds no production crypto checks.

**Policy FIPS profiles.** The default FIPS build leaves Policy out.
`FIPS_POLICY_PROFILE` (`none`, `engine`, `api-key`, `jwt`, `both`; features
per profile in [the operator guide](../operating/fips.md#the-policy-filter-on-fips))
opts one in, and every FIPS target honors it: the build, `lint-fips`,
`test-fips`, `test-integration-fips`, `fips-deps`, `fips-report`,
`container-fips` (tagged `<version>-fips-policy-<profile>`), `fips-scan` and
`fips-runtime-probe`.

A Policy profile refuses to build its filter without a FIPS provider, so its
tests need one. `make test-fips-provider FIPS_POLICY_PROFILE=jwt` runs
`test-fips`, `test-fips-policy-startup` and `test-integration-fips` inside
the toolchain image with Red Hat's module activated by
`xtask/assets/fips/fips-provider.cnf`. It works with docker or podman on a
non-FIPS kernel, so `test-fips-host` remains the FIPS-host proof; on the host
itself those tests check the refusal instead. The `FIPS Policy profiles`
workflow runs the four profiles nightly and on dispatch. The JWT example
tests sign RS256 and ES256 tokens and DPoP proofs at run time with the
test-only keys in `tests/integration/fixtures/policy-fips/`; the runtime
probe signs its own with keys generated for the run.

`fips-deps` checks the profile's production graph (normal and build edges)
and, separately, the unit-test graph `make test-fips` compiles. A test edge
may not add a feature to a crypto-selecting crate (`jsonwebtoken`, the Policy
crates, rustls, openssl), may never bring in `aws-lc-rs`, and may bring in
another denied crate only with a reason under `[test_graph.test_only]` in
`fips-check.toml`.

**The fixtures.** `tests/integration/fixtures/fips/` holds a short RSA key
and a SHA-1-signed certificate, with the commands that made them in its
`README.md`.

## Simulating approved mode

A host not in FIPS mode can still exercise the approved-mode branch of every
behavior test against Red Hat's real module, by activating the FIPS provider
for the test processes alone with `xtask/assets/fips/fips-provider.cnf`.
Inside the toolchain image:

```console
make fips-toolchain
podman run --rm --userns=keep-id --security-opt label=disable -v "$PWD":/src -w /src \
    -v praxis-fips-host-cargo:/cargo:U -v praxis-fips-host-target:/target \
    -e OPENSSL_CONF=/src/xtask/assets/fips/fips-provider.cnf \
    praxis-fips-toolchain make test-fips test-integration-fips test-conformance-fips \
        FIPS_TARGET_DIR=/target FIPS_CARGO_EXTRA=--ignore-rust-version
```

The provider reports approved algorithms only, so the tests prove the
refusals. The kernel flag still reads `0`, so the `PRAXIS_REQUIRE_FIPS` test
proves the refusal to start instead of the serving path, and
`PRAXIS_FIPS_HOST` must stay unset (it would fail closed, correctly).

## The runner job

The `fips-host` job of the `FIPS` workflow runs on the self-hosted runner
labeled `fips` and `rhel`: a RHEL 9 host in FIPS mode with `git`, `make`,
`podman`, `gnupg2`, `gcc`, `gcc-c++`, `cmake` and `openssl-devel` installed
(the host-side commands, `cargo fips-check` and `cargo xtask fips`, compile
there, and `verify-image` checks Red Hat's signatures through gpg; the suites
compile inside the toolchain image). The runner's group must grant this
public repository access, which GitHub does not do by default. Its steps are
the composite action `.github/actions/fips-host`, so the release workflow can
run the same checks against a pushed image.

The hosted `ubi-image` job is the
[cargo-fips-check action](https://github.com/praxis-proxy/cargo-fips-check#github-action),
pinned by commit: the dependency report, the base image verification, the
build and report on UBI 9, the runtime image, one run of it and the scan,
followed here by the Policy startup scenarios.

The runner tests the exact image that job built and scanned: the action saves
the image as an artifact with its id (as `make fips-image-save` does), and
the runner loads it and checks the id against the one the hosted job
recorded (`make fips-image-load`). A self-hosted runner must never run a
fork's code, so on pull requests the job runs only for branches of this
repository; it also runs on every push to main, nightly, and on dispatch.
The release workflow's `fips-host` job pulls the pushed `-fips` image by
digest, attests and probes it (without repeating the suites), and the draft
release waits for it.

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

## Bundled data

Red Hat's release key, the `registries.d` entry for its signature store and
the list of FIPS provider module builds with their standing at NIST are
compiled into `cargo fips-check`; their provenance is in
[its README](https://github.com/praxis-proxy/cargo-fips-check#bundled-data).
To change any of them, change that tool and move `FIPS_CHECK_REV` (and
`CARGO_FIPS_CHECK_REV` in `Containerfile.fips`).

The one file in this tree is `xtask/assets/fips/fips-provider.cnf`, an
`OPENSSL_CONF` that activates the RHEL FIPS provider for one process, used by
the FIPS test targets on hosts not in FIPS mode. It is test infrastructure
only; the application never enables FIPS itself.

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
target/fips/tools/bin/cargo-fips-check verify-image registry.access.redhat.com/ubi9/ubi@sha256:<new digest>
```

Update both files only once verification passes. `make fips-verify-image`
fails while they disagree.
