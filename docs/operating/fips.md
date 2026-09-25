# FIPS 140-3

Praxis does all of its cryptography in the system OpenSSL library. On a Red
Hat Enterprise Linux 9 host in FIPS mode, that library's provider is the
validated module (Red Hat Enterprise Linux 9 OpenSSL FIPS Provider, CMVP
certificate #4857 at the time of writing; Red Hat keeps the current list at
<https://access.redhat.com/compliance/fips>). There, praxis does its TLS,
hashing and random numbers inside a FIPS 140-3 validated boundary. Praxis
itself is not a validated module and never turns FIPS mode on: the host does,
and praxis reports it and, on request, enforces it.

This page is for operators deploying the FIPS build. How the build is checked
is in [FIPS Tooling](../developing/fips.md).

## The FIPS build

The standard build (`make release`, `make container`) uses the default
features. The FIPS build leaves out what is not yet FIPS compliant:

| | Standard | FIPS |
|---|---|---|
| Make targets | `release`, `container` | `release-fips`, `container-fips` |
| Cargo features | defaults | `config-reload,admin-api` |
| `policy` filter (policy engine) | yes | no: its dependencies carry their own cryptography |
| Base image | Alpine, praxis built with upstream Rust | `ubi9/ubi-minimal`, praxis built with Red Hat's `rust-toolset` on `ubi9/ubi`, both pinned by digest and signature-verified |
| OpenSSL | Alpine's, dynamically linked | UBI's, dynamically linked (`openssl-libs` and `openssl-fips-provider-so`), the validated module on a FIPS host |
| Published tags | `<version>`, `<major>.<minor>`, `latest`, `sha-<hash>`, `nightly` (see [image tags](../release.md#image-tags)) | the same with a `-fips` suffix (`0.7.0-fips`, `latest-fips`) |

The FIPS build rejects a configuration that uses the `policy` filter at
startup. Everything else, including TLS listeners, mTLS, SNI, the admin API
and hot reload, works as in the standard build.

The binary links `libcrypto.so.3` and `libssl.so.3` dynamically. The only
crates in the image that do security-relevant cryptography are rustls and the
OpenSSL bindings, which hand every primitive to the system library.
[Scope and exemptions](#scope-and-exemptions) covers the rest.

## Host prerequisites

The module's Security Policy (section 11.2, "Crypto Officer guidance") sets
the terms; a deployment that does not meet them is not running the validated
module, whatever the image contains.

- A RHEL 9 host in FIPS mode. The Security Policy accepts both ways of
  getting there: `fips=1` on the kernel command line at installation, or
  `fips-mode-setup --enable` and a reboot afterwards. Red Hat's own guidance
  prefers installation time, since only then are all of the system's keys
  generated under FIPS mode. Either way `fips-mode-setup --check` must say
  `FIPS mode is enabled.`, `cat /proc/sys/crypto/fips_enabled` prints `1`,
  and the kernel command line carries `fips=1`.
- The system-wide crypto policy left at `FIPS`, with no restrictions added.
- `openssl list -providers` on the host lists the `fips` provider as active,
  with the version string the certificate names (`3.0.7-395c1a240fbfffd8`
  for certificate #4857). The Security Policy is explicit that the
  cryptographic boundary is that provider alone: a different build of the
  module, or any other provider, is not the validated module.
- A container runtime that passes the host's FIPS mode into the container,
  as podman and CRI-O on RHEL do: they bind-mount the FIPS crypto policy
  the image ships over the container's own, and the kernel flag is visible
  through `/proc`. The `-fips` image then needs no flag, environment
  variable or config: its OpenSSL reads the kernel flag and activates the
  validated provider itself. On a host that is not in FIPS mode the same
  image runs with OpenSSL's default provider, and the startup log says so.

The module that runs inside the container is the image's own
`openssl-fips-provider-so`, not the host's, so the same version requirement
applies to the image; see [what is validated](#what-is-validated-and-what-is-not)
for where the current image stands.

## Startup checks

At startup praxis installs its crypto provider and logs the FIPS status:

```text
installed rustls crypto provider provider="openssl" provider_fips=true kernel_fips=Some(true) fips_required=true
```

- `provider_fips`: whether OpenSSL's default properties select only
  FIPS-approved algorithms (`EVP_default_properties_is_fips_enabled`), which
  is what RHEL's FIPS mode configures.
- `kernel_fips`: `/proc/sys/crypto/fips_enabled`; `None` where the file does
  not exist (a container without `/proc`, a non-Linux host).

Set `PRAXIS_REQUIRE_FIPS=1` in production FIPS deployments. An empty value,
`0`, `false`, `no` or `off` leaves it off; any other value, a typo included,
turns it on. It is a check, not a switch. With it on, praxis refuses to start:

- unless both signals above are present, and names each one that is missing;
- when a listener's TLS configuration is not FIPS-approved by rustls;
- when the binary registers the `policy` filter, as the standard build does:
  the policy engine verifies JWTs with aws-lc-rs and its OAuth and Valkey
  plugins hash with the RustCrypto `hmac` and `sha2` crates, none of which
  is the system OpenSSL. Use the FIPS build.

Upstream connections always require Extended Master Secret and use the same
provider, so they are FIPS whenever the listeners are. Without the variable,
praxis starts either way and only logs the status.

```console
podman run --rm -e PRAXIS_REQUIRE_FIPS=1 ghcr.io/praxis-proxy/praxis:0.7.0-fips
```

On a host that is not in FIPS mode this exits immediately with:

```text
fatal: PRAXIS_REQUIRE_FIPS is set but FIPS mode is not in effect: the OpenSSL provider does not report FIPS-approved algorithms (is the fips provider active?); the kernel is not in FIPS mode (/proc/sys/crypto/fips_enabled is 0)
```

## TLS behavior

- **TLS 1.2 requires the Extended Master Secret extension (RFC 7627)** on
  listeners and upstream connections, in every build and with or without
  FIPS mode. A TLS 1.2 peer that cannot negotiate it fails the handshake;
  TLS 1.3 is unaffected. FIPS 140-3 requires it for TLS 1.2 key derivation,
  and rustls counts a configuration as FIPS only with it.
- **In FIPS mode the provider offers only what the module approves.**
  Non-approved algorithms are absent rather than failing later: the
  ChaCha20-Poly1305 cipher suites are not offered, MD5 does not exist, and
  keys or certificates the module refuses (short RSA keys, legacy signature
  algorithms) are rejected at load or first use. The module and the host's
  crypto policy decide what is approved, not praxis. A listener whose
  `cipher_suites` names only suites the provider does not offer fails to
  build, in every build and mode.
- **Random numbers** for every TLS operation come from OpenSSL's DRBG
  (`RAND_priv_bytes`). Randomness that protects nothing (load-balancer
  picks, request ids) uses ordinary Rust RNGs.

## Verifying a deployment

Two kinds of check, and both matter. The static checks prove what is in the
image and run anywhere; the runtime checks prove what the image does in FIPS
mode and need a FIPS host. CI runs both: the static checks on every pull
request, the runtime checks on a RHEL 9 runner in FIPS mode for every push
to main, nightly, for every pull request from a branch of this repository, and
against the pushed `-fips` image before a release is drafted (the `FIPS`
workflow and the release workflow's `fips-host` job).

On a developer machine (no FIPS host needed):

```console
make fips-signature-store  # once on Debian/Ubuntu: their podman has no entry for Red Hat's signature store
make fips-check    # build on UBI 9 with Red Hat's toolchain, print the compliance report
make container-fips
make fips-scanner  # build Red Hat's scanner (check-payload) at its pinned revision; needs Go
make fips-scan     # run it against the image, warnings fatal; needs oc
make test-integration-fips  # the test suites against the FIPS feature set, on this host's OpenSSL
```

On the FIPS host, from a checkout, with the image in podman's store:

```console
make fips-host-check     # attest the host and the image's module build: target/fips/host-attestation.{txt,json}
make fips-toolchain      # Red Hat's toolchain image, once
make test-fips-host      # the whole test suite as the FIPS build, inside that image, PRAXIS_FIPS_HOST=1
make fips-runtime-probe  # run the image under PRAXIS_REQUIRE_FIPS=1, probe its listener, check its startup line
```

What each proves:

- `fips-host-check` states the facts the Security Policy requires and fails
  on any that is missing: the kernel flag, `fips=1` on the command line, the
  `FIPS` crypto policy, `fips-mode-setup --check`, the provider the host's
  OpenSSL loads and its version. For the image it checks that podman
  propagated the FIPS policy into the container and reads the build of
  `fips.so` the image carries, then says whether that build is on a
  certificate, in validation, or unknown. It writes the attestation to keep
  with the run. A build in validation is a warning; `--require-certified`
  (`FIPS_HOST_CHECK_ARGS`) makes it a failure.
- `test-fips-host` runs every test suite with the proxy built exactly as the
  FIPS binary is, inside the UBI 9 toolchain image, so the OpenSSL and the
  module under test are the image's and the FIPS mode is the host's. The
  harness refuses to run unless the process really is in FIPS mode, and
  every FIPS behavior test takes its approved-mode branch: the listener
  negotiates only AES-GCM and the NIST curves and refuses ChaCha20-only and
  X25519-only clients, the upstream client offers only approved algorithms
  and refuses a TLS 1.2 peer without Extended Master Secret, a listener with
  a short RSA key cannot serve, a ChaCha20-only listener cannot start, MD5 is
  refused in process, and the binary serves under `PRAXIS_REQUIRE_FIPS=1`
  with the status line reporting both signals.
- `fips-runtime-probe` does the listener part of that against the shipped
  image itself, started under `PRAXIS_REQUIRE_FIPS=1`, and checks its
  startup line. This is the check against the bits that ship.

The manual equivalent, for one-off evidence:

```console
cat /proc/sys/crypto/fips_enabled                        # 1
podman run --rm -e PRAXIS_REQUIRE_FIPS=1 --entrypoint praxis \
    ghcr.io/praxis-proxy/praxis:<version>-fips --validate -c /etc/praxis/config.yaml
```

The second command exits 0, silently, only when the provider and the kernel
both report FIPS mode. It does not build the listener TLS
configurations or log the startup line; the workload does both when it
starts, so start it with `PRAXIS_REQUIRE_FIPS=1` as well and keep that line
as evidence.

Only a FIPS host can prove the kernel flag, the passing `PRAXIS_REQUIRE_FIPS`
path, RHEL's boot-time module integrity self-tests, and behavior under the
host-wide `FIPS` crypto policy. The local checks activate the provider, not
the policy.

## What is validated, and what is not

FIPS 140-3 validates cryptographic modules, not applications. The accurate
claim for praxis is this: the FIPS build performs all of its cryptography
through the Red Hat Enterprise Linux 9 OpenSSL FIPS Provider, a FIPS 140-3
validated module (CMVP certificate #4857), when run on a RHEL 9 host in FIPS
mode as described above. The checks on this page are the evidence for it.
Three things the checks cannot supply belong in any claim:

- **The module build.** Certificate #4857 names module version
  `3.0.7-395c1a240fbfffd8`, the build RHEL 9.2 through 9.6 and their UBI
  images ship. The UBI 9.8 images the build currently pins ship
  `openssl-fips-provider-so-3.0.7-11.el9_8`,
  a June 2026 rebuild for CVE-2026-31790 whose module version is
  `3.0.7-cda111b5812c30d4`. NIST's Modules In Process list shows a Red Hat
  submission for this module under review; until it is on a certificate, the
  image carries a module in validation, not the validated one. `fips-host-check`
  says so on every run (`xtask/assets/fips/certified-modules.json` is the
  list it consults), and the release gate can be made to fail on it with
  `--require-certified` once that is the policy.
- **The operating environment.** The certificate's tested environments are
  RHEL 9 on specific physical Intel, POWER and z machines. A virtual machine
  or another processor is covered by the CMVP's porting rules for software
  modules, not by testing; say "on RHEL 9 in FIPS mode", not "on a tested
  platform".
- **The architecture.** rustls runs the TLS protocol and calls the module for
  every primitive: hashes, HMAC, HKDF and the TLS 1.2 PRF, key exchange,
  signatures, AEAD and random bytes. The key schedule is composed from those
  calls outside the module boundary, as it is for every TLS stack that uses
  the provider. Whether that composition is acceptable is a question for the
  party the claim is made to (Red Hat for a Red Hat product, an assessor
  otherwise), and should be settled with them in writing.

## Scope and exemptions

Crypto-adjacent components, and why each is acceptable in the FIPS image or
kept out of it:

| Component | Use | Disposition |
|---|---|---|
| rustls, rustls-webpki, rustls-pki-types, rustls-pemfile, tokio-rustls | TLS protocol engine, X.509 path building, PEM parsing; no cryptography of their own | compliant through the OpenSSL provider |
| rustls-openssl (published from the Pingora fork as `quixotic-plecostomus-rustls-openssl`), openssl, openssl-sys | the provider and the bindings; dynamic link to the system `libcrypto.so.3` | compliant |
| rand, rand_chacha, chacha20 | request ids, load-balancer picks (rand's ChaCha-based RNG) | not security functions |
| ahash, crc32fast, blake2, digest | hash maps, gzip checksums, Pingora cache keys | not security functions |
| x509-parser (parsing only, no `verify` feature) | peer certificate fields in the Pingora fork; praxis's own SPIFFE use is outside the FIPS feature set | parse only |
| subtle, zeroize | constant-time comparison, wiping | helpers |
| policy engine (`policy` filter) | JWT, OAuth, Valkey builtins carry aws-lc, sha2 and hmac | not in the FIPS build |
| `basic_auth` filter (feature `basic-auth-filter`) | password hashing through OpenSSL's SHA-256 (EVP) | not in the FIPS build (the feature is off by default); ready to join it |
| sha1, rcgen, ring | test utilities and fixtures | development only, absent from the shipped binary and its manifest |

The report and Red Hat's scanner check the last row on every build: the
embedded crate manifest lists no denied crate, and the binary defines no
symbol of a bundled crypto backend.
