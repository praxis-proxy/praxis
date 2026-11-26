# FIPS 140-3

Praxis does all of its cryptography in the system OpenSSL library. On a Red
Hat Enterprise Linux 9 host in FIPS mode, that library's provider is the Red
Hat Enterprise Linux 9 OpenSSL FIPS Provider. Module version
`3.0.7-395c1a240fbfffd8` is validated (CMVP certificate #4857 at the time of
writing; Red Hat keeps the current list at
<https://access.redhat.com/compliance/fips>), and with it praxis's TLS,
hashing and random numbers run inside a FIPS 140-3 validated boundary. The
UBI 9.8 images the FIPS build pins ship module version
`3.0.7-cda111b5812c30d4`, which is in validation, not yet on a certificate;
see [What is validated, and what is not](#what-is-validated-and-what-is-not).
Praxis itself is not a validated module and never turns FIPS mode on: the
host does, and praxis reports it and, on request, enforces it.

This page is for operators deploying the FIPS build. How the build is checked
is in [FIPS Tooling](../developing/fips.md).

## The FIPS build

The FIPS build leaves out what is not yet FIPS compliant:

| | Standard | FIPS |
|---|---|---|
| Make targets | `release`, `container` | `release-fips`, `container-fips` |
| Cargo features | defaults | `pingora,config-reload,admin-api` |
| `policy` filter (policy engine) | yes | no by default; opt-in on the FIPS backend, see [The policy filter on FIPS](#the-policy-filter-on-fips) |
| Base image | Alpine, praxis built with upstream Rust | `ubi9/ubi-minimal`, praxis built with Red Hat's `rust-toolset` on `ubi9/ubi`, both pinned by digest and signature-verified |
| OpenSSL | Alpine's, dynamically linked | UBI's, dynamically linked (`openssl-libs` and `openssl-fips-provider-so`), the validated module on a FIPS host |
| Published tags | `<version>`, `<major>.<minor>`, `latest`, `sha-<hash>`, `nightly` (see [image tags](../developing/release.md#image-tags)) | the same with a `-fips` suffix (`0.8.0-fips`, `latest-fips`) |

The default FIPS build rejects a configuration that uses the `policy` filter
at startup. Everything else, including TLS listeners, mTLS, SNI, the admin
API and hot reload, works as in the standard build.

The binary links `libcrypto.so.3` and `libssl.so.3` dynamically. The only
crates in the image that do security-relevant cryptography are rustls and the
OpenSSL bindings, which hand every primitive to the system library;
[Scope and exemptions](#scope-and-exemptions) covers the rest.

## Host prerequisites

The module's Security Policy (section 11.2, "Crypto Officer guidance") sets
the terms. A deployment that does not meet them is not running the validated
module, whatever the image contains.

- A RHEL 9 host in FIPS mode, set either with `fips=1` on the kernel command
  line at installation or with `fips-mode-setup --enable` and a reboot. Red
  Hat prefers installation time, since only then are all of the system's keys
  generated under FIPS mode. Either way `fips-mode-setup --check` must say
  `FIPS mode is enabled.`, `cat /proc/sys/crypto/fips_enabled` prints `1`,
  and the kernel command line carries `fips=1`.
- The system-wide crypto policy left at `FIPS`, with no restrictions added.
- `openssl list -providers` lists the `fips` provider as active, with the
  version string the certificate names (`3.0.7-395c1a240fbfffd8` for
  certificate #4857). The cryptographic boundary is that provider alone: a
  different build of the module, or any other provider, is not the validated
  module.
- A container runtime that passes the host's FIPS mode into the container, as
  podman and CRI-O on RHEL do: they bind-mount the FIPS crypto policy the
  image ships over the container's own, and the kernel flag is visible
  through `/proc`. The `-fips` image then needs no flag, environment variable
  or config; its OpenSSL reads the kernel flag and activates the validated
  provider itself. On a host not in FIPS mode the same image runs with
  OpenSSL's default provider, and the startup log says so.

The module inside the container is the image's own `openssl-fips-provider-so`,
not the host's, so the version requirement applies to the image too; see
[what is validated](#what-is-validated-and-what-is-not).

## Startup checks

At startup praxis installs its crypto provider and logs the FIPS status:

```text
installed rustls crypto provider provider="openssl" provider_fips=true kernel_fips=Some(true) crypto_policy=Some("FIPS") fips_required=true
```

- `provider_fips`: whether OpenSSL's default properties select only
  FIPS-approved algorithms (`EVP_default_properties_is_fips_enabled`), as
  RHEL's FIPS mode configures.
- `kernel_fips`: `/proc/sys/crypto/fips_enabled`; `None` where the file does
  not exist (a container without `/proc`, a non-Linux host).
- `crypto_policy`: the active system crypto policy from
  `/etc/crypto-policies/config`; `None` on platforms without crypto-policies
  support. The policy must be visible inside the container: a runtime that
  does not propagate it refuses to start when FIPS is required.

Set `PRAXIS_REQUIRE_FIPS=1` in production FIPS deployments. An empty value,
`0`, `false`, `no` or `off` leaves it off; any other value, a typo included,
turns it on. It is a check, not a switch. With it on, praxis refuses to start:

- unless all three signals above are present, naming each one that is missing;
- when a listener's TLS configuration is not FIPS-approved by rustls;
- when the binary registers a `policy` filter that fails its compiled FIPS
  assessment. The standard build does: its policy engine verifies JWTs with
  aws-lc-rs and hashes with the RustCrypto `hmac` and `sha2` crates, none of
  which is the system OpenSSL. A build that opts into Policy on the FIPS
  backend passes only when every compiled Policy builtin uses that backend,
  no host policy plugin factory is registered, and the experimental Policy
  rate limiter (`policy-experimental-ratelimit`) is left out, since that
  combination has not been validated.

The check covers what is compiled in, not whether the host can run it. Policy
checks that itself at filter construction, on startup and on every reload;
see [The policy filter on FIPS](#the-policy-filter-on-fips).

Upstream connections always require Extended Master Secret and use the same
provider, so they are FIPS whenever the listeners are. Without the variable,
praxis starts either way and only logs the status.

```console
podman run --rm -e PRAXIS_REQUIRE_FIPS=1 ghcr.io/praxis-proxy/praxis:0.8.0-fips
```

On a host not in FIPS mode this exits immediately with:

```text
fatal: PRAXIS_REQUIRE_FIPS is set but FIPS mode is not in effect: the OpenSSL provider does not report FIPS-approved algorithms (is the fips provider active?); the kernel is not in FIPS mode (/proc/sys/crypto/fips_enabled is 0); the system crypto policy is "DEFAULT", not FIPS (/etc/crypto-policies/config)
```

## TLS behavior

- **TLS 1.2 requires the Extended Master Secret extension (RFC 7627)** on
  listeners and upstream connections, in every build and mode. A TLS 1.2
  peer that cannot negotiate it fails the handshake; TLS 1.3 is unaffected.
  FIPS 140-3 requires it for TLS 1.2 key derivation, and rustls counts a
  configuration as FIPS only with it.
- **In FIPS mode the provider offers only what the module approves.**
  ChaCha20-Poly1305 suites are not offered, MD5 does not exist, and keys or
  certificates the module refuses (short RSA keys, legacy signature
  algorithms) are rejected at load or first use. The module and the host's
  crypto policy decide what is approved, not praxis. In every build and mode,
  a listener whose `cipher_suites` names only suites the provider does not
  offer fails to build.
- **Random numbers** for every TLS operation come from OpenSSL's DRBG
  (`RAND_priv_bytes`). Randomness that protects nothing (load-balancer picks,
  request ids) uses ordinary Rust RNGs.

## Verifying a deployment

Static checks prove what is in the image and run anywhere; runtime checks
prove what it does in FIPS mode and need a FIPS host. CI runs both (see
[the runner job](../developing/fips.md#the-runner-job)).

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

- `fips-host-check` checks the facts the Security Policy requires and fails on
  any that is missing: the kernel flag, `fips=1` on the command line, the
  `FIPS` crypto policy, `fips-mode-setup --check`, and the provider the
  host's OpenSSL loads and its version. For the image, it checks that podman
  propagated the FIPS policy into the container, reads the build of `fips.so`
  the image carries, and says whether that build is on a certificate, in
  validation, or unknown. It writes the attestation to keep with the run. A
  build in validation is a warning; `--require-certified`
  (`FIPS_HOST_CHECK_ARGS`) makes it a failure.
- `test-fips-host` runs every suite as the FIPS binary, with the image's
  OpenSSL and module and the host's FIPS mode, and refuses to run unless the
  process really is in FIPS mode. The tests then prove that the listener
  negotiates only AES-GCM and the NIST curves and refuses ChaCha20-only and
  X25519-only clients, the upstream client offers only approved algorithms
  and refuses a TLS 1.2 peer without Extended Master Secret, a listener with
  a short RSA key cannot serve, a ChaCha20-only listener cannot start, MD5 is
  refused in process, and the binary serves under `PRAXIS_REQUIRE_FIPS=1`
  with the status line reporting all three signals. See
  [The FIPS host run](../developing/fips.md#the-fips-host-run).
- `fips-runtime-probe` runs the listener part of that against the shipped
  image itself, started under `PRAXIS_REQUIRE_FIPS=1`, and checks its startup
  line.

The manual equivalent, for one-off evidence:

```console
cat /proc/sys/crypto/fips_enabled                        # 1
podman run --rm -e PRAXIS_REQUIRE_FIPS=1 --entrypoint praxis \
    ghcr.io/praxis-proxy/praxis:<version>-fips --validate -c /etc/praxis/config.yaml
```

The second command exits 0, silently, only when the provider, the kernel and
the crypto policy all report FIPS mode. It does not build the listener TLS
configurations or log the startup line; the workload does both when it
starts, so start it with `PRAXIS_REQUIRE_FIPS=1` as well and keep that line
as evidence.

Only a FIPS host can prove the kernel flag, the passing `PRAXIS_REQUIRE_FIPS`
path, RHEL's boot-time module integrity self-tests, and behavior under the
host-wide `FIPS` crypto policy. The local checks activate the provider, not
the policy.

## What is validated, and what is not

FIPS 140-3 validates cryptographic modules, not applications. The accurate
claim for praxis: the FIPS build performs all of its cryptography through the
Red Hat Enterprise Linux 9 OpenSSL FIPS Provider, a FIPS 140-3 validated
module (CMVP certificate #4857), when run on a RHEL 9 host in FIPS mode as
described above. The checks on this page are the evidence. Any claim must
also address three things the checks cannot supply:

- **The module build.** Certificate #4857 names module version
  `3.0.7-395c1a240fbfffd8`, the build RHEL 9.2 through 9.6 and their UBI
  images ship. The UBI 9.8 images the build currently pins ship
  `openssl-fips-provider-so-3.0.7-11.el9_8`, a June 2026 rebuild for
  CVE-2026-31790 whose module version is `3.0.7-cda111b5812c30d4`. NIST's
  Modules In Process list shows a Red Hat submission for this module under
  review; until it is on a certificate, the image carries a module in
  validation, not the validated one. `fips-host-check` says so on every run
  (the list it consults is compiled into `cargo fips-check`), and
  `--require-certified` can make the release gate fail on it once that is
  the policy.
- **The operating environment.** The certificate's tested environments are
  RHEL 9 on specific physical Intel, POWER and z machines. A virtual machine
  or another processor is covered by the CMVP's porting rules for software
  modules, not by testing; say "on RHEL 9 in FIPS mode", not "on a tested
  platform".
- **The architecture.** rustls runs the TLS protocol and calls the module for
  every primitive: hashes, HMAC, HKDF and the TLS 1.2 PRF, key exchange,
  signatures, AEAD and random bytes. The key schedule is composed from those
  calls outside the module boundary, as in every TLS stack that uses the
  provider. Whether that is acceptable is for the party the claim is made to
  (Red Hat for a Red Hat product, an assessor otherwise) to decide; settle it
  with them in writing.

## The policy filter on FIPS

The default FIPS build leaves the `policy` filter out. A build that opts into
it on the FIPS backend (`policy-crypto-fips`, with `policy-api-key-fips` or
`policy-jwt-fips`) relies on the host for its provider setup:

- **Configure OpenSSL before praxis starts.** The FIPS provider must be
  active, through the host's FIPS mode or `OPENSSL_CONF`, before the first
  policy document loads. Praxis never loads or enables a provider itself.
- **FIPS JWT needs FIPS defaults.** `policy-jwt-fips` verifies signatures with
  OpenSSL calls that carry no property query, so the process default must
  reach only the FIPS module: `default_properties = fips=yes`, as a FIPS-mode
  host sets. Policy enforces this when it loads JWT configuration and refuses
  a provider that is merely loaded beside the default one. Configure the
  running host, not the build machine: cargo's own TLS can fail under
  FIPS-only defaults.
- **No other `jsonwebtoken` provider.** Policy installs its OpenSSL provider
  for `jsonwebtoken` on the first JWT load and refuses, as a provider
  conflict, one installed earlier in the process by host code or a
  dependency. Later loads, including reloads, reuse Policy's own.

A failure in any of these fails filter construction with a
`policy.crypto_failed` error naming the remedy, and Policy logs the
`policy_crypto_failure` alarm. At startup praxis exits; on a reload the
previous pipeline keeps serving. A missing SHA-256 provider is a startup
failure, never an API-key request answered with 401.

To build one, name a profile: `make container-fips FIPS_POLICY_PROFILE=jwt`
(or `engine`, `api-key`, `both`). The image is tagged
`<version>-fips-policy-<profile>`, separate from the published policy-free
one, and `make fips-runtime-probe FIPS_POLICY_PROFILE=jwt` sends API-key, JWT
and DPoP traffic through it. See
[`examples/configs/security/policy-jwt-fips.yaml`](../../examples/configs/security/policy-jwt-fips.yaml).

| Profile | Policy features | Status |
|---|---|---|
| `none` (published image) | none | supported |
| `engine` | `policy-engine,policy-crypto-fips` | supported |
| `api-key` | `policy-api-key-fips` | supported |
| `jwt` | `policy-jwt-fips` | supported |
| `both` | `policy-api-key-fips,policy-jwt-fips` | supported |
| any of the above plus `policy-experimental-ratelimit` | adds the Limitador rate limiter | unvalidated; refused under `PRAXIS_REQUIRE_FIPS` |

The limiter combination is unvalidated because Limitador enables `uuid`'s
`fast-rng` feature, which switches every `uuid` v4 in the process, Policy's
included, from the OS RNG (`getrandom`) to `rand 0.10`'s `chacha20` RNG.
Praxis already links `rand` for request ids, but not for Policy's ids. The
feature edge is in Limitador's own dependency declaration, so neither Praxis
nor Policy can turn it off. No denied crate enters the graph, but the change
of RNG behind Policy's ids has not been reviewed, so a build with both
features refuses to start when FIPS is required.

JWT under FIPS accepts RS256/384/512, PS256/384/512 and ES256/384 on RSA
2048-8192 or P-256/P-384 keys, and refuses HMAC, EdDSA and
`decoding_key: { kind: secret }` at load.

Every DPoP-enabled trusted issuer (`dpop.mode` of `optional` or `required`),
FIPS or not, must set `dpop.external_base_url` to the URL clients address,
such as `https://api.example.com`. Without it the proof's `htu` would be
compared against a URL rebuilt from the client-sent `Host` header, so the
filter refuses to build and names the plugin and the issuer.

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
| policy engine (`policy` filter) | the default bundle's JWT, OAuth, Valkey builtins carry aws-lc, sha2 and hmac | not in the default FIPS build; the opt-in FIPS selections hash and verify through OpenSSL |
| `basic_auth` filter (feature `basic-auth-filter`) | password hashing through OpenSSL's SHA-256 (EVP) | not in the FIPS build (the feature is off by default); ready to join it |
| sha1, rcgen, ring | test utilities and fixtures | development only, absent from the shipped binary and its manifest |

The report and Red Hat's scanner check the last row on every build: the
embedded crate manifest lists no denied crate, and the binary defines no
symbol of a bundled crypto backend.
