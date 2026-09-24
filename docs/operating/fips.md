# FIPS 140-3

Praxis performs all of its cryptography in the system OpenSSL library. On a
Red Hat Enterprise Linux 9 host in FIPS mode that library's provider is the
validated module (Red Hat Enterprise Linux 9 OpenSSL FIPS Provider, CMVP
certificate #4857 at the time of writing; Red Hat keeps the current list at
<https://access.redhat.com/compliance/fips>), so a praxis running there does
its TLS, hashing and random numbers inside a FIPS 140-3 validated boundary.
Praxis itself is not a validated module and never enables FIPS mode on its
own: FIPS mode comes from the host, and praxis reports and, on request,
enforces it.

This page is for operators deploying the FIPS build. How the build is checked
and how the tooling works is in [FIPS Tooling](../developing/fips.md).

## The FIPS build

The standard build (`make release`, `make container`) enables the default
feature set. The FIPS build turns off what is known not to be FIPS compliant
yet, so nobody has to know which features to pick:

| | Standard | FIPS |
|---|---|---|
| Make targets | `release`, `container` | `release-fips`, `container-fips` |
| Cargo features | defaults | `config-reload,admin-api` |
| `policy` filter (policy engine) | yes | no: its dependencies carry their own cryptography |
| Base image | Alpine, praxis built with upstream Rust | `ubi9/ubi-minimal`, praxis built with Red Hat's `rust-toolset` on `ubi9/ubi`, both pinned by digest and signature-verified |
| OpenSSL | Alpine's, dynamically linked | UBI's, dynamically linked (`openssl-libs` and `openssl-fips-provider-so`), the validated module on a FIPS host |
| Published tags | `<version>`, `<major>.<minor>`, `latest`, `sha-<hash>`, `nightly` (see [image tags](../release.md#image-tags)) | the same with a `-fips` suffix (`0.6.0-fips`, `latest-fips`) |

A configuration that uses the `policy` filter is rejected at startup by the
FIPS build. Everything else in the default feature set, including TLS
listeners, mTLS, SNI, the admin API and hot reload, behaves as in the
standard build.

The binary links `libcrypto.so.3` and `libssl.so.3` dynamically. The only
crates performing security-relevant cryptography in the image are the rustls
protocol engine and the OpenSSL bindings that delegate every primitive to the
system library; the rest of the crypto-adjacent crates in the image are
listed in the exemption table at the end of this page.

## Host prerequisites

- A RHEL 9 host in FIPS mode, enabled at install time or with
  `fips-mode-setup --enable` and a reboot: `cat /proc/sys/crypto/fips_enabled`
  prints `1` and `openssl list -providers` lists `fips`. RHEL 9 is the
  validated operating environment; the module that runs inside the container
  is UBI's own `openssl-fips-provider-so`, the host contributes the kernel
  flag.
- A container runtime that passes the host's FIPS mode into the container,
  as podman and CRI-O on RHEL do. The `-fips` image then needs no flag,
  environment variable or config: the OpenSSL inside it reads the kernel flag
  and activates the validated provider by itself. On a host that is not in
  FIPS mode the same image runs with OpenSSL's default provider, and the
  startup log says so.

## Startup: what praxis reports and enforces

At startup praxis installs its one crypto provider and logs what it found:

```text
installed rustls crypto provider provider=openssl provider_fips=true kernel_fips=Some(true) fips_required=true
```

- `provider_fips`: whether OpenSSL's default properties select FIPS-approved
  algorithms only (`EVP_default_properties_is_fips_enabled`), which is what
  RHEL's FIPS mode configures.
- `kernel_fips`: `/proc/sys/crypto/fips_enabled`; `None` where the file does
  not exist (a container without `/proc`, a non-Linux host).

Set `PRAXIS_REQUIRE_FIPS=1` in production FIPS deployments. Only an empty
value, `0`, `false`, `no` or `off` leave it off; any other value, a typo
included, turns it on. It is a check, never a switch: praxis then refuses
to start unless both signals are present, naming each one that is missing,
and refuses any listener TLS configuration that rustls does not consider
FIPS-approved. Upstream connections always require Extended Master Secret
and share the same provider, so they are FIPS whenever the listeners are.
Without the variable praxis starts either way and only logs the status.

```console
podman run --rm -e PRAXIS_REQUIRE_FIPS=1 ghcr.io/praxis-proxy/praxis:0.6.0-fips
```

On a host that is not in FIPS mode this exits immediately with

```text
fatal: PRAXIS_REQUIRE_FIPS is set but FIPS mode is not in effect: the OpenSSL provider does not report FIPS-approved algorithms (is the fips provider active?); the kernel is not in FIPS mode (/proc/sys/crypto/fips_enabled is 0)
```

## What changes under FIPS mode

- **TLS 1.2 requires the Extended Master Secret extension (RFC 7627)** on
  listeners and on upstream connections, in every build and regardless of
  FIPS mode; a TLS 1.2 peer that cannot negotiate it fails the handshake.
  TLS 1.3 is unaffected. This is what FIPS 140-3 requires of TLS 1.2 key
  derivation, and rustls counts a configuration as FIPS only with it.
- **The provider offers only what the system OpenSSL can perform.** In FIPS
  mode non-approved algorithms are absent rather than failing later: for
  example the ChaCha20-Poly1305 cipher suites are not offered, MD5 does not
  exist, and keys or certificates the module refuses (short RSA keys, legacy
  signature algorithms) are rejected at load or at first use. Which
  algorithms are approved is decided by the validated module and the host's
  crypto policy, not by praxis. A listener whose `cipher_suites` names only
  suites the module does not offer fails to build in every build and mode,
  since it would have nothing to negotiate.
- **Random numbers** come from OpenSSL's DRBG (`RAND_priv_bytes`) for every
  TLS operation. Non-security randomness (load-balancer picks, request ids)
  uses ordinary Rust RNGs, which is fine: they protect nothing.

## Verifying a deployment

On a developer machine (no FIPS host needed):

```console
make fips-signature-store  # once on Debian/Ubuntu: their podman has no entry for Red Hat's signature store
make fips-check    # build on UBI 9 with Red Hat's toolchain, print the compliance report
make container-fips
make fips-scanner  # build Red Hat's scanner (check-payload) at its pinned revision; needs Go
make fips-scan     # run it against the image, warnings fatal
```

On the FIPS host, the two things only it can prove:

```console
cat /proc/sys/crypto/fips_enabled                        # 1
podman run --rm -e PRAXIS_REQUIRE_FIPS=1 --entrypoint praxis \
    ghcr.io/praxis-proxy/praxis:<version>-fips --validate -c /etc/praxis/config.yaml
```

The second command exits 0 only when the provider and the kernel both report
FIPS mode; it prints nothing in that case. The listener TLS configurations
are checked, and the startup line above is logged, when the real workload
starts, so run it the same way with `PRAXIS_REQUIRE_FIPS=1` and keep that
line as evidence.

What the local checks cannot prove, and only a FIPS host can: the kernel flag
and the positive `PRAXIS_REQUIRE_FIPS` path, RHEL's boot-time module
integrity self-tests, and behaviour under the host-wide `FIPS` crypto policy
(the local checks activate the provider, not the policy).

## Scope and exemptions

Every crypto-adjacent component in the FIPS image, and why it is compliant:

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

The report and Red Hat's scanner both confirm the last row on every build:
the embedded crate manifest lists none of the denied crates, and the binary
defines no symbol of a bundled crypto backend.
