# TLS

Working example configs for every TLS scenario live in
[`examples/configs/protocols/`]:

| Example | Scenario |
| ------- | -------- |
| [tls-termination] | HTTPS listener, plain HTTP upstream |
| [tls-http-reencrypt] | HTTPS listener, TLS upstream |
| [tls-multi-cert] | SNI with multiple certificates |
| [tls-version-constraint] | TLS 1.3 only |
| [tls-mtls-listener] | Require client certificate |
| [tls-mtls-listener-request] | Request (optional) client cert |
| [tls-mtls-upstream] | Client cert to upstream |
| [tls-mtls-both] | mTLS on both sides |
| [tls-verify-disabled] | Skip upstream cert verify (dev) |
| [upstream-tls] | Plain listener, TLS upstream |
| [upstream-ca-file] | Global CA for all upstreams |
| [tcp-tls-termination] | TLS on TCP listener |
| [tcp-tls-mtls] | mTLS on TCP listener |

[`examples/configs/protocols/`]: ../../examples/configs/protocols/
[tls-termination]: ../../examples/configs/protocols/tls-termination.yaml
[tls-http-reencrypt]: ../../examples/configs/protocols/tls-http-reencrypt.yaml
[tls-multi-cert]: ../../examples/configs/protocols/tls-multi-cert.yaml
[tls-version-constraint]: ../../examples/configs/protocols/tls-version-constraint.yaml
[tls-mtls-listener]: ../../examples/configs/protocols/tls-mtls-listener.yaml
[tls-mtls-listener-request]: ../../examples/configs/protocols/tls-mtls-listener-request.yaml
[tls-mtls-upstream]: ../../examples/configs/protocols/tls-mtls-upstream.yaml
[tls-mtls-both]: ../../examples/configs/protocols/tls-mtls-both.yaml
[tls-verify-disabled]: ../../examples/configs/protocols/tls-verify-disabled.yaml
[upstream-tls]: ../../examples/configs/protocols/upstream-tls.yaml
[upstream-ca-file]: ../../examples/configs/protocols/upstream-ca-file.yaml
[tcp-tls-termination]: ../../examples/configs/protocols/tcp-tls-termination.yaml
[tcp-tls-mtls]: ../../examples/configs/protocols/tcp-tls-mtls.yaml

## Listener TLS

Add `tls` to any listener. Files are PEM, and the cert file may include the
full chain.

```yaml
tls:
  certificates:
    - cert_path: /etc/praxis/tls/cert.pem
      key_path: /etc/praxis/tls/key.pem
```

For local development, generate a pair with `mkcert` and point `cert_path`
and `key_path` at its files:

```console
mkcert -install
mkcert localhost 127.0.0.1
```

### SNI and Multiple Certificates

With several certificates on one listener, the SNI picks the certificate.
Entries with `server_names` match those hostnames; wildcards like
`*.example.com` match single-level subdomains. Mark exactly one entry
`default: true` as the fallback for unmatched SNI. An entry without
`server_names` that is not `default: true` is rejected as ambiguous. With no
default entry, unmatched SNI is rejected. See [tls-multi-cert].

### Certificate Hot-Reload

Hot-reload is on by default for single-cert listeners; multi-cert SNI
listeners are excluded automatically. Set `hot_reload: false` to turn it off.
It is compiled in by the `config-reload` build feature (on by default); a
binary built without it serves the certificate statically. See
[Build Features](build-features.md).

The proxy watches the cert and key files. On a filesystem event (from
certbot, cert-manager, or Vault PKI, for example) it swaps in the new
certificate atomically after a 500ms debounce. Existing connections are
unaffected; only new handshakes use the rotated certificate.

The debounce covers atomic rename patterns used by Kubernetes secret mounts,
certbot, and cert-manager: a rotation that writes a temp file and renames it
over the original triggers one reload after the rename. A filesystem that
emits no event for an atomic update is caught by a ten-second fallback poll,
so detection can take up to one poll interval plus the reload time.

If the new certificate fails to parse, the proxy logs a warning and keeps
serving the previous one. It retries a failed reload on a timer even without
another file change, backing off exponentially up to 60s between attempts,
so a file caught mid-write is picked up once it is complete.

To reload all configuration, certificates included, restart through the
process supervisor; in-flight connections drain according to the shutdown
settings. SIGHUP is reserved for configuration reload handling and is not a
graceful-restart signal.

### Minimum TLS Version

`min_version` sets the minimum protocol version: `tls12` (default) or
`tls13`. See [tls-version-constraint].

### Listener mTLS

`client_ca` and `client_cert_mode` require or request client certificates.

| Mode | Behavior |
| ---- | -------- |
| `none` | Do not request a client certificate (default) |
| `request` | Ask for a cert but allow connections without one |
| `require` | Reject connections without a valid client cert |

`client_ca` is required when mode is `request` or `require`, and setting
`client_ca` with mode `none` is rejected at validation rather than ignored.
See [tls-mtls-listener] and [tls-mtls-listener-request].

### Certificate Revocation Lists (CRL)

Add `crl_paths` to `client_ca` to reject client certificates listed in a
CRL. Each path points to a PEM-encoded CRL file; paths containing `..` are
rejected at validation.

```yaml
tls:
  client_cert_mode: require
  client_ca:
    ca_path: /etc/praxis/tls/client-ca.pem
    crl_paths:
      - /etc/praxis/tls/client-ca.crl
  certificates:
    - cert_path: /etc/praxis/tls/cert.pem
      key_path: /etc/praxis/tls/key.pem
```

CRL checking applies only to listener client authentication. Upstream
(cluster) CRL checking is not implemented, so `tls.ca.crl_paths` on a cluster
is rejected at config validation.

Revocation policy:

- CRLs are checked for the whole chain, not only the leaf.
- When CRLs are configured, a certificate whose issuer has no CRL is
  rejected (unknown revocation status is denied).
- A CRL past its `nextUpdate` is still accepted, so refresh CRL files
  yourself.

CRL and CA files reload only on listeners with exactly one certificate and
`hot_reload` not set to `false`. Every other listener needs a restart to pick
up a new CRL.

Listeners with client authentication and TLS hot-reload disable TLS 1.2 and
TLS 1.3 session resumption, including when client certificates are optional
(`request`). Every new connection does a full handshake against the current
CA and CRLs, which costs more than a resumed one. Static mTLS listeners and
listeners without client authentication keep session resumption. A reload
does not end established connections or handshakes that already
authenticated, and those cannot create resumable sessions that bypass the new
trust.

After a CA replacement (not a CRL update), the `CertificateRequest` still
advertises the old CA names until restart. Clients that filter their
certificates by CA name (browsers, Java) may then offer none. During
rotation, use a CA bundle that holds both the old and the new CA.

## Cluster TLS

Add `tls:` to a cluster to connect to its endpoints over TLS. `sni` sets the
backend SNI hostname, and `verify` controls certificate verification
(default `true`). See [upstream-tls] and [tls-verify-disabled].

A verifying cluster without `sni` needs `authority: { from: endpoint }`,
which verifies each endpoint against its own hostname, or an IP endpoint
against the certificate's IP SAN. The alternative,
`insecure_options.allow_tls_without_sni`, takes the name from the cluster's
fixed `authority` or the client's `Host` header; see
[Security Hardening](security-hardening.md).

To present a client certificate to upstreams (upstream mTLS), see
[tls-mtls-upstream] and [tls-mtls-both].

### Active health probes

The experimental `tls-health-check` feature verifies upstream TLS identities
or probes HTTPS endpoints with the cluster TLS settings. See
[TLS and HTTPS probes](health-checking.md#tls-and-https-probes) for trust,
server-name selection, and the TLS 1.3 client-authentication limitation.

## CA Trust

Upstream CA trust is chosen in this order:

1. Per-cluster CA (`tls.ca.ca_path`), for that cluster only.
2. Global CA (`runtime.upstream_ca_file`), for every cluster without its own
   `tls.ca`.
3. The system trust store, when neither is set.

The global CA replaces the system trust store rather than adding to it. If
backends use both a private CA and public CAs, build a combined PEM bundle.
See [upstream-ca-file].

## Timeouts

Pingora enforces a hardcoded 60-second TLS handshake timeout. For a total
TCP + TLS connection budget, set `total_connection_timeout_ms` on the
cluster; see [configuration.md](configuration.md).

## Certificate and Key Security

Praxis warns at startup if a private key is group or world readable.

```console
chmod 600 /etc/praxis/tls/key.pem
chown praxis:praxis /etc/praxis/tls/key.pem
```

Keep private keys out of version control and off unencrypted disk; use a
secrets manager or encrypted storage.

## Cipher Suites

Praxis uses rustls, which supports only TLS 1.2 and 1.3 and has no weak
cipher suites. rustls picks suites automatically unless the listener TLS
block sets `cipher_suites`; then only the listed suites are offered. An empty
list is rejected at validation. TLS 1.2 suites cannot be used when
`min_version` is `tls13`. See [tls-cipher-suites].

```yaml
tls:
  cipher_suites:
    - tls13_aes_256_gcm_sha384
    - tls13_chacha20_poly1305_sha256
  certificates:
    - cert_path: /etc/praxis/tls/cert.pem
      key_path: /etc/praxis/tls/key.pem
```

### Available Suites

| Config value | Suite |
| ------------ | ----- |
| `tls13_aes_128_gcm_sha256` | TLS 1.3 AES-128-GCM with SHA-256 |
| `tls13_aes_256_gcm_sha384` | TLS 1.3 AES-256-GCM with SHA-384 |
| `tls13_chacha20_poly1305_sha256` | TLS 1.3 ChaCha20-Poly1305 with SHA-256 |
| `tls12_ecdhe_ecdsa_with_aes_128_gcm_sha256` | TLS 1.2 ECDHE-ECDSA AES-128-GCM |
| `tls12_ecdhe_ecdsa_with_aes_256_gcm_sha384` | TLS 1.2 ECDHE-ECDSA AES-256-GCM |
| `tls12_ecdhe_ecdsa_with_chacha20_poly1305_sha256` | TLS 1.2 ECDHE-ECDSA ChaCha20-Poly1305 |
| `tls12_ecdhe_rsa_with_aes_128_gcm_sha256` | TLS 1.2 ECDHE-RSA AES-128-GCM |
| `tls12_ecdhe_rsa_with_aes_256_gcm_sha384` | TLS 1.2 ECDHE-RSA AES-256-GCM |
| `tls12_ecdhe_rsa_with_chacha20_poly1305_sha256` | TLS 1.2 ECDHE-RSA ChaCha20-Poly1305 |

[tls-cipher-suites]: ../../examples/configs/protocols/tls-cipher-suites.yaml
