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

Add `tls` to any listener. PEM format; the cert file
may include the full chain. See [tls-termination] for
a complete example.

```yaml
tls:
  certificates:
    - cert_path: /etc/praxis/tls/cert.pem
      key_path: /etc/praxis/tls/key.pem
```

### SNI and Multiple Certificates

Multiple certificates on a single listener enable
SNI-based selection. Entries with `server_names` match
those hostnames; wildcard entries like `*.example.com`
match single-level subdomains. Mark exactly one entry with
`default: true` to serve as the fallback for unmatched
SNI. An entry without `server_names` that is not marked
`default: true` is rejected as ambiguous. If no entry
has `default: true`, unmatched SNI is rejected (no
fallback). See [tls-multi-cert].

### Certificate Hot-Reload

Certificate hot-reload is enabled by default. Cert and
key files are watched for changes. When modified (e.g. by
certbot, cert-manager, or Vault PKI), the proxy atomically
picks up the new certificate within 500ms. Existing
connections are unaffected; only new TLS handshakes use the
rotated certificate.

To explicitly disable hot-reload, set `hot_reload: false`.
Multi-cert SNI configs auto-disable hot-reload.

**Constraints:**

- Hot-reload applies only to single-cert listeners.
  Multi-cert SNI configs are automatically excluded.
- If the new certificate fails to parse, the proxy logs
  a warning and continues serving the previous valid
  certificate. Consecutive failures trigger exponential
  backoff (up to 60s) to avoid log spam.

**Debounce behavior:** filesystem events are debounced by
500ms to handle atomic rename patterns used by Kubernetes
secret mounts, certbot, and cert-manager. A cert-manager
rotation that writes a temp file and then renames it over
the original triggers a single reload after the rename
completes.

**Alternative: graceful restart.** Pingora supports
graceful restart via SIGHUP with FD passing. This reloads
all configuration including certificates, but drains
in-flight connections. Use graceful restart when
hot-reload is not needed or for config changes beyond
certificate rotation.

### Minimum TLS Version

`min_version` restricts the minimum protocol version:
`tls12` (default) or `tls13`. See
[tls-version-constraint].

### Listener mTLS

Require or request client certificates with
`client_ca` and `client_cert_mode`.

| Mode | Behavior |
| ---- | -------- |
| `none` | Do not request a client certificate (default) |
| `request` | Ask for a cert but allow connections without one |
| `require` | Reject connections without a valid client cert |

`client_ca` is required when mode is `request` or
`require`. See [tls-mtls-listener] and
[tls-mtls-listener-request].

### Local dev with mkcert

```console
mkcert -install
mkcert localhost 127.0.0.1
```

Point `cert_path` and `key_path` at the generated files.

## Cluster TLS

Add `tls:` to a cluster to TLS-connect to endpoints.
`sni` sets the backend SNI hostname. `verify` controls
certificate verification (default: `true`). See
[upstream-tls] and [tls-verify-disabled].

### Upstream mTLS (Client Certificate)

Present a client certificate to upstream servers.
See [tls-mtls-upstream] and [tls-mtls-both].

## CA Trust

Three levels of CA trust, evaluated in order:

1. **Per-cluster CA** (`tls.ca.ca_path`): applies to
   one cluster only.
2. **Global CA** (`runtime.upstream_ca_file`): applies
   to all clusters without their own `tls.ca`.
3. **System trust store**: used when neither of the
   above is set.

The global CA **replaces** the system trust store (not
additive). If backends use both a private CA and
public CAs, create a combined PEM bundle. See
[upstream-ca-file].

## Timeouts

Pingora enforces a 60-second TLS handshake timeout
(hardcoded). For total connection budgets (TCP + TLS),
use `total_connection_timeout_ms` on the cluster. See
[configuration.md](configuration.md) for details.

## Certificate and Key Security

Private keys should have restrictive file permissions.
Praxis warns at startup if keys are group or world
readable.

```console
chmod 600 /etc/praxis/tls/key.pem
chown praxis:praxis /etc/praxis/tls/key.pem
```

Don't store private keys in version control or
unencrypted on disk. Use a secrets manager or
encrypted storage solution.

## Ciphers and Protocol

Praxis uses rustls, which supports TLS 1.2 and 1.3
only. No weak cipher suites are available. The cipher
selection follows rustls defaults and is not
configurable at this time.
