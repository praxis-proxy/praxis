---
sidebar_position: 3
title: TLS & mTLS
---

# TLS

Working example configs for every TLS scenario live in
[`examples/configs/protocols/`](https://github.com/praxis-proxy/praxis/tree/main/examples/configs/protocols):

| Example | Scenario |
| ------- | -------- |
| [tls-termination](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-termination.yaml) | HTTPS listener, plain HTTP upstream |
| [tls-http-reencrypt](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-http-reencrypt.yaml) | HTTPS listener, TLS upstream |
| [tls-multi-cert](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-multi-cert.yaml) | SNI with multiple certificates |
| [tls-version-constraint](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-version-constraint.yaml) | TLS 1.3 only |
| [tls-mtls-listener](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-mtls-listener.yaml) | Require client certificate |
| [tls-mtls-listener-request](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-mtls-listener-request.yaml) | Request (optional) client cert |
| [tls-mtls-upstream](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-mtls-upstream.yaml) | Client cert to upstream |
| [tls-mtls-both](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-mtls-both.yaml) | mTLS on both sides |
| [tls-verify-disabled](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-verify-disabled.yaml) | Skip upstream cert verify (dev) |
| [upstream-tls](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/upstream-tls.yaml) | Plain listener, TLS upstream |
| [upstream-ca-file](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/upstream-ca-file.yaml) | Global CA for all upstreams |
| [tcp-tls-termination](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tcp-tls-termination.yaml) | TLS on TCP listener |
| [tcp-tls-mtls](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tcp-tls-mtls.yaml) | mTLS on TCP listener |

## Listener TLS

Add `tls` to any listener. PEM format; the cert file
may include the full chain. See [tls-termination](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-termination.yaml) for
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
fallback). See [tls-multi-cert](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-multi-cert.yaml).

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
[tls-version-constraint](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-version-constraint.yaml).

### Listener mTLS

Require or request client certificates with
`client_ca` and `client_cert_mode`.

| Mode | Behavior |
| ---- | -------- |
| `none` | Do not request a client certificate (default) |
| `request` | Ask for a cert but allow connections without one |
| `require` | Reject connections without a valid client cert |

`client_ca` is required when mode is `request` or
`require`. See [tls-mtls-listener](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-mtls-listener.yaml) and
[tls-mtls-listener-request](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-mtls-listener-request.yaml).

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
[upstream-tls](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/upstream-tls.yaml) and [tls-verify-disabled](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-verify-disabled.yaml).

### Upstream mTLS (Client Certificate)

Present a client certificate to upstream servers.
See [tls-mtls-upstream](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-mtls-upstream.yaml) and [tls-mtls-both](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/tls-mtls-both.yaml).

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
[upstream-ca-file](https://github.com/praxis-proxy/praxis/blob/main/examples/configs/protocols/upstream-ca-file.yaml).

## Timeouts

Pingora enforces a 60-second TLS handshake timeout
(hardcoded). For total connection budgets (TCP + TLS),
use `total_connection_timeout_ms` on the cluster. See
[Configuration](/docs/configuration/overview) for details.

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
