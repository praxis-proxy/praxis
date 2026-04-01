# TLS

Praxis terminates TLS via rustls on listeners, forwarding plaintext
HTTP to backends.

```text
Client --TLS--> Praxis --HTTP--> Backend
```

## Configuration

Add `tls` to any listener. PEM format, cert may include the full chain.

```yaml
listeners:
  - name: secure
    address: "0.0.0.0:443"
    filter_chains: [routing]
    tls:
      cert_path: /etc/praxis/tls/cert.pem
      key_path: /etc/praxis/tls/key.pem
```

## HTTP + HTTPS

```yaml
listeners:
  - name: http
    address: "0.0.0.0:80"
    filter_chains: [routing]
  - name: https
    address: "0.0.0.0:443"
    filter_chains: [routing]
    tls:
      cert_path: /etc/praxis/tls/cert.pem
      key_path: /etc/praxis/tls/key.pem
```

Both reference the same filter chains, sharing the
pipeline.

## Multiple certificates

Each listener carries its own cert:

```yaml
listeners:
  - name: app
    address: "0.0.0.0:8443"
    tls:
      cert_path: /etc/praxis/tls/app.pem
      key_path: /etc/praxis/tls/app-key.pem
  - name: api
    address: "0.0.0.0:9443"
    tls:
      cert_path: /etc/praxis/tls/api.pem
      key_path: /etc/praxis/tls/api-key.pem
```

## Local dev with mkcert

```console
mkcert -install
mkcert localhost 127.0.0.1
```

```yaml
listeners:
  - name: local
    address: "127.0.0.1:8443"
    tls:
      cert_path: ./localhost+1.pem
      key_path: ./localhost+1-key.pem
```

## Upstream re-encryption

Set `upstream_tls: true` to TLS-connect to backends:

```text
Client --TLS--> Praxis --TLS--> Backend
```

```yaml
- filter: load_balancer
  clusters:
    - name: backend
      upstream_tls: true
      upstream_sni: "backend.internal"
      endpoints:
        - "10.0.0.1:443"
```

`upstream_sni` sets the backend SNI hostname. Defaults to the
incoming `Host` header.

## Backend encryption only

Praxis can accept plain HTTP on the frontend and
encrypt traffic to backends. This is useful when TLS
termination happens elsewhere (e.g. a cloud load
balancer) but backends require encrypted connections.

```text
Client --HTTP--> Praxis --TLS--> Backend
```

Omit `tls` from the listener and set `upstream_tls` on
the cluster:

```yaml
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [routing]

filter_chains:
  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            upstream_tls: true
            upstream_sni: "backend.internal"
            endpoints:
              - "10.0.0.1:443"
```

## Ciphers

TLS 1.2+ only, rustls defaults (no weak suites).
