# Quickstart

Build the release binary:

```console
make release
```

Start Praxis:

```console
./target/release/praxis
```

The server starts on `127.0.0.1:8080` with a built-in
default configuration. Verify it:

```console
curl http://127.0.0.1:8080/
```

```json
{"status": "ok", "server": "praxis"}
```

## Proxy to a backend

Create `praxis.yaml`:

```yaml
# The backend below is on loopback, which the SSRF endpoint check
# rejects unless you opt in. Drop this block once your backends are
# on real addresses.
insecure_options:
  allow_private_endpoints: true

listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]

filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:3000"
```

> **Note:** Praxis rejects upstream endpoints that resolve to
> loopback, link-local, or cloud-metadata addresses by default, as an
> SSRF guard. `insecure_options.allow_private_endpoints: true` opts a
> config into using them — appropriate for local development, not for
> production configs pointing at real backends.

Start Praxis with your config:

```console
./target/release/praxis -c praxis.yaml
```

Requests to port 8080 are now forwarded to your backend
on port 3000:

```console
curl http://127.0.0.1:8080/
```

## Next steps

- [Configuration](operating/configuration.md): filter
  chains, routing, load balancing, TLS, and all options.
- [Example configs](../examples/configs/): working YAML
  for every feature.
- [Filters](filters/README.md): built-in filters and
  how to write your own.
- [HTTP Filter Tutorial](filters/http-filter-tutorial.md):
  build and run a custom filter from scratch.
