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

- [Configuration](configuration.md): filter chains,
  routing, load balancing, TLS, and all options.
- [Example configs](../examples/configs/): working YAML
  for every feature.
- [Filters](filters.md): built-in filters and how to
  write your own.
