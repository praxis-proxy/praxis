# Build from source and run a local proxy

To run the published container image without a Rust toolchain, use the
[quickstart](quickstart.md).

This walkthrough builds Praxis from a checkout and forwards a request through
it to a local backend. You need Git, Make, curl, and the build prerequisites
in [contributor setup](../developing/getting-started.md#requirements). Use a
non-root account and leave ports 3000 and 8080 free.

Run all commands from the repository root. In an existing checkout, skip the
clone and run `make release`. The binary comes from your checkout, not a
pinned release.

```console
git clone https://github.com/praxis-proxy/praxis.git
cd praxis
make release
```

## Start the backend

In a second terminal, start a backend with a recognizable response:

```console
cargo xtask echo --address 127.0.0.1:3000 --body '{"source":"local-backend"}'
```

If port 3000 is taken, the echo utility picks another port and logs it. Free
port 3000 and restart it before continuing. Check the backend directly from
the first terminal:

```console
curl --fail-with-body http://127.0.0.1:3000/
```

Expected body:

```json
{"source":"local-backend"}
```

## Configure and start Praxis

If a `praxis.yaml` already exists in the repository root, move it to an
unused backup path and restore it when you finish. Then create this
`praxis.yaml`:

```yaml
# Local development only: permit the literal loopback backend.
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

The literal loopback backend needs `allow_private_endpoints`; a literal IP
does not need `allow_private_upstreams`. Remove the exception before
deploying, and see [security hardening](../operating/security-hardening.md)
for runtime DNS checks and scoped trust for private upstream hostnames.
Other settings are in the [configuration reference](../operating/configuration.md).

Start Praxis in the first terminal and leave it running:

```console
./target/release/praxis -c praxis.yaml
```

From a third terminal, request the proxy:

```console
curl --fail-with-body http://127.0.0.1:8080/
```

The expected body is the backend's, `{"source":"local-backend"}`. Stop
Praxis and the echo server with Ctrl+C.

## If the request fails

- **Connection refused on port 8080:** check the Praxis startup logs and
  whether another process holds the listener address.
- **Upstream connection failure:** curl port 3000 directly and check the echo
  server's logged address. Both processes must stay running.
- **Wrong response or route:** confirm you started Praxis with `-c praxis.yaml`
  and that the router's `cluster: backend` matches the load balancer's cluster
  name.
- **Private endpoint rejection:** the loopback fixture needs the exception
  shown. For DNS names and real deployments, follow security hardening
  instead of adding broad bypass flags.

See [diagnostics](../operating/diagnostics.md) for config checks and logs.

## Optional: built-in responder

Praxis loads `praxis.yaml` from the working directory, or the file in
`PRAXIS_CONFIG`, when present. With neither, it starts a default responder on
port 8080 that does not forward anywhere. Remove the sample `praxis.yaml`
(keep any backup where it is), then run:

```console
unset PRAXIS_CONFIG
./target/release/praxis
```

From another terminal:

```console
curl --fail-with-body http://127.0.0.1:8080/
```

```json
{"status": "ok", "server": "praxis"}
```

Stop it with Ctrl+C and restore any config you backed up.

## Quick Test Servers

The echo utility serves static responses without a YAML config (it still
builds and runs Rust code):

```console
cargo xtask echo --status 201 --body '{"created": true}' --header "X-Custom: value"
```

The debug utility runs Praxis with debug logs, an admin API on port 9090,
and one worker thread:

```console
cargo xtask debug
cargo xtask debug examples/configs/traffic-management/basic-reverse-proxy.yaml
```

Run one server at a time when they use the same listener port.

## Next steps

- [Configuration](../operating/configuration.md): every option.
- [TLS](../operating/tls.md): certificates and upstream verification.
- [Contributor setup](../developing/getting-started.md): build, test, and lint.
- [Example configs](../../examples/configs/): working YAML
  for every feature.
- [Filters](../filters/README.md): built-in filters and
  how to write your own.
- [HTTP Filter Tutorial](../developing/http-filter-tutorial.md):
  build and run a custom filter from scratch.
