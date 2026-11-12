# Quickstart: run a local reverse proxy

This source-build walkthrough starts a local backend, then forwards an HTTP
request through Praxis to it. You need Git, Make, curl, and the build
prerequisites in [contributor setup](developing/getting-started.md#requirements).
Use a non-root account and leave ports 3000 and 8080 free.

Clone the repository and run all commands from its root. Open a second
terminal in the same checkout when instructed:

```console
git clone https://github.com/praxis-proxy/praxis.git
cd praxis
make release
```

Already working in a checkout? Run `make release` there instead of cloning.
These instructions use the binary built from your checkout; they do not pin
a released version.

## Start the backend

In the second terminal, start a backend with a recognizable response:

```console
cargo xtask echo --address 127.0.0.1:3000 --body '{"source":"local-backend"}'
```

Leave it running. Check its startup log: if the address is occupied, the echo
utility selects another port. Free port 3000 and restart it before continuing.

In the first terminal, verify the backend directly:

```console
curl --fail-with-body http://127.0.0.1:3000/
```

Expected body:

```json
{"source":"local-backend"}
```

## Configure and start Praxis

Before creating the sample, check whether `praxis.yaml` already exists in
the repository root. If it does, move it to a backup path that is not already
in use and keep that backup until you finish the walkthrough, including the
optional default-responder check. Do not overwrite an existing config or
backup.

Create the walkthrough's sample `praxis.yaml` in the repository root:

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

The literal loopback backend requires `allow_private_endpoints` for this local
fixture. Remove that development exception before deploying and review
[security hardening](operating/security-hardening.md), including runtime DNS
checks and scoped trust for private upstream hostnames. The literal IP in
this example does not need `allow_private_upstreams`. See the
[configuration reference](operating/configuration.md) for other settings.

In the first terminal, start Praxis and leave it running:

```console
./target/release/praxis -c praxis.yaml
```

In a third terminal, request the proxy:

```console
curl --fail-with-body http://127.0.0.1:8080/
```

Expected body:

```json
{"source":"local-backend"}
```

| Request port | Process | What success shows |
| --- | --- | --- |
| `3000` | Echo backend | The backend is listening. |
| `8080` | Configured Praxis | The proxy reaches the backend. |

## Stop and clean up

Press Ctrl+C in the Praxis and echo terminals. Remove only the sample
`praxis.yaml` created for this walkthrough. If you preserved an existing
config, restore it to its original path now, unless you are continuing to
the optional default-responder check below; restore it after that check
instead. Keep the sample's development exception out of production configs.

## If the request fails

- **Connection refused on port 8080:** check Praxis startup logs and confirm
  another process has not taken the listener address.
- **Upstream connection failure:** curl port 3000 directly and check the echo
  server's logged address. Both processes must stay running.
- **Wrong response or route:** confirm you started Praxis with `-c praxis.yaml`
  and that the router's `cluster: backend` matches the load balancer's cluster
  name. See [configuration](operating/configuration.md).
- **Private endpoint rejection:** the literal loopback fixture needs the
  shown exception. For DNS names and real deployments, follow
  [security hardening](operating/security-hardening.md) instead of adding
  broad bypass flags.

See [diagnostics](operating/diagnostics.md) for config checks and logs.

## Optional: built-in responder

After stopping the proxy on port 8080, remove only the sample `praxis.yaml`
created above and leave any preserved config in its backup location. If you
already restored it, move it aside again without overwriting your backup.
Clear any `PRAXIS_CONFIG` environment variable. Praxis automatically loads
either when present. Then start it without a config:

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

This is the built-in default responder on port 8080. It does not forward to
the echo backend. Stop it with Ctrl+C before reusing that port, then restore
any preserved config to its original path.

## Quick Test Servers

For local experiments, the echo utility serves static responses without a
YAML config (it still builds and runs Rust code):

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

- [Configuration](operating/configuration.md): filter
  chains, routing, load balancing, TLS, and all options.
- [TLS](operating/tls.md): certificates and upstream verification.
- [Contributor setup](developing/getting-started.md): build, test, and lint.
- [Example configs](../examples/configs/): working YAML
  for every feature.
- [Filters](filters/README.md): built-in filters and
  how to write your own.
- [HTTP Filter Tutorial](filters/http-filter-tutorial.md):
  build and run a custom filter from scratch.
