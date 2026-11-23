# Quickstart: run Praxis in a container

This walkthrough runs the published Praxis container image as an HTTP reverse
proxy in front of a small backend, sends a request through it, and cleans up.
It needs no Rust toolchain. To build the binary yourself, use
[build from source](build-from-source.md).

## Prerequisites

- Docker or Podman. The commands use `docker`; with Podman, run the same
  commands with `podman`.
- curl.
- Port 8080 free on the host's loopback interface.

The published images are built for `linux/amd64`. On another architecture,
such as Apple silicon, add `--platform linux/amd64` to each `docker run`
command (this relies on your container engine's emulation) or
[build from source](build-from-source.md).

Pick the release to run. Image tags are listed on the
[package page](https://github.com/praxis-proxy/praxis/pkgs/container/praxis);
this page uses `0.8.0`:

```console
export PRAXIS_IMAGE=ghcr.io/praxis-proxy/praxis:0.8.0
```

## Write the configs

Create an empty working directory and change into it. Both containers in this
walkthrough run Praxis: one is the backend, the other is the proxy.

The backend answers every request with a fixed JSON body. Save it as
`backend.yaml`:

```yaml
admin:
  metrics_address: "127.0.0.1:9902"

listeners:
  - name: backend
    address: "0.0.0.0:8080"
    filter_chains: [respond]

filter_chains:
  - name: respond
    filters:
      - filter: static_response
        status: 200
        headers:
          - name: Content-Type
            value: application/json
        body: '{"source":"quickstart-backend"}'
```

The proxy routes every path to a cluster whose endpoint is the backend
container. Save it as `praxis.yaml`:

```yaml
admin:
  metrics_address: "127.0.0.1:9902"

listeners:
  - name: web
    address: "0.0.0.0:8080"
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
              - "backend:8080"
            trusted_private_endpoints:
              - "backend"
```

The container network gives `backend` a private address. Praxis refuses
upstream hostnames that resolve to private addresses unless the cluster lists
the host in `trusted_private_endpoints`. Without that entry the proxy returns
`502 Bad Gateway`. The entry trusts only that host, and only for RFC 1918 and
IPv6 unique-local addresses. Before trusting a name in a real deployment,
read [security hardening](../operating/security-hardening.md).

The `admin` block keeps the health endpoint on loopback inside each container,
where the image's built-in health check probes it.

Check the proxy config before starting it:

```console
docker run --rm -v "$PWD/praxis.yaml:/etc/praxis/config.yaml:ro" \
  "$PRAXIS_IMAGE" --validate
```

The command prints nothing and exits with status 0 when the config is valid.

On SELinux hosts, append `,Z` to each volume option (`:ro,Z`) so the
container can read the mounted file.

## Start the backend and the proxy

Create a network so the proxy can reach the backend by name:

```console
docker network create praxis-quickstart
```

Start the backend. It is not published on the host:

```console
docker run -d --rm --name backend --network praxis-quickstart \
  -v "$PWD/backend.yaml:/etc/praxis/config.yaml:ro" \
  "$PRAXIS_IMAGE"
```

Start the proxy and publish its listener on the host's loopback interface:

```console
docker run -d --rm --name praxis --network praxis-quickstart \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/praxis.yaml:/etc/praxis/config.yaml:ro" \
  "$PRAXIS_IMAGE"
```

The image's entrypoint is `praxis -c /etc/praxis/config.yaml`, so the
mounted file replaces the image's default config.

## Send a request

```console
curl --fail-with-body http://127.0.0.1:8080/
```

Expected body:

```json
{"source":"quickstart-backend"}
```

The response comes from the backend container through the proxy. The proxy
adds a `via: 1.1 praxis` response header, which `curl -i` shows.

## Clean up

```console
docker stop praxis backend
docker network rm praxis-quickstart
```

The containers were started with `--rm`, so stopping them removes them.
Delete `backend.yaml` and `praxis.yaml` when you no longer need them.

## If the request fails

- **Connection refused:** run `docker ps` to check that the `praxis`
  container is running, and `docker logs praxis` for startup errors. Another
  process may hold port 8080.
- **`502 Bad Gateway`:** run `docker logs praxis`. A log line saying the
  upstream resolved to a private address means the `trusted_private_endpoints`
  entry is missing or does not match the endpoint host. Also check that the
  `backend` container is running on the same network.
- **Permission denied reading the config:** on SELinux hosts, add `,Z` to the
  volume options.

See [diagnostics](../operating/diagnostics.md) for config checks and logs.

## Next steps

- [Configuration](../operating/configuration.md): listeners, filter chains,
  routing, load balancing, and runtime settings.
- [TLS](../operating/tls.md): certificates and upstream verification.
- [Security hardening](../operating/security-hardening.md): production
  deployment guidance.
- [Filters](../filters/README.md) and the
  [filter reference](../filters/reference.md): every built-in filter.
- [Example configs](../../examples/README.md): working YAML for each feature.
