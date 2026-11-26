# Quickstart: run Praxis in a container

Run the published Praxis image as an HTTP reverse proxy in front of a small
backend and send a request through it. No Rust toolchain is needed; to build
the binary yourself, see [build from source](build-from-source.md).

## Prerequisites

- Docker or Podman (replace `docker` with `podman` in the commands).
- curl.
- Port 8080 free on the host's loopback interface.

Images are built for `linux/amd64`. On another architecture, such as Apple
silicon, add `--platform linux/amd64` to each `docker run` (this relies on
your engine's emulation) or build from source.

Image tags are listed on the
[package page](https://github.com/praxis-proxy/praxis/pkgs/container/praxis).
This page uses `0.8.0`:

```console
export PRAXIS_IMAGE=ghcr.io/praxis-proxy/praxis:0.8.0
```

## Write the configs

In an empty working directory, write two configs. Both containers run Praxis:
one as the backend, one as the proxy.

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

The proxy routes every path to the backend container. Save it as
`praxis.yaml`:

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
upstream hostnames that resolve to private addresses (the proxy returns
`502 Bad Gateway`) unless the cluster lists the host in
`trusted_private_endpoints`. The entry trusts only that host, and only for
RFC 1918 and IPv6 unique-local addresses. Read
[security hardening](../operating/security-hardening.md) before trusting a
name in a real deployment.

The `admin` block keeps the health endpoint on loopback inside each container,
where the image's built-in health check probes it.

Validate the proxy config:

```console
docker run --rm -v "$PWD/praxis.yaml:/etc/praxis/config.yaml:ro" \
  "$PRAXIS_IMAGE" --validate
```

A valid config prints nothing and exits with status 0. On SELinux hosts, append `,Z` to
each volume option (`:ro,Z`) so the container can read the file.

## Start the backend and the proxy

Create a network so the proxy reaches the backend by name:

```console
docker network create praxis-quickstart
```

Start the backend (not published on the host):

```console
docker run -d --rm --name backend --network praxis-quickstart \
  -v "$PWD/backend.yaml:/etc/praxis/config.yaml:ro" \
  "$PRAXIS_IMAGE"
```

Start the proxy, publishing its listener on host loopback:

```console
docker run -d --rm --name praxis --network praxis-quickstart \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/praxis.yaml:/etc/praxis/config.yaml:ro" \
  "$PRAXIS_IMAGE"
```

The image's entrypoint is `praxis -c /etc/praxis/config.yaml`, so the
mounted file replaces the default config.

## Send a request

```console
curl --fail-with-body http://127.0.0.1:8080/
```

Expected body:

```json
{"source":"quickstart-backend"}
```

The proxy adds a `via: 1.1 praxis` response header (see it with `curl -i`).

## Clean up

```console
docker stop praxis backend
docker network rm praxis-quickstart
```

Stopping the containers removes them (`--rm`). Delete `praxis.yaml` when
you no longer need it; [route requests](route-requests.md) reuses
`backend.yaml`.

## If the request fails

- **Connection refused:** check `docker ps` for the `praxis` container and
  `docker logs praxis` for startup errors. Another process may hold port 8080.
- **`502 Bad Gateway`:** check `docker logs praxis`. A log line saying the
  upstream resolved to a private address means the `trusted_private_endpoints`
  entry is missing or doesn't match the endpoint host. Also check that the
  `backend` container is running on the same network.
- **Permission denied reading the config:** on SELinux hosts, add `,Z` to the
  volume options.

See [diagnostics](../operating/diagnostics.md) for config checks and logs.

## Next steps

- [Route requests](route-requests.md): add a second backend and send each
  path to the right one.
- [Configuration](../operating/configuration.md): listeners, filter chains,
  routing, load balancing, and runtime settings.
- [TLS](../operating/tls.md): certificates and upstream verification.
- [Security hardening](../operating/security-hardening.md): production
  deployment guidance.
- [Filters](../filters/README.md) and the
  [filter reference](../filters/reference.md): every built-in filter.
- [Example configs](../../examples/README.md): working YAML for each feature.
