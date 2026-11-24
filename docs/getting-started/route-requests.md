# Route requests to two backends

This walkthrough extends the [quickstart](quickstart.md): one listener sends
requests under `/catalog/` to a second backend and every other path to the
first, and you check which backend answers each request. It uses the same
image, working directory and `backend.yaml`.

## Before you start

Complete the quickstart, including its clean-up step, so port 8080, the
container names and the `praxis-quickstart` network are free. Keep
`PRAXIS_IMAGE` exported and stay in the working directory that holds
`backend.yaml`.

## Write the configs

The second backend is a copy of the first with a different response body:

```console
sed 's/quickstart-backend/catalog-backend/' backend.yaml > catalog.yaml
```

Save the proxy configuration as `routes.yaml`:

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
          - path_prefix: "/catalog/"
            cluster: catalog
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "backend:8080"
            trusted_private_endpoints:
              - "backend"
          - name: catalog
            endpoints:
              - "catalog:8080"
            trusted_private_endpoints:
              - "catalog"
```

The `router` picks a cluster for each request, and the `load_balancer` picks
an endpoint in that cluster. The longest matching prefix wins, whatever the
order of the routes, so `/catalog/items` goes to `catalog` and `/` falls back
to `backend`. Each cluster trusts only its own container name; see the
quickstart for why `trusted_private_endpoints` is needed.

Check the proxy config before starting it:

```console
docker run --rm -v "$PWD/routes.yaml:/etc/praxis/config.yaml:ro" \
  "$PRAXIS_IMAGE" --validate
```

The command prints nothing and exits with status 0 when the config is valid.
On SELinux hosts, append `,Z` to each volume option (`:ro,Z`).

## Start the backends and the proxy

```console
docker network create praxis-quickstart
docker run -d --rm --name backend --network praxis-quickstart \
  -v "$PWD/backend.yaml:/etc/praxis/config.yaml:ro" \
  "$PRAXIS_IMAGE"
docker run -d --rm --name catalog --network praxis-quickstart \
  -v "$PWD/catalog.yaml:/etc/praxis/config.yaml:ro" \
  "$PRAXIS_IMAGE"
docker run -d --rm --name praxis --network praxis-quickstart \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/routes.yaml:/etc/praxis/config.yaml:ro" \
  "$PRAXIS_IMAGE"
```

## Send a request to each route

A path under `/catalog/` reaches the catalog backend:

```console
curl --fail-with-body http://127.0.0.1:8080/catalog/items
```

```json
{"source":"catalog-backend"}
```

Any other path matches the `/` fallback:

```console
curl --fail-with-body http://127.0.0.1:8080/
```

```json
{"source":"quickstart-backend"}
```

Prefixes match whole path segments, and a trailing slash on the prefix makes
no difference: `/catalog` and `/catalog/items` go to `catalog`, while
`/catalogue` goes to `backend`. Use `path` instead of `path_prefix` for an
exact match.

## Clean up

```console
docker stop praxis catalog backend
docker network rm praxis-quickstart
```

Delete `catalog.yaml` and `routes.yaml` when you no longer need them.

## Next steps

- [Router filter](../filters/http/traffic_management/router.md): host and
  header matching, exact paths and per-route retries.
- [Load balancing](../operating/load-balancing.md): several endpoints per
  cluster, strategies and weights.
- [Rehearse a reload](../operating/reload.md): change a running proxy's
  routes without a restart.
