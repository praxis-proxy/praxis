# Rehearse a configuration reload

Praxis watches its config file and swaps in new filter pipelines when it
changes, without a restart. This walkthrough rehearses that on one container:
check a response, validate a candidate file, replace the watched file, confirm
the reload in the log, and check the new response. Run through it before
changing a production proxy.

[Configuration](configuration.md#dynamic-configuration-reload) lists which
settings reload, which need a restart, which changes are rejected, and which
state survives.

## Before you start

You need the tools from the [quickstart](../getting-started/quickstart.md):
Docker or Podman, curl, port 8080 free on loopback, and `PRAXIS_IMAGE`
exported. The default build includes the `config-reload` feature this page
relies on.

## Start a proxy with a watched config

Create an empty working directory with a `config` subdirectory, and save this
as `config/config.yaml`:

```yaml
admin:
  metrics_address: "127.0.0.1:9902"

listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [respond]

filter_chains:
  - name: respond
    filters:
      - filter: static_response
        status: 200
        body: "before reload"
```

Mount the directory, not the file. Replacing a file swaps its inode, and a
container that bind-mounts the single file keeps seeing the old one:

```console
docker run -d --rm --name praxis -p 127.0.0.1:8080:8080 \
  -v "$PWD/config:/etc/praxis:ro" \
  "$PRAXIS_IMAGE"
```

On SELinux hosts, use `:ro,z` here and in the validation command below, so
both containers can read the directory. Check the response:

```console
curl --fail-with-body http://127.0.0.1:8080/
```

```text
before reload
```

## Validate a candidate

Write the change to a separate file in the same directory. Praxis reloads
only when `config.yaml` or a document a configured filter reads changes, so
the new candidate file triggers nothing, and keeping it next to `config.yaml`
keeps the final rename within one directory.

Copy the config with its permissions first, then write into the copy.
Overwriting an existing file keeps its mode, so a config holding credentials
never becomes readable by other users. `chmod u+w` adds write access for you
only, in case `config.yaml` is read-only. This change edits only the response
body:

```console
cp -p config/config.yaml config/candidate.yaml
chmod u+w config/candidate.yaml
sed 's/before reload/after reload/' config/config.yaml > config/candidate.yaml
```

Validate it with the same image as the running proxy:

```console
docker run --rm -v "$PWD/config/candidate.yaml:/etc/praxis/config.yaml:ro" \
  "$PRAXIS_IMAGE" --validate
```

Validation parses the file, builds the filter pipelines, and exits without
binding a listener. A valid file prints nothing and exits 0; review any
warnings before you continue.

## Apply the change

Note the time, then move the validated file over the watched one. A rename
replaces the file in one step, so the watcher never reads a half-written
config:

```console
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mv config/candidate.yaml config/config.yaml
```

Check the log written since then, so an earlier reload cannot answer for this
one:

```console
docker logs --since "$since" praxis 2>&1 |
  grep -E 'config reload (complete|failed)|failed to read config file'
```

The watcher waits briefly for edits to settle, so repeat the command if it
prints nothing at first. With Podman on macOS, host file changes may not reach
the Podman machine and no reload happens; run the walkthrough inside
`podman machine ssh` instead.

A `config reload failed` or `failed to read config file` line means Praxis
rejected the file and kept serving the previous config; read the error before
you try again. After a rejected reload, `praxis --dump` shows the file on
disk, not what is running; `GET /api/pipelines` from
[diagnostics](diagnostics.md) shows the live pipelines.

Send a new request:

```console
curl --fail-with-body http://127.0.0.1:8080/
```

```text
after reload
```

Requests that were already in progress finish on the previous pipeline.

## Clean up

```console
docker stop praxis
```

Delete the working directory when you no longer need it.
