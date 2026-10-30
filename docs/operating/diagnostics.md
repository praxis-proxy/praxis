# Diagnostics

Use the CLI, admin API, and process logs to inspect a
running proxy or investigate a failed startup.

## Version and Configuration

Run these commands with the same binary, configuration,
and environment as the affected instance:

```console
praxis --version
praxis --validate --config praxis.yaml
praxis --dump --config praxis.yaml > effective-config.yaml
```

`--validate` and `--dump` exit without binding listeners.
Both return a non-zero exit status on failure and write
warnings and errors to stderr. Listener startup can still
fail if a port is unavailable or TLS files cannot be loaded.

The dump includes configuration defaults and resolved
top-level listener chains. It reads the file on disk;
after a failed reload, the running proxy may still use
an older config.
Known secrets are redacted by name, but custom secret
fields may remain. Review the output before sharing it.

See [Validating Configuration] and
[Dumping Effective Configuration] for details.

[Validating Configuration]: configuration.md#validating-configuration
[Dumping Effective Configuration]:
configuration.md#dumping-effective-configuration

## Live State

The examples below use separate admin and health/metrics
listeners:

```yaml
admin:
  address: "127.0.0.1:9901"
  metrics_address: "127.0.0.1:9902"
```

Both require the `admin-api` build feature, enabled by
default. Neither listener has authentication. Keep the
admin interface on loopback or a trusted, access-controlled
network, and restrict access to health and metrics too.
See [Admin] for binding restrictions.

[Admin]: configuration.md#admin

Inspect the running proxy:

```console
curl -fsS http://127.0.0.1:9901/api/stats
curl -fsS http://127.0.0.1:9901/api/pipelines
curl -sS -i http://127.0.0.1:9902/ready
curl -fsS http://127.0.0.1:9902/metrics
```

What to check:

- `GET /api/stats`: `version.display`, uptime, listener
  activity and upstream health. `version.git_sha` is
  present when available at build time.
- `GET /api/pipelines`: resolved live pipelines, including
  branches. Use `?listener=NAME` to inspect one listener.
- `GET /healthy`: liveness. Returns `200` once the
  listener accepts requests.
- `GET /ready`: upstream readiness. Returns `503` when a
  cluster has no healthy endpoints. With no health
  checks, this returns `200`.
- `GET /metrics`: request, error, health and reload
  metrics.

`/api/*` uses port 9901 in this example; health and metrics
use 9902. `/ready` is an upstream health check, not a
drain-status endpoint. Enable `admin.verbose` only when
per-cluster readiness detail is needed; it exposes
internal topology.

See [Observability] for endpoint responses and metric
definitions, and [Health Checking] for probe behaviour.

[Observability]: observability.md
[Health Checking]: health-checking.md

## Temporary Debug Logging

Read the current log settings, then enable debug logging
for the config watcher for five minutes:

```console
curl -fsS http://127.0.0.1:9901/api/log-level
curl -fsS -X PUT http://127.0.0.1:9901/api/log-level \
  -H 'Content-Type: application/json' \
  -d '{"module":"praxis::watcher","level":"debug","duration_secs":300}'
```

The overlay expires automatically. Clear it early with:

```console
curl -fsS -X DELETE 'http://127.0.0.1:9901/api/log-level?module=praxis::watcher'
```

See [Runtime Log Levels] for global overlays and limits.
For startup failures, use `RUST_LOG` and
`PRAXIS_LOG_FORMAT=json` when starting the process; the
admin API only responds once its listener is bound.

[Runtime Log Levels]: observability.md#runtime-log-levels-apilog-level

## Startup and Reload Failures

Keep the startup or reload error and the preceding log
messages. Warnings identify active `insecure_options`,
experimental features and unsafe file permissions.

With the default Pingora backend, an occupied listener
address causes binding to retry before failing. The admin
endpoints may still respond; test the affected listener too.

For reloads, look for `config reload complete`. A failed
reload logs the error with `config reload failed`, or
with `failed to read config file for reload` when the
file cannot be read. Rejected configurations leave the
previous pipelines serving traffic. A `requires restart`
warning means a startup-only setting has not taken effect.

The metrics `praxis_config_reload_total{result="success"}`
and `praxis_config_reload_total{result="failure"}` count
reload outcomes. `praxis_config_reload_last_success_timestamp`
records the last successful reload as Unix time in seconds.
Compare these with `/api/pipelines` and the process logs
when checking whether an edit took effect.

See [Dynamic Configuration Reload] for settings that can
reload and changes that require a restart or are rejected.

[Dynamic Configuration Reload]: configuration.md#dynamic-configuration-reload

## Draining Before Shutdown

Stop routing new traffic to the instance before sending
SIGTERM. Wait for active work to finish, using
`praxis_http_active_requests` for HTTP and
`praxis_tcp_active_connections` for TCP, together with
the access logs. Long-lived streams may need a separate
drain window.

With the default Pingora backend, the request grace period
after SIGTERM is at most five seconds. Increasing
`shutdown_timeout_secs` does not extend that period.
Allow time for shutdown and for logs and spans to flush
before forcing the process to exit.
See [Graceful Shutdown] for the timeout behaviour.

[Graceful Shutdown]: configuration.md#graceful-shutdown
