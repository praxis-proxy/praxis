# Diagnostics

How to inspect a running proxy or investigate a failed startup with the CLI,
the admin API, and process logs.

## Version and Configuration

Run these with the same binary, configuration, and environment as the
affected instance:

```console
praxis --version
praxis --validate --config praxis.yaml
praxis --dump --config praxis.yaml > effective-config.yaml
```

Neither `--validate` nor `--dump` binds listeners, so startup can still fail
on a busy port or an unloadable TLS file. The dump reads the file on disk:
after a failed reload, the running proxy may still be on an older config.
Known secrets are redacted by name, but custom secret fields may remain, so
review the dump before sharing it. Exit codes and output are in
[Validating Configuration] and [Dumping Effective Configuration].

[Validating Configuration]: configuration.md#validating-configuration
[Dumping Effective Configuration]:
configuration.md#dumping-effective-configuration

## Live State

These examples put the admin API on 9901 and health and metrics on 9902:

```yaml
admin:
  address: "127.0.0.1:9901"
  metrics_address: "127.0.0.1:9902"
```

Both need the `admin-api` build feature (on by default), and neither has
authentication; see [Admin] for binding restrictions.

[Admin]: configuration.md#admin

```console
curl -fsS http://127.0.0.1:9901/api/stats
curl -fsS http://127.0.0.1:9901/api/pipelines
curl -sS -i http://127.0.0.1:9902/ready
curl -fsS http://127.0.0.1:9902/metrics
```

| Endpoint | What to check |
|-|-|
| `GET /api/stats` | `version.display`, uptime, listener activity and upstream health. `version.git_sha` is present when available at build time. |
| `GET /api/pipelines` | Resolved live pipelines, including branches. Use `?listener=NAME` to inspect one listener. |
| `GET /ready` | Why a replica is unready (see below). |
| `GET /metrics` | Request, error, health and reload metrics; see [Observability]. |

`/ready` returns `503` while the replica is initializing, draining or
stopped, and the body names the phase (`{"status":"draining"}` during
shutdown). With active health checks it also carries cluster counts. Once
serving, the default `admin.readiness: serving` stays `200` when a cluster
has no healthy endpoints, and `readiness: upstreams` returns `503`, so the body tells you whether the replica is shutting down or an
upstream is down. `admin.verbose` adds per-cluster detail but exposes
internal topology; enable it only when needed. Probe behavior is in
[Health Checking].

[Observability]: observability.md
[Health Checking]: health-checking.md

## Temporary Debug Logging

Read the current log settings, then turn on debug logging for the config
watcher for five minutes:

```console
curl -fsS http://127.0.0.1:9901/api/log-level
curl -fsS -X PUT http://127.0.0.1:9901/api/log-level \
  -H 'Content-Type: application/json' \
  -d '{"module":"praxis::watcher","level":"debug","duration_secs":300}'
```

The overlay expires on its own. To clear it early:

```console
curl -fsS -X DELETE 'http://127.0.0.1:9901/api/log-level?module=praxis::watcher'
```

[Runtime Log Levels] covers global overlays and limits. The admin API exists
only after startup, so for startup failures set `RUST_LOG` and
`PRAXIS_LOG_FORMAT=json` when starting the process.

[Runtime Log Levels]: observability.md#runtime-log-levels-apilog-level

## Startup and Reload Failures

Keep the startup or reload error and the log lines before it. Warnings name
active `insecure_options`, experimental features and unsafe file permissions.

With the default Pingora backend, an occupied listener address makes binding
retry before it fails. The admin endpoints may still answer, so test the
affected listener too.

For reloads, look for `config reload complete` or `config reload failed` and
its error. A rejected config leaves the previous pipelines serving. A
`requires restart` warning means a startup-only setting has not taken effect.

`praxis_config_reload_total{result="success"}` and
`praxis_config_reload_total{result="failure"}` count reload outcomes, and
`praxis_config_reload_last_success_timestamp` holds the last successful
reload as Unix time in seconds. Compare them with `/api/pipelines` and the
logs to check whether an edit took effect. [Dynamic Configuration Reload]
lists what reloads, what needs a restart, and what is rejected.

[Dynamic Configuration Reload]: configuration.md#dynamic-configuration-reload

## Draining Before Shutdown

Stop routing new traffic to the instance before sending SIGTERM, then wait
for active work to finish: watch `praxis_http_active_requests` for HTTP,
`praxis_tcp_active_connections` for TCP, and the access logs. Long-lived
streams may need their own drain window.

With the default Pingora backend, requests get at most five seconds after
SIGTERM, however high `shutdown_timeout_secs` is, so long-lived and streaming
responses are cut when that expires. Drain them before SIGTERM if they need
longer, and allow time for logs and spans to flush before forcing the
process to exit. See [Graceful Shutdown] for the timing.

[Graceful Shutdown]: configuration.md#graceful-shutdown
