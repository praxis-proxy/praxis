# Changelog

<!-- markdownlint-disable MD013 -->

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

> **Types of changes:**
>
> - **Added**: for new features.
> - **Changed**: for changes in existing functionality.
> - **Deprecated**: for soon-to-be removed features.
> - **Removed**: for now removed features.
> - **Fixed**: for any bug fixes.
> - **Security**: in case of vulnerabilities.

## [Unreleased]

### Added

- Named filter chains take a `conditions:` list that every filter in the chain
  inherits, ANDed with the filter's own conditions, wherever the chain is used
  (listeners, branch chains, outbound bindings).
  ([#1286](https://github.com/praxis-proxy/praxis/pull/1286))
- `access_log` takes an optional `template` that renders each record as one
  text line from `{field}` placeholders, such as
  `'{method} {path} {status} {duration_ms}ms'`. It can't be combined with
  `fields`. ([#1323](https://github.com/praxis-proxy/praxis/pull/1323))
- `access_log` takes an optional `sink` that writes records to stdout or to a
  file opened for append, as NDJSON (or the `template` line, if one is set),
  bypassing the tracing subscriber. Delivery is best effort: if the writer
  falls behind, records are dropped rather than blocking requests.
  ([#1324](https://github.com/praxis-proxy/praxis/pull/1324))
- `url_rewrite` has a `preserve_query_params_only` operation that keeps only
  the listed query parameters and drops the rest.
  ([#1339](https://github.com/praxis-proxy/praxis/pull/1339))
- With the `otel` feature and an OTLP exporter, Praxis continues a valid
  inbound W3C `traceparent` and exports a client span for each upstream
  attempt, so traces link across Praxis hops. The forwarded `traceparent` now
  names that client span instead of a synthetic hop ID.
  ([#1347](https://github.com/praxis-proxy/praxis/pull/1347))
- Filter conditions take `headers_present`, a list of header names that must
  all be present (any value), in both request and response conditions.
  ([#1348](https://github.com/praxis-proxy/praxis/pull/1348))
- Rust API: `praxis-proxy-filter` adds the `ClientResponseHeadersCommitted` and
  `StreamBodySuppressed` request extension markers, a typed
  `CalloutResponseTooLarge` error, and
  `FilteredSubrequestExecutor::for_callout_with_limits` for separate buffered
  and streaming callout limits.
  ([#1349](https://github.com/praxis-proxy/praxis/pull/1349))
- `router` routes accept an optional `hedge_policy` (`initial_requests`,
  `max_attempts`, `per_try_timeout_ms`, `budget_percent`), validated at load.
  Nothing sends hedged requests yet; requests still take the single-upstream
  path. ([#1361](https://github.com/praxis-proxy/praxis/pull/1361))

### Changed

- **Breaking:** `/healthy`, `/ready` and `/metrics` moved off `admin.address`
  to their own listener, `admin.metrics_address`, which may bind a non-loopback
  address without `insecure_options.allow_public_admin`. Set it and move probes
  and scrapes there. The container image now exposes and health-checks port
  9902 instead of 9901.
  ([#1342](https://github.com/praxis-proxy/praxis/pull/1342))
- Config validation rejects an `admin.address` or `admin.metrics_address` that
  overlaps the other or a proxy listener.
  ([#1342](https://github.com/praxis-proxy/praxis/pull/1342))
- **Breaking:** Rust API: `ConditionMatch` and `ResponseConditionMatch` have a
  new public `headers_present` field, so struct literals need
  `headers_present: None`.
  ([#1348](https://github.com/praxis-proxy/praxis/pull/1348))

### Removed

- **Breaking:** Rust API: `praxis-proxy-protocol` drops
  `add_admin_endpoints_to_pingora_server` and
  `add_admin_endpoints_to_pingora_server_with_recorder`. Use
  `add_admin_api_to_pingora_server`,
  `add_health_endpoint_to_pingora_server_with_pipelines` and
  `add_prometheus_upkeep_to_pingora_server`.
  ([#1342](https://github.com/praxis-proxy/praxis/pull/1342))
- **Breaking:** Rust API: `praxis-proxy-filter` drops
  `set_policy_subrequest_connector` and
  `registered_policy_subrequest_connector`. Call
  `FilterRegistry::set_policy_connector` on the registry you build pipelines
  from. ([#1344](https://github.com/praxis-proxy/praxis/pull/1344))

### Fixed

- HTTP/1.1 responses with a body go out chunked when a response filter removes
  the upstream `Content-Length`. Before, they were delimited by closing the
  connection, so clients couldn't reuse it.
  ([#1284](https://github.com/praxis-proxy/praxis/pull/1284))
- A retry that moves to another endpoint keeps the SNI the first attempt took
  from the cluster authority or the client `Host`, instead of using the new
  endpoint's address (or no SNI at all for an IP endpoint).
  ([#1343](https://github.com/praxis-proxy/praxis/pull/1343))
- Policy filters built for two runtimes in one process no longer end up on
  each other's sub-request pool, admission limit and circuit breaker.
  ([#1344](https://github.com/praxis-proxy/praxis/pull/1344))
- A TLS cluster that reaches an IP endpoint without `tls.sni` now verifies it
  against the certificate's IP SAN; before, every request failed with a 502,
  verify on or off. `authority: { from: endpoint }` with IP endpoints no
  longer needs `allow_tls_without_sni`.
  ([#1345](https://github.com/praxis-proxy/praxis/pull/1345))
- Rust API: `Config::from_yaml` and `Config::validate` reject a bad
  `runtime.log_overrides` entry. Before, such a config loaded fine and failed
  later unless the caller ran the logging validators itself.
  ([#1346](https://github.com/praxis-proxy/praxis/pull/1346))
- Bodies buffered in `StreamBuffer` mode now hold memory in proportion to the
  payload. Before, lots of tiny chunks (small HTTP/2 DATA frames, say) could
  keep far more memory alive than the body limit allowed.
  ([#1351](https://github.com/praxis-proxy/praxis/pull/1351))

### Security

- `--dump` and the admin `/api/pipelines` view now redact credential-looking
  header matcher values (`authorization`, `x-session-id` and the like) in
  filter and chain conditions, and `--dump` redacts `credential_injection`
  values nested in `iterative_request_router` steps. Both used to print them
  as configured. ([#1286](https://github.com/praxis-proxy/praxis/pull/1286))

Releases 0.1.0 through 0.7.3 came out before this file existed; their notes
are on [GitHub Releases](https://github.com/praxis-proxy/praxis/releases).

[Unreleased]: https://github.com/praxis-proxy/praxis/compare/v0.7.3...HEAD
