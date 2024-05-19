# Praxis Core

Shared types, config schema, and server life-cycle. Every other crate depends on this one.

## Key Types

### Config

| Type | Purpose |
|------|---------|
| `Config` | Top-level proxy configuration: listeners, pipeline entries, runtime options, and optional body-size limits. Loaded via `Config::from_file`. |
| `Listener` | A single listening address, `protocol` (`http` / `tcp`, default `http`), optional TLS config (`TlsConfig { cert_path, key_path }`), and optional `upstream` address (required for `protocol: tcp`). |
| `ProtocolKind` | Enum discriminant for `Listener.protocol`: `Http` (default) or `Tcp`. |
| `FilterChainConfig` | A named, reusable group of filters. Listeners reference chains by name via `filter_chains:`. |
| `PipelineEntry` | One filter slot in the pipeline: `filter` name, `config` YAML blob, optional `conditions` / `response_conditions`. |
| `Condition` | Request-phase predicate: `path`, `path_prefix`, `methods`, `headers`. Used in `when`/`unless` gates. |
| `ResponseCondition` | Response-phase predicate: `status`, `headers`. Gates `on_response` execution. |
| `Route` | A routing rule: `path_prefix`, optional `host`, and target `cluster` name. |
| `Cluster` | A named group of upstream endpoints with connection timeouts, a load-balancing strategy, and optional upstream TLS settings (`upstream_tls`, `upstream_sni`). |
| `Endpoint` | One upstream endpoint — either a plain `"host:port"` string or `{ address, weight }` for weighted round-robin. |
| `LoadBalancerStrategy` | Load-balancing algorithm for a cluster. Either a `SimpleStrategy` string (`round_robin` / `least_connections`) or a `ParameterisedStrategy` map (`consistent_hash` with an optional `header`). Defaults to `round_robin`. |
| `RuntimeConfig` | Runtime tuning: `threads` (0 = auto-detect CPUs) and `work_stealing` (default `true`). |

### Connectivity

| Type | Purpose |
|------|---------|
| `connectivity::Upstream` | Upstream peer: address, TLS flag, SNI, and connection options. |
| `connectivity::ConnectionOptions` | Per-upstream timeout tuning (connect, idle, read, write). |

### Errors & Server

| Type | Purpose |
|------|---------|
| `ProxyError` | Error enum with three variants: `Config`, `NoRoute`, `NoUpstream`. |
| `server::build_http_server` | Creates a bootstrapped Pingora `Server` with graceful shutdown and runtime config. Protocol crates add their services; the binary calls `run_forever()`. |
