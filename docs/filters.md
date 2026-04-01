# Filters

## Listeners

```mermaid
flowchart LR
    Client -->|TCP| L0["Listener (named)"]
    L0 -->|rustls| TLS
    TLS --> Resolve["Chain Resolution"]
    Resolve --> Pipeline["Filter Pipeline"]
    Pipeline --> Pool["Upstream Pool"]
    Pool --> Backend

    Config["Config (YAML)"] -. startup .-> Chains
    Chains["filter_chains:"] -. per listener .-> Resolve
```

Each listener has a `name` and a list of `filter_chains`.
At startup, the referenced chains are resolved and
concatenated into a single pipeline per listener. Different
listeners can compose different subsets of chains.

## Filter Chains

Filter chains are named, reusable groups of filters defined
at the top level of the config. A listener references one or
more chains by name; the filters are concatenated in order
to form that listener's pipeline.

```mermaid
flowchart LR
    subgraph "Listener: public"
        direction LR
        S["security chain"] --> O["observability chain"]
        O --> R["routing chain"]
    end

    subgraph "Listener: internal"
        direction LR
        O1["observability chain"] --> R2["routing chain"]
    end
```

This enables reuse without duplication. A "security" chain
can be shared across public listeners while internal
listeners skip it entirely.

### Protocol-Specific Filters

Every filter belongs to exactly one protocol level. HTTP
filters implement the `HttpFilter` trait (`on_request`,
`on_response`, body hooks). TCP filters implement the
`TcpFilter` trait (`on_connect`, `on_disconnect`). There
is no generic filter that operates at both levels. The
`AnyFilter` enum tags each filter with its protocol for
storage in a unified pipeline.

Built-in filters are organized by protocol, then by
category:

```text
builtins/
  http/                       HTTP protocol filters
    ai/                       AI workloads (inference, agentic)
    observability/            Access logs, request IDs
    payload_processing/       Body field extraction
    security/                 Forwarded headers, IP ACL
    traffic_management/       Router, load balancer, timeout
    transformation/           Header manipulation
  tcp/                        TCP protocol filters
    observability/            Connection logging
```

At runtime, pipeline execution dispatches to the correct
filter type. HTTP execution (`execute_http_request`,
`execute_http_response`, body hooks) calls only HTTP
filters, skipping TCP entries. TCP execution
(`execute_tcp_connect`, `execute_tcp_disconnect`) calls
only TCP filters, skipping HTTP entries.

**Protocol stack model.** Higher-level protocols include
lower levels. HTTP's stack includes TCP, so an HTTP
listener accepts both HTTP and TCP filters in its
pipeline. A TCP listener accepts only TCP filters.
Validation enforces this via `ProtocolKind::supports()`.

| Listener Protocol | HTTP Filters | TCP Filters |
| --- | --- | --- |
| `http` (default) | Yes | Yes |
| `tcp` | No | Yes |

```mermaid
flowchart TD
    AnyFilter --> HttpFilter
    AnyFilter --> TcpFilter

    HttpListener["HTTP Listener"] -->|supports| HttpFilter
    HttpListener -->|supports| TcpFilter
    TcpListener["TCP Listener"] -->|supports| TcpFilter
```

## What Stays Outside Filters

- TCP/TLS, HTTP framing, connection pooling: adapters
- Config loading and validation: `praxis-core`
- Pipeline executor and `HttpFilterContext`: `praxis-filter`

## HttpFilter Trait

Every HTTP behavior in Praxis is an `HttpFilter`:

```rust
#[async_trait]
pub trait HttpFilter: Send + Sync {
    fn name(&self) -> &'static str;
    async fn on_request(
        &self, ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError>;
    async fn on_response(
        &self, ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
    // Body hooks and access/mode methods omitted for
    // brevity; see "Body Access" section below.
}
```

The trait also defines body access, body mode, and body
hook methods. See [Body Access](#body-access-http-only)
below for the full API.

`on_request` runs in order, `on_response` in reverse.

## TcpFilter Trait

TCP-level filters implement `TcpFilter`:

```rust
#[async_trait]
pub trait TcpFilter: Send + Sync {
    fn name(&self) -> &'static str;
    async fn on_connect(
        &self, ctx: &mut TcpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
    async fn on_disconnect(
        &self, ctx: &mut TcpFilterContext<'_>,
    ) -> Result<(), FilterError> {
        Ok(())
    }
}
```

`on_connect` fires when a TCP connection is accepted.
`on_disconnect` fires when the connection closes. Both
hooks have default implementations that pass through.

## FilterAction

- `Continue` : pass to next filter
- `Reject(rejection)` : stop pipeline, respond now
- `Release` : forward accumulated StreamBuffer data to
  upstream; behaves as `Continue` in non-StreamBuffer
  contexts

```rust
FilterAction::Reject(Rejection::status(429)
    .with_header("Retry-After", "60")
    .with_body(b"rate limit exceeded" as &[u8]))
```

## HttpFilterContext

Shared state flowing through HTTP filters for a request:

```rust
pub struct HttpFilterContext<'a> {
    pub client_addr: Option<IpAddr>,
    pub cluster: Option<String>,
    pub extra_request_headers: Vec<(String, String)>,
    pub request: &'a Request,
    pub request_start: Instant,
    pub response_header: Option<&'a mut Response>,
    pub request_body_bytes: u64,
    pub response_body_bytes: u64,
    pub upstream: Option<Upstream>,
}
```

## TcpFilterContext

Per-connection state for TCP filters:

```rust
pub struct TcpFilterContext<'a> {
    pub remote_addr: &'a str,
    pub local_addr: &'a str,
    pub upstream_addr: &'a str,
    pub connect_time: Instant,
    pub bytes_in: u64,
    pub bytes_out: u64,
}
```

## AnyFilter

The `AnyFilter` enum wraps both filter variants for storage
in a unified registry and pipeline:

```rust
pub enum AnyFilter {
    Http(Box<dyn HttpFilter>),
    Tcp(Box<dyn TcpFilter>),
}
```

Each variant reports its `protocol_level()` as
`ProtocolKind::Http` or `ProtocolKind::Tcp`.

## Body Access (HTTP only)

Filters see headers only by default. Opt in:

```rust
fn request_body_access(&self) -> BodyAccess {
    BodyAccess::ReadOnly // or ReadWrite
}
```

| Access           | Hooks? | Modify? |
| ---------------- | ------ | ------- |
| `None` (default) | No     | No      |
| `ReadOnly`       | Yes    | No      |
| `ReadWrite`      | Yes    | Yes     |

### Body Mode

| Mode                          | Behavior        | Use case                  |
| ----------------------------- | --------------- | ------------------------- |
| `Stream` (default)            | Per chunk       | Logging, transforms       |
| `Buffer { max_bytes }`        | Full body       | JSON, payload routing     |
| `StreamBuffer { max_bytes }`  | Deferred stream | Inspection before forward |

If any filter requests `Buffer`, the pipeline buffers.

### StreamBuffer Mode

`StreamBuffer` combines streaming inspection with deferred
forwarding. Filters see each chunk as it arrives (like
`Stream`) but the protocol layer accumulates them and does
not forward to upstream until a filter returns
`FilterAction::Release` or end-of-stream is reached.

```rust
fn request_body_mode(&self) -> BodyMode {
    // No limit (default):
    BodyMode::StreamBuffer { max_bytes: None }

    // With a limit (413 on overflow):
    // BodyMode::StreamBuffer { max_bytes: Some(1_048_576) }
}
```

A filter signals release by returning
`FilterAction::Release` from `on_request_body` or
`on_response_body`. After release, remaining chunks flow
through in stream mode.

When `max_bytes` is `None` (default), StreamBuffer
accumulates without limit. When `Some(n)`, requests
exceeding `n` bytes receive 413.

This mode is useful for:

- **AI inference proxies**: inspect prompt content for
  routing, token counting, or content policy before
  forwarding
- **Security gateways**: scan payloads for malware
  signatures, PII, or injection attacks with early
  rejection
- **Body-based routing**: peek at request body content
  (e.g. JSON model field) to select a cluster, then
  release and forward

### Body Hooks

```rust
// Async
async fn on_request_body(
    &self, ctx: &mut HttpFilterContext<'_>,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
) -> Result<FilterAction, FilterError>;

// Sync (upstream constraint)
fn on_response_body(
    &self, ctx: &mut HttpFilterContext<'_>,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
) -> Result<FilterAction, FilterError>;
```

Override `needs_request_context() -> true` to access request
headers in body hooks.

## Conditional Execution

Add `conditions` to any filter chain entry. Fields within a
condition are ANDed; all conditions must pass.

| Field         | Matches when                 |
| ------------- | ---------------------------- |
| `path`        | URI exactly equals value     |
| `path_prefix` | URI starts with value        |
| `methods`     | Method in list               |
| `headers`     | All listed headers match     |

```yaml
filter_chains:
  - name: main
    filters:
      - filter: headers
        conditions:
          - when:
              path_prefix: "/api"
          - unless:
              headers:
                x-internal: "true"
        request_add:
          - name: "X-Api-Version"
            value: "v2"
```

Use `path` for exact matching (e.g., health checks on `/`):

```yaml
- filter: static_response
  conditions:
    - when:
        path: "/"
  status: 200
  body: "ok"
```

Skipped on request = skipped on response.

### Response Conditions

Use `response_conditions` to gate `on_response` execution.
Response predicates: `status` (list of status codes),
`headers`.

```yaml
- filter: headers
  response_conditions:
    - when:
        status: [200, 201]
  response_set:
    - name: "Cache-Control"
      value: "public, max-age=60"
```

A filter can have both `conditions` (request phase) and
`response_conditions` (response phase).

## Built-in Filters

| Filter | Category | Protocol | Key config |
| --- | --- | --- | --- |
| `router` | Traffic Management | HTTP | `routes[].path_prefix`, `.host`, `.cluster` |
| `load_balancer` | Traffic Management | HTTP | `clusters[].endpoints`, `.load_balancer_strategy` |
| `timeout` | Traffic Management | HTTP | `timeout_ms` (504 on exceed) |
| `static_response` | Traffic Management | HTTP | `status` (required), `headers`, `body` |
| `headers` | Transformation | HTTP | `request_add`, `response_add/set/remove` |
| `request_id` | Observability | HTTP | Propagates/generates `X-Request-ID` |
| `access_log` | Observability | HTTP | Structured JSON logging; optional `sample_rate` |
| `tcp_access_log` | Observability | TCP | Structured JSON connection logging |
| `forwarded_headers` | Security | HTTP | `trusted_proxies` (CIDR list) |
| `ip_acl` | Security | HTTP | `allow` / `deny` (CIDR lists); 403 on denial |
| `json_body_field` | Payload Processing | HTTP | Extract a JSON body field and promote to header |
| `model_to_header` | AI / Inference | HTTP | Extract JSON "model" field and promote to X-Model header. Requires `ai-inference` feature. |

## json_body_field

Extracts a top-level field from the JSON request body and
promotes its value to a request header. Uses StreamBuffer
mode to inspect the body before upstream selection.

```yaml
filter: json_body_field
field: model       # JSON field to extract
header: X-Model    # header to set with the extracted value
```

The filter parses each body chunk as JSON using
`serde_json`. When the target field is found, its value is
promoted to the configured header and the body is released
for forwarding. Subsequent filters (e.g. the router) can
then match on the promoted header.

Non-string values (numbers, booleans) are converted to
their string representation.

## model_to_header

> Requires the `ai-inference` feature:
> `cargo build -p praxis --features ai-inference`

Convenience wrapper around `json_body_field` for AI
inference proxying. Extracts the `"model"` field from the
JSON request body and promotes it to a request header
(default: `X-Model`). Subsequent filters (e.g. the router)
can match on that header for model-based routing.

```yaml
filter: model_to_header
header: X-Model   # optional, defaults to X-Model
```

Equivalent to:

```yaml
filter: json_body_field
field: model
header: X-Model
```

## Custom Filters

### HTTP Filter Example

Create a crate for your filter(s):

```toml
[dependencies]
praxis-filter = { git = "https://github.com/shaneutt/praxis" }
async-trait = "0.1"
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
```

```rust
// my_filters/src/lib.rs
use async_trait::async_trait;
use praxis_filter::{
    HttpFilter, FilterAction, HttpFilterContext,
    FilterError, Rejection,
};
use serde::Deserialize;

pub struct ApiKeyFilter { valid_keys: Vec<String> }

#[derive(Deserialize)]
struct Config { keys: Vec<String> }

impl ApiKeyFilter {
    pub fn from_config(
        config: &serde_yaml::Value,
    ) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: Config =
            serde_yaml::from_value(config.clone())?;
        Ok(Box::new(Self { valid_keys: cfg.keys }))
    }
}

#[async_trait]
impl HttpFilter for ApiKeyFilter {
    fn name(&self) -> &'static str { "api_key" }

    async fn on_request(
        &self, ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        let key = ctx.request.headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok());
        match key {
            Some(k)
                if self.valid_keys.iter().any(|v| v == k)
            => {
                Ok(FilterAction::Continue)
            }
            _ => Ok(FilterAction::Reject(
                Rejection::status(401),
            )),
        }
    }
}
```

Factory signature:
`fn(&serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError>`.
Filters are created once at startup, must be `Send + Sync`.

### TCP Filter Example

```rust
use async_trait::async_trait;
use praxis_filter::{
    TcpFilter, TcpFilterContext, FilterAction, FilterError,
};

pub struct ConnectionLogger;

#[async_trait]
impl TcpFilter for ConnectionLogger {
    fn name(&self) -> &'static str { "connection_logger" }

    async fn on_connect(
        &self, ctx: &mut TcpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        tracing::info!(
            remote = ctx.remote_addr,
            "new connection"
        );
        Ok(FilterAction::Continue)
    }

    async fn on_disconnect(
        &self, ctx: &mut TcpFilterContext<'_>,
    ) -> Result<(), FilterError> {
        tracing::info!(
            remote = ctx.remote_addr,
            "connection closed"
        );
        Ok(())
    }
}
```

### Custom Binary Example

Wire your filters into a custom binary (`main.rs`):

```rust
use my_filters::ApiKeyFilter;
use praxis_filter::register_filters;

register_filters! {
    http "api_key" => ApiKeyFilter::from_config,
}

fn main() {
    let cli_path: Option<&str> = None; // or parse from args
    let config = praxis::load_config(cli_path);

    // init tracing, then start the server (blocks forever)
    tracing_subscriber::fmt().init();
    praxis::run_server(config);
}
```

Your `Cargo.toml` needs `praxis`, `praxis-filter`, and
`tracing-subscriber` as dependencies alongside your filter
crate.

The `register_filters!` macro uses `http "name" => factory`
syntax. TCP filters use `tcp "name" => factory`.

### YAML Config

```yaml
filter_chains:
  - name: main
    filters:
      - filter: api_key
        keys: ["secret-key-1", "secret-key-2"]  # use env/secrets in production
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
```

The YAML block under `filter: api_key` is passed as-is to
`from_config`. Conditions work with custom filters with no
extra code.

For detailed configuration of individual built-in filters,
see [configuration.md](configuration.md). For best
practices when writing custom filters, see
[extensions.md](extensions.md).
