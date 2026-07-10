# Extensions

Praxis is designed to be extended. The core library provides
the building blocks for building bespoke proxy servers.
Multiple extension mechanisms are provided to support a
variety of needs.

## Auto-Discovery (Recommended)

External filter crates can self-register into Praxis at
build time. The operator adds a `Cargo.toml` dependency
and writes YAML config with zero Rust code changes to Praxis.

### How It Works

1. The external crate uses `export_filters!` to declare
   its filters
2. The crate's `Cargo.toml` carries a
   `[package.metadata.praxis-filters]` marker
3. The Praxis server's `build.rs` runs `cargo metadata`,
   discovers marked crates, and generates registration code
4. At startup, discovered filters are registered alongside
   built-ins

### External Crate Setup

In the external crate's `Cargo.toml`:

```toml
[package]
name = "my-auth-filters"
version = "0.1.0"

# Empty marker: tells the Praxis build script this crate exports filters.
# The actual filter names and factories are declared in export_filters!.
[package.metadata.praxis-filters]

[dependencies]
async-trait = "0.1"
praxis-proxy-filter = "0.4"
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9.34"
```

In the external crate's `src/lib.rs`:

```rust
use async_trait::async_trait;
use praxis_filter::{
    FilterAction, FilterError, HttpFilter,
    HttpFilterContext, export_filters,
};

pub struct MyAuthFilter { /* ... */ }

#[async_trait]
impl HttpFilter for MyAuthFilter {
    fn name(&self) -> &'static str { "my_auth" }

    async fn on_request(
        &self, _ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

impl MyAuthFilter {
    pub fn from_config(
        config: &serde_yaml::Value,
    ) -> Result<Box<dyn HttpFilter>, FilterError> {
        // Parse config and construct the filter
        Ok(Box::new(Self { /* ... */ }))
    }
}

export_filters! {
    http "my_auth" => MyAuthFilter::from_config,
}
```

### Operator Usage

Add the crate to the Praxis server's `Cargo.toml`:

```toml
[dependencies]
my-auth-filters = "0.1"
```

Then reference the filter by name in YAML:

```yaml
filter_chains:
  - name: main
    filters:
      - filter: my_auth
        some_option: "value"
```

Rebuild and run — no other changes needed.

### Duplicate Detection

If an external filter name collides with a built-in or
another external filter, the server panics at startup
with a clear error message. Filter names must be unique
across all sources.

## Rust Extensions (Manual Registration)

Compile-time extensions with zero overhead. Implement
`HttpFilter` or `TcpFilter` in your own crate, register it,
and reference it in YAML config. Use this approach when
building a custom Praxis binary with inline filters that
don't need to be shared as a separate crate.

1. Implement `HttpFilter` (`on_request`, `on_response`,
   body hooks) or `TcpFilter` (`on_connect`,
   `on_disconnect`)
2. Register with `register_filters!`
3. Reference by name in YAML filter chains

### HTTP Filter

```rust
use async_trait::async_trait;
use serde::Deserialize;
use praxis_filter::{
    FilterAction, FilterError, HttpFilter,
    HttpFilterContext, Rejection, register_filters,
};

struct MaxBodyGuard {
    max_content_length: u64,
    reject_status: u16,
}

impl MaxBodyGuard {
    pub fn from_config(
        config: &serde_yaml::Value,
    ) -> Result<Box<dyn HttpFilter>, FilterError> {
        #[derive(Deserialize)]
        struct Cfg {
            max_content_length: u64,
            #[serde(default = "default_status")]
            reject_status: u16,
        }
        fn default_status() -> u16 { 413 }

        let cfg: Cfg =
            serde_yaml::from_value(config.clone())?;
        Ok(Box::new(Self {
            max_content_length: cfg.max_content_length,
            reject_status: cfg.reject_status,
        }))
    }
}

#[async_trait]
impl HttpFilter for MaxBodyGuard {
    fn name(&self) -> &'static str { "max_body_guard" }

    async fn on_request(
        &self, ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        let too_large = ctx.request.headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|len| {
                len > self.max_content_length
            });

        if too_large {
            return Ok(FilterAction::Reject(
                Rejection::status(self.reject_status),
            ));
        }
        Ok(FilterAction::Continue)
    }
}

// In your binary:
register_filters! {
    http "max_body_guard" => MaxBodyGuard::from_config,
}
```

### TCP Filter

TCP custom filters implement `TcpFilter` and register with
the `tcp` keyword:

```rust
use async_trait::async_trait;
use praxis_filter::{
    FilterAction, FilterError, TcpFilter, TcpFilterContext,
};

struct ConnectionCounter { /* ... */ }

#[async_trait]
impl TcpFilter for ConnectionCounter {
    fn name(&self) -> &'static str {
        "connection_counter"
    }

    async fn on_connect(
        &self, ctx: &mut TcpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        // Track connection metrics
        Ok(FilterAction::Continue)
    }
}
```

### Custom Load Balancer

Load balancers are ordinary HTTP filters. The contract:
read `ctx.cluster` (set by the router), select an
endpoint, and set `ctx.upstream`. If your algorithm
tracks in-flight requests, use `on_response` to release
counters.

```rust
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use praxis_core::connectivity::{ConnectionOptions, Upstream};
use praxis_filter::{
    FilterAction, FilterError, HttpFilter, HttpFilterContext,
};

/// Picks the endpoint that has handled the fewest
/// total requests (lifetime, not in-flight).
pub struct FewestServedFilter {
    clusters: HashMap<String, Vec<EndpointCounter>>,
}

struct EndpointCounter {
    address: Arc<str>,
    served: AtomicUsize,
}

impl FewestServedFilter {
    pub fn from_config(
        config: &serde_yaml::Value,
    ) -> Result<Box<dyn HttpFilter>, FilterError> {
        #[derive(serde::Deserialize)]
        struct ClusterCfg {
            name: String,
            endpoints: Vec<String>,
        }

        let cfgs: Vec<ClusterCfg> = serde_yaml::from_value(
            config
                .get("clusters")
                .cloned()
                .unwrap_or_default(),
        )?;

        let clusters = cfgs
            .into_iter()
            .map(|c| {
                let counters = c
                    .endpoints
                    .into_iter()
                    .map(|addr| EndpointCounter {
                        address: Arc::from(addr.as_str()),
                        served: AtomicUsize::new(0),
                    })
                    .collect();
                (c.name, counters)
            })
            .collect();

        Ok(Box::new(Self { clusters }))
    }
}

#[async_trait]
impl HttpFilter for FewestServedFilter {
    fn name(&self) -> &'static str { "fewest_served" }

    async fn on_request(
        &self,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        let cluster = ctx.cluster.as_deref().ok_or(
            "fewest_served: no cluster set",
        )?;
        let endpoints =
            self.clusters.get(cluster).ok_or_else(|| {
                format!("fewest_served: unknown cluster \
                         '{cluster}'")
            })?;

        // Pick endpoint with lowest lifetime count.
        let pick = endpoints
            .iter()
            .min_by_key(|e| e.served.load(Ordering::Relaxed))
            .expect("cluster must have endpoints");

        pick.served.fetch_add(1, Ordering::Relaxed);

        ctx.upstream = Some(Upstream {
            address: Arc::clone(&pick.address),
            tls: None,
            connection: Arc::new(ConnectionOptions::default()),
        });

        Ok(FilterAction::Continue)
    }
}

// Register alongside the built-in filters:
register_filters! {
    http "fewest_served" => FewestServedFilter::from_config,
}
```

Then use it in config:

```yaml
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend

      - filter: fewest_served
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:3001"
              - "127.0.0.1:3002"
```

Key points:

- The router runs first and sets `ctx.cluster`.
- Your filter reads the cluster name, selects an endpoint,
  and writes `ctx.upstream`.
- The protocol layer connects to whatever `Upstream` you
  set (address, TLS, SNI, timeouts).
- For stateful algorithms, override `on_response` to
  update counters when a request completes.

### Registration

The `register_filters!` macro uses protocol-prefixed
syntax:

```rust
register_filters! {
    http "max_body_guard" => MaxBodyGuard::from_config,
}
```

TCP filters would use `tcp "name" => factory` syntax.

The macro generates a `custom_registry()` function that
returns a `FilterRegistry` with both built-in and custom
filters. Use it with the test utilities
(`start_proxy_with_registry`) or build your own server
bootstrap from the workspace crates (`praxis-core`,
`praxis-filter`, `praxis-protocol`).

### YAML Config

Any keys placed alongside `filter:` in the filter chain
entry are passed to `from_config` as a `serde_yaml::Value`:

```yaml
filter_chains:
  - name: security
    filters:
      - filter: max_body_guard
        max_content_length: 1048576   # 1 MiB
        reject_status: 413
        conditions:
          - when:
              methods: ["POST", "PUT", "PATCH"]
```

Custom filters participate identically to built-ins: same
ordering, context access, and short-circuit capability.

See the [filter system documentation](README.md) for the
full API reference.

## Best Practices

### Header trust boundaries

Never blindly trust `X-Forwarded-For` or
`X-Forwarded-Proto`. Attackers spoof these unless trusted
upstream sources are explicitly defined.

### Keep filters stateless when possible

Prefer reading all configuration at construction time
(in `from_config`) and keeping the filter struct
immutable. When shared mutable state is required (e.g.
counters, connection tracking), use atomics or interior
mutability with minimal lock scope. Filters are shared
across requests and must be `Send + Sync`.

### Return early with `Reject`, not panics

Use `FilterAction::Reject(Rejection::status(code))` to
abort request processing. Never panic inside a filter;
a panic takes down the worker thread. Return
`Err(...)` for unexpected failures and let the pipeline
handle the 500 response.

### Declare body access accurately

Only declare `request_body_access()` or
`response_body_access()` if your filter actually
inspects or modifies the body. Each declaration changes
how the pipeline buffers data. `BodyAccess::None` (the
default) avoids overhead. Use `ReadOnly` if you inspect
but do not modify, and `ReadWrite` only if you mutate
chunks in place.

### Choose the right body mode

- `Stream`: lowest latency; chunks flow through as they
  arrive. Best for filters that inspect headers only or
  process chunks independently.
- `StreamBuffer`: chunks flow through filters
  incrementally but forwarding to upstream is deferred
  until `Release` or end-of-stream. Use when body
  content influences routing, when you need the complete
  body (e.g. signature verification), or when you need
  to inspect the full body before upstream selection.
  Set `max_bytes` to avoid unbounded memory growth.

Two patterns for declaring `StreamBuffer`:

**Static declaration** (filter always needs the body):

```rust
fn request_body_mode(&self) -> BodyMode {
    BodyMode::StreamBuffer { max_bytes: Some(1_048_576) }
}
```

**Per-request upgrade** (conditional buffering):

```rust
async fn on_request(
    &self, ctx: &mut HttpFilterContext<'_>,
) -> Result<FilterAction, FilterError> {
    if needs_body_inspection(ctx) {
        ctx.set_request_body_mode(
            BodyMode::StreamBuffer {
                max_bytes: Some(1_048_576),
            },
        );
    }
    Ok(FilterAction::Continue)
}
```

### `on_response_body` is synchronous

Pingora's response body callback is not async. Do not
block the thread with `block_on` or heavy computation.
If you need async I/O during response payload processing,
spawn a background task and communicate via a channel.

### Use conditions instead of internal checks

Rather than writing `if req.method != "POST" { return
Continue }` inside your filter, declare conditions in
YAML:

```yaml
- filter: my_filter
  conditions:
    - when:
        methods: ["POST", "PUT"]
```

This keeps filter logic focused and lets operators
adjust gating without code changes.

### Use `extra_request_headers` for metadata

When your filter extracts values from the body or
computes derived data, promote it to a request header
via `ctx.extra_request_headers`. This makes the value
visible to downstream filters (e.g. the router) without
coupling filters to each other.

### Access KV stores for runtime mappings

Use `ctx.kv_stores` with `get_or_create` to access
runtime-updatable key-value data without restarting
the proxy. Stores are created on demand:

```rust
async fn on_request(
    &self,
    ctx: &mut HttpFilterContext<'_>,
) -> Result<FilterAction, FilterError> {
    if let Some(registry) = ctx.kv_stores {
        let store = registry.get_or_create("routing_overrides");
        if let Some(cluster) = store.get("preferred_cluster") {
            ctx.cluster = Some(Arc::from(cluster.as_ref()));
        }
    }
    Ok(FilterAction::Continue)
}
```

Operators update stores at runtime via the admin API
without config reloads:

```console
curl -X PUT http://127.0.0.1:9901/api/kv/routing_overrides/preferred_cluster \
     -d 'us-east-cluster'
```

### Handle missing `ctx.cluster` gracefully

If your filter depends on a cluster being set (like a
load balancer), return a clear error when
`ctx.cluster` is `None` rather than panicking:

```rust
let cluster = ctx.cluster.as_deref()
    .ok_or("my_filter: no cluster set")?;
```

### Provide `from_config` validation

Validate all configuration values in `from_config`
rather than deferring checks to request time. Fail fast
at startup with a descriptive error. Parse and
type-check every field; use `#[serde(default)]` for
optional fields with sensible defaults.

### Test with the integration harness

Use the integration test utilities (`free_port`,
`start_backend`, `start_proxy_with_registry`) to write
end-to-end tests for custom filters. Register your
filter with `FilterFactory::Http(Arc::new(factory))`,
build a minimal YAML config, and assert on status codes
and response bodies. See `tests/integration/` for
examples.
