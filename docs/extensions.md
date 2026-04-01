# Extensions

Praxis is designed to be extended. The core library provides
the building blocks for building bespoke proxy servers.
Multiple extension mechanisms are provided to support a
variety of needs.

## Rust Extensions (Preferred)

Compile-time extensions with zero overhead. Implement
`HttpFilter` or `TcpFilter` in your own crate, register it,
and reference it in YAML config.

1. Implement `HttpFilter` (`on_request`, `on_response`,
   body hooks) or `TcpFilter` (`on_connect`,
   `on_disconnect`)
2. Register with `register_filters!`
3. Reference by name in YAML filter chains

### HTTP Filter

```rust
use praxis_filter::{HttpFilter, register_filters};

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
use praxis_filter::{TcpFilter, TcpFilterContext};

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
            tls: false,
            sni: String::new(),
            connection: ConnectionOptions::default(),
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

See [filters.md](filters.md) for extensive documentation.

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
- `Buffer`: accumulates the entire body before
  delivering it. Use when your filter needs the complete
  body (e.g. signature verification). Set `max_bytes` to
  avoid unbounded memory growth.
- `StreamBuffer`: chunks flow through filters
  incrementally but forwarding to upstream is deferred
  until `Release` or end-of-stream. Use when body
  content influences routing or when you need to inspect
  the full body before upstream selection.

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

Use the integration test helpers (`free_port`,
`start_backend`, `start_proxy_with_registry`) to write
end-to-end tests for custom filters. Register your
filter with `FilterFactory::Http(Arc::new(factory))`,
build a minimal YAML config, and assert on status codes
and response bodies. See `tests/integration/` for
examples.
