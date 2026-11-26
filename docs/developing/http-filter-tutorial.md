# HTTP Filter Tutorial

This tutorial builds an HTTP filter in its own crate, registers it through
auto-discovery, tests it, and runs it behind a proxy config. The filter
returns `401 Unauthorized` when a request lacks a configured header. That is
not an authentication scheme; use a real security filter in production.

## 1. Create the filter crate

From the root of a Praxis checkout, create a library crate:

```console
cargo new --lib extensions/require-header-filter
```

Cargo adds it to the workspace. Replace its `Cargo.toml` with:

```toml
[package]
name = "require-header-filter"
version = "0.1.0"
edition = "2024"
publish = false

# This marker lets the Praxis build script discover the crate.
[package.metadata.praxis-filters]

[dependencies]
async-trait = "0.1"
http = "1"
praxis-filter = { package = "praxis-proxy-filter", path = "../../filter" }
serde = { version = "1", features = ["derive"] }
serde_yaml = { package = "yaml_serde", version = "0.10.4" }
```

The `[package.metadata.praxis-filters]` marker and the `export_filters!` call
below are what auto-discovery needs. Outside the Praxis repository, replace
the `path` dependency with the released `praxis-proxy-filter` version your
Praxis server uses.

## 2. Implement the filter

Replace `extensions/require-header-filter/src/lib.rs` with:

```rust
use async_trait::async_trait;
use praxis_filter::{
    FilterAction, FilterError, HttpFilter, HttpFilterContext, Rejection, export_filters, parse_filter_config,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequireHeaderConfig {
    header: String,
}

struct RequireHeaderFilter {
    header: String,
}

impl RequireHeaderFilter {
    fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let config: RequireHeaderConfig = parse_filter_config("require_header", config)?;
        http::header::HeaderName::from_bytes(config.header.as_bytes())
            .map_err(|_| FilterError::from(
                format!("require_header: invalid header name: '{}'", config.header),
            ))?;

        Ok(Box::new(Self { header: config.header }))
    }
}

#[async_trait]
impl HttpFilter for RequireHeaderFilter {
    fn name(&self) -> &'static str {
        "require_header"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if ctx.request.headers.contains_key(&self.header) {
            return Ok(FilterAction::Continue);
        }

        Ok(FilterAction::Reject(
            Rejection::status(401)
                .with_header("content-type", "text/plain")
                .with_body("missing required header"),
        ))
    }
}

export_filters! {
    http "require_header" => RequireHeaderFilter::from_config,
}
```

- `RequireHeaderConfig` is the YAML schema. `deny_unknown_fields` catches
  misspelled settings at startup.
- `from_config` validates once, when the filter is built. The `HeaderName`
  check rejects an invalid name at startup instead of failing every request.
- `on_request` returns `Continue` to run the next filter, or `Reject` to stop
  the pipeline and respond immediately.
- `export_filters!` maps the YAML name `require_header` to its factory as an
  HTTP filter.

One filter instance serves all requests concurrently, so keep its fields
immutable as here, or make them safe for concurrent access.

## 3. Test construction and registration

Add these tests to the bottom of `src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use praxis_filter::FilterRegistry;

    use super::*;

    #[test]
    fn registers_and_builds_filter() {
        let mut registry = FilterRegistry::with_builtins();
        register_filters(&mut registry);
        let config = serde_yaml::from_str("header: x-api-key").expect("configuration should parse");

        let filter = registry.create("require_header", &config).expect("filter should build");

        assert_eq!(filter.name(), "require_header", "factory should produce filter with matching name");
    }

    #[test]
    fn rejects_unknown_configuration_fields() {
        let config = serde_yaml::from_str("header: x-api-key\nunexpected: true").expect("configuration should parse");

        let error = RequireHeaderFilter::from_config(&config)
            .err()
            .expect("unknown field should fail");

        assert!(error.to_string().contains("unexpected"), "error should mention the unknown field");
    }
}
```

Run the tests:

```console
cargo test -p require-header-filter
```

They check that the exported factory registers under the expected name and
that invalid settings fail at startup.

## 4. Add the filter to the Praxis server

Auto-discovery scans the `praxis-proxy` server's direct runtime
dependencies. Add this entry under `[dependencies]` in
`crates/server/Cargo.toml`:

```toml
require-header-filter = { path = "../extensions/require-header-filter" }
```

No server Rust changes are needed: on the next build, the server's build
script finds the marker and calls the crate's generated `register_filters`
function.

## 5. Configure the filter

Create `require-header.yaml` in the repository root:

```yaml
listeners:
  - name: default
    address: "127.0.0.1:8080"
    filter_chains:
      - main

filter_chains:
  - name: main
    filters:
      - filter: require_header
        header: x-api-key

      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend

      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:3000"
```

`require_header` runs before routing, so a rejected request never reaches the
backend.

## 6. Run it end to end

Start a temporary backend in one terminal:

```console
python3 -m http.server 3000
```

Start Praxis in another:

```console
cargo run -p praxis-proxy -- -c require-header.yaml
```

Without the header, the request is rejected:

```console
curl -i http://127.0.0.1:8080/
```

```text
HTTP/1.1 401 Unauthorized
content-type: text/plain

missing required header
```

With the header, it reaches the backend:

```console
curl -i -H 'x-api-key: tutorial' \
  http://127.0.0.1:8080/
```

The Python server answers `200 OK`.

## Where to go next

- [Filter System](../filters/README.md): lifecycle, context fields, body
  access, and execution order.
- [Extensions](extensions.md): manual registration, TCP filters, custom load
  balancers, and best practices.
- [Adding a Built-in Filter](adding-filters.md): what a filter contributed to
  Praxis itself needs.
- [Payload Processing](../architecture/payload-processing.md): streaming and
  buffered body filters. A header-only filter like this one needs no body
  access.
