# HTTP Filter Tutorial

This tutorial builds a small HTTP filter from scratch. The
filter requires requests to contain a configured header and
returns `401 Unauthorized` when the header is missing.

By the end, you will have:

- a standalone Rust crate containing an HTTP filter
- typed YAML configuration
- automatic filter registration in Praxis
- a unit test for construction and registration
- a working proxy configuration you can exercise with `curl`

The filter is intentionally small so the lifecycle is easy to
see. Requiring a header is not, by itself, an authentication
scheme; use an appropriate security filter in production.

## 1. Create the filter crate

From the root of a Praxis checkout, create a library crate:

```console
cargo new --lib extensions/require-header-filter
```

Cargo adds the crate to the workspace. Replace the new crate's
`Cargo.toml` with:

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
praxis-filter = { package = "praxis-proxy-filter", path = "../../filter" }
serde = { version = "1", features = ["derive"] }
serde_yaml = { package = "yaml_serde", version = "0.10.4" }
```

Two pieces enable auto-discovery:

1. `[package.metadata.praxis-filters]` marks this as a
   filter crate.
2. The `export_filters!` call below exposes its factories.

For a filter crate outside the Praxis repository, replace the
`path` dependency with the released `praxis-proxy-filter`
version used by your Praxis server.

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

The implementation has four parts:

- `RequireHeaderConfig` is the operator-facing YAML schema.
  `deny_unknown_fields` catches misspelled settings at startup.
- `from_config` validates configuration once and constructs the
  filter. Request hooks should not repeatedly parse configuration.
- `on_request` returns `Continue` to run the next filter or
  `Reject` to stop the pipeline and send a response immediately.
- `export_filters!` associates the YAML name `require_header`
  with its factory and declares it as an HTTP-level filter.

Filter instances are shared across requests, so their fields must
be safe to access concurrently. Immutable configuration, as used
here, is the simplest design.

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

        assert_eq!(filter.name(), "require_header");
    }

    #[test]
    fn rejects_unknown_configuration_fields() {
        let config = serde_yaml::from_str("header: x-api-key\nunexpected: true").expect("configuration should parse");

        let error = RequireHeaderFilter::from_config(&config)
            .err()
            .expect("unknown field should fail");

        assert!(error.to_string().contains("unexpected"));
    }
}
```

Run the tests:

```console
cargo test -p require-header-filter
```

These tests prove that the exported factory registers under the
expected name and that invalid settings fail during startup. The
live check below proves the request behavior end to end.

## 4. Add the filter to the Praxis server

Auto-discovery scans the `praxis-proxy` server's direct runtime
dependencies. Add this entry under `[dependencies]` in
`server/Cargo.toml`:

```toml
require-header-filter = { path = "../extensions/require-header-filter" }
```

No Rust changes to the server are needed. On the next build, the
server build script finds the crate marker and calls its generated
`register_filters` function.

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

Order matters. `require_header` runs before routing, so a rejected
request never reaches the backend.

## 6. Run it end to end

Start a temporary backend in one terminal:

```console
python3 -m http.server 3000
```

Start Praxis in another:

```console
cargo run -p praxis-proxy -- -c require-header.yaml
```

A request without the configured header is rejected:

```console
curl -i http://127.0.0.1:8080/
```

```text
HTTP/1.1 401 Unauthorized
content-type: text/plain

missing required header
```

Providing the header allows the request to reach the backend:

```console
curl -i -H 'x-api-key: tutorial' \
  http://127.0.0.1:8080/
```

The response should be `200 OK` from the Python server.

## Where to go next

- [Filter System](README.md) explains the request/response
  lifecycle, context fields, body access, and execution order.
- [Extensions](extensions.md) covers manual registration, TCP
  filters, custom load balancers, and production practices.
- [Adding a Built-in Filter](../developing/adding-filters.md)
  lists the documentation, example, and integration-test
  requirements for contributing a filter to Praxis itself.
- [Payload Processing](../architecture/payload-processing.md)
  explains streaming and buffered body filters. Header-only
  filters like this tutorial's filter need no body access.
