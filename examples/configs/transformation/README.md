# Transformation Examples

Transformation filters modify requests and responses in flight: paths, URLs,
and headers.

## When to Use

- Normalize request paths before routing
- Add, remove, or change headers for backend compatibility
- Rewrite URLs to match backend expectations
- Inject metadata into requests

## Key Filters

- [`path_rewrite`](../../../docs/filters/http/transformation/path_rewrite.md):
  prefix replacement or regex substitution on the request path.
- [`url_rewrite`](../../../docs/filters/http/transformation/url_rewrite.md):
  rewrites the request path and query. Routing and forwarding choose the
  upstream host and scheme.
- [`headers`](../../../docs/filters/http/transformation/headers.md): adds,
  removes, or replaces request and response headers.
- [`grpc_status`](../../../docs/filters/http/transformation/grpc_status.md):
  returns proxy-generated errors in the form gRPC clients expect.

Apply rewrites early in the pipeline, before routing. Use reserved headers
(`x-praxis-*`) for internal metadata to avoid conflicts, and test rewrites
with edge cases (special characters, empty values).

## Related Documentation

- [Filter Reference](../../../docs/filters/README.md)
- [Life of a Request](../../../docs/architecture/life-of-a-request.md)
