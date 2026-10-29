# Transformation Examples

Transformation filters modify requests and responses in flight, rewriting URLs, headers, and bodies.

## When to Use

- Normalize request paths before routing
- Add, remove, or modify headers for backend compatibility
- Rewrite URLs to match backend expectations
- Transform response payloads (e.g., SSE, WebSocket, gRPC-Web)
- Inject metadata into requests

## Key Filters

**Path Rewrite**: Rewrites request paths using prefix replacement or regex substitution.

**URL Rewrite**: Modifies the full request URL (scheme, host, port, path, query).

**Header Manipulation**: Adds, removes, or replaces request and response headers.

**SSE Transform**: Processes server-sent events streams, filtering or modifying events.

**gRPC-Web**: Translates between gRPC-Web (browser) and gRPC (backend) protocols.

## Best Practices

- Apply rewrites early in the pipeline before routing decisions
- Use reserved headers (`x-praxis-*`) for internal metadata to avoid conflicts
- Test transformations with edge cases (special characters, empty values)
- Document rewrite rules inline for maintainability

## Related Documentation

- [Filter Reference](../../../docs/filters/README.md)
- [Life of a Request](../../../docs/architecture/life-of-a-request.md)
