# Protocol Examples

Protocol-specific configurations for HTTP/1.1, HTTP/2, gRPC, WebSocket, TCP, and hybrid scenarios.

## When to Use

- Proxy gRPC services with protocol translation (gRPC-Web, health checks, timeouts)
- Handle WebSocket upgrades and bidirectional messaging
- Implement TCP-level proxying for non-HTTP protocols
- Mix HTTP and TCP listeners in a single proxy instance
- Configure protocol-specific features (H2 settings, gRPC status codes)

## Key Protocols

**HTTP/1.1 & HTTP/2**: Native support with automatic protocol detection and upgrade handling. HTTP/2 multiplexing, flow control, and server push are managed by Pingora.

**gRPC**: First-class support for gRPC proxying with health checks, timeout propagation, status code handling, and metadata inspection.

**gRPC-Web**: Protocol translation between browser-based gRPC-Web clients and backend gRPC services.

**WebSocket.** Pingora can pass through an explicitly permitted handshake.
Required body processing known from the request blocks upstream dispatch. If a
response condition selects required processing on the upstream 101, Praxis
returns 502 before opening the tunnel. After upgrade, WebSocket frames bypass
HTTP body filters.

**TCP**: Raw TCP proxying for non-HTTP protocols with connection metrics and access logging.

## Best Practices

- Use gRPC health checks (`grpc.health.v1.Health/Check`) for gRPC upstreams
- Configure appropriate timeouts for long-lived connections (WebSocket, streaming gRPC)
- Enable access logging at the TCP level for non-HTTP traffic
- Test protocol upgrades (WebSocket, HTTP/2 → HTTP/1.1 downgrade) under load

## Related Documentation

- [Adding a Protocol](../../../docs/developing/adding-protocols.md)
- [gRPC Configuration](../../../docs/filters/http/traffic_management/grpc_timeout.md)
