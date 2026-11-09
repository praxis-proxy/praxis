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

**WebSocket**: Pingora can transparently pass through an explicitly permitted WebSocket handshake. Selected filters that declare required HTTP body processing cause the handshake to be rejected before upstream dispatch. After upgrade, frames bypass HTTP request/response filters; message inspection remains separate work.

**TCP**: Raw TCP proxying for non-HTTP protocols with connection metrics and access logging.

## Best Practices

- Use gRPC health checks (`grpc.health.v1.Health/Check`) for gRPC upstreams
- Configure appropriate timeouts for long-lived connections (WebSocket, streaming gRPC)
- Enable access logging at the TCP level for non-HTTP traffic
- Test protocol upgrades (WebSocket, HTTP/2 → HTTP/1.1 downgrade) under load

## Related Documentation

- [Protocol Support](../../../docs/architecture/protocols.md)
- [gRPC Configuration](../../../docs/filters/http/traffic_management/grpc_timeout.md)
- [WebSocket Handling](../../../docs/operating/websocket.md)
