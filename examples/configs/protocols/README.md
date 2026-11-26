# Protocol Examples

Configs for HTTP/1.1, HTTP/2, gRPC, WebSocket, TCP, and mixed HTTP and TCP
listeners. The `tls-*` and `tcp-tls-*` configs cover TLS termination, mTLS,
SNI, and upstream TLS.

## When to Use

- Proxy gRPC services (gRPC-Web, health checks, timeouts)
- Handle WebSocket upgrades and bidirectional messaging
- Proxy non-HTTP protocols over TCP
- Mix HTTP and TCP listeners in one proxy
- Configure protocol-specific features (H2 settings, gRPC status codes)

## Key Protocols

**HTTP/1.1 and HTTP/2**: Pingora handles HTTP/2 multiplexing and flow
control, and upgrade handling.

**gRPC**: health checks (`grpc.health.v1.Health/Check`), timeout propagation,
status code handling, and metadata inspection. **gRPC-Web** is translated
between browser clients and gRPC backends.

**WebSocket.** Pingora can pass through an explicitly permitted handshake.
Required body processing known from the request blocks upstream dispatch. If a
response condition selects required processing on the upstream 101, Praxis
returns 502 before opening the tunnel. After upgrade, WebSocket frames bypass
HTTP body filters. Set timeouts for long-lived connections (WebSocket,
streaming gRPC).

**TCP**: raw TCP proxying with connection metrics and access logging.

## Related Documentation

- [WebSocket Handling](../../../docs/operating/websocket.md)
- [Adding a Protocol](../../../docs/developing/adding-protocols.md)
- [gRPC Configuration](../../../docs/filters/http/traffic_management/grpc_timeout.md)
