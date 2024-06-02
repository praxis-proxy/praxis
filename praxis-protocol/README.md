# Praxis Protocol

Protocol implementations for the Praxis proxy. Each
sub-module handles one protocol family.

| Module | Status | Purpose |
|--------|--------|---------|
| `http` | Active | HTTP/1.1 + HTTP/2 via Pingora |
| `tcp` | Active | Raw TCP / L4 forwarding |
| `http3` | Stub | HTTP/3 over QUIC (planned) |
| `udp` | Stub | UDP proxying (planned) |

See the [architecture docs](../docs/architecture.md) for
the `Protocol` trait and how to add new implementations.
