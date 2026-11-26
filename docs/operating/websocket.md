# WebSocket Handling

Praxis can pass through an HTTP/1.1 WebSocket handshake on the Pingora
backend. After a valid `101 Switching Protocols` response, Pingora forwards
WebSocket bytes as an opaque bidirectional tunnel, and HTTP body hooks do not
see WebSocket frames. The [WebSocket example](../../examples/configs/protocols/websocket.yaml)
is a complete Pingora configuration with a functional bidirectional test.

## Listener admission policy

With `upgrade_policy` omitted, Pingora's existing behavior applies to a valid
WebSocket handshake, and offers of only other protocols continue as ordinary
HTTP requests with the upgrade headers stripped. To make the choice explicit,
configure a listener policy:

```yaml
listeners:
  - name: public
    address: "0.0.0.0:8080"
    protocol: http
    upgrade_policy:
      default: deny
      protocols:
        websocket: passthrough
    filter_chains: [main]
```

An explicit policy defaults to `deny`, and a protocol rule overrides that
fallback. `passthrough` is supported only for `websocket` on Pingora; a
passthrough rule for another protocol is a configuration error. Protocol
names are case-insensitive, and duplicates after normalization are rejected.
HTTP upgrade policy is not valid on a TCP listener.

The Hyper backend does not support upgrades. It rejects WebSocket handshake
requests, and startup fails if its listener policy permits WebSocket
passthrough. An explicit deny policy is valid on Hyper.

## Required HTTP body processing

A Rust `HttpFilter` declares body access and whether that processing is
required:

```rust
fn request_body_access(&self) -> BodyAccess {
    BodyAccess::ReadOnly(BodyRequirement::Required)
}
```

Use `Required` when the filter's configured job cannot be skipped, and
`Optional` for best-effort body observation. The declaration applies to the
filter's selected request path, including the body phases it declares; an
inactive condition or branch does not block an upgrade. An unconditional
required body declaration on the selected path gives an otherwise permitted
WebSocket request a local `403` before Praxis contacts the upstream, and
listener permission cannot override it. Required response-body work with a
response condition is evaluated against the filtered response: a matching
condition on a final 101 fails the handshake with 502.

Audit request conditions as well as body requirements. A WebSocket handshake
is a `GET`, so a filter conditioned on `methods: [POST]` is not selected for
it, and its `Required` declaration does not block the upgrade. To deny
upgrades on a listener, use its `upgrade_policy`. For a body filter's
required processing to cover WebSocket handshakes, its conditions must select
`GET` requests.

This protects processing of the HTTP handshake request only. After an
accepted `101`, body hooks stay out of the lifecycle because WebSocket frames
are not HTTP bodies. Message-aware policy, accounting, or transformation
needs a managed WebSocket implementation.

Custom filters must add an explicit `BodyRequirement::Optional` or
`BodyRequirement::Required` to every `BodyAccess::ReadOnly` and
`BodyAccess::ReadWrite` declaration; `BodyAccess::None` remains the default.
See the [CHANGELOG](../../CHANGELOG.md) for this breaking change.

## Handshake validation and limits

Praxis accepts one valid HTTP/1.1 `websocket` offer using WebSocket version
13. Before committing the upgrade it validates the client key, the upstream
`Sec-WebSocket-Accept` response, the selected subprotocol, and the selected
extension names. Endpoints negotiate extension parameters, and filters must
preserve the negotiated subprotocol and extensions.

| Failure | Status |
| ------- | ------ |
| Malformed handshake | `400` |
| Denied WebSocket offer, or mixed WebSocket protocol offer | `403` |
| Unsolicited or invalid upstream `101` | `502` |

General `CONNECT`, HTTP/2 extended CONNECT, multiple Upgrade protocols, and
non-WebSocket upgrade passthrough are not supported. Ordinary HTTP/1.1 and
HTTP/2 requests go through the normal filter pipeline.
