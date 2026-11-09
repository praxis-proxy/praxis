# WebSocket Handling

Praxis can pass through an HTTP/1.1 WebSocket handshake on the Pingora
backend. After a valid `101 Switching Protocols` response, Pingora forwards
WebSocket bytes as an opaque bidirectional tunnel. HTTP body hooks do not see
WebSocket frames.

## Listener admission policy

An omitted `upgrade_policy` preserves the existing Pingora behavior for a
valid WebSocket handshake. Other Upgrade protocols are refused because the
adapter does not support them. To make that choice explicit, configure a
listener policy:

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

An explicit policy defaults to `deny`. A protocol rule overrides that
fallback. `passthrough` is currently supported only for `websocket` on
Pingora; a passthrough rule for another protocol is a configuration error.
Protocol names are case-insensitive, and duplicate names after normalization
are rejected. HTTP upgrade policy is not valid on a TCP listener.

The Hyper backend does not support upgrades. It rejects upgrade requests, and
startup fails if its listener policy permits WebSocket passthrough. An
explicit deny policy is valid on Hyper.

## Required HTTP body processing

A Rust `HttpFilter` declares body access and whether that processing is
required:

```rust
fn request_body_access(&self) -> BodyAccess {
    BodyAccess::ReadOnly(BodyRequirement::Required)
}
```

Use `Required` when the filter's configured responsibility cannot be skipped.
Use `Optional` for best-effort body observation. The declaration applies to the
filter's selected request path, including the body phases it declares. An
inactive condition or branch does not block an upgrade. A selected required
body declaration makes an otherwise permitted WebSocket request receive a
local `403` before Praxis contacts the upstream. Listener permission cannot
override this requirement.

When migrating filters, audit their request conditions as well as their body
requirements. A WebSocket handshake is a `GET`, so a filter conditioned on
`methods: [POST]` is not selected for that handshake and its `Required`
declaration does not block the upgrade. If upgrades must be denied for a
listener, use that listener's `upgrade_policy`; if the body filter's required
processing should also apply to WebSocket handshakes, its conditions must
select `GET` requests.

This protects processing of the HTTP handshake request. It does not inspect
WebSocket messages. After an accepted `101`, body hooks remain out of the
lifecycle because WebSocket frames are not HTTP bodies. Message-aware policy,
accounting, or transformation needs a managed WebSocket implementation.

Changing `BodyAccess::ReadOnly` and `BodyAccess::ReadWrite` to include
`BodyRequirement` is a breaking Rust API change for custom filters. Add an
explicit `BodyRequirement::Optional` or `BodyRequirement::Required` to every
body-access declaration. `BodyAccess::None` remains the default.

## Handshake validation and limits

Praxis accepts one valid HTTP/1.1 `websocket` offer using WebSocket version 13.
It validates the client key, the upstream `Sec-WebSocket-Accept` response, and
any selected subprotocol before committing the upgrade. Malformed handshakes
receive `400`; denied or unsupported upgrades receive `403`; unsolicited or
invalid upstream `101` responses fail as `502`.

General `CONNECT`, HTTP/2 extended CONNECT, multiple Upgrade protocols, and
non-WebSocket upgrade passthrough are outside this support. Ordinary HTTP/1.1
and HTTP/2 requests continue through the normal filter pipeline.

See the [WebSocket example](../../examples/configs/protocols/websocket.yaml)
for a complete Pingora configuration and a functional bidirectional test.
