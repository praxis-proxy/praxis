# Adding a Protocol

## Overview

Protocols translate between external network protocols
and the internal filter pipeline. Each protocol
registers one or more Pingora services that bind
listeners and dispatch traffic through the filter
pipeline.

## Steps

### 1. Implement `Protocol`

Create a module under `protocol/src/` and implement
the [`Protocol`] trait:

```rust
pub trait Protocol: Send {
    fn register(
        self: Box<Self>,
        server: &mut PingoraServerRuntime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<Vec<watch::Sender<bool>>, ProxyError>;
}
```

`register` filters listeners by protocol kind, resolves
pipelines from `ListenerPipelines`, and registers
Pingora services on `PingoraServerRuntime`. Return any
TLS certificate watcher shutdown senders; the caller
keeps them alive until server shutdown.

**Reference implementations:**

- **HTTP**: `protocol/src/http/pingora/mod.rs`
  (`PingoraHttp`)
- **TCP**: `protocol/src/tcp/mod.rs` (`PingoraTcp`)

### 2. Add `ProtocolKind` variant

Add a variant to `ProtocolKind` in
`core/src/config/listener.rs`:

```rust
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolKind {
    #[default]
    Http,
    Tcp,
    // NewProtocol,
}
```

The `#[serde(rename_all = "lowercase")]` attribute maps
YAML values (e.g. `protocol: tcp`) to enum variants.

### 3. Wire in `server.rs`

In `server/src/server.rs`, add a branch to
`register_protocols` that checks for listeners using
the new protocol kind and registers the implementation:

```rust
if config.listeners.iter().any(|l| l.protocol == ProtocolKind::NewProtocol) {
    let shutdowns = Box::new(NewProtocolImpl)
        .register(server, config, pipelines)
        .unwrap_or_else(|e| fatal(&e));
    all_shutdowns.extend(shutdowns);
}
```

### 4. Add filter compatibility

If the protocol uses a different filter trait than
`HttpFilter` or `TcpFilter`, define the new trait in
`filter/src/` and ensure the pipeline engine can
dispatch to it.

### 5. Test and document

- Add unit tests for the protocol implementation
- Add integration tests under `tests/integration/`
- Add example configs under `examples/configs/`
- Update `examples/README.md`
- Update `docs/features.md` with the new protocol

[`Protocol`]: ../../protocol/src/lib.rs
