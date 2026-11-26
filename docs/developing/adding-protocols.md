# Adding a Protocol

A protocol is what a listener speaks. It registers services on the network
backend's runtime that bind listeners and run traffic through the filter
pipeline. The backend is the library that owns the sockets; to add one, see
[Adding a Network Backend](adding-backends.md).

## Steps

### 1. Implement `Protocol`

Create a module under `crates/protocol/src/` that implements the
[`Protocol`] trait:

```rust
pub trait Protocol: Send {
    fn register(
        self: Box<Self>,
        server: &mut praxis_core::backend::Runtime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<Vec<watch::Sender<bool>>, ProxyError>;
}
```

`register` picks the listeners of its protocol kind, resolves their
pipelines from `ListenerPipelines`, and registers services on the backend
runtime (`backend::Runtime` is the selected backend's runtime type). It
returns any TLS certificate watcher shutdown senders, which the caller keeps
alive until server shutdown.

The reference implementations, exposed as
`praxis_protocol::backend::{Http, Tcp}`, are `PingoraHttp` in
`crates/protocol/src/http/pingora/mod.rs` and `PingoraTcp` in
`crates/protocol/src/tcp/service.rs`.

### 2. Add `ProtocolKind` variant

Add a variant to `ProtocolKind` in
`crates/core/src/config/listener.rs`:

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

`#[serde(rename_all = "lowercase")]` maps YAML values such as
`protocol: tcp` to variants.

### 3. Wire in `server.rs`

In `crates/server/src/server.rs`, add a branch to `register_protocols` that
registers the implementation when a listener uses the new kind:

```rust
if config.listeners.iter().any(|l| l.protocol == ProtocolKind::NewProtocol) {
    let shutdowns = Box::new(NewProtocolImpl)
        .register(server, config, pipelines)
        .unwrap_or_else(|e| fatal(&e));
    all_shutdowns.extend(shutdowns);
}
```

### 4. Add filter compatibility

If the protocol needs a filter trait other than `HttpFilter` or `TcpFilter`,
define it in `crates/filter/src/` and make the pipeline engine dispatch to
it.

### 5. Test and document

Add unit tests, integration tests under `tests/integration/`, and example
configs under `examples/configs/`. Update `examples/README.md` and add the
protocol to `docs/features.md`.

[`Protocol`]: ../../crates/protocol/src/lib.rs
