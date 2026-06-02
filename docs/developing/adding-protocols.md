# Adding a Protocol

1. Implement the `Protocol` trait in a new module under
   `protocol/src/`.
2. Add a variant to `ProtocolKind` in
   `core/src/config/listener.rs`.
3. Wire it up in `server/src/server.rs` where the protocol
   is selected.
