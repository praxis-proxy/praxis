//! HTTP/1.1 and HTTP/2 protocol implementation backed by Pingora.

/// Pingora-backed HTTP implementation.
pub mod pingora;

pub use pingora::{
    PingoraHttp,
    handler::{HTTPHandler, load_http_handler},
    health::HealthService,
};
