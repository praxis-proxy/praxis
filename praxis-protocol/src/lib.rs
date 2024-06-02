#![deny(unsafe_code)]
#![deny(unreachable_pub)]

//! Protocol adapters for Praxis.

use praxis_core::{ProxyError, ServerRuntime, config::Config};

mod pipelines;
pub use pipelines::ListenerPipelines;

/// HTTP/1.1 and HTTP/2 protocol implementations.
pub mod http;
/// HTTP/3 protocol implementations (work in progress).
pub mod http3;
/// Raw TCP/L4 forwarding protocol.
pub mod tcp;
/// UDP protocol implementations (work in progress).
pub mod udp;

// -----------------------------------------------------------------------------
// Protocol
// -----------------------------------------------------------------------------

/// A protocol implementation that registers services onto a shared server
/// runtime.
///
/// Implementors ([`PingoraHttp`], [`PingoraTcp`]) bind listeners and wire
/// them to the filter pipeline during startup.
///
/// [`PingoraHttp`]: http::PingoraHttp
/// [`PingoraTcp`]: tcp::PingoraTcp
pub trait Protocol: Send {
    /// Register this protocol's services. Does not block.
    fn register(
        self: Box<Self>,
        server: &mut ServerRuntime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<(), ProxyError>;
}
