//! Body access declarations, buffering, and capability computation.

mod access;
mod buffer;
mod capabilities;
mod mode;

pub use access::BodyAccess;
pub use buffer::{BodyBuffer, BodyBufferOverflow};
pub use capabilities::BodyCapabilities;
pub use mode::BodyMode;
