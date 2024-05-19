//! Upstream connectivity types used by the filter pipeline and protocol layer.

mod cidr;
mod connection_options;
mod upstream;

pub use cidr::CidrRange;
pub use connection_options::ConnectionOptions;
pub use upstream::Upstream;
