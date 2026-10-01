// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Upstream connectivity types used by the filter pipeline and protocol layer.

mod classification;
mod connection_options;
mod network;
/// Shared [`HttpPeer`] construction utilities for TLS and connection options.
///
/// [`HttpPeer`]: pingora_core::upstreams::peer::HttpPeer
pub mod peer;
mod target;
mod trusted_private;
mod upstream;

pub(crate) use classification::classify_without_nat64;
pub use classification::{IpClassification, classify_ip};
pub use connection_options::ConnectionOptions;
pub use network::{CidrRange, is_private_ip, normalize_mapped_ipv4};
pub use target::{
    InvalidTarget, PreparedSubrequest, PreparedTarget, UrlTargetError, prepare_url_target, validate_url_target,
};
pub(crate) use trusted_private::strip_root_dot;
pub use trusted_private::validate_host_entries;
pub use upstream::Upstream;
