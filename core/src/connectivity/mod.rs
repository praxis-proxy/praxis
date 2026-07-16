// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Upstream connectivity types used by the filter pipeline and protocol layer.

mod connection_options;
mod network;
mod upstream;

pub use connection_options::ConnectionOptions;
pub use network::{CidrRange, is_private_ip, normalize_mapped_ipv4};
pub use upstream::Upstream;
