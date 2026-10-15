// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Revision-specific peer construction, kept separate for the baseline adapter.

use std::{net::SocketAddr, sync::Arc};

use praxis_core::{config::UpstreamHttpVersion, egress::PeerSpec};

/// Revision-specific peer type used by the common workload.
pub(crate) type BenchPeer = PeerSpec;

/// Build a loopback peer with an explicitly selected HTTP version.
#[must_use]
pub(crate) fn build_peer(address: SocketAddr, http2: bool) -> BenchPeer {
    let mut peer = PeerSpec::plain(address);
    Arc::make_mut(&mut peer.connection).http_version = if http2 {
        UpstreamHttpVersion::H2
    } else {
        UpstreamHttpVersion::H1
    };
    peer
}
