// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration test for the `peer_identity_trust` example config.
//!
//! This filter requires mTLS peer identity information that is only
//! available when the listener has TLS with client certificate
//! verification enabled. A full end-to-end test requires TLS test
//! infrastructure (CA, server cert, client cert). This test validates
//! that the config parses and the filter constructs successfully.

use std::collections::HashMap;

use super::load_example_config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn peer_identity_trust_example_parses() {
    let config = load_example_config(
        "security/peer-identity-trust.yaml",
        19999,
        HashMap::from([("127.0.0.1:3000", 19998_u16)]),
    );
    assert!(
        !config.listeners.is_empty(),
        "peer_identity_trust config should have at least one listener"
    );
}
