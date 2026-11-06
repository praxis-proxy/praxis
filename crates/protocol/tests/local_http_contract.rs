// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Public-interface integration for the compiled minimal local handler.

#![cfg(feature = "local-http")]
#![expect(clippy::unwrap_used, reason = "integration assertion")]

#[path = "../examples/local_http.rs"]
mod example;

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn minimal_local_service_runs_with_only_public_interfaces() {
        super::example::run_example().await.unwrap();
    }
}
