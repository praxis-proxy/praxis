// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The stand-in runtime for a build with no network backend.

use super::{ServerRuntime, ShutdownFuture};
use crate::config::Config;

/// Runtime for a build that carries no network backend.
///
/// It exists so the library crates compile and type-check without a backend;
/// there are no protocol adapters to register onto it, and running it logs
/// that nothing can be served and returns at once.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableRuntime;

impl ServerRuntime for UnavailableRuntime {
    fn from_config(config: &Config) -> Self {
        _ = config;
        Self
    }

    fn run_until_shutdown(self) {
        self.run_with_shutdown(Box::pin(std::future::ready(())));
    }

    fn run_with_shutdown(self, shutdown: ShutdownFuture) {
        drop(shutdown);
        tracing::error!("no network backend is compiled into this build; nothing to serve");
    }
}
