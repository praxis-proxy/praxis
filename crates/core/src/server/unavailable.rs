// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The stand-in runtime for a build with no network backend.

use super::{LifecycleHandle, ServerRuntime, ShutdownFuture};
use crate::config::Config;

/// Runtime for a build that carries no network backend.
///
/// It exists so the library crates compile and type-check without a backend;
/// there are no protocol adapters to register onto it, and running it logs
/// that nothing can be served and returns at once.
#[derive(Clone, Debug, Default)]
pub struct UnavailableRuntime {
    /// Shared lifecycle state, which stops as soon as the runtime runs.
    lifecycle: LifecycleHandle,
}

impl ServerRuntime for UnavailableRuntime {
    /// Build the runtime from `config`, which is unused because no backend is present.
    fn from_config(config: &Config) -> Self {
        _ = config;
        Self::default()
    }

    /// Report that nothing can be served and return.
    fn run_until_shutdown(self) {
        self.run_with_shutdown(Box::pin(std::future::ready(())));
    }

    /// Drop `shutdown`, log that nothing can be served, and stop.
    ///
    /// The lifecycle still ends in `Stopped` so management code waiting for a
    /// terminal phase is released rather than blocked on `Initializing`.
    fn run_with_shutdown(self, shutdown: ShutdownFuture) {
        drop(shutdown);
        tracing::error!("no network backend is compiled into this build; nothing to serve");
        self.lifecycle.begin_drain();
        self.lifecycle.mark_stopped();
    }

    /// Return a clone of the runtime's lifecycle handle.
    fn lifecycle(&self) -> LifecycleHandle {
        self.lifecycle.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::LifecyclePhase;

    #[test]
    fn running_without_a_backend_stops_the_lifecycle() {
        let runtime = UnavailableRuntime::default();
        let lifecycle = runtime.lifecycle();

        runtime.run_until_shutdown();

        assert_eq!(
            lifecycle.phase(),
            LifecyclePhase::Stopped,
            "a runtime with nothing to serve must still reach a terminal phase"
        );
    }
}
