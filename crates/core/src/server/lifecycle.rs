// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Process-scoped lifecycle state shared by runtimes and protocol adapters.

use std::sync::Arc;

use tokio::sync::watch;

// -----------------------------------------------------------------------------
// LifecyclePhase
// -----------------------------------------------------------------------------

/// The externally visible phase of a Praxis server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecyclePhase {
    /// Configuration and listener startup are still in progress.
    Initializing,
    /// Required listeners and services are ready to accept work.
    Serving,
    /// Shutdown has begun; no later transition may resume serving.
    Draining,
    /// Shutdown has completed.
    Stopped,
}

// -----------------------------------------------------------------------------
// LifecycleError
// -----------------------------------------------------------------------------

/// Why a lifecycle transition could not be applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// A serving transition was attempted after shutdown began.
    ShutdownStarted,
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShutdownStarted => formatter.write_str("server shutdown has already started"),
        }
    }
}

impl std::error::Error for LifecycleError {}

// -----------------------------------------------------------------------------
// LifecycleHandle
// -----------------------------------------------------------------------------

/// Cloneable handle for the one server lifecycle state machine.
///
/// The watch channel is both the source of truth and the notification
/// mechanism. Keeping the state in one channel prevents readiness readers and
/// shutdown listeners from observing contradictory copies of the phase.
#[derive(Clone, Debug)]
pub struct LifecycleHandle {
    state: Arc<watch::Sender<LifecyclePhase>>,
}

impl Default for LifecycleHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl LifecycleHandle {
    /// Create a lifecycle handle in the initializing phase.
    #[must_use]
    pub fn new() -> Self {
        let (sender, _receiver) = watch::channel(LifecyclePhase::Initializing);
        Self {
            state: Arc::new(sender),
        }
    }

    /// Return the current lifecycle phase.
    #[must_use]
    pub fn phase(&self) -> LifecyclePhase {
        *self.state.borrow()
    }

    /// Subscribe to future lifecycle transitions.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<LifecyclePhase> {
        self.state.subscribe()
    }

    /// Publish serving after all required startup work has succeeded.
    pub fn mark_serving(&self) -> Result<(), LifecycleError> {
        if matches!(self.phase(), LifecyclePhase::Draining | LifecyclePhase::Stopped) {
            return Err(LifecycleError::ShutdownStarted);
        }
        _ = self.transition(|phase| match phase {
            LifecyclePhase::Initializing => Some(LifecyclePhase::Serving),
            LifecyclePhase::Serving => Some(LifecyclePhase::Serving),
            LifecyclePhase::Draining | LifecyclePhase::Stopped => None,
        });
        if matches!(self.phase(), LifecyclePhase::Draining | LifecyclePhase::Stopped) {
            Err(LifecycleError::ShutdownStarted)
        } else {
            Ok(())
        }
    }

    /// Begin an irreversible drain and report whether this call won the race.
    pub fn begin_drain(&self) -> bool {
        self.transition(|phase| match phase {
            LifecyclePhase::Initializing | LifecyclePhase::Serving => Some(LifecyclePhase::Draining),
            LifecyclePhase::Draining | LifecyclePhase::Stopped => None,
        })
    }

    /// Mark shutdown complete.
    pub fn mark_stopped(&self) {
        self.transition(|phase| match phase {
            LifecyclePhase::Stopped => Some(LifecyclePhase::Stopped),
            LifecyclePhase::Initializing | LifecyclePhase::Serving | LifecyclePhase::Draining => {
                Some(LifecyclePhase::Stopped)
            },
        });
    }

    /// Apply one state transition through the watch channel's synchronized value.
    fn transition(&self, transition: impl FnOnce(LifecyclePhase) -> Option<LifecyclePhase>) -> bool {
        self.state.send_if_modified(|phase| match transition(*phase) {
            Some(next) => {
                let changed = *phase != next;
                *phase = next;
                changed
            },
            None => false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_initializing_and_can_become_serving() {
        let lifecycle = LifecycleHandle::new();

        assert_eq!(lifecycle.phase(), LifecyclePhase::Initializing);
        assert!(lifecycle.mark_serving().is_ok());
        assert_eq!(lifecycle.phase(), LifecyclePhase::Serving);
    }

    #[test]
    fn drain_is_irreversible_and_repeated_drain_is_a_noop() {
        let lifecycle = LifecycleHandle::new();

        assert!(lifecycle.begin_drain());
        assert!(!lifecycle.begin_drain());
        assert_eq!(lifecycle.phase(), LifecyclePhase::Draining);
        assert_eq!(lifecycle.mark_serving(), Err(LifecycleError::ShutdownStarted));
    }

    #[test]
    fn stopped_wins_over_later_transitions() {
        let lifecycle = LifecycleHandle::new();

        lifecycle.mark_stopped();
        assert_eq!(lifecycle.phase(), LifecyclePhase::Stopped);
        assert!(!lifecycle.begin_drain());
        assert_eq!(lifecycle.mark_serving(), Err(LifecycleError::ShutdownStarted));
    }

    #[test]
    fn clones_and_subscribers_observe_one_state() {
        let lifecycle = LifecycleHandle::new();
        let clone = lifecycle.clone();
        let mut receiver = clone.subscribe();

        assert!(lifecycle.mark_serving().is_ok());
        assert!(receiver.has_changed().is_ok_and(|changed| changed));
        assert_eq!(*receiver.borrow_and_update(), LifecyclePhase::Serving);
        assert_eq!(clone.phase(), LifecyclePhase::Serving);
    }
}
