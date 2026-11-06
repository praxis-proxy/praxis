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
    /// Write the error's operator-facing description.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShutdownStarted => f.write_str("server shutdown has already started"),
        }
    }
}

impl std::error::Error for LifecycleError {}

// -----------------------------------------------------------------------------
// LifecycleHandle
// -----------------------------------------------------------------------------

/// Cloneable handle for the one server lifecycle state machine.
///
/// The watch channel is both the source of truth and the notification mechanism.
#[derive(Clone, Debug)]
pub struct LifecycleHandle {
    /// The watch channel holding the current phase and notifying subscribers.
    state: Arc<watch::Sender<LifecyclePhase>>,
}

impl Default for LifecycleHandle {
    /// Build a handle in the initializing phase, like [`LifecycleHandle::new`].
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
    ///
    /// This is a state assertion: calling it while already serving is a no-op
    /// that notifies no subscriber.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::ShutdownStarted`] once shutdown has begun.
    pub fn mark_serving(&self) -> Result<(), LifecycleError> {
        let mut accepted = false;
        self.state.send_if_modified(|phase| match phase {
            LifecyclePhase::Initializing => {
                accepted = true;
                *phase = LifecyclePhase::Serving;
                true
            },
            LifecyclePhase::Serving => {
                accepted = true;
                false
            },
            LifecyclePhase::Draining | LifecyclePhase::Stopped => false,
        });
        accepted.then_some(()).ok_or(LifecycleError::ShutdownStarted)
    }

    /// Begin an irreversible drain and report whether this call won the race.
    pub fn begin_drain(&self) -> bool {
        self.transition(|phase| match phase {
            LifecyclePhase::Initializing | LifecyclePhase::Serving => Some(LifecyclePhase::Draining),
            LifecyclePhase::Draining | LifecyclePhase::Stopped => None,
        })
    }

    /// Mark shutdown complete.
    ///
    /// Completion is only valid from [`LifecyclePhase::Draining`]; other phases
    /// are ignored, so callers must [`begin_drain`] first.
    ///
    /// [`begin_drain`]: Self::begin_drain
    pub fn mark_stopped(&self) {
        _ = self.transition(|phase| match phase {
            LifecyclePhase::Draining => Some(LifecyclePhase::Stopped),
            LifecyclePhase::Initializing | LifecyclePhase::Serving | LifecyclePhase::Stopped => None,
        });
    }

    /// Apply one state transition through the watch channel's synchronized value.
    ///
    /// `transition` runs while the channel holds its lock, so it must be a pure
    /// next-phase calculation: no blocking, external work, or re-entry. Returns
    /// whether the transition was accepted, not whether the phase changed.
    fn transition(&self, transition: impl FnOnce(LifecyclePhase) -> Option<LifecyclePhase>) -> bool {
        let mut accepted = false;
        self.state.send_if_modified(|phase| match transition(*phase) {
            Some(next) => {
                accepted = true;
                let changed = *phase != next;
                *phase = next;
                changed
            },
            None => false,
        });
        accepted
    }
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn starts_initializing_and_can_become_serving() {
        let lifecycle = LifecycleHandle::new();

        assert_eq!(lifecycle.phase(), LifecyclePhase::Initializing);
        lifecycle.mark_serving().unwrap();
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
    fn stopped_requires_a_drain_and_wins_over_later_transitions() {
        let lifecycle = LifecycleHandle::new();

        lifecycle.mark_stopped();
        assert_eq!(
            lifecycle.phase(),
            LifecyclePhase::Initializing,
            "completion must not skip startup and its cleanup"
        );

        lifecycle.mark_serving().unwrap();
        lifecycle.mark_stopped();
        assert_eq!(
            lifecycle.phase(),
            LifecyclePhase::Serving,
            "completion must not overwrite serving without a drain"
        );

        assert!(lifecycle.begin_drain());
        lifecycle.mark_stopped();
        assert_eq!(lifecycle.phase(), LifecyclePhase::Stopped);
        assert!(!lifecycle.begin_drain());
        assert_eq!(lifecycle.mark_serving(), Err(LifecycleError::ShutdownStarted));
    }

    #[test]
    fn repeated_mark_serving_is_an_idempotent_noop() {
        let lifecycle = LifecycleHandle::new();
        let mut receiver = lifecycle.subscribe();

        lifecycle.mark_serving().unwrap();
        assert!(receiver.has_changed().is_ok_and(|changed| changed));
        receiver.borrow_and_update();

        lifecycle.mark_serving().unwrap();
        assert!(
            !receiver.has_changed().is_ok_and(|changed| changed),
            "a repeated mark_serving must not notify subscribers"
        );
        assert_eq!(lifecycle.phase(), LifecyclePhase::Serving);
    }

    #[test]
    fn clones_and_subscribers_observe_one_state() {
        let lifecycle = LifecycleHandle::new();
        let clone = lifecycle.clone();
        let mut receiver = clone.subscribe();

        lifecycle.mark_serving().unwrap();
        assert!(receiver.has_changed().is_ok_and(|changed| changed));
        assert_eq!(*receiver.borrow_and_update(), LifecyclePhase::Serving);
        assert_eq!(clone.phase(), LifecyclePhase::Serving);
    }
}
