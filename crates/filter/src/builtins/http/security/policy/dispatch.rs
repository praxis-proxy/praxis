// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bounded dispatch of async policy hooks from synchronous filter phases.
//!
//! `on_response_body` is synchronous, so the policy filter must block its
//! worker thread while a hook runs. The engine spawns every handler onto the
//! runtime the hook runs on, so a hook run on the worker's own runtime would
//! need the very thread that is blocked waiting for it: on a current-thread
//! worker (`runtime.work_stealing: false`) or a single worker, every response
//! hook would deadlock. Hooks therefore run on a small dedicated runtime whose
//! own threads drive its tasks, IO and timers.

use std::{
    sync::{OnceLock, mpsc},
    time::Duration,
};

use tokio::runtime::{Builder, Handle, Runtime};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Worker threads on the dispatch runtime. Response hooks mostly await the
/// engine's handlers and their outbound calls, so a small pool is enough and
/// the proxy's thread count is not doubled.
const DISPATCH_WORKER_THREADS: usize = 2;

/// Engine handler budgets one response dispatch may use. The engine bounds
/// each handler by `engine_settings.plugin_timeout`, so a single budget would
/// cut short a hook that runs a second handler after the first.
const HANDLER_BUDGETS_PER_DISPATCH: u32 = 2;

/// Floor for the dispatch bound, so a `plugin_timeout` of zero leaves the
/// engine time to report its own timeout instead of failing every response.
const MIN_RESPONSE_DISPATCH_TIMEOUT: Duration = Duration::from_secs(1); // 1 s

/// Thread name for the dispatch runtime's workers.
const THREAD_NAME: &str = "praxis-policy-dispatch";

// -----------------------------------------------------------------------------
// Statics
// -----------------------------------------------------------------------------

/// The process-wide dispatch runtime; `None` records a failed build. A static,
/// so it survives reloads and is never dropped from an async context.
static RUNTIME: OnceLock<Option<Runtime>> = OnceLock::new();

// -----------------------------------------------------------------------------
// DispatchError
// -----------------------------------------------------------------------------

/// Why a blocking dispatch produced no result.
#[derive(Debug, thiserror::Error)]
pub(super) enum DispatchError {
    /// The hook task ended without a result, e.g. because it panicked.
    #[error("hook task ended without a result")]
    Abandoned,

    /// The hook did not finish within the limit and was aborted.
    #[error("hook did not finish within {0:?}")]
    TimedOut(Duration),

    /// The dispatch runtime could not be built.
    #[error("dispatch runtime unavailable")]
    Unavailable,
}

// -----------------------------------------------------------------------------
// Dispatch
// -----------------------------------------------------------------------------

/// The bound for one response-phase dispatch, given the engine's per-handler
/// timeout in seconds.
pub(super) fn response_dispatch_timeout(plugin_timeout_secs: u64) -> Duration {
    Duration::from_secs(plugin_timeout_secs)
        .saturating_mul(HANDLER_BUDGETS_PER_DISPATCH)
        .max(MIN_RESPONSE_DISPATCH_TIMEOUT)
}

/// Run `future` on the dispatch runtime, blocking the calling thread for at
/// most `limit`. Safe to call from any thread, including a worker of a
/// current-thread tokio runtime.
///
/// # Errors
///
/// Returns [`DispatchError::TimedOut`] after aborting a hook that outlives
/// `limit`, [`DispatchError::Abandoned`] if the hook ends without a result,
/// and [`DispatchError::Unavailable`] if the runtime cannot be built.
pub(super) fn block_on_bounded<F>(future: F, limit: Duration) -> Result<F::Output, DispatchError>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let runtime = dispatch_runtime().ok_or(DispatchError::Unavailable)?;
    let (tx, rx) = mpsc::sync_channel(1);
    let task = runtime.spawn(async move {
        drop(tx.send(future.await));
    });

    rx.recv_timeout(limit).map_err(|e| match e {
        mpsc::RecvTimeoutError::Timeout => {
            task.abort();
            DispatchError::TimedOut(limit)
        },
        mpsc::RecvTimeoutError::Disconnected => DispatchError::Abandoned,
    })
}

/// Whether the caller runs on the dispatch runtime. Never builds it.
pub(super) fn on_dispatch_runtime() -> bool {
    let Some(Some(runtime)) = RUNTIME.get() else {
        return false;
    };
    Handle::try_current().is_ok_and(|current| current.id() == runtime.handle().id())
}

// -----------------------------------------------------------------------------
// Dispatch Runtime
// -----------------------------------------------------------------------------

/// Build the dispatch runtime now, so a failure stops startup instead of
/// failing responses later.
///
/// # Errors
///
/// Returns [`DispatchError::Unavailable`] if the runtime cannot be built.
pub(super) fn ensure_dispatch_runtime() -> Result<(), DispatchError> {
    dispatch_runtime().map(drop).ok_or(DispatchError::Unavailable)
}

/// The dispatch runtime, built on first use.
fn dispatch_runtime() -> Option<&'static Runtime> {
    RUNTIME
        .get_or_init(|| {
            Builder::new_multi_thread()
                .worker_threads(DISPATCH_WORKER_THREADS)
                .enable_all()
                .thread_name(THREAD_NAME)
                .build()
                .inspect_err(|e| {
                    tracing::error!(target: "policy.filter", error = %e, "policy: failed to build the dispatch runtime");
                })
                .ok()
        })
        .as_ref()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use std::{sync::mpsc, time::Duration};

    use super::{
        DispatchError, block_on_bounded, ensure_dispatch_runtime, on_dispatch_runtime, response_dispatch_timeout,
    };

    #[test]
    fn returns_the_hook_output() -> Result<(), DispatchError> {
        let output = block_on_bounded(async { 7 }, Duration::from_secs(5))?;
        assert_eq!(output, 7, "the hook's output must reach the caller");
        Ok(())
    }

    #[test]
    fn times_out_and_aborts_a_stalled_hook() {
        let (alive_tx, alive_rx) = mpsc::channel::<()>();
        let result = block_on_bounded(
            async move {
                let _alive = alive_tx;
                std::future::pending::<()>().await;
            },
            Duration::from_millis(50),
        );
        assert!(
            matches!(result, Err(DispatchError::TimedOut(limit)) if limit == Duration::from_millis(50)),
            "a hook that never finishes must fail closed with a timeout, got {result:?}"
        );
        assert_eq!(
            alive_rx.recv_timeout(Duration::from_secs(5)),
            Err(mpsc::RecvTimeoutError::Disconnected),
            "the timed-out hook must be aborted, dropping its state"
        );
    }

    #[test]
    fn reports_a_hook_that_ends_without_a_result() {
        let result: Result<(), DispatchError> =
            block_on_bounded(async { panic!("hook panicked") }, Duration::from_secs(5));
        assert!(
            matches!(result, Err(DispatchError::Abandoned)),
            "a panicked hook closes the channel and must not be read as a result, got {result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_timer_awaiting_hook_completes_from_a_current_thread_runtime() -> Result<(), DispatchError> {
        let output = block_on_bounded(
            async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                "woke"
            },
            Duration::from_secs(5),
        )?;
        assert_eq!(
            output, "woke",
            "a hook awaiting a timer must not deadlock a current-thread worker"
        );
        Ok(())
    }

    #[test]
    fn the_bound_covers_two_handler_budgets() {
        assert_eq!(
            response_dispatch_timeout(30),
            Duration::from_secs(60),
            "a dispatch must outlast two engine handler budgets"
        );
        assert_eq!(
            response_dispatch_timeout(0),
            Duration::from_secs(1),
            "a zero plugin timeout must still leave the engine time to answer"
        );
        assert_eq!(
            response_dispatch_timeout(u64::MAX),
            Duration::MAX,
            "an extreme plugin timeout must saturate, not overflow"
        );
    }

    #[test]
    fn only_tasks_on_the_dispatch_runtime_report_being_on_it() -> Result<(), DispatchError> {
        ensure_dispatch_runtime()?;
        assert!(!on_dispatch_runtime(), "a plain thread is not on the dispatch runtime");
        let inside = block_on_bounded(async { on_dispatch_runtime() }, Duration::from_secs(5))?;
        assert!(inside, "a dispatched hook runs on the dispatch runtime");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_worker_runtime_is_not_the_dispatch_runtime() -> Result<(), DispatchError> {
        ensure_dispatch_runtime()?;
        assert!(
            !on_dispatch_runtime(),
            "a worker runtime must keep using the shared connection pool"
        );
        Ok(())
    }
}
