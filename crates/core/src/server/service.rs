// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Runtime services contributed by an embedding distribution.
//!
//! The public contract deliberately hides Pingora. A downstream service gets
//! an owned shutdown signal and a one-shot readiness notifier while Praxis
//! adapts it to the server runtime internally.

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use pingora_core::{
    server::ShutdownWatch,
    services::{ServiceReadyNotifier, background::BackgroundService},
};
use tokio::sync::oneshot;
use tracing::error;

/// Boxed future returned by a [`RuntimeService`].
pub type RuntimeServiceFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Aggregate readiness of all runtime services registered with a server.
///
/// A clone can be shared with an administrative readiness endpoint. It reports
/// ready when no runtime services are registered or after every registered
/// service explicitly signals readiness and while those services remain alive.
#[derive(Clone, Debug, Default)]
pub struct RuntimeReadiness {
    /// Number of registered services that have not signaled readiness.
    pending: Arc<AtomicUsize>,
}

impl RuntimeReadiness {
    /// Whether every registered runtime service has signaled readiness.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.pending.load(Ordering::Acquire) == 0
    }

    /// Register one service that must signal readiness.
    pub(super) fn register(&self) -> RuntimeReadinessRegistration {
        self.pending.fetch_add(1, Ordering::AcqRel);
        RuntimeReadinessRegistration {
            pending: Arc::clone(&self.pending),
            reported: AtomicBool::new(false),
        }
    }
}

/// One runtime service's contribution to aggregate readiness.
pub(super) struct RuntimeReadinessRegistration {
    /// Shared pending-service count.
    pending: Arc<AtomicUsize>,
    /// Whether this service currently contributes readiness.
    reported: AtomicBool,
}

impl RuntimeReadinessRegistration {
    /// Mark this service ready exactly once.
    fn notify_ready(&self) {
        if !self.reported.swap(true, Ordering::AcqRel) {
            let previous = self.pending.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(previous > 0, "runtime readiness count must not underflow");
        }
    }

    /// Revoke readiness after a process-lifetime service exits.
    fn notify_unready(&self) {
        if self.reported.swap(false, Ordering::AcqRel) {
            self.pending.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// A process-lifetime task that must run on the serving runtime.
///
/// Implementations receive no Pingora types or mutable server handles. They
/// may initialize runtime-bound resources, signal readiness, process commands,
/// and must remain alive until shutdown after signaling readiness. Returning
/// before signaling readiness keeps dependent proxy listeners gated until
/// shutdown. Returning later revokes administrative readiness, though listeners
/// that already started cannot be withdrawn.
///
/// The shutdown signal begins graceful shutdown; requests accepted before it
/// may continue through the configured grace period. A service may stop its
/// worker loop when signaled, but it must not close or invalidate resources
/// shared with request handlers. Request-visible resources must remain usable
/// until their final consumer-owned handle is dropped after draining.
pub trait RuntimeService: Send + Sync + 'static {
    /// Run this service until it completes or the server shuts down.
    fn run(self: Arc<Self>, context: RuntimeServiceContext) -> RuntimeServiceFuture;
}

/// Owned context passed to a [`RuntimeService`].
pub struct RuntimeServiceContext {
    /// One-shot readiness notifier.
    ready: RuntimeReady,
    /// Server shutdown signal.
    shutdown: RuntimeShutdown,
}

impl RuntimeServiceContext {
    /// Split the context into independently owned shutdown and readiness
    /// handles.
    pub fn into_parts(self) -> (RuntimeShutdown, RuntimeReady) {
        (self.shutdown, self.ready)
    }
}

/// Start-of-drain shutdown signal for a [`RuntimeService`].
///
/// Existing proxy requests may still be running when this signal changes.
/// Stop background work, but retain resources used by request handlers until
/// their final consumer-owned handles are dropped.
pub struct RuntimeShutdown {
    /// Pingora's watch receiver, kept private at the public boundary.
    inner: ShutdownWatch,
}

impl RuntimeShutdown {
    /// Whether shutdown has already been requested.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        *self.inner.borrow()
    }

    /// Wait until the shutdown state changes.
    ///
    /// Returns `false` only when the server dropped the signal without sending
    /// another value. Callers should stop background work in either case, but
    /// this is not a post-drain resource-destruction signal.
    pub async fn changed(&mut self) -> bool {
        self.inner.changed().await.is_ok()
    }
}

/// One-shot readiness notifier for a [`RuntimeService`].
///
/// Holding this value keeps the service unready. Consume it with
/// [`notify_ready`](Self::notify_ready) after required initialization has
/// completed. Dropping it without notification keeps dependent proxy listeners
/// gated.
#[must_use = "runtime services must explicitly signal readiness"]
pub struct RuntimeReady {
    /// One-shot signal observed by the internal Pingora adapter.
    sender: Option<oneshot::Sender<()>>,
}

impl RuntimeReady {
    /// Mark the service ready and allow dependent server startup to proceed.
    pub fn notify_ready(mut self) {
        if let Some(sender) = self.sender.take() {
            let _sent = sender.send(());
        }
    }
}

/// Pingora adapter for a public [`RuntimeService`].
pub(super) struct RuntimeServiceAdapter {
    /// Human-readable service name used for lifecycle diagnostics.
    name: Arc<str>,
    /// Downstream task behind the opaque boundary.
    service: Arc<dyn RuntimeService>,
    /// This service's contribution to aggregate runtime readiness.
    readiness: RuntimeReadinessRegistration,
}

impl RuntimeServiceAdapter {
    /// Wrap a downstream task for Pingora registration.
    pub(super) fn new(name: &str, service: Arc<dyn RuntimeService>, readiness: RuntimeReadinessRegistration) -> Self {
        Self {
            name: Arc::from(name),
            service,
            readiness,
        }
    }

    /// Forward one successful worker initialization to both readiness views.
    fn notify_ready(&self, ready_notifier: ServiceReadyNotifier) {
        self.readiness.notify_ready();
        ready_notifier.notify_ready();
    }

    /// Spawn the worker so both future construction and polling panics become
    /// a [`tokio::task::JoinError`] observed by the adapter.
    fn spawn_worker(&self, shutdown: ShutdownWatch, ready_sender: oneshot::Sender<()>) -> tokio::task::JoinHandle<()> {
        let service = Arc::clone(&self.service);
        tokio::spawn(async move {
            service
                .run(RuntimeServiceContext {
                    ready: RuntimeReady {
                        sender: Some(ready_sender),
                    },
                    shutdown: RuntimeShutdown { inner: shutdown },
                })
                .await;
        })
    }
}

#[async_trait]
impl BackgroundService for RuntimeServiceAdapter {
    async fn start_with_ready_notifier(&self, shutdown: ShutdownWatch, ready_notifier: ServiceReadyNotifier) {
        let readiness_shutdown = shutdown.clone();
        let (ready_sender, mut ready_receiver) = oneshot::channel();
        let mut service = self.spawn_worker(shutdown, ready_sender);

        tokio::select! {
            signal = &mut ready_receiver => {
                match signal {
                    Ok(()) => {
                        self.notify_ready(ready_notifier);
                        let result = service.await;
                        self.readiness.notify_unready();
                        log_worker_exit(&self.name, result, *readiness_shutdown.borrow());
                    },
                    Err(_closed) => {
                        log_worker_exit(&self.name, service.await, *readiness_shutdown.borrow());
                        hold_unready_until_shutdown(readiness_shutdown).await;
                    },
                }
            },
            result = &mut service => {
                _ = ready_receiver.try_recv();
                log_worker_exit(&self.name, result, *readiness_shutdown.borrow());
                hold_unready_until_shutdown(readiness_shutdown).await;
            },
        }
    }
}

/// Report a worker that failed or stopped before server shutdown.
fn log_worker_exit(name: &str, result: Result<(), tokio::task::JoinError>, shutdown_requested: bool) {
    match result {
        Err(error) => error!(service = name, %error, "runtime service task failed"),
        Ok(()) if !shutdown_requested => error!(service = name, "runtime service exited before shutdown"),
        Ok(()) => {},
    }
}

/// Keep dependent proxy listeners gated when a service exits before it is
/// ready. Pingora's notifier signals readiness when dropped, so the adapter
/// must retain it until shutdown instead of returning early.
async fn hold_unready_until_shutdown(mut shutdown: ShutdownWatch) {
    while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
}

#[cfg(test)]
#[expect(clippy::panic, reason = "tests verify that panicking runtime services fail closed")]
mod tests {
    use super::*;

    struct RecordingService {
        ran: AtomicBool,
    }

    struct NeverReadyService;

    struct DropsReadinessService {
        stopped: AtomicBool,
    }

    struct PanickingService;

    struct SynchronouslyPanickingService;

    struct ReadyThenPanicsService {
        panic_gate: Arc<tokio::sync::Notify>,
    }

    impl RuntimeService for RecordingService {
        fn run(self: Arc<Self>, context: RuntimeServiceContext) -> RuntimeServiceFuture {
            Box::pin(async move {
                let (mut shutdown, ready) = context.into_parts();
                self.ran.store(true, Ordering::SeqCst);
                ready.notify_ready();
                _ = shutdown.changed().await;
            })
        }
    }

    impl RuntimeService for NeverReadyService {
        fn run(self: Arc<Self>, _context: RuntimeServiceContext) -> RuntimeServiceFuture {
            Box::pin(async {})
        }
    }

    impl RuntimeService for DropsReadinessService {
        fn run(self: Arc<Self>, context: RuntimeServiceContext) -> RuntimeServiceFuture {
            Box::pin(async move {
                let (mut shutdown, ready) = context.into_parts();
                drop(ready);
                _ = shutdown.changed().await;
                self.stopped.store(true, Ordering::SeqCst);
            })
        }
    }

    impl RuntimeService for PanickingService {
        fn run(self: Arc<Self>, _context: RuntimeServiceContext) -> RuntimeServiceFuture {
            Box::pin(async move {
                panic!("runtime initialization failed");
            })
        }
    }

    impl RuntimeService for SynchronouslyPanickingService {
        fn run(self: Arc<Self>, _context: RuntimeServiceContext) -> RuntimeServiceFuture {
            panic!("runtime future construction failed");
        }
    }

    impl RuntimeService for ReadyThenPanicsService {
        fn run(self: Arc<Self>, context: RuntimeServiceContext) -> RuntimeServiceFuture {
            Box::pin(async move {
                let (_shutdown, ready) = context.into_parts();
                ready.notify_ready();
                self.panic_gate.notified().await;
                panic!("runtime failed after initialization");
            })
        }
    }

    fn adapter(name: &str, service: Arc<dyn RuntimeService>) -> (RuntimeServiceAdapter, RuntimeReadiness) {
        let readiness = RuntimeReadiness::default();
        let registration = readiness.register();
        (RuntimeServiceAdapter::new(name, service, registration), readiness)
    }

    #[tokio::test]
    async fn adapter_runs_service_and_forwards_readiness() {
        let service = Arc::new(RecordingService {
            ran: AtomicBool::new(false),
        });
        let adapter_service: Arc<dyn RuntimeService> = Arc::<RecordingService>::clone(&service);
        let (adapter, readiness) = adapter("recording", adapter_service);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, mut ready_rx) = tokio::sync::watch::channel(false);
        let running = tokio::spawn(async move {
            adapter
                .start_with_ready_notifier(shutdown_rx, ServiceReadyNotifier::new(ready_tx))
                .await;
        });

        assert!(ready_rx.changed().await.is_ok(), "readiness sender should remain live");
        assert!(service.ran.load(Ordering::SeqCst), "runtime service should run");
        assert!(*ready_rx.borrow(), "readiness should be forwarded");
        assert!(readiness.is_ready(), "aggregate readiness should be forwarded");
        assert!(
            shutdown_tx.send(true).is_ok(),
            "runtime service should observe shutdown"
        );
        assert!(running.await.is_ok(), "runtime service task should stop cleanly");
        assert!(!readiness.is_ready(), "stopped service must revoke aggregate readiness");
    }

    #[tokio::test]
    async fn adapter_keeps_dependents_unready_when_service_exits_early() {
        let (adapter, readiness) = adapter("never-ready", Arc::new(NeverReadyService));
        let adapter = Arc::new(adapter);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let running = tokio::spawn({
            let adapter = Arc::clone(&adapter);
            async move {
                adapter
                    .start_with_ready_notifier(shutdown_rx, ServiceReadyNotifier::new(ready_tx))
                    .await;
            }
        });

        tokio::task::yield_now().await;
        assert!(!*ready_rx.borrow(), "early exit must not release dependents");
        assert!(!readiness.is_ready(), "early exit must keep aggregate readiness false");
        assert!(
            shutdown_tx.send(true).is_ok(),
            "runtime service should observe shutdown"
        );
        assert!(running.await.is_ok(), "runtime service task should stop cleanly");
    }

    #[tokio::test]
    async fn dropped_readiness_keeps_polling_worker_until_shutdown() {
        let service = Arc::new(DropsReadinessService {
            stopped: AtomicBool::new(false),
        });
        let adapter_service: Arc<dyn RuntimeService> = Arc::<DropsReadinessService>::clone(&service);
        let (adapter, readiness) = adapter("drops-readiness", adapter_service);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let running = tokio::spawn(async move {
            adapter
                .start_with_ready_notifier(shutdown_rx, ServiceReadyNotifier::new(ready_tx))
                .await;
        });

        tokio::task::yield_now().await;
        assert!(!*ready_rx.borrow(), "dropped readiness must not release dependents");
        assert!(!readiness.is_ready(), "aggregate readiness must remain false");
        assert!(shutdown_tx.send(true).is_ok(), "worker should still observe shutdown");
        assert!(running.await.is_ok(), "adapter should stop cleanly");
        assert!(
            service.stopped.load(Ordering::SeqCst),
            "worker must complete its shutdown cleanup"
        );
    }

    #[tokio::test]
    async fn worker_panic_keeps_readiness_closed_until_shutdown() {
        let (adapter, readiness) = adapter("panicking", Arc::new(PanickingService));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let running = tokio::spawn(async move {
            adapter
                .start_with_ready_notifier(shutdown_rx, ServiceReadyNotifier::new(ready_tx))
                .await;
        });

        tokio::task::yield_now().await;
        assert!(!*ready_rx.borrow(), "panic must not release dependents");
        assert!(!readiness.is_ready(), "panic must keep aggregate readiness false");
        assert!(
            shutdown_tx.send(true).is_ok(),
            "adapter should remain alive until shutdown"
        );
        assert!(
            running.await.is_ok(),
            "worker panic must not unwind through the adapter"
        );
    }

    #[tokio::test]
    async fn synchronous_run_panic_keeps_readiness_closed_until_shutdown() {
        let (adapter, readiness) = adapter("synchronous-panic", Arc::new(SynchronouslyPanickingService));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let running = tokio::spawn(async move {
            adapter
                .start_with_ready_notifier(shutdown_rx, ServiceReadyNotifier::new(ready_tx))
                .await;
        });

        tokio::task::yield_now().await;
        assert!(!*ready_rx.borrow(), "synchronous panic must not release dependents");
        assert!(!readiness.is_ready(), "synchronous panic must keep readiness false");
        assert!(
            shutdown_tx.send(true).is_ok(),
            "adapter should remain alive until shutdown"
        );
        assert!(
            running.await.is_ok(),
            "synchronous panic must not unwind through the adapter"
        );
    }

    #[tokio::test]
    async fn post_ready_panic_revokes_aggregate_readiness() {
        let panic_gate = Arc::new(tokio::sync::Notify::new());
        let (adapter, readiness) = adapter(
            "post-ready-panic",
            Arc::new(ReadyThenPanicsService {
                panic_gate: Arc::clone(&panic_gate),
            }),
        );
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, mut ready_rx) = tokio::sync::watch::channel(false);
        let running = tokio::spawn(async move {
            adapter
                .start_with_ready_notifier(shutdown_rx, ServiceReadyNotifier::new(ready_tx))
                .await;
        });

        assert!(ready_rx.changed().await.is_ok(), "service should become ready first");
        assert!(readiness.is_ready(), "aggregate readiness should initially be true");
        panic_gate.notify_one();
        assert!(running.await.is_ok(), "worker panic must not escape the adapter");
        assert!(
            !readiness.is_ready(),
            "post-ready worker failure must revoke aggregate readiness"
        );
    }
}
