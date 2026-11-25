// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Process-lifetime work contributed by an embedding server.

use std::{pin::Pin, sync::Arc};

use tokio::sync::{mpsc, watch};
#[cfg(any(feature = "pingora", feature = "hyper"))]
use tokio::task::JoinSet;

use super::{LifecycleHandle, LifecyclePhase};

/// Boxed future for an embedding service.
pub type RuntimeServiceFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Work that must initialize on the selected serving backend.
///
/// Signal readiness only once requests can use the initialized resource.
/// At drain, stop background work and leave resources accessible through
/// consumer-owned handles for in-flight requests.
pub trait RuntimeService: Send + Sync + 'static {
    /// Run the service on the backend runtime.
    fn run(self: Arc<Self>, context: RuntimeServiceContext) -> RuntimeServiceFuture;
}

/// Readiness and drain handles for a contributed service.
pub struct RuntimeServiceContext {
    /// Process drain notification.
    shutdown: RuntimeShutdown,
    /// One-shot readiness notification.
    ready: RuntimeReady,
}

impl RuntimeServiceContext {
    /// Take independent ownership of the drain and readiness handles.
    pub fn into_parts(self) -> (RuntimeShutdown, RuntimeReady) {
        (self.shutdown, self.ready)
    }
}

/// Signals the beginning of drain while in-flight requests can still run.
pub struct RuntimeShutdown(watch::Receiver<LifecyclePhase>);

impl RuntimeShutdown {
    /// Whether drain or shutdown has begun.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        matches!(*self.0.borrow(), LifecyclePhase::Draining | LifecyclePhase::Stopped)
    }

    /// Wait until drain begins or the owning runtime disappears.
    pub async fn requested(&mut self) {
        let _notification = self
            .0
            .wait_for(|phase| matches!(phase, LifecyclePhase::Draining | LifecyclePhase::Stopped))
            .await;
    }
}

/// One-shot startup readiness signal. Dropping it without notification fails startup.
#[must_use = "report readiness explicitly once the service is usable"]
pub struct RuntimeReady {
    /// Events delivered to the runtime supervisor.
    events: mpsc::UnboundedSender<ServiceEvent>,
    /// Service name, consumed when readiness is explicitly reported.
    name: Option<Arc<str>>,
}

impl RuntimeReady {
    /// Report that resource initialization is complete.
    pub fn notify_ready(mut self) {
        self.name.take();
        let _sent = self.events.send(ServiceEvent::Ready);
    }
}

impl Drop for RuntimeReady {
    fn drop(&mut self) {
        if let Some(name) = self.name.take() {
            let _sent = self.events.send(ServiceEvent::Abandoned(name));
        }
    }
}

/// Readiness of the embedding services independent of listener readiness.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RuntimeServicesStatus {
    /// Every contributed service is ready, including when none registered.
    #[default]
    Ready,
    /// One or more services are initializing.
    Initializing,
    /// A service failed before startup completed.
    StartupFailed(Arc<str>),
    /// A service exited after startup.
    Unavailable,
}

/// Shared view of service readiness for backend adapters.
#[derive(Clone, Debug, Default)]
pub(super) struct RuntimeServicesGate(Arc<watch::Sender<RuntimeServicesStatus>>);

impl RuntimeServicesGate {
    /// Read readiness without subscribing.
    pub(super) fn status(&self) -> RuntimeServicesStatus {
        self.0.borrow().clone()
    }

    /// Wait until initialization succeeds or fails.
    #[cfg(any(feature = "pingora", feature = "hyper"))]
    pub(super) async fn wait_for_initialization(&self) -> bool {
        let mut status = self.0.subscribe();
        status
            .wait_for(|state| *state != RuntimeServicesStatus::Initializing)
            .await
            .is_ok_and(|state| {
                matches!(
                    *state,
                    RuntimeServicesStatus::Ready | RuntimeServicesStatus::Unavailable
                )
            })
    }

    /// Wait until a service aborts startup.
    #[cfg(any(feature = "pingora", feature = "hyper"))]
    pub(super) async fn startup_failed(&self) {
        let mut status = self.0.subscribe();
        let _notification = status
            .wait_for(|state| matches!(state, RuntimeServicesStatus::StartupFailed(_)))
            .await;
    }
}

/// Named service contribution registered before startup.
pub type RuntimeServiceRegistration = (Arc<str>, Arc<dyn RuntimeService>);

/// Events emitted when a service consumes or abandons its readiness handle.
#[cfg_attr(
    not(any(feature = "pingora", feature = "hyper")),
    expect(dead_code, reason = "without a serving backend no worker can report readiness")
)]
enum ServiceEvent {
    /// A service initialized.
    Ready,
    /// A service abandoned initialization.
    Abandoned(Arc<str>),
}

/// Wait for backend shutdown without exposing a borrowed watch value.
#[cfg(any(feature = "pingora", feature = "hyper"))]
pub(super) async fn wait_for_backend_shutdown(shutdown: &mut watch::Receiver<bool>) {
    let _notification = shutdown.wait_for(|requested| *requested).await;
}

/// Prepare the shared gate before backend registration.
#[cfg(any(feature = "pingora", feature = "hyper"))]
pub(super) fn prepare(lifecycle: &LifecycleHandle) {
    lifecycle
        .runtime_services_gate()
        .0
        .send_replace(RuntimeServicesStatus::Initializing);
}

/// Run all contributed services concurrently and supervise readiness.
#[expect(
    clippy::too_many_lines,
    reason = "readiness, worker completion, and drain are supervised together"
)]
#[cfg(any(feature = "pingora", feature = "hyper"))]
pub(super) async fn supervise(services: Vec<RuntimeServiceRegistration>, lifecycle: LifecycleHandle) {
    let (send, mut events) = mpsc::unbounded_channel();
    let mut remaining = services.len();
    let mut shutdown = RuntimeShutdown(lifecycle.subscribe());
    let mut workers = JoinSet::new();
    let mut names = std::collections::HashMap::with_capacity(remaining);
    for (name, service) in services {
        let context = RuntimeServiceContext {
            shutdown: RuntimeShutdown(lifecycle.subscribe()),
            ready: RuntimeReady {
                events: send.clone(),
                name: Some(Arc::clone(&name)),
            },
        };
        let worker = workers.spawn(async move { service.run(context).await });
        names.insert(worker.id(), name);
    }
    let gate = lifecycle.runtime_services_gate();
    let mut draining = false;
    while !workers.is_empty() {
        tokio::select! {
            biased;
            () = shutdown.requested(), if !draining => draining = true,
            Some(result) = workers.join_next_with_id() => {
                let id = match result {
                    Ok((id, ())) => id,
                    Err(error) => {
                        tracing::error!(%error, service = ?names.get(&error.id()), "runtime service failed");
                        error.id()
                    },
                };
                if let Some(name) = names.remove(&id)
                    && !draining
                {
                    service_failed(gate, &name);
                }
            }
            Some(event) = events.recv(), if !draining => match event {
                ServiceEvent::Ready => {
                    remaining = remaining.saturating_sub(1);
                    if remaining == 0 && gate.status() == RuntimeServicesStatus::Initializing {
                        gate.0.send_replace(RuntimeServicesStatus::Ready);
                    }
                },
                ServiceEvent::Abandoned(name) => service_failed(gate, &name),
            },
        }
    }
}

/// Record service loss, preserving the identity of the first startup failure.
#[cfg(any(feature = "pingora", feature = "hyper"))]
fn service_failed(gate: &RuntimeServicesGate, name: &Arc<str>) {
    gate.0.send_if_modified(|status| {
        match status {
            RuntimeServicesStatus::Initializing => *status = RuntimeServicesStatus::StartupFailed(Arc::clone(name)),
            RuntimeServicesStatus::Ready => *status = RuntimeServicesStatus::Unavailable,
            RuntimeServicesStatus::StartupFailed(_) | RuntimeServicesStatus::Unavailable => return false,
        }
        tracing::error!(service = %name, "required runtime service stopped or abandoned readiness");
        true
    });
}

#[cfg(test)]
#[cfg(any(feature = "pingora", feature = "hyper"))]
#[expect(clippy::expect_used, reason = "test coordination failures should fail the test")]
mod tests {
    use std::time::Duration;

    use tokio::sync::Notify;

    use super::*;

    /// Worker controlled by the test, whose resource exists until its final handle drops.
    #[derive(Default)]
    struct ControlledService {
        /// Releases initialization.
        initialize: Notify,
        /// Confirms the readiness handle was consumed.
        signaled: Notify,
        /// Forces a worker exit independently of drain.
        exit: Notify,
    }

    impl RuntimeService for ControlledService {
        fn run(self: Arc<Self>, context: RuntimeServiceContext) -> RuntimeServiceFuture {
            Box::pin(async move {
                let (mut shutdown, ready) = context.into_parts();
                tokio::select! {
                    () = self.initialize.notified() => {},
                    () = self.exit.notified() => return,
                    () = shutdown.requested() => return,
                }
                ready.notify_ready();
                self.signaled.notify_one();
                tokio::select! {
                    () = self.exit.notified() => {},
                    () = shutdown.requested() => {},
                }
            })
        }
    }

    /// Initialization failure keeps the listener gate closed and names the failed service.
    #[tokio::test]
    async fn startup_failure_keeps_the_gate_closed() {
        let lifecycle = LifecycleHandle::new();
        prepare(&lifecycle);
        let worker = Arc::new(ControlledService::default());
        worker.exit.notify_one();
        let workers: Vec<RuntimeServiceRegistration> = vec![(Arc::from("store"), worker)];
        let gate = lifecycle.runtime_services_gate();
        let supervisor = tokio::spawn(supervise(workers, lifecycle.clone()));

        let ready = tokio::time::timeout(Duration::from_secs(2), gate.wait_for_initialization())
            .await
            .expect("startup failure must unblock the gate");
        assert!(!ready, "listeners must stay closed");
        assert_eq!(gate.status(), RuntimeServicesStatus::StartupFailed(Arc::from("store")));
        supervisor.await.expect("failed worker was reaped");
    }

    /// All registrations must signal before gate release. A later exit revokes readiness.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one scenario checks readiness, service loss, and drain"
    )]
    async fn waits_for_each_service_and_revokes_readiness_on_exit() {
        let lifecycle = LifecycleHandle::new();
        let first = Arc::new(ControlledService::default());
        let second = Arc::new(ControlledService::default());
        prepare(&lifecycle);
        let first_worker = Arc::clone(&first);
        let second_worker = Arc::clone(&second);
        let workers: Vec<RuntimeServiceRegistration> =
            vec![(Arc::from("first"), first_worker), (Arc::from("second"), second_worker)];
        let supervisor = tokio::spawn(supervise(workers, lifecycle.clone()));
        let gate = lifecycle.runtime_services_gate();
        let mut status = gate.0.subscribe();
        let bound = Duration::from_secs(2);
        first.initialize.notify_one();
        tokio::time::timeout(bound, first.signaled.notified())
            .await
            .expect("first signal");
        assert_eq!(
            gate.status(),
            RuntimeServicesStatus::Initializing,
            "second service is pending"
        );

        second.initialize.notify_one();
        assert!(
            tokio::time::timeout(bound, gate.wait_for_initialization())
                .await
                .expect("ready"),
            "both services initialized"
        );

        first.exit.notify_one();
        let revoked = tokio::time::timeout(
            bound,
            status.wait_for(|state| *state == RuntimeServicesStatus::Unavailable),
        )
        .await
        .expect("readiness revoked")
        .expect("gate retained");
        drop(revoked);
        lifecycle.begin_drain();
        supervisor.await.expect("remaining service finished draining");
    }
}
