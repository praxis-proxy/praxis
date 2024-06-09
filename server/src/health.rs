//! Background health check task spawning.

use std::sync::Arc;

use praxis_core::{config::Config, health::HealthRegistry};
use tokio_util::sync::CancellationToken;
use tracing::info;

// -----------------------------------------------------------------------------
// Health Check Tasks
// -----------------------------------------------------------------------------

/// Spawn background health check tasks on a dedicated tokio runtime.
///
/// The spawned thread listens for `ctrl_c` and cancels the
/// [`CancellationToken`] so that every health check loop exits
/// cleanly via `shutdown.cancelled()` before the thread returns.
pub(crate) fn spawn_health_check_tasks(config: &Config, registry: &HealthRegistry, shutdown: CancellationToken) {
    if registry.is_empty() {
        return;
    }

    let clusters = config.clusters.clone();
    let registry = Arc::clone(registry);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("health check runtime");
        rt.block_on(async {
            praxis_protocol::http::pingora::health_check_runner::spawn_health_checks(&clusters, &registry, &shutdown);
            tokio::signal::ctrl_c().await.ok();
            info!("ctrl_c received, cancelling health check tasks");
            shutdown.cancel();
        });
    });
}
