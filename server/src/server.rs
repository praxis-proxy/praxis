//! Server bootstrap: protocol registration and startup.

use praxis_core::{
    ServerRuntime,
    config::{Config, ProtocolKind},
    health::build_health_registry,
};
use praxis_filter::FilterRegistry;
use praxis_protocol::{Protocol, http::PingoraHttp, tcp::PingoraTcp};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{config::fatal, health::spawn_health_check_tasks, pipelines::resolve_pipelines};

// -----------------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------------

/// Build filter pipelines using the built-in registry, register protocols and run the server.
///
/// Config is owned for the server's lifetime (never returns).
#[allow(clippy::needless_pass_by_value)]
pub fn run_server(config: Config) -> ! {
    run_server_with_registry(config, FilterRegistry::with_builtins())
}

/// Build filter pipelines from the given registry, register protocols and run the server.
///
/// Use this variant when you need custom filters beyond the built-ins (e.g. via [`register_filters!`]).
///
/// Assumes tracing is already initialized. Blocks until the process is terminated; never returns.
///
/// Config is owned for the server's lifetime (never returns).
///
/// [`register_filters!`]: praxis_filter::register_filters
#[allow(clippy::needless_pass_by_value)]
pub fn run_server_with_registry(config: Config, registry: FilterRegistry) -> ! {
    info!("building filter pipelines");
    warn_insecure_key_permissions(&config);

    let health_registry = build_health_registry(&config.clusters);
    let pipelines = resolve_pipelines(&config, &registry, &health_registry).unwrap_or_else(|e| fatal(&e));

    info!("initializing server");
    let mut server = ServerRuntime::new(&config);

    let (has_http, has_tcp) = config.listeners.iter().fold((false, false), |(h, t), l| {
        (
            h || l.protocol == ProtocolKind::Http,
            t || l.protocol == ProtocolKind::Tcp,
        )
    });

    if has_http {
        Box::new(PingoraHttp)
            .register(&mut server, &config, &pipelines)
            .unwrap_or_else(|e| fatal(&e));
    }
    if has_tcp {
        Box::new(PingoraTcp)
            .register(&mut server, &config, &pipelines)
            .unwrap_or_else(|e| fatal(&e));
    }

    let shutdown = CancellationToken::new();
    spawn_health_check_tasks(&config, &health_registry, shutdown);

    info!("starting server");
    server.run()
}

// -----------------------------------------------------------------------------
// TLS Key Permission Checks
// -----------------------------------------------------------------------------

/// Warn if any TLS private key file has group or world read/write permissions.
///
/// Does not fail; advisory only.
#[cfg(unix)]
fn warn_insecure_key_permissions(config: &Config) {
    use std::os::unix::fs::PermissionsExt;

    for listener in &config.listeners {
        if let Some(ref tls) = listener.tls
            && let Ok(meta) = std::fs::metadata(&tls.key_path)
        {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    listener = %listener.name,
                    path = %tls.key_path,
                    mode = format!("{:04o}", mode & 0o7777),
                    "TLS private key file has overly permissive \
                     permissions; recommend chmod 0600"
                );
            }
        }
    }
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
fn warn_insecure_key_permissions(_config: &Config) {}
