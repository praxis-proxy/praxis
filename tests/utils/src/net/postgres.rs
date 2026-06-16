// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `PostgreSQL` container lifecycle for integration tests.
//!
//! Spawns a `PostgreSQL` container on a random host port and
//! removes it on drop. Requires `docker` or `podman` on `$PATH`
//! (or set `CONTAINER_ENGINE` to override detection).

use std::{
    process::Command,
    thread,
    time::{Duration, Instant},
};

use super::port::free_port;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Container image to use for `PostgreSQL`.
const PG_IMAGE: &str = "docker.io/library/postgres:17-alpine";

/// Default database user.
const PG_USER: &str = "praxis";

/// Default database password.
const PG_PASSWORD: &str = "praxis";

/// Default database name.
const PG_DATABASE: &str = "praxis";

/// Maximum time to wait for the container to accept connections.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval between readiness polls.
const READY_POLL_INTERVAL: Duration = Duration::from_millis(100);

// -----------------------------------------------------------------------------
// PostgresGuard
// -----------------------------------------------------------------------------

/// RAII guard that manages a `PostgreSQL` container lifecycle.
///
/// Spawns a `postgres:17-alpine` container on a random host
/// port, waits for TCP readiness, and kills the container on
/// drop. The container runs with `--rm` so it is also removed
/// after being killed.
///
/// # Panics
///
/// Panics if no container engine is found, if the container
/// fails to start, or if `PostgreSQL` does not become ready
/// within the timeout.
pub struct PostgresGuard {
    /// Container ID (short hash from `docker run`).
    container_id: String,

    /// Host port mapped to container port 5432.
    port: u16,

    /// Container engine command (`docker` or `podman`).
    engine: String,
}

impl PostgresGuard {
    /// Connection URL for this container.
    pub fn url(&self) -> String {
        format!(
            "postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{}/{PG_DATABASE}",
            self.port
        )
    }

    /// Host port mapped to `PostgreSQL`'s 5432.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for PostgresGuard {
    fn drop(&mut self) {
        let _ = Command::new(&self.engine).args(["kill", &self.container_id]).output();
    }
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Start a `PostgreSQL` container and wait for it to accept
/// connections.
///
/// Uses `CONTAINER_ENGINE` env var if set, otherwise probes
/// for `podman` then `docker` on `$PATH`.
///
/// # Panics
///
/// Panics if no container engine is available, the container
/// fails to start, or `PostgreSQL` does not become ready within
/// 30 seconds.
pub fn start_postgres() -> PostgresGuard {
    let engine = detect_container_engine();
    let port = free_port();
    let container_id = run_container(&engine, port);
    let guard = PostgresGuard {
        container_id,
        port,
        engine,
    };

    wait_for_postgres(&guard.engine, &guard.container_id);

    guard
}

// -----------------------------------------------------------------------------
// Internal Helpers
// -----------------------------------------------------------------------------

/// Spawn a detached `PostgreSQL` container on the given port.
fn run_container(engine: &str, port: u16) -> String {
    let output = Command::new(engine)
        .args([
            "run",
            "-d",
            "--rm",
            "-e",
            &format!("POSTGRES_USER={PG_USER}"),
            "-e",
            &format!("POSTGRES_PASSWORD={PG_PASSWORD}"),
            "-e",
            &format!("POSTGRES_DB={PG_DATABASE}"),
            "-p",
            &format!("{port}:5432"),
            PG_IMAGE,
        ])
        .output()
        .expect("failed to execute container engine");

    assert!(
        output.status.success(),
        "container engine failed to start postgres: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout)
        .expect("container ID should be valid UTF-8")
        .trim()
        .to_owned()
}

/// Detect the container engine to use.
fn detect_container_engine() -> String {
    if let Ok(engine) = std::env::var("CONTAINER_ENGINE") {
        return engine;
    }

    for candidate in ["podman", "docker"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            return candidate.to_owned();
        }
    }

    panic!("no container engine found — install podman or docker, or set CONTAINER_ENGINE");
}

/// Poll until `PostgreSQL` is ready to accept queries.
///
/// Uses `pg_isready` inside the container to verify the
/// database is fully initialized, not just TCP-listening.
fn wait_for_postgres(engine: &str, container_id: &str) {
    let deadline = Instant::now() + READY_TIMEOUT;

    while Instant::now() < deadline {
        let ok = Command::new(engine)
            .args(["exec", container_id, "pg_isready", "-U", PG_USER])
            .output()
            .is_ok_and(|o| o.status.success());
        if ok {
            return;
        }
        thread::sleep(READY_POLL_INTERVAL);
    }

    panic!("`PostgreSQL` container did not become ready within {READY_TIMEOUT:?}");
}
