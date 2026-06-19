// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Network utilities for benchmark orchestration.

use std::time::Duration;

use crate::error::BenchmarkError;

// -----------------------------------------------------------------------------
// Network Constants
// -----------------------------------------------------------------------------

/// Interval between health check polls.
const HEALTH_POLL_INTERVAL: Duration = Duration::from_millis(250);

// -----------------------------------------------------------------------------
// TCP Readiness
// -----------------------------------------------------------------------------

/// Poll a TCP address until a connection succeeds or timeout.
pub(crate) async fn wait_for_tcp(addr: &str, timeout: Duration) -> Result<(), BenchmarkError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(BenchmarkError::ToolFailed {
                tool: "health_check".into(),
                code: -1,
                stderr: format!("timeout waiting for TCP on {addr}"),
            });
        }

        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }

        tokio::time::sleep(HEALTH_POLL_INTERVAL).await;
    }
}

// -----------------------------------------------------------------------------
// HTTP Readiness
// -----------------------------------------------------------------------------

/// Poll an HTTP URL until it returns 200 or timeout.
pub(crate) async fn wait_for_http(url: &str, timeout: Duration) -> Result<(), BenchmarkError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(BenchmarkError::ToolFailed {
                tool: "health_check".into(),
                code: -1,
                stderr: format!("timeout waiting for HTTP on {url}"),
            });
        }

        if let Ok(resp) = simple_http_get(url).await
            && (resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200"))
        {
            return Ok(());
        }

        tokio::time::sleep(HEALTH_POLL_INTERVAL).await;
    }
}

/// Minimal HTTP GET using raw TCP (no external dependency).
async fn simple_http_get(url: &str) -> Result<String, BenchmarkError> {
    let stripped = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = stripped.split_once('/').unwrap_or((stripped, ""));

    let mut stream = tokio::net::TcpStream::connect(host_port).await?;

    let request = format!(
        "GET /{path} HTTP/1.1\r\n\
         Host: {host_port}\r\n\
         Connection: close\r\n\r\n"
    );

    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()).await?;

    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf).await?;

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// -----------------------------------------------------------------------------
// Docker Cleanup
// -----------------------------------------------------------------------------

/// Stop and remove a Docker container by name.
pub(crate) async fn stop_container(name: &str) {
    let _status = tokio::process::Command::new("docker")
        .args(["rm", "-f", name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
}

// -----------------------------------------------------------------------------
// Git Commit Detection
// -----------------------------------------------------------------------------

/// Detect the current git commit SHA.
pub fn detect_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            o.status
                .success()
                .then(|| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        })
        .unwrap_or_else(|| "unknown".into())
}
