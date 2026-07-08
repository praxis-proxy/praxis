// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Runner orchestration for benchmark execution.
//!
//! The `Runner` coordinates the full benchmark lifecycle:
//! start proxy, start backend, warmup, measurement, result
//! collection, repetition, and median computation.

use std::{process::Stdio, time::Duration};

use tempfile::TempDir;
use tracing::info;

use crate::{
    error::BenchmarkError,
    net::{detect_commit, stop_container, wait_for_http, wait_for_tcp},
    proxy::ProxyConfig,
    result::ScenarioResults,
    scenario::{Scenario, Workload},
    stats::DockerStatsCollector,
    tools::{
        fortio::{self, FortioConfig, FortioProtocol},
        vegeta::{self, VegetaConfig},
    },
};

// -----------------------------------------------------------------------------
// Runner Constants
// -----------------------------------------------------------------------------

/// Default port for the Fortio echo backend.
const DEFAULT_BACKEND_PORT: u16 = 18080;

/// Maximum time to wait for health check readiness.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(120);

// -----------------------------------------------------------------------------
// Runner
// -----------------------------------------------------------------------------

/// Orchestrates benchmark execution for a scenario against
/// one or more proxy configurations.
#[derive(Debug)]
pub struct Runner {
    /// The scenario to run.
    pub scenario: Scenario,

    /// Port for the Fortio echo backend.
    pub backend_port: u16,

    /// Git commit SHA for result tagging.
    pub commit: String,

    /// Include raw tool reports in results.
    pub include_raw_report: bool,
}

impl Runner {
    /// Create a runner for the given scenario.
    #[must_use]
    pub fn new(scenario: Scenario) -> Self {
        Self {
            scenario,
            backend_port: DEFAULT_BACKEND_PORT,
            commit: detect_commit(),
            include_raw_report: false,
        }
    }

    /// Override the backend port.
    #[must_use]
    pub fn with_backend_port(mut self, port: u16) -> Self {
        self.backend_port = port;
        self
    }

    /// Override the commit SHA used for result tagging.
    #[must_use]
    pub fn with_commit(mut self, commit: String) -> Self {
        self.commit = commit;
        self
    }

    /// Include raw tool reports in results.
    #[must_use]
    pub fn with_raw_report(mut self, include: bool) -> Self {
        self.include_raw_report = include;
        self
    }

    /// Run the scenario against a proxy, collecting [`ScenarioResults`].
    ///
    /// # Errors
    ///
    /// Returns [`BenchmarkError`] if the backend, proxy, or load
    /// generator fails to start, or if result parsing fails.
    #[expect(
        clippy::large_stack_frames,
        reason = "benchmark orchestration allocates tooling structs"
    )]
    pub async fn run(&self, proxy: &dyn ProxyConfig) -> Result<ScenarioResults, BenchmarkError> {
        info!(scenario = %self.scenario.name, proxy = proxy.name(), "starting benchmark run");

        let mut backend = self.start_backend().await?;
        let mut proxy_proc = self.start_proxy(proxy).await?;
        self.wait_for_proxy(proxy).await?;

        if !self.scenario.warmup.is_zero() {
            info!(duration = ?self.scenario.warmup, "running warmup");
            self.run_load(proxy, self.scenario.warmup).await?;
        }

        let mut collector = proxy.container_name().map(DockerStatsCollector::new);
        if let Some(ref mut c) = collector {
            info!(container = c.container_name(), "starting resource metrics collection");
            c.start();
        }

        let mut results = self.run_measurement_rounds(proxy).await?;

        let resource = match collector {
            Some(c) => c.stop().await,
            None => None,
        };
        if resource.is_some() {
            info!(scenario = %self.scenario.name, "attaching resource metrics to results");
        }
        for run in &mut results.runs {
            run.resource.clone_from(&resource);
        }

        results.compute_median();
        info!(scenario = %self.scenario.name, "benchmark complete");

        self.cleanup(proxy, &mut proxy_proc, &mut backend).await;
        Ok(results)
    }

    /// Start the Fortio echo backend.
    async fn start_backend(&self) -> Result<tokio::process::Child, BenchmarkError> {
        info!(port = self.backend_port, "starting Fortio echo backend");
        let backend = fortio::start_echo_server(self.backend_port)?;
        let port = self.backend_port;
        wait_for_tcp(&format!("127.0.0.1:{port}"), HEALTH_TIMEOUT).await?;
        info!(port = self.backend_port, "backend started");
        Ok(backend)
    }

    /// Start the proxy process, cleaning up stale containers first.
    async fn start_proxy(&self, proxy: &dyn ProxyConfig) -> Result<tokio::process::Child, BenchmarkError> {
        if let Some(name) = proxy.container_name() {
            info!(container = name, "removing stale container from previous run");
            stop_container(name).await;
        }
        info!(proxy = proxy.name(), "starting proxy");
        let (cmd, args) = proxy.start_command();
        let proc = tokio::process::Command::new(&cmd)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(BenchmarkError::Io)?;
        info!(proxy = proxy.name(), "proxy started");
        Ok(proc)
    }

    /// Wait for the proxy to become healthy.
    async fn wait_for_proxy(&self, proxy: &dyn ProxyConfig) -> Result<(), BenchmarkError> {
        info!(proxy = proxy.name(), "waiting for proxy health");
        if let Some(url) = proxy.health_url() {
            wait_for_http(&url, HEALTH_TIMEOUT).await?;
        } else {
            wait_for_tcp(proxy.listen_address(), HEALTH_TIMEOUT).await?;
        }
        info!(proxy = proxy.name(), "proxy ready");
        Ok(())
    }

    /// Execute all measurement runs, returning aggregated results.
    async fn run_measurement_rounds(&self, proxy: &dyn ProxyConfig) -> Result<ScenarioResults, BenchmarkError> {
        info!(runs = self.scenario.runs, "starting measurement runs");
        let mut results = ScenarioResults {
            scenario: self.scenario.name.clone(),
            proxy: proxy.name().into(),
            runs: Vec::with_capacity(self.scenario.runs as usize),
            median: None,
        };
        for i in 0..self.scenario.runs {
            info!(run = i + 1, total = self.scenario.runs, "measurement run");
            let json = self.run_load(proxy, self.scenario.duration).await?;
            let result = self.parse_result(&json, proxy.name())?;
            results.runs.push(result);
        }
        Ok(results)
    }

    /// Stop proxy and backend processes.
    async fn cleanup(
        &self,
        proxy: &dyn ProxyConfig,
        proxy_proc: &mut tokio::process::Child,
        backend: &mut tokio::process::Child,
    ) {
        info!(scenario = %self.scenario.name, "cleaning up proxy and backend");
        if let Some(name) = proxy.container_name() {
            stop_container(name).await;
        }
        let _kill_proxy = proxy_proc.kill().await;
        let _kill_backend = backend.kill().await;
    }

    /// Run load generation for a single measurement window.
    async fn run_load(&self, proxy: &dyn ProxyConfig, duration: Duration) -> Result<String, BenchmarkError> {
        let url = format!("http://{}/", proxy.listen_address());
        let addr: String = proxy.listen_address().into();
        dispatch_workload(&self.scenario.workload, &url, addr, duration).await
    }

    /// Parse the raw JSON output from a load tool into a
    /// `BenchmarkResult`.
    fn parse_result(&self, json: &str, proxy_name: &str) -> Result<crate::result::BenchmarkResult, BenchmarkError> {
        let raw = self.include_raw_report;
        match &self.scenario.workload {
            Workload::TcpThroughput | Workload::TcpConnectionRate | Workload::HighConnectionCount { .. } => {
                fortio::parse(json, &self.scenario.name, proxy_name, &self.commit, raw)
            },
            _ => vegeta::parse(json, &self.scenario.name, proxy_name, &self.commit, raw),
        }
    }
}

// -----------------------------------------------------------------------------
// Workload Dispatch
// -----------------------------------------------------------------------------

/// Dispatch a workload to the appropriate load tool.
#[expect(
    clippy::large_stack_frames,
    reason = "load tool configs contain large inline buffers"
)]
async fn dispatch_workload(
    workload: &Workload,
    url: &str,
    addr: String,
    duration: Duration,
) -> Result<String, BenchmarkError> {
    match workload {
        Workload::SmallRequests { concurrency } => {
            vegeta::run(&vegeta_config(url, "GET", 0, (*concurrency).min(64), duration, None)).await
        },
        Workload::LargePayload { body_size } => run_post_load(url, 16, *body_size, duration).await,
        Workload::LargePayloadHighConcurrency { concurrency, body_size } => {
            run_post_load(url, (*concurrency).min(64), *body_size, duration).await
        },
        Workload::Sustained => vegeta::run(&vegeta_config(url, "GET", 500, 32, duration, None)).await,
        Workload::Ramp {
            start_qps,
            end_qps,
            step,
        } => run_ramp(url, *start_qps, *end_qps, *step, duration).await,
        Workload::HighConnectionCount { connections } => {
            fortio::run(&fortio_config(url.into(), FortioProtocol::Http, *connections, duration)).await
        },
        Workload::TcpThroughput => fortio::run(&fortio_config(addr, FortioProtocol::Tcp, 8, duration)).await,
        Workload::TcpConnectionRate => fortio::run(&fortio_config(addr, FortioProtocol::Tcp, 1, duration)).await,
    }
}

/// Run a POST vegeta load with a generated body.
async fn run_post_load(
    url: &str,
    workers: u32,
    body_size: usize,
    duration: Duration,
) -> Result<String, BenchmarkError> {
    vegeta::run(&vegeta_config(
        url,
        "POST",
        0,
        workers,
        duration,
        Some(vec![b'x'; body_size]),
    ))
    .await
}

// -----------------------------------------------------------------------------
// Config Builders
// -----------------------------------------------------------------------------

/// Build a [`VegetaConfig`] with common defaults.
#[expect(clippy::too_many_arguments, reason = "builder parameters")]
fn vegeta_config(
    target: &str,
    method: &str,
    rate: u32,
    workers: u32,
    duration: Duration,
    body: Option<Vec<u8>>,
) -> VegetaConfig {
    VegetaConfig {
        target: target.into(),
        rate,
        duration,
        workers,
        method: method.into(),
        body,
    }
}

/// Build a [`FortioConfig`] with common defaults.
fn fortio_config(target: String, protocol: FortioProtocol, connections: u32, duration: Duration) -> FortioConfig {
    FortioConfig {
        target,
        protocol,
        qps: 0,
        duration,
        connections,
        no_catchup: true,
        h2: false,
    }
}

// -----------------------------------------------------------------------------
// Ramp
// -----------------------------------------------------------------------------

/// Run a ramp workload: step through QPS levels and return the result from the final step.
async fn run_ramp(
    url: &str,
    start_qps: u32,
    end_qps: u32,
    step: u32,
    total_duration: Duration,
) -> Result<String, BenchmarkError> {
    let steps: Vec<u32> = (start_qps..=end_qps).step_by(step.max(1) as usize).collect();
    if steps.is_empty() {
        return Err(BenchmarkError::ToolFailed {
            tool: "ramp".into(),
            code: -1,
            stderr: "no ramp steps generated".into(),
        });
    }

    let (_tmpdir, target_path, step_duration) = prepare_ramp_targets(url, &steps, total_duration).await?;
    run_ramp_steps(&steps, &target_path, step_duration).await
}

/// Write ramp targets and compute step duration.
///
/// Returns the [`TempDir`] (must be kept alive), target file path,
/// and per-step duration.
async fn prepare_ramp_targets(
    url: &str,
    steps: &[u32],
    total_duration: Duration,
) -> Result<(TempDir, std::path::PathBuf, Duration), BenchmarkError> {
    let dir = tempfile::Builder::new()
        .prefix("praxis-ramp-")
        .tempdir()
        .map_err(BenchmarkError::Io)?;
    let target_path = dir.path().join("vegeta-targets.txt");
    tokio::fs::write(&target_path, format!("GET {url}\n"))
        .await
        .map_err(BenchmarkError::Io)?;
    let step_duration = Duration::from_secs((total_duration.as_secs() / steps.len() as u64).max(1));
    Ok((dir, target_path, step_duration))
}

/// Execute each ramp step, returning the final step's JSON.
async fn run_ramp_steps(
    steps: &[u32],
    target_path: &std::path::Path,
    step_duration: Duration,
) -> Result<String, BenchmarkError> {
    let mut last_json = String::new();
    for qps in steps {
        info!(qps, "ramp step");
        let workers = (*qps).min(64);
        let mut attack_cmd = tokio::process::Command::new("vegeta");
        attack_cmd
            .arg("attack")
            .arg("-targets")
            .arg(target_path)
            .arg("-rate")
            .arg(qps.to_string())
            .arg("-duration")
            .arg(format!("{}s", step_duration.as_secs()))
            .arg("-workers")
            .arg(workers.to_string());
        last_json = vegeta::run_vegeta_pipeline(&mut attack_cmd).await?;
    }
    Ok(last_json)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::scenario::{Scenario, Workload};

    #[test]
    fn runner_construction() {
        let scenario = Scenario {
            name: "test_scenario".into(),
            workload: Workload::SmallRequests { concurrency: 100 },
            warmup: Duration::from_secs(5),
            duration: Duration::from_secs(10),
            runs: 3,
        };

        let runner = Runner::new(scenario)
            .with_backend_port(19090)
            .with_commit("test123".into());

        assert_eq!(runner.scenario.name, "test_scenario");
        assert_eq!(runner.backend_port, 19090);
        assert_eq!(runner.commit, "test123");
    }
}
