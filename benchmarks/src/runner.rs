//! Runner orchestration for benchmark execution.
//!
//! The [`Runner`] coordinates the full benchmark lifecycle:
//! start proxy, start backend, warmup, measurement, result
//! collection, repetition, and median computation.

use std::time::Duration;

use tracing::info;

use crate::{
    error::BenchmarkError,
    proxy::ProxyConfig,
    result::ScenarioResults,
    scenario::{Scenario, Workload},
    tools::{
        fortio::{self, FortioConfig, FortioProtocol},
        vegeta::{self, VegetaConfig},
    },
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default port for the Fortio echo backend.
const DEFAULT_BACKEND_PORT: u16 = 18080;

/// Maximum time to wait for health check readiness.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(120);

/// Interval between health check polls.
const HEALTH_POLL_INTERVAL: Duration = Duration::from_millis(250);

// -----------------------------------------------------------------------------
// Runner
// -----------------------------------------------------------------------------

/// Orchestrates benchmark execution for a scenario against
/// one or more proxy configurations.
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
    pub async fn run(&self, proxy: &dyn ProxyConfig) -> Result<ScenarioResults, BenchmarkError> {
        info!(
            scenario = %self.scenario.name,
            proxy = proxy.name(),
            "starting benchmark run"
        );

        info!(port = self.backend_port, "starting Fortio echo backend");
        let mut backend = fortio::start_echo_server(self.backend_port).await?;
        wait_for_tcp(&format!("127.0.0.1:{}", self.backend_port), HEALTH_TIMEOUT).await?;
        info!(port = self.backend_port, "backend started");

        if let Some(name) = proxy.container_name() {
            info!(container = name, "removing stale container from previous run");
            stop_container(name).await;
        }

        info!(proxy = proxy.name(), "starting proxy");
        let (cmd, args) = proxy.start_command();
        let mut proxy_proc = tokio::process::Command::new(&cmd)
            .args(&args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(BenchmarkError::Io)?;
        info!(proxy = proxy.name(), "proxy started");

        info!(proxy = proxy.name(), "waiting for proxy health");
        if let Some(url) = proxy.health_url() {
            wait_for_http(&url, HEALTH_TIMEOUT).await?;
        } else {
            wait_for_tcp(proxy.listen_address(), HEALTH_TIMEOUT).await?;
        }
        info!(proxy = proxy.name(), "proxy ready");

        if !self.scenario.warmup.is_zero() {
            info!(
                duration = ?self.scenario.warmup,
                "running warmup"
            );
            self.run_load(proxy, self.scenario.warmup).await?;
        }

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

        results.compute_median();
        info!(scenario = %self.scenario.name, "benchmark complete");

        info!(scenario = %self.scenario.name, "cleaning up proxy and backend");
        if let Some(name) = proxy.container_name() {
            stop_container(name).await;
        }
        let _ = proxy_proc.kill().await;
        let _ = backend.kill().await;

        Ok(results)
    }

    /// Run load generation for a single measurement window.
    async fn run_load(&self, proxy: &dyn ProxyConfig, duration: Duration) -> Result<String, BenchmarkError> {
        let url = format!("http://{}/", proxy.listen_address());

        match &self.scenario.workload {
            Workload::SmallRequests { concurrency } => {
                let config = VegetaConfig {
                    target: url,
                    rate: 0,
                    duration,
                    workers: (*concurrency).min(64),
                    method: "GET".into(),
                    body: None,
                };
                vegeta::run(&config).await
            },
            Workload::LargePayload { body_size } => {
                let body = vec![b'x'; *body_size];
                let config = VegetaConfig {
                    target: url,
                    rate: 0,
                    duration,
                    workers: 16,
                    method: "POST".into(),
                    body: Some(body),
                };
                vegeta::run(&config).await
            },
            Workload::LargePayloadHighConcurrency { concurrency, body_size } => {
                let body = vec![b'x'; *body_size];
                let config = VegetaConfig {
                    target: url,
                    rate: 0,
                    duration,
                    workers: (*concurrency).min(64),
                    method: "POST".into(),
                    body: Some(body),
                };
                vegeta::run(&config).await
            },
            Workload::HighConnectionCount { connections } => {
                let config = FortioConfig {
                    target: url,
                    protocol: FortioProtocol::Http,
                    qps: 0,
                    duration,
                    connections: *connections,
                    no_catchup: true,
                    h2: false,
                };
                fortio::run(&config).await
            },
            Workload::Sustained => {
                let config = VegetaConfig {
                    target: url,
                    rate: 500,
                    duration,
                    workers: 32,
                    method: "GET".into(),
                    body: None,
                };
                vegeta::run(&config).await
            },
            Workload::Ramp {
                start_qps,
                end_qps,
                step,
            } => run_ramp(&url, *start_qps, *end_qps, *step, duration).await,
            Workload::TcpThroughput => {
                let config = FortioConfig {
                    target: proxy.listen_address().into(),
                    protocol: FortioProtocol::Tcp,
                    qps: 0,
                    duration,
                    connections: 8,
                    no_catchup: true,
                    h2: false,
                };
                fortio::run(&config).await
            },
            Workload::TcpConnectionRate => {
                let config = FortioConfig {
                    target: proxy.listen_address().into(),
                    protocol: FortioProtocol::Tcp,
                    qps: 0,
                    duration,
                    connections: 1,
                    no_catchup: true,
                    h2: false,
                };
                fortio::run(&config).await
            },
        }
    }

    /// Parse the raw JSON output from a load tool into a
    /// [`BenchmarkResult`].
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
// Ramp
// -----------------------------------------------------------------------------

/// Run a ramp workload: step through QPS levels and return the result from the final (highest) step.
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

    let step_duration = Duration::from_secs((total_duration.as_secs() / steps.len() as u64).max(1));
    let dir = std::env::temp_dir().join("praxis-bench");
    std::fs::create_dir_all(&dir).ok();

    let target_spec = format!("GET {url}\n");
    let target_path = dir.join("vegeta-targets.txt");
    std::fs::write(&target_path, &target_spec).map_err(BenchmarkError::Io)?;

    let mut last_json = String::new();
    for qps in &steps {
        info!(qps, "ramp step");
        let pipeline = format!(
            "vegeta attack \
             -targets {targets} \
             -rate {qps} -duration {dur}s -workers {workers} \
             | vegeta report --type=json",
            targets = target_path.display(),
            dur = step_duration.as_secs(),
            workers = (*qps).min(64),
        );
        last_json = vegeta::run_vegeta_pipeline(&pipeline).await?;
    }

    Ok(last_json)
}

// -----------------------------------------------------------------------------
// Docker Cleanup
// -----------------------------------------------------------------------------

/// Stop and remove a Docker container by name.
async fn stop_container(name: &str) {
    let _ = tokio::process::Command::new("docker")
        .args(["rm", "-f", name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Poll a TCP address until a connection succeeds or timeout.
async fn wait_for_tcp(addr: &str, timeout: Duration) -> Result<(), BenchmarkError> {
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

/// Poll an HTTP URL until it returns 200 or timeout.
async fn wait_for_http(url: &str, timeout: Duration) -> Result<(), BenchmarkError> {
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

/// Detect the current git commit SHA.
pub fn detect_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_owned())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".into())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::scenario::{Scenario, Workload};

    /// Verify that [`Runner`] can be constructed with a scenario.
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
