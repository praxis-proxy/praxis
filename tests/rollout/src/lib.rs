// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! KIND rollout acceptance harness for the Kubernetes reference base.

#![forbid(unsafe_code)]
#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the acceptance CLI reports progress and cleanup failures"
)]
#![expect(
    clippy::disallowed_methods,
    reason = "the rollout harness is synchronous and intentionally sleeps between polls"
)]
#![expect(
    clippy::too_many_lines,
    reason = "acceptance orchestration keeps scenario steps together"
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsStr,
    io::Write as _,
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, ValueEnum};
use praxis_test_utils::{ContinuousLoadDriver, https_client_config, tls_serial, write_test_certificate};
use tempfile::{NamedTempFile, TempDir};

mod admin;

/// Per-request timeout for every kubectl invocation.
const KUBECTL_REQUEST_TIMEOUT: &str = "30s";

/// Per-attempt network timeout for the in-cluster wget listener probe.
const HTTP_PROBE_TIMEOUT_SECS: u64 = 5;

/// Exit codes that mean the proxy died by panic or signal.
///
/// `101` is a Rust panic, and `128 + N` is death by signal `N`: `132` is
/// SIGILL, `134` SIGABRT, `135` SIGBUS, `136` SIGFPE, `137` SIGKILL, and
/// `139` SIGSEGV.
const CRASH_EXIT_CODES: [i64; 7] = [101, 132, 134, 135, 136, 137, 139];

/// Longest tag a container engine accepts, including the generated suffix.
const MAX_IMAGE_TAG_LEN: usize = 128;

/// Retains pod lifecycle events, including containers removed during rollouts.
struct PodWatch {
    /// Watch process, stopped even when a scenario returns an error.
    child: Child,
    /// JSON event stream retained until the acceptance assertions finish.
    events: NamedTempFile,
    /// Terminations already present when the watch started.
    ///
    /// These are pre-watch startup retries: a nonzero exit here is tolerated
    /// unless it is a panic or signal. Anything else is a rollout failure.
    startup_retries: BTreeSet<(String, String)>,
}

/// Runs an OpenSSL client inside the cluster so pod IPs can be probed directly.
struct TlsProbePod {
    /// Cluster owning the temporary probe pod.
    cluster: String,
}

impl TlsProbePod {
    /// Starts the temporary pod and waits until OpenSSL is installed.
    fn start(cluster: &str) -> Result<Self, String> {
        kubectl(cluster, ["delete", "pod", "tls-probe", "--ignore-not-found"])?;
        let probe = Self {
            cluster: cluster.to_owned(),
        };
        kubectl(
            cluster,
            [
                "run",
                "tls-probe",
                "--image=docker.io/library/alpine:3.20",
                "--restart=Never",
                "--command",
                "--",
                "sh",
                "-c",
                "apk add --no-cache openssl && sleep 600",
            ],
        )?;
        kubectl(
            cluster,
            ["wait", "--for=condition=Ready", "pod/tls-probe", "--timeout=180s"],
        )?;
        wait_for_openssl(cluster)?;
        Ok(probe)
    }
}

impl Drop for TlsProbePod {
    fn drop(&mut self) {
        if let Err(error) = kubectl(&self.cluster, ["delete", "pod", "tls-probe", "--ignore-not-found"]) {
            eprintln!("failed to delete TLS probe pod: {error}");
        }
    }
}

/// Formats a pod IP for a URL authority or socket address, bracketing IPv6
/// literals so a port cannot be parsed as part of the address.
fn pod_ip_literal(pod_ip: &str, pod: &str) -> Result<String, String> {
    let address = pod_ip
        .trim()
        .parse::<IpAddr>()
        .map_err(|error| format!("parse pod IP for {pod}: {error}"))?;
    Ok(match address {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
    })
}

/// Runs a wget client inside the cluster so listener probes are pod-to-pod.
///
/// A direct connection distinguishes a listener's HTTP response from an API
/// server or kubectl failure, which the pod proxy endpoint cannot.
struct HttpProbePod {
    /// Cluster owning the temporary probe pod.
    cluster: String,
}

impl HttpProbePod {
    /// Starts the temporary pod and waits until it can run wget.
    fn start(cluster: &str) -> Result<Self, String> {
        kubectl(cluster, ["delete", "pod", "http-probe", "--ignore-not-found"])?;
        let probe = Self {
            cluster: cluster.to_owned(),
        };
        kubectl(
            cluster,
            [
                "run",
                "http-probe",
                "--image=docker.io/library/alpine:3.20",
                "--restart=Never",
                "--command",
                "--",
                "sleep",
                "600",
            ],
        )?;
        kubectl(
            cluster,
            ["wait", "--for=condition=Ready", "pod/http-probe", "--timeout=120s"],
        )?;
        Ok(probe)
    }

    /// Probes one pod's listener with wget and classifies the outcome.
    fn probe(&self, pod: &str, port: u16, timeout: Duration) -> Result<ProbeOutcome, String> {
        let pod_ip = kubectl(&self.cluster, ["get", "pod", pod, "-o=jsonpath={.status.podIP}"])?;
        let pod_ip = pod_ip.trim();
        if pod_ip.is_empty() {
            return Ok(ProbeOutcome::Inconclusive);
        }
        let host = pod_ip_literal(pod_ip, pod)?;
        let exec_seconds = timeout.as_secs().max(1);
        let wget_seconds = exec_seconds.min(HTTP_PROBE_TIMEOUT_SECS);
        let request_timeout = format!("--request-timeout={exec_seconds}s");
        let command =
            format!("timeout {exec_seconds} wget -T {wget_seconds} -S -O /dev/null http://{host}:{port}/ 2>&1");
        let args = vec![
            request_timeout,
            "exec".to_owned(),
            "http-probe".to_owned(),
            "--".to_owned(),
            "sh".to_owned(),
            "-c".to_owned(),
            command,
        ];
        match kubectl(&self.cluster, args) {
            Ok(_) => Ok(ProbeOutcome::Reachable),
            Err(error) => Ok(classify_probe_error(&error)),
        }
    }
}

impl Drop for HttpProbePod {
    fn drop(&mut self) {
        if let Err(error) = kubectl(&self.cluster, ["delete", "pod", "http-probe", "--ignore-not-found"]) {
            eprintln!("failed to delete HTTP probe pod: {error}");
        }
    }
}

impl PodWatch {
    /// Starts watching before any disruption and waits for the initial list.
    fn start(cluster: &str) -> Result<Self, String> {
        let events = NamedTempFile::new().map_err(|error| error.to_string())?;
        let output = events.reopen().map_err(|error| error.to_string())?;
        let child = Command::new("kubectl")
            .args([
                "--context",
                &format!("kind-{cluster}"),
                "-n",
                "praxis",
                "get",
                "pods",
                "-l",
                "app.kubernetes.io/instance=rollout",
                "--watch",
                "--output-watch-events",
                "-o=json",
            ])
            .stdout(output)
            .spawn()
            .map_err(|error| error.to_string())?;
        // Keep the child under the cleanup guard before the fallible snapshot,
        // so a snapshot error still kills the spawned watch.
        let mut watch = Self {
            child,
            events,
            startup_retries: BTreeSet::new(),
        };
        watch.startup_retries = startup_retries(cluster)?;
        for _ in 0..100 {
            if watch.child.try_wait().map_err(|error| error.to_string())?.is_some() {
                return Err("pod watch exited before scenarios began".to_owned());
            }
            let content = std::fs::read_to_string(watch.events.path()).map_err(|error| error.to_string())?;
            if content
                .lines()
                .next()
                .is_some_and(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
            {
                return Ok(watch);
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err("pod watch did not return its initial list".to_owned())
    }

    /// Stops the watch and validates every retained lifecycle event.
    fn finish(mut self) -> Result<(), String> {
        if self.child.try_wait().map_err(|error| error.to_string())?.is_some() {
            return Err("pod watch exited during the scenarios".to_owned());
        }
        self.wait_until_quiet()?;
        self.child.kill().map_err(|error| error.to_string())?;
        self.child.wait().map_err(|error| error.to_string())?;
        let events = std::fs::read_to_string(self.events.path()).map_err(|error| error.to_string())?;
        check_pod_events(&events, &self.startup_retries)
    }

    /// Waits until the watch has flushed the completed disruptions.
    ///
    /// `kubectl --watch` cannot request a bookmark, so the stream is only known
    /// to be caught up once it stops appending events. The wait is bounded so a
    /// stuck watch still fails instead of hiding a missing exit.
    fn wait_until_quiet(&mut self) -> Result<(), String> {
        let started = Instant::now();
        let mut last_len = 0;
        let mut quiet_since: Option<Instant> = None;
        loop {
            if self.child.try_wait().map_err(|error| error.to_string())?.is_some() {
                return Err("pod watch exited during the scenarios".to_owned());
            }
            let len = self
                .events
                .as_file()
                .metadata()
                .map_err(|error| error.to_string())?
                .len();
            if len == last_len {
                if quiet_since.get_or_insert_with(Instant::now).elapsed() >= Duration::from_secs(2) {
                    return Ok(());
                }
            } else {
                last_len = len;
                quiet_since = None;
            }
            if started.elapsed() >= Duration::from_secs(30) {
                return Err("pod watch did not become quiet before the scenarios finished".to_owned());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for PodWatch {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

/// Records the terminations present just before the watch starts.
///
/// Matching on `(pod UID, container ID)` identifies a termination instance.
/// `finishedAt` has second granularity, so two exits in the same second would
/// otherwise collide; the container ID is unique per container instance.
fn startup_retries(cluster: &str) -> Result<BTreeSet<(String, String)>, String> {
    let pods = kubectl(
        cluster,
        ["get", "pods", "-l", "app.kubernetes.io/instance=rollout", "-o=json"],
    )?;
    let pods: serde_json::Value =
        serde_json::from_str(&pods).map_err(|error| format!("parse pod snapshot: {error}"))?;
    Ok(terminations(&pods))
}

/// Collects `(pod UID, container ID)` for every terminated container instance.
fn terminations(pods: &serde_json::Value) -> BTreeSet<(String, String)> {
    let mut retries = BTreeSet::new();
    let items = pods.get("items").and_then(serde_json::Value::as_array);
    for pod in items.into_iter().flatten() {
        let Some(uid) = pod.pointer("/metadata/uid").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let containers = pod
            .pointer("/status/containerStatuses")
            .and_then(serde_json::Value::as_array);
        for container in containers.into_iter().flatten() {
            for state_path in ["/state/terminated", "/lastState/terminated"] {
                if let Some(container_id) = container
                    .pointer(state_path)
                    .and_then(|state| state.get("containerID"))
                    .and_then(serde_json::Value::as_str)
                {
                    retries.insert((uid.to_owned(), container_id.to_owned()));
                }
            }
        }
    }
    retries
}

/// Validates exits from current and previous states and retains deleted pods.
fn check_pod_events(events: &str, startup_retries: &BTreeSet<(String, String)>) -> Result<(), String> {
    let mut latest = BTreeMap::new();
    let mut deletion_deadlines = BTreeMap::new();
    for event in serde_json::Deserializer::from_str(events).into_iter::<serde_json::Value>() {
        let event = match event {
            Ok(event) => event,
            Err(error) => return Err(format!("parse pod watch: {error}")),
        };
        if event.get("type").and_then(|value| value.as_str()) == Some("BOOKMARK") {
            continue;
        }
        if event.get("type").and_then(|value| value.as_str()) == Some("ERROR") {
            return Err(format!("pod watch error: {event}"));
        }
        let pod = event
            .get("object")
            .ok_or_else(|| "pod watch omitted object".to_owned())?;
        let uid = pod
            .pointer("/metadata/uid")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "pod watch omitted UID".to_owned())?;
        record_deletion_deadline(&mut deletion_deadlines, uid, pod)?;
        check_pod_exit(pod, false, deletion_deadlines.get(uid), Some(startup_retries))?;
        latest.insert(uid.to_owned(), event);
    }
    if latest.is_empty() {
        return Err("pod watch captured no pods".to_owned());
    }
    for event in latest.values() {
        let pod = event
            .get("object")
            .ok_or_else(|| "pod watch omitted object".to_owned())?;
        let terminating = event.get("type").and_then(|value| value.as_str()) == Some("DELETED")
            || pod
                .pointer("/metadata/deletionTimestamp")
                .is_some_and(|value| !value.is_null());
        let deadline = pod
            .pointer("/metadata/uid")
            .and_then(|value| value.as_str())
            .and_then(|uid| deletion_deadlines.get(uid));
        check_pod_exit(pod, terminating, deadline, Some(startup_retries))?;
    }
    Ok(())
}

/// Records the strictest graceful deletion deadline observed for a pod.
///
/// Kubernetes sets `deletionGracePeriodSeconds` to zero on the final deletion
/// event, so a zero-grace event must not replace the original graceful
/// deadline. A later positive-grace event may shorten that deadline.
fn record_deletion_deadline(
    deadlines: &mut BTreeMap<String, chrono::DateTime<chrono::FixedOffset>>,
    uid: &str,
    pod: &serde_json::Value,
) -> Result<(), String> {
    let Some(timestamp) = pod
        .pointer("/metadata/deletionTimestamp")
        .and_then(|value| value.as_str())
    else {
        return Ok(());
    };
    let deadline = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|error| format!("parse pod deletion deadline: {error}"))?;
    let grace_period = pod
        .pointer("/metadata/deletionGracePeriodSeconds")
        .and_then(serde_json::Value::as_i64);
    let entry = deadlines.entry(uid.to_owned());
    if grace_period.is_some_and(|period| period > 0) {
        entry
            .and_modify(|current| {
                if deadline < *current {
                    *current = deadline;
                }
            })
            .or_insert(deadline);
    } else {
        entry.or_insert(deadline);
    }
    Ok(())
}

/// Rejects any exit after the watch started and any crash signal, and requires
/// terminating pods to have exited by their deadline.
///
/// The proxy can restart with a nonzero code while the operator reconciles the
/// initial config; those terminations are in `startup_retries` and are not a
/// rollout failure. Any termination absent from that set, and any panic or
/// signal regardless of when it happened, is fatal.
fn check_pod_exit(
    pod: &serde_json::Value,
    terminating: bool,
    deadline: Option<&chrono::DateTime<chrono::FixedOffset>>,
    startup_retries: Option<&BTreeSet<(String, String)>>,
) -> Result<(), String> {
    let containers = pod
        .pointer("/status/containerStatuses")
        .and_then(|value| value.as_array());
    if terminating && containers.is_none_or(Vec::is_empty) {
        return Err(format!("terminating pod has no exit status: {pod}"));
    }
    for container in containers.into_iter().flatten() {
        for path in ["/state/terminated", "/lastState/terminated"] {
            let terminated = container.pointer(path);
            if let Some(code) = terminated
                .and_then(|state| state.get("exitCode"))
                .and_then(serde_json::Value::as_i64)
                && code != 0
            {
                let uid = pod
                    .pointer("/metadata/uid")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let container_id = terminated
                    .and_then(|state| state.get("containerID"))
                    .and_then(serde_json::Value::as_str);
                let pre_watch = container_id.is_some_and(|container_id| {
                    startup_retries.is_some_and(|retries| retries.contains(&(uid.to_owned(), container_id.to_owned())))
                });
                if CRASH_EXIT_CODES.contains(&code) || !pre_watch {
                    return Err(format!("container exited abnormally ({code}): {pod}"));
                }
            }
        }
        if terminating {
            let finished = container
                .pointer("/state/terminated/finishedAt")
                .and_then(|value| value.as_str())
                .ok_or_else(|| format!("terminating container has no observed exit: {pod}"))?;
            let finished = chrono::DateTime::parse_from_rfc3339(finished).map_err(|error| error.to_string())?;
            let deadline = deadline.ok_or_else(|| format!("terminating pod has no deletion deadline: {pod}"))?;
            if finished > *deadline {
                return Err(format!("container exceeded its termination deadline: {pod}"));
            }
        }
    }
    Ok(())
}

/// Command-line options for `cargo xtask rollout`.
#[derive(Debug, Parser)]
#[expect(clippy::struct_excessive_bools, reason = "each command-line flag is independent")]
pub struct Args {
    /// KIND cluster name.
    #[arg(long, default_value = "praxis-rollout")]
    cluster_name: String,

    /// Data-plane image loaded into KIND.
    #[arg(long, default_value = "localhost/praxis:rollout")]
    image: String,

    /// Operator image loaded into KIND.
    #[arg(long, default_value = "localhost/praxis-operator:rollout")]
    operator_image: String,

    /// Directory containing the operator source and Containerfile.
    #[arg(long, default_value = "../operator")]
    operator_dir: PathBuf,

    /// Directory containing the operator-owned rollout-test kustomization.
    #[arg(long, default_value = "../operator/deploy/rollout-test")]
    manifest_dir: PathBuf,

    /// Scenarios to run; repeat the flag for a subset.
    #[arg(long, value_enum)]
    scenarios: Vec<Scenario>,

    /// Keep the KIND cluster after the run.
    #[arg(long)]
    keep_cluster: bool,

    /// Reuse an existing KIND cluster, which this run mutates and leaves behind.
    #[arg(long)]
    reuse_cluster: bool,

    /// Reuse the local image, skipping the build but loading it into KIND.
    #[arg(long)]
    skip_build: bool,
}

/// Rollout scenarios exercised under continuous HTTP/1.1 and HTTP/2 load.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Scenario {
    /// Delete one data-plane pod.
    PodDelete,
    /// Roll the data plane to another image tag.
    RollingUpdate,
    /// Apply a `ConfigMap` change that Praxis can hot-reload.
    ConfigHotReload,
    /// Apply a `ConfigMap` change that requires a rollout.
    ConfigRollout,
    /// Replace the TLS Secret and verify the new certificate is served.
    TlsRotation,
    /// Drain a worker while the disruption budget protects service capacity.
    NodeDrain,
    /// Take the test upstream down while traffic uses the healthy upstream.
    UpstreamDown,
}

/// Runs the rollout acceptance harness.
///
/// # Errors
///
/// Returns a descriptive error when a prerequisite, Kubernetes operation, or
/// acceptance assertion fails.
pub fn run(args: &Args) -> Result<(), String> {
    let engine = env::var("CONTAINER_ENGINE").unwrap_or_else(|_| "docker".to_owned());
    check_prerequisites(&engine)?;
    let image = qualified_image(&args.image)?;
    let operator_image = qualified_image(&args.operator_image)?;
    let created_ports = create_cluster(&args.cluster_name, &engine)?;
    let created_cluster = created_ports.is_some();
    require_owned_cluster(created_cluster, args.reuse_cluster, &args.cluster_name)?;
    let mut cluster_cleanup = ClusterCleanup {
        cluster: args.cluster_name.clone(),
        engine: engine.clone(),
        active: created_cluster && !args.keep_cluster,
    };
    install_gateway_api(&args.cluster_name)?;
    let (image, next_image) = build_and_load_images(&ImageBuild {
        engine: &engine,
        cluster: &args.cluster_name,
        image: &image,
        operator_image: &operator_image,
        operator_dir: &args.operator_dir,
        skip_build: args.skip_build,
    })?;

    let temp_dir = TempDir::new().map_err(|error| format!("create temporary directory: {error}"))?;
    write_test_certificate(&temp_dir, "tls")?;
    write_test_certificate(&temp_dir, "rotated")?;
    let client_config = https_client_config(&[temp_dir.path().join("tls.crt"), temp_dir.path().join("rotated.crt")])?;
    let manifest_dir = args.manifest_dir.to_string_lossy();
    let manifest = kubectl(
        &args.cluster_name,
        [
            "kustomize",
            "--load-restrictor=LoadRestrictionsNone",
            manifest_dir.as_ref(),
        ],
    )?;
    let manifest = manifest
        .replace("__OPERATOR_IMAGE__", &operator_image)
        .replace("__PRAXIS_IMAGE__", &image);
    ensure_namespace(&args.cluster_name)?;
    apply_tls_secret(&args.cluster_name, &temp_dir, "tls")?;
    kubectl_stdin(&args.cluster_name, ["apply", "-f", "-"], &manifest)?;
    wait_for_deployment(&args.cluster_name, "praxis-rollout")?;
    kubectl(
        &args.cluster_name,
        ["-n", "praxis", "rollout", "restart", "deployment/praxis-rollout"],
    )?;
    for deployment in ["praxis-operator", "backend", "healthy-backend", "praxis-rollout"] {
        wait_for_rollout(&args.cluster_name, &format!("deployment/{deployment}"))?;
    }

    wait_for_deployment_image(&args.cluster_name, &image)?;
    wait_for_rollout(&args.cluster_name, "deployment/praxis-rollout")?;
    wait_for_ready_proxy_replicas(&args.cluster_name)?;
    wait_for_termination(&args.cluster_name)?;

    let (http_port, https_port) = match created_ports {
        Some(ports) => ports,
        None => cluster_host_ports(&engine, &args.cluster_name)?,
    };
    let http_endpoint = local_endpoint(http_port);
    let https_endpoint = local_endpoint(https_port);
    wait_for_body(&http_endpoint, "/", "ok", 120)?;
    admin::check(&args.cluster_name)?;
    let watch = PodWatch::start(&args.cluster_name)?;
    let load = ContinuousLoadDriver::start_with_https(&http_endpoint, &https_endpoint, client_config);
    for _ in 0..100 {
        let report = load.snapshot();
        if report.http1 > 0 && report.http2 > 0 && report.https > 0 {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let initial = load.snapshot();
    if initial.http1 == 0 || initial.http2 == 0 || initial.https == 0 {
        return Err("HTTP/1.1, HTTP/2, and HTTPS load must succeed before scenarios begin".to_owned());
    }
    for scenario in selected_scenarios(&args.scenarios) {
        let before = load.snapshot();
        println!("==> rollout scenario: {scenario:?}");
        match scenario {
            Scenario::PodDelete => delete_pod(&args.cluster_name)?,
            Scenario::RollingUpdate => rolling_update(&args.cluster_name, &next_image)?,
            Scenario::ConfigHotReload => config_hot_reload(&args.cluster_name)?,
            Scenario::ConfigRollout => config_rollout(&args.cluster_name)?,
            Scenario::TlsRotation => rotate_tls(&args.cluster_name, &temp_dir, &https_endpoint)?,
            Scenario::NodeDrain => drain_node(&args.cluster_name)?,
            Scenario::UpstreamDown => upstream_down(&args.cluster_name)?,
        }
        wait_for_termination(&args.cluster_name)?;
        admin::check(&args.cluster_name)?;
        let snapshot = load.snapshot();
        if snapshot.http1 <= before.http1 || snapshot.http2 <= before.http2 || snapshot.https <= before.https {
            return Err(format!("{scenario:?} did not serve traffic from every protocol"));
        }
        println!(
            "==> {scenario:?}: {} requests, {} failures",
            snapshot.total(),
            snapshot.failures
        );
    }

    watch.finish()?;
    let report = load.stop();
    if report.failures != 0 {
        return Err(format!(
            "rollout failed {}/{} requests; first failure: {}",
            report.failures,
            report.total(),
            report.first_failure.unwrap_or_else(|| "unknown".to_owned())
        ));
    }
    if report.http1 == 0 || report.http2 == 0 || report.https == 0 {
        return Err("rollout completed without traffic from every load protocol".to_owned());
    }
    println!(
        "==> rollout passed: {} HTTP/1.1, {} HTTP/2, and {} HTTPS requests, zero failures ({} stale HTTP/1.1 replays, {} safe HTTP/2 GOAWAY replay attempts)",
        report.http1, report.http2, report.https, report.http1_replays, report.http2_replays
    );

    if created_cluster && !args.keep_cluster {
        run_command(kind_command(&engine).args(["delete", "cluster", "--name", &args.cluster_name]))?;
        cluster_cleanup.active = false;
    }
    Ok(())
}

/// Preserves requested order while running each stateful scenario only once.
fn selected_scenarios(requested: &[Scenario]) -> Vec<Scenario> {
    let requested = if requested.is_empty() {
        Scenario::value_variants()
    } else {
        requested
    };
    let mut unique = Vec::new();
    for scenario in requested {
        if !unique.contains(scenario) {
            unique.push(*scenario);
        }
    }
    unique
}

/// Deletes the acceptance cluster when an early return leaves it behind.
///
/// Only a cluster this run created is ever deleted; a reused cluster is left
/// for its owner.
struct ClusterCleanup {
    /// KIND cluster to delete.
    cluster: String,
    /// Container engine used by KIND.
    engine: String,
    /// Whether cleanup remains necessary.
    active: bool,
}

impl Drop for ClusterCleanup {
    fn drop(&mut self) {
        if self.active {
            drop(run_command(kind_command(&self.engine).args([
                "delete",
                "cluster",
                "--name",
                &self.cluster,
            ])));
        }
    }
}

/// Keeps load running until terminating pods disappear before the next scenario.
fn wait_for_termination(cluster: &str) -> Result<(), String> {
    for _ in 0..35 {
        let pending = kubectl(
            cluster,
            [
                "get",
                "pods",
                "-l",
                "app.kubernetes.io/instance=rollout",
                "-o=jsonpath={.items[?(@.metadata.deletionTimestamp)].metadata.name}",
            ],
        )?;
        if pending.is_empty() {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err("proxy pods remained terminating after 35 seconds".to_owned())
}

/// Installs the Gateway API CRDs used by the operator.
fn install_gateway_api(cluster: &str) -> Result<(), String> {
    kubectl(
        cluster,
        [
            "apply",
            "-f",
            "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/standard-install.yaml",
        ],
    )?;
    for crd in ["gatewayclasses", "gateways", "httproutes"] {
        kubectl(
            cluster,
            [
                "wait",
                "--for=condition=Established",
                &format!("crd/{crd}.gateway.networking.k8s.io"),
                "--timeout=120s",
            ],
        )?;
    }
    Ok(())
}

/// Applies the namespace used by the rollout resources.
fn ensure_namespace(cluster: &str) -> Result<(), String> {
    kubectl_stdin(
        cluster,
        ["apply", "-n", "praxis", "-f", "-"],
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: praxis\n",
    )?;
    Ok(())
}

/// Verifies tools required by the harness.
fn check_prerequisites(engine: &str) -> Result<(), String> {
    for command in ["cargo", engine, "kind"] {
        if !command_available(Command::new(command).arg("--version")) {
            return Err(format!("required command is unavailable: {command}"));
        }
    }
    if !command_available(Command::new("openssl").arg("version")) {
        return Err("required command is unavailable: openssl".to_owned());
    }
    if !command_available(Command::new("kubectl").args(["version", "--client"])) {
        return Err("required command is unavailable: kubectl".to_owned());
    }
    Ok(())
}

/// Whether a version-check command starts successfully.
fn command_available(command: &mut Command) -> bool {
    command.output().is_ok_and(|output| output.status.success())
}

/// Creates a one-control-plane, three-worker KIND cluster when absent.
fn create_cluster(name: &str, engine: &str) -> Result<Option<(u16, u16)>, String> {
    let clusters = kind_command(engine)
        .args(["get", "clusters"])
        .output()
        .map_err(|error| format!("list KIND clusters: {error}"))?;
    if !clusters.status.success() {
        return Err(format!(
            "list KIND clusters: {}",
            String::from_utf8_lossy(&clusters.stderr).trim()
        ));
    }
    if String::from_utf8_lossy(&clusters.stdout)
        .lines()
        .any(|cluster| cluster == name)
    {
        return Ok(None);
    }

    let (http_port, https_port) = free_host_ports()?;
    let config = format!(
        "kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30080
        hostPort: {http_port}
        listenAddress: 127.0.0.1
        protocol: TCP
      - containerPort: 30443
        hostPort: {https_port}
        listenAddress: 127.0.0.1
        protocol: TCP
  - role: worker
  - role: worker
  - role: worker
"
    );
    let mut file = NamedTempFile::new().map_err(|error| error.to_string())?;
    file.write_all(config.as_bytes())
        .map_err(|error| format!("write KIND config: {error}"))?;
    let mut command = kind_command(engine);
    command.args([
        "create",
        "cluster",
        "--name",
        name,
        "--config",
        file.path().to_string_lossy().as_ref(),
        "--wait",
        "120s",
    ]);
    if let Err(error) = run_command(&mut command) {
        // A failed create can still leave a partially created cluster behind.
        // Delete only what this attempt made; an existing cluster returned
        // above, before any mutation.
        if let Err(cleanup) = run_command(kind_command(engine).args(["delete", "cluster", "--name", name])) {
            eprintln!("failed to clean up the partially created cluster {name}: {cleanup}");
        }
        return Err(error);
    }
    Ok(Some((http_port, https_port)))
}

/// Reserves two distinct unused localhost ports for KIND host mappings.
///
/// Both listeners stay bound until both ports have been read. Releasing the
/// first before selecting the second lets the kernel hand out the same port
/// twice, and Docker rejects duplicate host mappings.
fn free_host_ports() -> Result<(u16, u16), String> {
    let first =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|error| format!("reserve a KIND host port: {error}"))?;
    let second =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|error| format!("reserve a KIND host port: {error}"))?;
    let first_port = first
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| format!("read the reserved host port: {error}"))?;
    let second_port = second
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| format!("read the reserved host port: {error}"))?;
    drop((first, second));
    Ok((first_port, second_port))
}

/// Discovers the retained cluster's published HTTP and HTTPS host ports.
///
/// A cluster created with `--keep-cluster` keeps its dynamic KIND mappings,
/// which the next `--reuse-cluster` run does not know. Read them from the
/// control-plane container instead of assuming the default ports.
fn cluster_host_ports(engine: &str, cluster: &str) -> Result<(u16, u16), String> {
    let container = format!("{cluster}-control-plane");
    let output = Command::new(engine)
        .args(["inspect", "--format", "{{json .NetworkSettings.Ports}}", &container])
        .output()
        .map_err(|error| format!("inspect the retained KIND cluster: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "inspect the retained KIND cluster: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse_host_ports(&String::from_utf8_lossy(&output.stdout))
}

/// Reads the published port for one container port from an engine's
/// `NetworkSettings.Ports` JSON.
fn parse_host_ports(ports: &str) -> Result<(u16, u16), String> {
    let ports: serde_json::Value =
        serde_json::from_str(ports).map_err(|error| format!("parse engine port mappings: {error}"))?;
    Ok((
        published_host_port(&ports, "30080/tcp")?,
        published_host_port(&ports, "30443/tcp")?,
    ))
}

/// Returns the published host port for `container_port`.
fn published_host_port(ports: &serde_json::Value, container_port: &str) -> Result<u16, String> {
    ports
        .get(container_port)
        .and_then(serde_json::Value::as_array)
        .and_then(|bindings| bindings.first())
        .and_then(|binding| binding.get("HostPort"))
        .and_then(json_port)
        .ok_or_else(|| format!("retained cluster publishes no host port for {container_port}"))
}

/// Decodes a host port that an engine may serialize as a number or a string.
fn json_port(value: &serde_json::Value) -> Option<u16> {
    value
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .or_else(|| value.as_str().and_then(|port| port.parse().ok()))
}

/// Refuses to mutate a cluster this run did not create unless asked to.
fn require_owned_cluster(created: bool, reuse: bool, name: &str) -> Result<(), String> {
    if created || reuse {
        return Ok(());
    }
    Err(format!(
        "KIND cluster {name} already exists; pass --reuse-cluster to run against it or choose a new --cluster-name"
    ))
}

/// Uses the selected provider for every KIND operation, including image loads.
fn kind_command(engine: &str) -> Command {
    let mut command = Command::new("kind");
    let engine_path = Path::new(engine);
    // KIND expects a provider name, not a path; keep the full path for builds.
    let provider = engine_path
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|name| !name.is_empty())
        .unwrap_or(engine);
    command.env("KIND_EXPERIMENTAL_PROVIDER", provider);
    // KIND resolves the provider through `PATH`. When the engine was named by
    // path, make its directory discoverable without dropping existing entries.
    if let Some(directory) = engine_path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        command.env("PATH", path_with_prepended(directory));
    }
    command
}

/// Prepends `directory` to `PATH` while preserving every existing entry.
fn path_with_prepended(directory: &Path) -> std::ffi::OsString {
    let mut paths = env::var_os("PATH")
        .map(|path| env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    if !paths.iter().any(|existing| existing == directory) {
        paths.insert(0, directory.to_path_buf());
    }
    env::join_paths(paths).unwrap_or_else(|_| env::var_os("PATH").unwrap_or_default())
}

/// Removes the per-run image tags on every exit path.
///
/// The stable `--skip-build` tag is never in this list, so a failed or
/// successful run leaves it in place for the next reuse.
struct GeneratedImages {
    /// Container engine that owns the local tags.
    engine: String,
    /// Per-run tags created by this attempt.
    tags: Vec<String>,
}

impl Drop for GeneratedImages {
    fn drop(&mut self) {
        for tag in &self.tags {
            match Command::new(&self.engine).args(["rmi", "-f", tag]).output() {
                Ok(output) if !output.status.success() => eprintln!(
                    "failed to remove generated image {tag}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
                Ok(_) => {},
                Err(error) => eprintln!("failed to remove generated image {tag}: {error}"),
            }
        }
    }
}

/// Inputs for building and loading the rollout images.
struct ImageBuild<'build> {
    /// Container engine used to build and load images.
    engine: &'build str,
    /// KIND cluster that receives the images.
    cluster: &'build str,
    /// Praxis data-plane image reference.
    image: &'build str,
    /// Operator image reference.
    operator_image: &'build str,
    /// Operator source directory.
    operator_dir: &'build Path,
    /// Whether image builds are skipped.
    skip_build: bool,
}

/// Builds the proxy and operator images and loads them into KIND.
///
/// Returns the unique run and rolling-update image references.
fn build_and_load_images(build: &ImageBuild<'_>) -> Result<(String, String), String> {
    let (run_image, next_image) = unique_images(build.image)?;
    let _generated = GeneratedImages {
        engine: build.engine.to_owned(),
        tags: vec![run_image.clone(), next_image.clone()],
    };
    if !build.skip_build {
        run_command(Command::new(build.engine).args(["build", "-t", &run_image, "-f", "Containerfile", "."]))?;
        run_command(Command::new(build.engine).args(["tag", &run_image, build.image]))?;
        run_command(Command::new(build.engine).args([
            "build",
            "-t",
            build.operator_image,
            "-f",
            build.operator_dir.join("Containerfile").to_string_lossy().as_ref(),
            build.operator_dir.to_string_lossy().as_ref(),
        ]))?;
    }
    if build.skip_build {
        require_local_image(build.engine, build.image)?;
        require_local_image(build.engine, build.operator_image)?;
        run_command(Command::new(build.engine).args(["tag", build.image, &run_image]))?;
        run_command(Command::new(build.engine).args(["tag", build.image, &next_image]))?;
    } else {
        run_command(Command::new(build.engine).args(["tag", &run_image, &next_image]))?;
    }
    let archives = TempDir::new().map_err(|error| format!("create image archive directory: {error}"))?;
    for (index, loaded_image) in [&run_image, &next_image, &build.operator_image.to_owned()]
        .into_iter()
        .enumerate()
    {
        let archive = archives.path().join(format!("image-{index}.tar"));
        let archive = archive.to_string_lossy().into_owned();
        run_command(Command::new(build.engine).args(["save", "-o", &archive, loaded_image]))?;
        run_command(kind_command(build.engine).args(["load", "image-archive", &archive, "--name", build.cluster]))?;
    }
    Ok((run_image, next_image))
}

/// Requires an image built by an earlier run to exist in the local store.
///
/// `--skip-build` reuses tags from a previous run, so a stale or missing tag
/// must fail here rather than as an opaque `kind load` or `ImagePull` error.
fn require_local_image(engine: &str, image: &str) -> Result<(), String> {
    let inspected = Command::new(engine)
        .args(["image", "inspect", image])
        .output()
        .map_err(|error| format!("inspect local image {image}: {error}"))?;
    if inspected.status.success() {
        return Ok(());
    }
    Err(format!(
        "--skip-build requires {image} in the local image store: {}",
        String::from_utf8_lossy(&inspected.stderr).trim()
    ))
}

/// Gives an image per-run tags so Kubernetes sees a new pod template.
fn unique_images(image: &str) -> Result<(String, String), String> {
    let (name, tag) = image
        .rsplit_once(':')
        .ok_or_else(|| format!("image must be tagged: {image}"))?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("read system time: {error}"))?
        .as_nanos();
    let run_suffix = format!("-{nanos}");
    let next_suffix = format!("-next-{nanos}");
    let budget = MAX_IMAGE_TAG_LEN.saturating_sub(run_suffix.len().max(next_suffix.len()));
    let base: String = tag.chars().take(budget).collect();
    if base.is_empty() {
        return Err(format!("image tag is too short to make a per-run tag: {image}"));
    }
    Ok((
        format!("{name}:{base}{run_suffix}"),
        format!("{name}:{base}{next_suffix}"),
    ))
}

/// Qualifies local image names consistently for Docker, Podman and containerd.
fn qualified_image(image: &str) -> Result<String, String> {
    let (name, tag) = image
        .rsplit_once(':')
        .ok_or_else(|| format!("image must be tagged: {image}"))?;
    if tag.is_empty() || tag.contains('/') || image.contains('@') {
        return Err(format!("image must use a tag rather than a digest: {image}"));
    }
    let qualified = name
        .split_once('/')
        .is_some_and(|(registry, _)| registry == "localhost" || registry.contains('.') || registry.contains(':'));
    Ok(if qualified {
        image.to_owned()
    } else {
        format!("localhost/{image}")
    })
}

/// Applies certificate files as the `praxis-tls` Secret.
fn apply_tls_secret(cluster: &str, temp_dir: &TempDir, prefix: &str) -> Result<(), String> {
    let cert = temp_dir.path().join(format!("{prefix}.crt"));
    let key = temp_dir.path().join(format!("{prefix}.key"));
    let manifest = kubectl(
        cluster,
        [
            "create",
            "secret",
            "tls",
            "praxis-tls",
            "--cert",
            cert.to_string_lossy().as_ref(),
            "--key",
            key.to_string_lossy().as_ref(),
            "--dry-run=client",
            "-o=yaml",
        ],
    )?;
    kubectl_stdin(cluster, ["apply", "-n", "praxis", "-f", "-"], &manifest)?;
    Ok(())
}

/// Deletes one data-plane pod and waits for the Deployment to restore it.
fn delete_pod(cluster: &str) -> Result<(), String> {
    let pods = kubectl(
        cluster,
        ["get", "pods", "-l", "app.kubernetes.io/instance=rollout", "-o=name"],
    )?;
    let pod = pods
        .lines()
        .next()
        .ok_or_else(|| "no Praxis pod to delete".to_owned())?;
    kubectl(cluster, ["delete", pod, "--wait=true", "--timeout=35s"])?;
    wait_for_ready_proxy_replicas(cluster)
}

/// Changes the operator's data-plane image and waits for both rollouts.
fn rolling_update(cluster: &str, image: &str) -> Result<(), String> {
    kubectl(
        cluster,
        [
            "-n",
            "praxis-system",
            "set",
            "env",
            "deployment/praxis-operator",
            &format!("PRAXIS_IMAGE={image}"),
        ],
    )?;
    wait_for_rollout(cluster, "deployment/praxis-operator")?;
    wait_for_deployment_image(cluster, image)?;
    wait_for_rollout(cluster, "deployment/praxis-rollout")
}

/// Changes a route rewrite and waits for the generated config to hot-reload.
fn config_hot_reload(cluster: &str) -> Result<(), String> {
    let before = pod_identity(cluster)?;
    let pods = pod_names(cluster)?;
    replace_route_rewrite(cluster, "/config-v1", "/config-v2")?;
    wait_for_pod_body(cluster, &pods, "/config-version", "config-v2", 120)?;
    if pod_identity(cluster)? != before {
        return Err("config hot reload restarted a proxy".to_owned());
    }
    assert_replicas_share_config_hash(cluster)
}

/// Adds a listener and waits for the required data-plane rollout.
fn config_rollout(cluster: &str) -> Result<(), String> {
    let before = deployment_config_hash(cluster)?;
    let listener = serde_json::json!({
        "name": "rollout-extra",
        "port": 8081,
        "protocol": "HTTP",
    });
    let patch = format!(r#"[{{"op":"add","path":"/spec/listeners/-","value":{listener}}}]"#);
    kubectl(cluster, ["patch", "gateway", "rollout", "--type=json", "-p", &patch])?;
    wait_for_config_hash_change(cluster, &before)?;
    wait_for_rollout(cluster, "deployment/praxis-rollout")?;
    let pods = proxy_pod_names(&proxy_pods(cluster)?)?;
    let probe = HttpProbePod::start(cluster)?;
    wait_for_pod_port(&probe, &pods, 8081, 60)?;
    assert_replicas_share_config_hash(cluster)
}

/// Waits until every proxy pod answers on a listener port.
fn wait_for_pod_port(probe: &HttpProbePod, pods: &[String], port: u16, timeout_secs: u64) -> Result<(), String> {
    wait_for_listener(pods, port, timeout_secs, |pod, port, timeout| {
        probe.probe(pod, port, timeout)
    })
}

/// Waits until every pod's listener positively answers through `probe`.
///
/// A listener is accepted only when the pod itself answers. Transport and
/// inconclusive failures keep the wait going, so an API error cannot fake
/// readiness.
fn wait_for_listener(
    pods: &[String],
    port: u16,
    timeout_secs: u64,
    mut probe: impl FnMut(&str, u16, Duration) -> Result<ProbeOutcome, String>,
) -> Result<(), String> {
    let timeout = Duration::from_secs(timeout_secs);
    let started = Instant::now();
    let mut last_probe = "no probe completed".to_owned();
    loop {
        let mut all_listening = true;
        for pod in pods {
            // Every attempt gets what is left of the wait budget, so a listener
            // that accepts but never answers cannot outlive the deadline.
            let remaining = timeout.saturating_sub(started.elapsed());
            match probe(pod, port, remaining.max(Duration::from_millis(1))) {
                Ok(ProbeOutcome::Reachable) => {},
                Ok(ProbeOutcome::Unreachable) => {
                    last_probe = format!("{pod}:{port}: no listener accepted the connection");
                    all_listening = false;
                },
                Ok(ProbeOutcome::Inconclusive) => {
                    last_probe = format!("{pod}:{port}: probe was inconclusive");
                    all_listening = false;
                },
                Err(error) => {
                    last_probe = format!("{pod}:{port}: {error}");
                    all_listening = false;
                },
            }
        }
        if all_listening {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!(
                "proxy pods did not accept on port {port}; last probe: {last_probe}"
            ));
        }
        thread::sleep(Duration::from_secs(1));
    }
}

/// What one failed listener probe proves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeOutcome {
    /// The pod itself answered, so the listener is up.
    Reachable,
    /// No process accepted the connection.
    Unreachable,
    /// The API server or kubectl failed before the pod could answer.
    Inconclusive,
}

/// Classifies a wget probe failure by its text.
///
/// A pod answer is any failure that is neither a transport error nor a
/// kubectl/API failure; wget reports the listener's HTTP status (for example a
/// 404) without those markers, which proves the listener answered.
fn classify_probe_error(error: &str) -> ProbeOutcome {
    let error = error.to_ascii_lowercase();
    let transport = [
        "connection refused",
        "can't connect",
        "no route to host",
        "network is unreachable",
        "i/o timeout",
        "deadline exceeded",
        "exit code 124",
        "exit code 143",
    ];
    if transport.iter().any(|marker| error.contains(marker)) {
        return ProbeOutcome::Unreachable;
    }
    let api = [
        "error from server",
        "error:",
        "unable to",
        "forbidden",
        "unauthorized",
        "the server could not find",
        "timeout: not found",
    ];
    if api.iter().any(|marker| error.contains(marker)) {
        return ProbeOutcome::Inconclusive;
    }
    ProbeOutcome::Reachable
}

/// Waits until the operator has applied the requested data-plane image.
fn wait_for_deployment_image(cluster: &str, image: &str) -> Result<(), String> {
    for _ in 0..120 {
        let current = kubectl(
            cluster,
            [
                "get",
                "deployment/praxis-rollout",
                "-o=jsonpath={.spec.template.spec.containers[0].image}",
            ],
        )?;
        if current.trim() == image {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err(format!("data-plane image did not become {image} within 120 seconds"))
}

/// Returns the config hash baked into the data-plane pod template.
fn deployment_config_hash(cluster: &str) -> Result<String, String> {
    kubectl(
        cluster,
        [
            "get",
            "deployment/praxis-rollout",
            "-o=jsonpath={.spec.template.metadata.annotations.praxis\\.sh/config-hash}",
        ],
    )
}

/// Requires every proxy replica to run the config revision in the pod template.
///
/// The hash each pod carries is the revision it was created with. Comparing it
/// with the deployment template catches a replica that did not converge after a
/// rollout; a hot reload can change the live config without changing this
/// annotation, which needs the runtime exposure tracked in #1296.
fn assert_replicas_share_config_hash(cluster: &str) -> Result<(), String> {
    let expected = deployment_config_hash(cluster)?;
    let pods = kubectl(
        cluster,
        ["get", "pods", "-l", "app.kubernetes.io/instance=rollout", "-o=json"],
    )?;
    let pods: serde_json::Value = serde_json::from_str(&pods).map_err(|error| format!("parse proxy pods: {error}"))?;
    let mut hashes = Vec::new();
    for pod in pods
        .get("items")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        // A rolling update leaves old replicas terminating; they are not part
        // of the converged set this check compares.
        if pod
            .pointer("/metadata/deletionTimestamp")
            .is_some_and(|value| !value.is_null())
        {
            continue;
        }
        if pod.pointer("/status/phase").and_then(serde_json::Value::as_str) != Some("Running") {
            continue;
        }
        let hash = pod
            .pointer("/metadata/annotations/praxis.sh~1config-hash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        hashes.push(hash.to_owned());
    }
    parse_replica_hashes(&hashes, expected.trim())
}

/// Compares the replicas' config hashes with the deployment's revision.
fn parse_replica_hashes(hashes: &[String], expected: &str) -> Result<(), String> {
    if hashes.len() != 2 {
        return Err(format!("expected two proxy replicas, found {}", hashes.len()));
    }
    if hashes.iter().any(|hash| hash.trim() != expected) {
        return Err(format!(
            "proxy replicas report different config hashes {hashes:?}, expected {expected}"
        ));
    }
    Ok(())
}

/// Waits until the operator has baked a new config hash into the pod template.
fn wait_for_config_hash_change(cluster: &str, before: &str) -> Result<(), String> {
    for _ in 0..120 {
        let current = deployment_config_hash(cluster)?;
        if current != before {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err("data-plane config hash did not change within 120 seconds".to_owned())
}

/// Patches the route rewrite that drives the operator-generated config.
fn replace_route_rewrite(cluster: &str, old: &str, new: &str) -> Result<(), String> {
    let current = kubectl(
        cluster,
        [
            "get",
            "httproute",
            "rollout",
            "-o=jsonpath={.spec.rules[0].filters[0].urlRewrite.path.replaceFullPath}",
        ],
    )?;
    if current.trim() != old {
        return Err(format!("route rewrite was not {old}: {current}"));
    }
    let patch = format!(
        r#"[{{"op":"replace","path":"/spec/rules/0/filters/0/urlRewrite/path/replaceFullPath","value":"{new}"}}]"#
    );
    kubectl(cluster, ["patch", "httproute", "rollout", "--type=json", "-p", &patch])?;
    Ok(())
}

/// Replaces the TLS Secret and verifies every proxy serves the new serial.
fn rotate_tls(cluster: &str, temp_dir: &TempDir, endpoint: &str) -> Result<(), String> {
    let identity = pod_identity(cluster)?;
    let trusted_certificates = [temp_dir.path().join("tls.crt"), temp_dir.path().join("rotated.crt")];
    let before = tls_serial(endpoint, &trusted_certificates)?;
    let initial_serial = certificate_serial(&temp_dir.path().join("tls.crt"))?;
    if before != initial_serial {
        return Err("service did not serve the initial test certificate".to_owned());
    }
    let rotated_serial = certificate_serial(&temp_dir.path().join("rotated.crt"))?;
    let pods = pod_names(cluster)?;
    let _probe = TlsProbePod::start(cluster)?;
    for pod in &pods {
        pod_tls_serial(cluster, pod, Duration::from_secs(30))?;
    }
    apply_tls_secret(cluster, temp_dir, "rotated")?;
    let mut last_probe = "no probe completed".to_owned();
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(120))
        .ok_or_else(|| "the TLS rotation deadline overflowed".to_owned())?;
    loop {
        let mut all_rotated = true;
        for pod in &pods {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                // Expiring mid-loop must never let an unchecked replica pass.
                all_rotated = false;
                break;
            }
            match pod_tls_serial(cluster, pod, remaining) {
                Ok(serial) => {
                    last_probe = format!("{pod}: serial {serial}, expected {rotated_serial}");
                    if serial != rotated_serial {
                        all_rotated = false;
                    }
                },
                Err(error) => {
                    last_probe = format!("{pod}: {error}");
                    all_rotated = false;
                },
            }
        }
        if all_rotated {
            if pod_identity(cluster)? != identity {
                return Err("certificate rotation restarted a proxy".to_owned());
            }
            let public_serial = tls_serial(endpoint, &trusted_certificates)?;
            if public_serial != rotated_serial {
                return Err(format!(
                    "public endpoint serves serial {public_serial}, expected {rotated_serial}"
                ));
            }
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "rotated TLS certificate was not served within 120 seconds; last probe: {last_probe}"
            ));
        }
        thread::sleep(remaining.min(Duration::from_secs(1)));
    }
}

/// Reads and canonicalizes a certificate file's serial number.
fn certificate_serial(path: &Path) -> Result<String, String> {
    let output = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(path)
        .args(["-noout", "-serial"])
        .output()
        .map_err(|error| format!("read certificate serial: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "read certificate serial: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    tls_serial_from_output(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| "certificate omitted its serial".to_owned())
}

/// Returns the names of every data-plane pod.
fn pod_names(cluster: &str) -> Result<Vec<String>, String> {
    proxy_pod_names(&proxy_pods(cluster)?)
}

/// Reads the deployed proxy pod specifications and current status.
fn proxy_pods(cluster: &str) -> Result<serde_json::Value, String> {
    let pods = kubectl(
        cluster,
        ["get", "pods", "-l", "app.kubernetes.io/instance=rollout", "-o=json"],
    )?;
    serde_json::from_str(&pods).map_err(|error| format!("parse data-plane pods: {error}"))
}

/// Requires both Running proxy replicas before per-pod acceptance assertions.
fn proxy_pod_names(pods: &serde_json::Value) -> Result<Vec<String>, String> {
    let items = pods
        .get("items")
        .and_then(|items| items.as_array())
        .ok_or_else(|| "data-plane pod list omitted items".to_owned())?;
    let names = items
        .iter()
        .filter(|pod| {
            pod.pointer("/metadata/deletionTimestamp").is_none()
                && pod.pointer("/status/phase").and_then(|phase| phase.as_str()) == Some("Running")
        })
        .map(|pod| {
            pod.pointer("/metadata/name")
                .and_then(|name| name.as_str())
                .map(str::to_owned)
                .ok_or_else(|| "data-plane pod omitted its name".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if names.len() != 2 {
        return Err(format!("expected two Running proxy replicas, found {}", names.len()));
    }
    Ok(names)
}

/// Reads the certificate serial served by one data-plane pod.
fn pod_tls_serial(cluster: &str, pod: &str, timeout: Duration) -> Result<String, String> {
    let pod_ip = kubectl(cluster, ["get", "pod", pod, "-o=jsonpath={.status.podIP}"])?;
    let connect_address = pod_ip_literal(pod_ip.trim(), pod)?;
    let seconds = timeout.as_secs().clamp(1, 30);
    let request_timeout = format!("--request-timeout={}s", timeout.as_secs().max(1));
    let command = format!(
        "/usr/bin/timeout {seconds} /usr/bin/openssl s_client -connect {connect_address}:8443 -servername localhost </dev/null 2>/dev/null | /usr/bin/openssl x509 -noout -serial"
    );
    let output = kubectl(
        cluster,
        vec![
            request_timeout,
            "exec".to_owned(),
            "tls-probe".to_owned(),
            "--".to_owned(),
            "sh".to_owned(),
            "-c".to_owned(),
            command,
        ],
    )?;
    tls_serial_from_output(&output).ok_or_else(|| format!("TLS probe for {pod} omitted its serial"))
}

/// Reads an HTTP path directly from one data-plane pod.
fn pod_http_body(cluster: &str, pod: &str, path: &str) -> Result<String, String> {
    let proxy_path = format!("/api/v1/namespaces/praxis/pods/{pod}:8080/proxy{path}");
    kubectl(cluster, ["get", "--raw", &proxy_path])
}

/// Waits until every data-plane pod returns the expected body.
fn wait_for_pod_body(
    cluster: &str,
    pods: &[String],
    path: &str,
    expected: &str,
    timeout_secs: u64,
) -> Result<(), String> {
    let started = Instant::now();
    let mut last_probe = "no probe completed".to_owned();
    loop {
        let mut all_ready = true;
        for pod in pods {
            match pod_http_body(cluster, pod, path) {
                Ok(body) => {
                    last_probe = format!("{pod}: {body}");
                    if body.trim() != expected {
                        all_ready = false;
                    }
                },
                Err(error) => {
                    last_probe = format!("{pod}: {error}");
                    all_ready = false;
                },
            }
        }
        if all_ready {
            return Ok(());
        }
        if started.elapsed() >= Duration::from_secs(timeout_secs) {
            return Err(format!("pods did not return {expected:?}; last probe: {last_probe}"));
        }
        thread::sleep(Duration::from_secs(1));
    }
}

/// Waits until the temporary TLS probe pod has installed OpenSSL.
fn wait_for_openssl(cluster: &str) -> Result<(), String> {
    for _ in 0..60 {
        if kubectl(cluster, ["exec", "tls-probe", "--", "/usr/bin/openssl", "version"]).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err("TLS probe pod did not install OpenSSL within 60 seconds".to_owned())
}

/// Extracts a certificate serial from OpenSSL's `serial=...` output.
fn tls_serial_from_output(output: &str) -> Option<String> {
    output
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix("serial="))
        .map(canonical_hex_serial)
}

/// Normalizes OpenSSL hexadecimal serial output.
fn canonical_hex_serial(serial: &str) -> String {
    let digits = serial.trim().trim_start_matches('0');
    if digits.is_empty() {
        "0".to_owned()
    } else {
        digits.to_uppercase()
    }
}

/// Returns pod UIDs and restart counts in stable name order.
fn pod_identity(cluster: &str) -> Result<String, String> {
    kubectl(
        cluster,
        [
            "get",
            "pods",
            "-l",
            "app.kubernetes.io/instance=rollout",
            "--sort-by=.metadata.name",
            "-o=jsonpath={.items[*].metadata.uid}/{.items[*].status.containerStatuses[*].restartCount}",
        ],
    )
}

/// Drains and uncordons one worker node.
fn drain_node(cluster: &str) -> Result<(), String> {
    let nodes = kubectl(
        cluster,
        [
            "get",
            "pods",
            "-l",
            "app.kubernetes.io/instance=rollout",
            "-o=jsonpath={.items[0].spec.nodeName}",
        ],
    )?;
    let node = nodes.trim();
    if node.is_empty() {
        return Err("no worker hosting a Praxis pod found".to_owned());
    }
    assert_disruption_budget(cluster)?;
    drain_and_uncordon(cluster, node)?;
    wait_for_ready_proxy_replicas(cluster)
}

/// Verifies the disruption budget protects one proxy replica during a drain.
fn assert_disruption_budget(cluster: &str) -> Result<(), String> {
    let pdb = kubectl(cluster, ["get", "pdb", "praxis-rollout", "-o=json"])?;
    let pdb = serde_json::from_str::<serde_json::Value>(&pdb).map_err(|error| format!("parse PDB: {error}"))?;
    let min_available = pdb.pointer("/spec/minAvailable").and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
    });
    if min_available != Some(1) {
        return Err("the disruption budget must require one available proxy replica".to_owned());
    }
    let allowed = pdb
        .pointer("/status/disruptionsAllowed")
        .and_then(serde_json::Value::as_i64);
    if !matches!(allowed, Some(value) if value >= 1) {
        return Err(format!("the disruption budget does not allow an eviction: {allowed:?}"));
    }
    let selector = pdb
        .pointer("/spec/selector")
        .ok_or_else(|| "the disruption budget has no selector".to_owned())?;
    let selector = selector_expression(selector)?;
    let selected = kubectl(
        cluster,
        [
            "get",
            "pods",
            "-l",
            &selector,
            "-o=jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}",
        ],
    )?;
    let mut selected = selected
        .lines()
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    selected.sort_unstable();
    let mut proxies = proxy_pod_names(&proxy_pods(cluster)?)?;
    proxies.sort_unstable();
    if selected != proxies {
        return Err(format!(
            "the disruption budget selects {selected:?}, expected exactly the proxy pods {proxies:?}"
        ));
    }
    Ok(())
}

/// Converts a PDB selector, including `matchExpressions`, to label-selector
/// syntax so the API evaluates the same selector the budget uses.
fn selector_expression(selector: &serde_json::Value) -> Result<String, String> {
    let mut requirements = Vec::new();
    if let Some(labels) = selector.get("matchLabels").and_then(serde_json::Value::as_object) {
        for (key, value) in labels {
            let value = value
                .as_str()
                .ok_or_else(|| format!("selector label {key} is not a string"))?;
            requirements.push(format!("{key}={value}"));
        }
    }
    if let Some(expressions) = selector.get("matchExpressions").and_then(serde_json::Value::as_array) {
        for expression in expressions {
            requirements.push(selector_requirement(expression)?);
        }
    }
    if requirements.is_empty() {
        return Err("the disruption budget selector matches every pod".to_owned());
    }
    Ok(requirements.join(","))
}

/// Converts one `matchExpressions` entry to label-selector syntax.
fn selector_requirement(expression: &serde_json::Value) -> Result<String, String> {
    let key = expression
        .get("key")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "selector expression has no key".to_owned())?;
    let operator = expression
        .get("operator")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "selector expression has no operator".to_owned())?;
    let values = expression
        .get("values")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| format!("selector expression for {key} has a non-string value"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let joined = values.join(",");
    match operator {
        "In" if !values.is_empty() => Ok(format!("{key} in ({joined})")),
        "NotIn" if !values.is_empty() => Ok(format!("{key} notin ({joined})")),
        "Exists" => Ok(key.to_owned()),
        "DoesNotExist" => Ok(format!("!{key}")),
        other => Err(format!("unsupported selector operator {other:?} for {key}")),
    }
}

/// Drains one node, always uncordons it, and reports both failures.
fn drain_and_uncordon(cluster: &str, node: &str) -> Result<(), String> {
    let drained = kubectl(
        cluster,
        [
            "drain",
            node,
            "--ignore-daemonsets",
            "--delete-emptydir-data",
            "--timeout=180s",
        ],
    );
    let uncordoned = kubectl(cluster, ["uncordon", node]);
    match (drained, uncordoned) {
        (Ok(_), Ok(_)) => Ok(()),
        (Ok(_), Err(error)) => Err(format!("uncordon {node}: {error}")),
        (Err(error), Ok(_)) => Err(format!("drain {node}: {error}")),
        (Err(error), Err(uncordon_error)) => Err(format!("drain {node}: {error}; uncordon {node}: {uncordon_error}")),
    }
}

/// Scales the test upstream to zero, asserts proxy readiness, and restores it.
fn upstream_down(cluster: &str) -> Result<(), String> {
    let outcome = upstream_down_asserted(cluster);
    let restored = kubectl(cluster, ["scale", "deployment/backend", "--replicas=2"])
        .and_then(|_| wait_for_rollout(cluster, "deployment/backend"));
    match (outcome, restored) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(format!("restore test upstream: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(restore_error)) => Err(format!("{error}; restore test upstream: {restore_error}")),
    }
}

/// Asserts that the proxy remains ready while the test upstream is down.
fn upstream_down_asserted(cluster: &str) -> Result<(), String> {
    let (monitor, window) = admin::ReadinessMonitor::start(cluster)?;
    let outcome: Result<(), String> = (|| {
        kubectl(cluster, ["scale", "deployment/backend", "--replicas=0"])?;
        kubectl(
            cluster,
            [
                "wait",
                "--for=delete",
                "pod",
                "-l",
                "app.kubernetes.io/name=backend",
                "--timeout=90s",
            ],
        )?;
        thread::sleep(Duration::from_secs(window.saturating_add(1)));
        Ok(())
    })();
    let observed = monitor.finish();
    match (outcome, observed) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) | (Err(error), Ok(())) => Err(error),
        (Err(error), Err(readiness)) => Err(format!("{error}; readiness: {readiness}")),
    }
}

/// Runs `kubectl` in the rollout cluster and returns stdout.
fn kubectl<I, S>(cluster: &str, args: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = args.into_iter().collect::<Vec<_>>();
    let mut command = Command::new("kubectl");
    command
        .arg("--context")
        .arg(format!("kind-{cluster}"))
        .arg("--namespace")
        .arg("praxis");
    command.arg("--request-timeout").arg(request_timeout(&args));
    for arg in args {
        command.arg(arg.as_ref());
    }
    let output = command.output().map_err(|error| format!("run kubectl: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "kubectl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Runs `kubectl` with standard input and returns stdout.
fn kubectl_stdin<I, S>(cluster: &str, args: I, input: &str) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = args.into_iter().collect::<Vec<_>>();
    let mut command = Command::new("kubectl");
    command
        .arg("--context")
        .arg(format!("kind-{cluster}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.arg("--request-timeout").arg(request_timeout(&args));
    for arg in args {
        command.arg(arg.as_ref());
    }
    let mut child = command.spawn().map_err(|error| format!("run kubectl: {error}"))?;
    if let Some(mut stdin) = child.stdin.take()
        && let Err(error) = stdin.write_all(input.as_bytes())
    {
        drop(stdin);
        drop(child.kill());
        drop(child.wait());
        return Err(format!("write kubectl input: {error}"));
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for kubectl: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "kubectl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Allows bounded watches to reach their command deadline while bounding API calls.
fn request_timeout<S>(args: &[S]) -> &'static str
where
    S: AsRef<OsStr>,
{
    if args.iter().any(|arg| {
        let arg = arg.as_ref().to_string_lossy();
        arg == "--timeout" || arg.starts_with("--timeout=")
    }) {
        "300s"
    } else {
        KUBECTL_REQUEST_TIMEOUT
    }
}

/// Waits for a Deployment rollout.
fn wait_for_rollout(cluster: &str, resource: &str) -> Result<(), String> {
    let namespace = if resource == "deployment/praxis-operator" {
        "praxis-system"
    } else {
        "praxis"
    };
    kubectl(
        cluster,
        ["-n", namespace, "rollout", "status", resource, "--timeout=240s"],
    )
    .map(|output| println!("{}", output.trim_end()))
}

/// Waits for both Praxis replicas to be ready and available within two minutes.
fn wait_for_ready_proxy_replicas(cluster: &str) -> Result<(), String> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(120))
        .ok_or_else(|| "readiness deadline overflows the clock".to_owned())?;
    loop {
        let pods = kubectl(
            cluster,
            ["get", "pods", "-l", "app.kubernetes.io/instance=rollout", "-o=json"],
        )?;
        let pods =
            serde_json::from_str::<serde_json::Value>(&pods).map_err(|error| format!("parse proxy pods: {error}"))?;
        let ready = pods
            .pointer("/items")
            .and_then(|items| items.as_array())
            .is_some_and(|items| {
                items
                    .iter()
                    .filter(|pod| {
                        pod.pointer("/metadata/deletionTimestamp").is_none()
                            && pod.pointer("/status/phase").and_then(|phase| phase.as_str()) == Some("Running")
                            && pod.pointer("/status/conditions").is_some_and(|conditions| {
                                conditions.as_array().is_some_and(|conditions| {
                                    conditions.iter().any(|condition| {
                                        condition.get("type").and_then(|kind| kind.as_str()) == Some("Ready")
                                            && condition.get("status").and_then(|status| status.as_str())
                                                == Some("True")
                                    })
                                })
                            })
                    })
                    .count()
                    == 2
            });
        if ready {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("proxy replicas did not become ready and available within 120 seconds".to_owned());
        }
        thread::sleep(Duration::from_secs(1));
    }
}

/// Waits for the Operator to create a Deployment before restarting it.
fn wait_for_deployment(cluster: &str, deployment: &str) -> Result<(), String> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(120) {
        match kubectl(cluster, ["get", "deployment", deployment, "-o=name"]) {
            Ok(_) => return Ok(()),
            Err(error) if error.contains("NotFound") => {},
            Err(error) => return Err(format!("check Deployment {deployment}: {error}")),
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err(format!("Deployment {deployment} was not created within 120 seconds"))
}

/// Returns a localhost endpoint published by the KIND control plane.
fn local_endpoint(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// Waits until an HTTP GET returns the expected body.
fn wait_for_body(endpoint: &str, path: &str, expected: &str, seconds: u64) -> Result<(), String> {
    for _ in 0..seconds {
        let result = std::panic::catch_unwind(|| praxis_test_utils::http_get(endpoint, path, Some("localhost")));
        if let Ok((status, body)) = result
            && status == 200
            && body.trim() == expected
        {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err(format!("timed out waiting for {path} to return {expected:?}"))
}

/// Runs a command, inheriting standard streams.
fn run_command(command: &mut Command) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|error| format!("run {}: {error}", command.get_program().to_string_lossy()))?;
    if !status.success() {
        return Err(format!("command failed: {}", command.get_program().to_string_lossy()));
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "fixture failures should abort unit tests")]
mod tests {
    use super::*;

    #[test]
    fn per_pod_checks_require_both_running_replicas() {
        for count in 0..=3 {
            let items = (0..count)
                .map(|index| {
                    serde_json::json!({
                        "metadata": {"name": format!("proxy-{index}")},
                        "status": {"phase": "Running"}
                    })
                })
                .collect::<Vec<_>>();
            let result = proxy_pod_names(&serde_json::json!({"items": items}));
            assert_eq!(
                result.is_ok(),
                count == 2,
                "exactly two replicas are required, found {count}"
            );
        }
    }

    #[test]
    fn per_pod_checks_exclude_pending_and_terminating_replicas() {
        let pods = serde_json::json!({"items": [
            {"metadata": {"name": "proxy-0"}, "status": {"phase": "Running"}},
            {"metadata": {"name": "proxy-1"}, "status": {"phase": "Running"}},
            {"metadata": {"name": "proxy-2"}, "status": {"phase": "Pending"}},
            {"metadata": {"name": "proxy-3", "deletionTimestamp": "2026-11-03T12:00:45Z"},
             "status": {"phase": "Running"}}
        ]});
        assert_eq!(
            proxy_pod_names(&pods).unwrap(),
            vec!["proxy-0", "proxy-1"],
            "only Running, undeleted replicas are selected"
        );
    }

    #[test]
    fn all_rollout_scenarios_are_selected_by_default() {
        assert_eq!(
            selected_scenarios(&[]),
            &[
                Scenario::PodDelete,
                Scenario::RollingUpdate,
                Scenario::ConfigHotReload,
                Scenario::ConfigRollout,
                Scenario::TlsRotation,
                Scenario::NodeDrain,
                Scenario::UpstreamDown
            ],
            "every acceptance scenario must be represented"
        );
    }

    #[test]
    fn repeated_stateful_scenarios_run_once_in_requested_order() {
        assert_eq!(
            selected_scenarios(&[
                Scenario::ConfigHotReload,
                Scenario::PodDelete,
                Scenario::ConfigHotReload
            ]),
            vec![Scenario::ConfigHotReload, Scenario::PodDelete],
            "duplicates must not rerun a stateful scenario or reorder explicit selections"
        );
    }

    #[test]
    fn reused_clusters_require_an_explicit_opt_in() {
        require_owned_cluster(true, false, "fresh").unwrap();
        require_owned_cluster(true, true, "fresh").unwrap();
        require_owned_cluster(false, true, "reused").unwrap();
        let error = require_owned_cluster(false, false, "reused").unwrap_err();
        assert!(error.contains("--reuse-cluster"), "reuse must be opt-in: {error}");
    }

    #[test]
    fn image_names_are_qualified_once() {
        for (image, expected) in [
            ("praxis:rollout", "localhost/praxis:rollout"),
            ("localhost/praxis:rollout", "localhost/praxis:rollout"),
            ("ghcr.io/praxis-proxy/praxis:test", "ghcr.io/praxis-proxy/praxis:test"),
            ("localhost:5000/praxis:test", "localhost:5000/praxis:test"),
        ] {
            assert_eq!(qualified_image(image).unwrap(), expected);
        }
        for image in ["praxis", "praxis:", "localhost:5000/praxis", "praxis@sha256:abc"] {
            assert!(qualified_image(image).is_err(), "accepted {image}");
        }
    }

    #[test]
    fn abnormal_container_exits_are_rejected() {
        for code in [1, 101, 132, 134, 136, 137, 139] {
            let pod = serde_json::json!({
                "status": {"containerStatuses": [{"state": {"terminated": {"exitCode": code}}}]}
            });
            assert!(
                check_pod_exit(&pod, false, None, None).is_err(),
                "exit code {code} must fail acceptance"
            );
        }
        let clean = serde_json::json!({
            "status": {"containerStatuses": [{"state": {"terminated": {"exitCode": 0}}}]}
        });
        assert!(
            check_pod_exit(&clean, false, None, None).is_ok(),
            "a clean exit must pass"
        );
    }

    #[test]
    fn any_nonzero_exit_in_current_and_previous_states_is_rejected() {
        for code in [1, 132, 136] {
            let current = serde_json::json!({
                "status": {"containerStatuses": [{"state": {"terminated": {"exitCode": code}}}]}
            });
            let previous = serde_json::json!({
                "status": {"containerStatuses": [{"lastState": {"terminated": {"exitCode": code}}}]}
            });
            for (path, pod) in [("state", current), ("lastState", previous)] {
                assert!(
                    check_pod_exit(&pod, false, None, None).is_err(),
                    "{path} exit code {code} must fail acceptance"
                );
            }
        }
    }

    #[test]
    fn retained_cluster_ports_are_discovered_from_the_engine() {
        let ports = r#"{
            "30080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "32770"}],
            "30443/tcp": [{"HostIp": "127.0.0.1", "HostPort": 32771}]
        }"#;
        assert_eq!(parse_host_ports(ports).unwrap(), (32770, 32771));
        assert!(
            parse_host_ports(r#"{"30080/tcp": []}"#).is_err(),
            "a reused cluster without an HTTPS mapping must fail"
        );
        assert!(
            parse_host_ports("not json").is_err(),
            "invalid inspect output must fail"
        );
    }

    #[test]
    fn listener_probe_classifies_answers_and_transport_failures() {
        assert_eq!(
            classify_probe_error("kubectl failed: 404 page not found"),
            ProbeOutcome::Reachable
        );
        assert_eq!(
            classify_probe_error("kubectl failed: dial tcp 10.244.1.5:8081: connect: connection refused"),
            ProbeOutcome::Unreachable
        );
        assert_eq!(
            classify_probe_error("kubectl failed: context deadline exceeded"),
            ProbeOutcome::Unreachable
        );
        assert_eq!(
            classify_probe_error("command terminated with exit code 124"),
            ProbeOutcome::Unreachable,
            "the exec cap must not look like a listener answer"
        );
        assert_eq!(
            classify_probe_error("kubectl failed: Error from server (Forbidden)"),
            ProbeOutcome::Inconclusive
        );
        assert_eq!(
            classify_probe_error("sh: timeout: not found"),
            ProbeOutcome::Inconclusive,
            "a missing exec cap is a probe environment failure"
        );
        assert_eq!(
            classify_probe_error("error: exec plugin: invalid apiVersion"),
            ProbeOutcome::Inconclusive
        );
        assert_eq!(classify_probe_error(""), ProbeOutcome::Reachable);
    }

    #[test]
    fn wait_for_pod_port_rejects_a_closed_listener() {
        let error =
            wait_for_listener(&["proxy".to_owned()], 8081, 0, |_, _, _| Ok(ProbeOutcome::Unreachable)).unwrap_err();
        assert!(
            error.contains("did not accept"),
            "closed listener must time out: {error}"
        );
    }

    #[test]
    fn wait_for_pod_port_accepts_an_http_answer() {
        wait_for_listener(&["proxy".to_owned()], 8081, 0, |_, _, _| Ok(ProbeOutcome::Reachable)).unwrap();
    }

    #[test]
    fn pod_ip_literals_bracket_ipv6_addresses() {
        assert_eq!(
            pod_ip_literal("10.244.1.5", "proxy").unwrap(),
            "10.244.1.5",
            "IPv4 literals stay unbracketed"
        );
        assert_eq!(
            pod_ip_literal("fd00::5", "proxy").unwrap(),
            "[fd00::5]",
            "IPv6 literals must keep the port out of the address"
        );
        assert!(
            pod_ip_literal("not-an-ip", "proxy").is_err(),
            "a malformed pod IP must not become a probe target"
        );
    }

    #[test]
    fn wait_for_pod_port_passes_the_remaining_budget_to_the_probe() {
        let mut budgets = Vec::new();
        wait_for_listener(&["proxy".to_owned()], 8081, 30, |_, _, budget| {
            budgets.push(budget);
            Ok(ProbeOutcome::Reachable)
        })
        .unwrap();

        let budget = budgets.first().copied().unwrap_or_default();
        assert_eq!(budgets.len(), 1, "one reachable pod ends the wait");
        assert!(
            budget > Duration::ZERO && budget <= Duration::from_secs(30),
            "the probe must get the remaining wait budget, got {budget:?}"
        );
    }

    #[test]
    fn wait_for_pod_port_does_not_accept_api_errors() {
        let error =
            wait_for_listener(&["proxy".to_owned()], 8081, 0, |_, _, _| Ok(ProbeOutcome::Inconclusive)).unwrap_err();
        assert!(
            error.contains("did not accept"),
            "an inconclusive probe must not prove the listener is up: {error}"
        );
    }

    #[test]
    fn replica_config_hashes_must_converge() {
        let pair = ["abc".to_owned(), "abc".to_owned()];
        parse_replica_hashes(&pair, "abc").unwrap();
        assert!(
            parse_replica_hashes(&["abc".to_owned(), "def".to_owned()], "abc").is_err(),
            "replicas on different revisions must fail"
        );
        assert!(
            parse_replica_hashes(&["abc".to_owned()], "abc").is_err(),
            "a missing replica must fail"
        );
        assert!(
            parse_replica_hashes(&pair, "def").is_err(),
            "a replica behind the template must fail"
        );
    }

    #[test]
    fn disruption_budget_selectors_include_expressions() {
        let selector = serde_json::json!({
            "matchLabels": {"app": "praxis"},
            "matchExpressions": [
                {"key": "tier", "operator": "In", "values": ["proxy", "edge"]},
                {"key": "debug", "operator": "DoesNotExist"}
            ]
        });
        assert_eq!(
            selector_expression(&selector).unwrap(),
            "app=praxis,tier in (proxy,edge),!debug"
        );
        assert!(
            selector_expression(&serde_json::json!({})).is_err(),
            "an empty selector matches every pod"
        );
        let unsupported = serde_json::json!({
            "matchExpressions": [{"key": "tier", "operator": "Gt", "values": ["1"]}]
        });
        assert!(
            selector_expression(&unsupported).is_err(),
            "unsupported operators must fail closed"
        );
    }

    #[test]
    fn reserved_host_ports_are_distinct() {
        for _ in 0..10 {
            let (http, https) = free_host_ports().unwrap();
            assert_ne!(http, https, "KIND host mappings must use distinct ports");
        }
    }

    #[test]
    fn generated_image_tags_stay_within_the_engine_limit() {
        let long = format!("praxis:{}", "a".repeat(MAX_IMAGE_TAG_LEN));
        let (run, next) = unique_images(&long).unwrap();
        for image in [run, next] {
            let tag = image.rsplit_once(':').unwrap().1;
            assert!(
                tag.len() <= MAX_IMAGE_TAG_LEN,
                "tag exceeds the engine limit: {} characters",
                tag.len()
            );
        }
    }

    #[test]
    fn tls_serial_output_is_parsed() {
        assert_eq!(
            tls_serial_from_output("CONNECTED\nserial=0123456789ABCDEF\n"),
            Some("123456789ABCDEF".to_owned())
        );
        assert_eq!(tls_serial_from_output("CONNECTED\n"), None);
    }

    /// A deleted pod whose observed exit precedes its Kubernetes deadline.
    fn deleted_pod_event() -> serde_json::Value {
        serde_json::json!({
            "type": "DELETED",
            "object": {
                "metadata": {
                    "uid": "old-proxy",
                    "deletionTimestamp": "2026-11-03T12:00:30Z",
                    "deletionGracePeriodSeconds": 15
                },
                "status": { "containerStatuses": [{ "state": { "terminated": {
                    "exitCode": 0, "finishedAt": "2026-11-03T12:00:05Z"
                } } }] }
            }
        })
    }

    /// No terminations predate the watch in these fixtures.
    fn no_startup_retries() -> BTreeSet<(String, String)> {
        BTreeSet::new()
    }

    #[test]
    fn startup_baseline_collects_both_termination_states_by_container_id() {
        let pods = serde_json::json!({
            "items": [{
                "metadata": {"uid": "proxy"},
                "status": {"containerStatuses": [{
                    "state": {"terminated": {"exitCode": 1, "containerID": "container-current"}},
                    "lastState": {"terminated": {"exitCode": 1, "containerID": "container-previous"}}
                }]}
            }]
        });
        let retries = terminations(&pods);
        assert!(
            retries.contains(&("proxy".to_owned(), "container-current".to_owned())),
            "a current termination must seed the baseline"
        );
        assert!(
            retries.contains(&("proxy".to_owned(), "container-previous".to_owned())),
            "a previous termination must seed the baseline"
        );
    }

    #[test]
    fn deleted_pod_exits_remain_part_of_acceptance_checks() {
        let healthy = serde_json::json!({
            "type": "ADDED", "object": { "metadata": { "uid": "new-proxy" } }
        });
        let mut deleted = deleted_pod_event();
        check_pod_events(&format!("{deleted}\n{healthy}"), &no_startup_retries()).unwrap();
        *deleted
            .pointer_mut("/object/status/containerStatuses/0/state/terminated/exitCode")
            .unwrap() = 137.into();
        assert!(
            check_pod_events(&format!("{deleted}\n{healthy}"), &no_startup_retries())
                .unwrap_err()
                .contains("abnormally")
        );
    }

    #[test]
    fn startup_retries_are_tolerated_but_crash_signals_are_not() {
        let retries = BTreeSet::from([("proxy".to_owned(), "container-a".to_owned())]);
        let retry = serde_json::json!({
            "metadata": {"uid": "proxy"},
            "status": {"containerStatuses": [{"lastState": {"terminated": {
                "exitCode": 1, "containerID": "container-a"
            }}}]}
        });
        assert!(
            check_pod_exit(&retry, false, None, Some(&retries)).is_ok(),
            "a pre-watch startup retry is not a rollout failure"
        );
        let mut in_current_state = retry.clone();
        let status = in_current_state.pointer_mut("/status/containerStatuses/0").unwrap();
        let terminated = status.pointer_mut("/lastState/terminated").unwrap().take();
        status
            .as_object_mut()
            .unwrap()
            .insert("state".to_owned(), serde_json::json!({"terminated": terminated}));
        assert!(
            check_pod_exit(&in_current_state, false, None, Some(&retries)).is_ok(),
            "a pre-watch retry observed in state.terminated is also tolerated"
        );
        for code in [139, 135] {
            let mut crashed = retry.clone();
            *crashed
                .pointer_mut("/status/containerStatuses/0/lastState/terminated/exitCode")
                .unwrap() = code.into();
            assert!(
                check_pod_exit(&crashed, false, None, Some(&retries)).is_err(),
                "crash signal {code} must fail even before the watch started"
            );
        }
        let mut new_instance = retry.clone();
        *new_instance
            .pointer_mut("/status/containerStatuses/0/lastState/terminated/containerID")
            .unwrap() = "container-b".into();
        assert!(
            check_pod_exit(&new_instance, false, None, Some(&retries)).is_err(),
            "a new exit in the same second must not match the baseline"
        );
        let mut absent_id = retry;
        absent_id
            .pointer_mut("/status/containerStatuses/0/lastState/terminated")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("containerID");
        assert!(
            check_pod_exit(&absent_id, false, None, Some(&retries)).is_err(),
            "a termination without a container ID cannot be a known retry"
        );
    }

    #[test]
    fn deleted_pods_must_have_observed_exits_within_grace() {
        let mut deleted = deleted_pod_event();
        *deleted
            .pointer_mut("/object/status/containerStatuses/0/state/terminated/finishedAt")
            .unwrap() = "2026-11-03T12:00:46Z".into();
        assert!(
            check_pod_events(&deleted.to_string(), &no_startup_retries())
                .unwrap_err()
                .contains("deadline")
        );
        *deleted.pointer_mut("/object/status/containerStatuses/0/state").unwrap() =
            serde_json::json!({ "running": {} });
        assert!(
            check_pod_events(&deleted.to_string(), &no_startup_retries())
                .unwrap_err()
                .contains("no observed exit")
        );
    }

    #[test]
    fn pod_watch_must_capture_valid_events() {
        assert!(check_pod_events("", &no_startup_retries()).is_err());
        assert!(
            check_pod_events(
                r#"{"type":"ERROR","object":{"message":"expired"}}"#,
                &no_startup_retries()
            )
            .is_err()
        );
        assert!(check_pod_events(&format!("{}\n{{", deleted_pod_event()), &no_startup_retries()).is_err());
    }

    #[test]
    fn clean_exits_after_the_deletion_deadline_are_rejected() {
        let mut deleted = deleted_pod_event();
        *deleted
            .pointer_mut("/object/status/containerStatuses/0/state/terminated/finishedAt")
            .unwrap() = "2026-11-03T12:00:31Z".into();
        assert!(
            check_pod_events(&deleted.to_string(), &no_startup_retries())
                .unwrap_err()
                .contains("deadline"),
            "a clean exit one second beyond the deadline must fail acceptance"
        );
    }

    #[test]
    fn api_timeouts_allow_bounded_watches_to_finish() {
        assert_eq!(
            request_timeout(&["get", "pods"]),
            "30s",
            "polls must bound API requests"
        );
        assert_eq!(
            request_timeout(&["rollout", "status", "deployment/test", "--timeout=240s"]),
            "300s",
            "a bounded rollout must be allowed to reach its deadline"
        );
    }

    #[test]
    fn deleted_pods_may_exit_at_their_deletion_deadline() {
        let mut deleted = deleted_pod_event();
        *deleted
            .pointer_mut("/object/status/containerStatuses/0/state/terminated/finishedAt")
            .unwrap() = "2026-11-03T12:00:30Z".into();
        check_pod_events(&deleted.to_string(), &no_startup_retries()).unwrap();
    }

    #[test]
    fn final_deleted_events_use_the_initial_deletion_deadline() {
        let terminating = serde_json::json!({
            "type": "MODIFIED",
            "object": {
                "metadata": {
                    "uid": "old-proxy",
                    "deletionTimestamp": "2026-11-03T12:00:45Z",
                    "deletionGracePeriodSeconds": 15
                },
                "status": { "containerStatuses": [{ "state": { "running": {} } }] }
            }
        });
        let mut deleted = deleted_pod_event();
        *deleted
            .pointer_mut("/object/metadata/deletionGracePeriodSeconds")
            .unwrap() = 0.into();
        *deleted
            .pointer_mut("/object/status/containerStatuses/0/state/terminated/finishedAt")
            .unwrap() = "2026-11-03T12:00:35Z".into();
        check_pod_events(&format!("{terminating}\n{deleted}"), &no_startup_retries()).unwrap();
    }

    #[test]
    fn shortened_grace_periods_use_the_strictest_deadline() {
        let terminating = serde_json::json!({
            "type": "MODIFIED",
            "object": {
                "metadata": {
                    "uid": "old-proxy",
                    "deletionTimestamp": "2026-11-03T12:00:45Z",
                    "deletionGracePeriodSeconds": 15
                },
                "status": { "containerStatuses": [{ "state": { "running": {} } }] }
            }
        });
        let mut deleted = deleted_pod_event();
        *deleted.pointer_mut("/object/metadata/deletionTimestamp").unwrap() = "2026-11-03T12:00:35Z".into();
        *deleted
            .pointer_mut("/object/metadata/deletionGracePeriodSeconds")
            .unwrap() = 5.into();
        *deleted
            .pointer_mut("/object/status/containerStatuses/0/state/terminated/finishedAt")
            .unwrap() = "2026-11-03T12:00:40Z".into();
        assert!(
            check_pod_events(&format!("{terminating}\n{deleted}"), &no_startup_retries())
                .unwrap_err()
                .contains("deadline")
        );
    }
}
