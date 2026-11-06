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
    collections::BTreeMap,
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

/// Retains pod lifecycle events, including containers removed during rollouts.
struct PodWatch {
    /// Watch process, stopped even when a scenario returns an error.
    child: Child,
    /// JSON event stream retained until the acceptance assertions finish.
    events: NamedTempFile,
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
        let mut watch = Self { child, events };
        for _ in 0..100 {
            if watch.child.try_wait().map_err(|error| error.to_string())?.is_some() {
                return Err("pod watch exited before scenarios began".to_owned());
            }
            if watch
                .events
                .as_file()
                .metadata()
                .map_err(|error| error.to_string())?
                .len()
                > 0
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
        self.child.kill().map_err(|error| error.to_string())?;
        self.child.wait().map_err(|error| error.to_string())?;
        let events = std::fs::read_to_string(self.events.path()).map_err(|error| error.to_string())?;
        check_pod_events(&events)
    }
}

impl Drop for PodWatch {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

/// Validates exits from current and previous states and retains deleted pods.
fn check_pod_events(events: &str) -> Result<(), String> {
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
        check_pod_exit(pod, false, deletion_deadlines.get(uid))?;
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
        check_pod_exit(pod, terminating, deadline)?;
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

/// Rejects SIGKILL and requires terminating pods to have exited by their deadline.
fn check_pod_exit(
    pod: &serde_json::Value,
    terminating: bool,
    deadline: Option<&chrono::DateTime<chrono::FixedOffset>>,
) -> Result<(), String> {
    let containers = pod
        .pointer("/status/containerStatuses")
        .and_then(|value| value.as_array());
    if terminating && containers.is_none_or(Vec::is_empty) {
        return Err(format!("terminating pod has no exit status: {pod}"));
    }
    for container in containers.into_iter().flatten() {
        for path in ["/state/terminated", "/lastState/terminated"] {
            if container
                .pointer(path)
                .and_then(|state| state.get("exitCode"))
                .and_then(serde_json::Value::as_i64)
                == Some(137)
            {
                return Err(format!("container exited with SIGKILL: {pod}"));
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
    let created_cluster = create_cluster(&args.cluster_name, &engine)?;
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
        operator_image: &args.operator_image,
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
        .replace("__OPERATOR_IMAGE__", &args.operator_image)
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

    let http_endpoint = local_endpoint(30080);
    let https_endpoint = local_endpoint(30443);
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
fn create_cluster(name: &str, engine: &str) -> Result<bool, String> {
    let clusters = kind_command(engine).arg("get").arg("clusters").output();
    if let Ok(output) = clusters
        && String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|cluster| cluster == name)
    {
        return Ok(false);
    }

    let config = "kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30080
        hostPort: 30080
        listenAddress: 127.0.0.1
        protocol: TCP
      - containerPort: 30443
        hostPort: 30443
        listenAddress: 127.0.0.1
        protocol: TCP
  - role: worker
  - role: worker
  - role: worker
";
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
    run_command(&mut command)?;
    Ok(true)
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
    command.env("KIND_EXPERIMENTAL_PROVIDER", engine);
    command
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
    for loaded_image in [&run_image, &next_image, &build.operator_image.to_owned()] {
        run_command(kind_command(build.engine).args(["load", "docker-image", loaded_image, "--name", build.cluster]))?;
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
    Ok((format!("{name}:{tag}-{nanos}"), format!("{name}:{tag}-next-{nanos}")))
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
    Ok(())
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
    wait_for_rollout(cluster, "deployment/praxis-rollout")
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
        pod_tls_serial(cluster, pod)?;
    }
    apply_tls_secret(cluster, temp_dir, "rotated")?;
    let mut last_probe = "no probe completed".to_owned();
    for _ in 0..120 {
        let mut all_rotated = true;
        for pod in &pods {
            match pod_tls_serial(cluster, pod) {
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
        thread::sleep(Duration::from_secs(1));
    }
    Err(format!(
        "rotated TLS certificate was not served within 120 seconds; last probe: {last_probe}"
    ))
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
fn pod_tls_serial(cluster: &str, pod: &str) -> Result<String, String> {
    let pod_ip = kubectl(cluster, ["get", "pod", pod, "-o=jsonpath={.status.podIP}"])?;
    let pod_ip = pod_ip
        .trim()
        .parse::<IpAddr>()
        .map_err(|error| format!("parse pod IP for {pod}: {error}"))?;
    let connect_address = match pod_ip {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
    };
    let command = format!(
        "/usr/bin/timeout 5 /usr/bin/openssl s_client -connect {connect_address}:8443 -servername localhost </dev/null 2>/dev/null | /usr/bin/openssl x509 -noout -serial"
    );
    let output = kubectl(cluster, ["exec", "tls-probe", "--", "sh", "-c", &command])?;
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
    drain_and_uncordon(cluster, node)?;
    wait_for_ready_proxy_replicas(cluster)
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
    admin::observe_readiness(cluster)
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
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|error| format!("write kubectl input: {error}"))?;
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

/// Waits for both Praxis replicas to be ready and available.
fn wait_for_ready_proxy_replicas(cluster: &str) -> Result<(), String> {
    for _ in 0..120 {
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
        thread::sleep(Duration::from_secs(1));
    }
    Err("proxy replicas did not become ready and available".to_owned())
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

    #[test]
    fn deleted_pod_exits_remain_part_of_acceptance_checks() {
        let healthy = serde_json::json!({
            "type": "ADDED", "object": { "metadata": { "uid": "new-proxy" } }
        });
        let mut deleted = deleted_pod_event();
        check_pod_events(&format!("{deleted}\n{healthy}")).unwrap();
        *deleted
            .pointer_mut("/object/status/containerStatuses/0/state/terminated/exitCode")
            .unwrap() = 137.into();
        assert!(
            check_pod_events(&format!("{deleted}\n{healthy}"))
                .unwrap_err()
                .contains("SIGKILL")
        );
    }

    #[test]
    fn deleted_pods_must_have_observed_exits_within_grace() {
        let mut deleted = deleted_pod_event();
        *deleted
            .pointer_mut("/object/status/containerStatuses/0/state/terminated/finishedAt")
            .unwrap() = "2026-11-03T12:00:46Z".into();
        assert!(check_pod_events(&deleted.to_string()).unwrap_err().contains("deadline"));
        *deleted.pointer_mut("/object/status/containerStatuses/0/state").unwrap() =
            serde_json::json!({ "running": {} });
        assert!(
            check_pod_events(&deleted.to_string())
                .unwrap_err()
                .contains("no observed exit")
        );
    }

    #[test]
    fn pod_watch_must_capture_valid_events() {
        assert!(check_pod_events("").is_err());
        assert!(check_pod_events(r#"{"type":"ERROR","object":{"message":"expired"}}"#).is_err());
        assert!(check_pod_events(&format!("{}\n{{", deleted_pod_event())).is_err());
    }

    #[test]
    fn clean_exits_after_the_deletion_deadline_are_rejected() {
        let mut deleted = deleted_pod_event();
        *deleted
            .pointer_mut("/object/status/containerStatuses/0/state/terminated/finishedAt")
            .unwrap() = "2026-11-03T12:00:31Z".into();
        assert!(
            check_pod_events(&deleted.to_string()).unwrap_err().contains("deadline"),
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
        check_pod_events(&deleted.to_string()).unwrap();
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
        check_pod_events(&format!("{terminating}\n{deleted}")).unwrap();
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
            check_pod_events(&format!("{terminating}\n{deleted}"))
                .unwrap_err()
                .contains("deadline")
        );
    }
}
