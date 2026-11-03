// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! KIND rollout acceptance harness for the Kubernetes reference base.

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
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, ValueEnum};
use praxis_test_utils::{ContinuousLoadDriver, https_client_config, tls_serial, write_test_certificate};
use tempfile::{NamedTempFile, TempDir};

/// Retains pod lifecycle events, including containers removed during rollouts.
struct PodWatch {
    /// Watch process, stopped even when a scenario returns an error.
    child: Child,
    /// JSON event stream retained until the acceptance assertions finish.
    events: NamedTempFile,
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
                "app.kubernetes.io/name=praxis",
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
        check_pod_exit(pod, false)?;
        let uid = pod
            .pointer("/metadata/uid")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "pod watch omitted UID".to_owned())?;
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
        check_pod_exit(pod, terminating)?;
    }
    Ok(())
}

/// Rejects SIGKILL and requires terminating pods to have exited by their deadline.
fn check_pod_exit(pod: &serde_json::Value, terminating: bool) -> Result<(), String> {
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
            let deadline = pod
                .pointer("/metadata/deletionTimestamp")
                .and_then(|value| value.as_str())
                .ok_or_else(|| format!("terminating pod has no deletion deadline: {pod}"))?;
            let finished = chrono::DateTime::parse_from_rfc3339(finished).map_err(|error| error.to_string())?;
            let deadline = chrono::DateTime::parse_from_rfc3339(deadline).map_err(|error| error.to_string())?;
            if finished > deadline {
                return Err(format!("container exceeded its termination deadline: {pod}"));
            }
        }
    }
    Ok(())
}

/// Command-line options for `cargo xtask rollout`.
#[derive(Debug, Parser)]
pub(crate) struct Args {
    /// KIND cluster name.
    #[arg(long, default_value = "praxis-rollout")]
    cluster_name: String,

    /// Data-plane image loaded into KIND.
    #[arg(long, default_value = "localhost/praxis:rollout")]
    image: String,

    /// Directory containing the operator-owned rollout-test kustomization.
    #[arg(long, default_value = "../operator/deploy/rollout-test")]
    manifest_dir: PathBuf,

    /// Scenarios to run; repeat the flag for a subset.
    #[arg(long, value_enum)]
    scenarios: Vec<Scenario>,

    /// Keep the KIND cluster after the run.
    #[arg(long)]
    keep_cluster: bool,

    /// Reuse the local image, skipping the build but loading it into KIND.
    #[arg(long)]
    skip_build: bool,
}

/// Rollout scenarios exercised under continuous HTTP/1.1 and HTTP/2 load.
#[derive(Clone, Copy, Debug, ValueEnum)]
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
pub(crate) fn run(args: &Args) -> Result<(), String> {
    let engine = env::var("CONTAINER_ENGINE").unwrap_or_else(|_| "docker".to_owned());
    check_prerequisites(&engine)?;
    let image = qualified_image(&args.image)?;
    create_cluster(&args.cluster_name, &engine)?;
    let (image, next_image) = build_and_load_image(&engine, &args.cluster_name, &image, args.skip_build)?;

    let temp_dir = TempDir::new().map_err(|error| format!("create temporary directory: {error}"))?;
    write_test_certificate(&temp_dir, "tls")?;
    write_test_certificate(&temp_dir, "rotated")?;
    let client_config = https_client_config(&[temp_dir.path().join("tls.crt"), temp_dir.path().join("rotated.crt")])?;
    let manifest_dir = args.manifest_dir.to_string_lossy();
    let manifest = kubectl(&args.cluster_name, ["kustomize", manifest_dir.as_ref()])?;
    let manifest = manifest.replace("image: localhost/praxis:rollout", &format!("image: {image}"));
    kubectl_stdin(&args.cluster_name, ["apply", "-f", "-"], &manifest)?;
    kubectl(&args.cluster_name, ["rollout", "restart", "deployment/praxis"])?;
    apply_tls_secret(&args.cluster_name, &temp_dir, "tls")?;
    for deployment in ["praxis", "backend", "healthy-backend"] {
        wait_for_rollout(&args.cluster_name, &format!("deployment/{deployment}"))?;
    }

    let http_endpoint = local_endpoint(30080);
    let https_endpoint = local_endpoint(30443);
    wait_for_body(&http_endpoint, "/", "ok", 120)?;
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
    let scenarios = if args.scenarios.is_empty() {
        Scenario::value_variants().to_vec()
    } else {
        args.scenarios.clone()
    };

    for scenario in scenarios {
        println!("==> rollout scenario: {scenario:?}");
        match scenario {
            Scenario::PodDelete => delete_pod(&args.cluster_name)?,
            Scenario::RollingUpdate => rolling_update(&args.cluster_name, &next_image)?,
            Scenario::ConfigHotReload => config_hot_reload(&args.cluster_name, &http_endpoint)?,
            Scenario::ConfigRollout => config_rollout(&args.cluster_name)?,
            Scenario::TlsRotation => rotate_tls(&args.cluster_name, &temp_dir, &https_endpoint)?,
            Scenario::NodeDrain => drain_node(&args.cluster_name)?,
            Scenario::UpstreamDown => upstream_down(&args.cluster_name)?,
        }
        wait_for_termination(&args.cluster_name)?;
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
        "==> rollout passed: {} HTTP/1.1, {} HTTP/2, and {} HTTPS requests, zero failures",
        report.http1, report.http2, report.https
    );

    if !args.keep_cluster {
        run_command(kind_command(&engine).args(["delete", "cluster", "--name", &args.cluster_name]))?;
    }
    Ok(())
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
                "app.kubernetes.io/name=praxis",
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

/// Verifies tools required by the harness.
fn check_prerequisites(engine: &str) -> Result<(), String> {
    for command in ["cargo", engine, "kind", "openssl"] {
        if !command_available(Command::new(command).arg("--version")) {
            return Err(format!("required command is unavailable: {command}"));
        }
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
fn create_cluster(name: &str, engine: &str) -> Result<(), String> {
    let clusters = kind_command(engine).arg("get").arg("clusters").output();
    if let Ok(output) = clusters
        && String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|cluster| cluster == name)
    {
        return Ok(());
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
    run_command(&mut command)
}

/// Uses the selected provider for every KIND operation, including image loads.
fn kind_command(engine: &str) -> Command {
    let mut command = Command::new("kind");
    command.env("KIND_EXPERIMENTAL_PROVIDER", engine);
    command
}

/// Builds the proxy image and loads it, plus its update tag, into KIND.
///
/// Returns the unique run and rolling-update image references.
fn build_and_load_image(
    engine: &str,
    cluster: &str,
    image: &str,
    skip_build: bool,
) -> Result<(String, String), String> {
    let (run_image, next_image) = unique_images(image)?;
    if !skip_build {
        run_command(Command::new(engine).args(["build", "-t", &run_image, "-f", "Containerfile", "."]))?;
    }
    run_command(Command::new(engine).args(["tag", image, &run_image]))?;
    run_command(Command::new(engine).args(["tag", image, &next_image]))?;
    for loaded_image in [&run_image, &next_image] {
        run_command(kind_command(engine).args(["load", "docker-image", loaded_image, "--name", cluster]))?;
    }
    Ok((run_image, next_image))
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
    kubectl_stdin(cluster, ["apply", "-f", "-"], &manifest)?;
    Ok(())
}

/// Deletes one data-plane pod and waits for the Deployment to restore it.
fn delete_pod(cluster: &str) -> Result<(), String> {
    let pods = kubectl(
        cluster,
        ["get", "pods", "-l", "app.kubernetes.io/name=praxis", "-o=name"],
    )?;
    let pod = pods
        .lines()
        .next()
        .ok_or_else(|| "no Praxis pod to delete".to_owned())?;
    kubectl(cluster, ["delete", pod, "--wait=true", "--timeout=35s"])?;
    wait_for_rollout(cluster, "deployment/praxis")
}

/// Changes the proxy image tag and waits for a zero-unavailable rollout.
fn rolling_update(cluster: &str, image: &str) -> Result<(), String> {
    let (name, tag) = image
        .rsplit_once(':')
        .ok_or_else(|| format!("image must be tagged: {image}"))?;
    let next = format!("{name}:{tag}-next");
    kubectl(
        cluster,
        ["set", "image", "deployment/praxis", &format!("praxis={next}")],
    )?;
    wait_for_rollout(cluster, "deployment/praxis")
}

/// Changes a hot-reloadable static response and waits for it to be served.
fn config_hot_reload(cluster: &str, endpoint: &str) -> Result<(), String> {
    let before = pod_identity(cluster)?;
    replace_config_value(cluster, "config-v1", "config-v2")?;
    wait_for_body(endpoint, "/config-version", "config-v2", 120)?;
    if pod_identity(cluster)? != before {
        return Err("config hot reload restarted a proxy".to_owned());
    }
    Ok(())
}

/// Changes runtime threads, restarts the Deployment, and waits for rollout.
fn config_rollout(cluster: &str) -> Result<(), String> {
    replace_config_value(cluster, "threads: 1", "threads: 2")?;
    kubectl(cluster, ["rollout", "restart", "deployment/praxis"])?;
    wait_for_rollout(cluster, "deployment/praxis")
}

/// Patches the `ConfigMap` by replacing one literal value.
fn replace_config_value(cluster: &str, old: &str, new: &str) -> Result<(), String> {
    let current = kubectl(
        cluster,
        ["get", "configmap", "praxis-config", "-o=jsonpath={.data.config\\.yaml}"],
    )?;
    let updated = current.replacen(old, new, 1);
    if updated == current {
        return Err(format!("ConfigMap did not contain expected value: {old}"));
    }
    let patch = format!(
        r#"{{"data":{{"config.yaml":{}}}}}"#,
        serde_json::to_string(&updated).map_err(|e| e.to_string())?
    );
    kubectl(
        cluster,
        ["patch", "configmap", "praxis-config", "--type=merge", "-p", &patch],
    )?;
    Ok(())
}

/// Replaces the TLS Secret and verifies every proxy serves the new serial.
fn rotate_tls(cluster: &str, temp_dir: &TempDir, endpoint: &str) -> Result<(), String> {
    let identity = pod_identity(cluster)?;
    let before = tls_serial(endpoint)?;
    let pod_endpoints = pod_tls_endpoints(cluster)?;
    apply_tls_secret(cluster, temp_dir, "rotated")?;
    for _ in 0..120 {
        let all_rotated = pod_endpoints
            .iter()
            .map(|pod_endpoint| tls_serial(pod_endpoint).map(|serial| serial != before))
            .all(|result| matches!(result, Ok(true)));
        if all_rotated {
            if pod_identity(cluster)? != identity {
                return Err("certificate rotation restarted a proxy".to_owned());
            }
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err("rotated TLS certificate was not served within 120 seconds".to_owned())
}

/// Returns the direct TLS endpoint of every Praxis pod.
fn pod_tls_endpoints(cluster: &str) -> Result<Vec<String>, String> {
    let addresses = kubectl(
        cluster,
        [
            "get",
            "pods",
            "-l",
            "app.kubernetes.io/name=praxis",
            "-o=jsonpath={range .items[*]}{.status.podIP}{'\\n'}{end}",
        ],
    )?;
    Ok(addresses.lines().map(|address| format!("{address}:8443")).collect())
}

/// Returns pod UIDs and restart counts in stable name order.
fn pod_identity(cluster: &str) -> Result<String, String> {
    kubectl(
        cluster,
        [
            "get",
            "pods",
            "-l",
            "app.kubernetes.io/name=praxis",
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
            "app.kubernetes.io/name=praxis",
            "-o=jsonpath={.items[0].spec.nodeName}",
        ],
    )?;
    let node = nodes.trim();
    if node.is_empty() {
        return Err("no worker hosting a Praxis pod found".to_owned());
    }
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
    drained?;
    uncordoned?;
    wait_for_rollout(cluster, "deployment/praxis")
}

/// Scales the test upstream to zero, asserts proxy readiness, and restores it.
fn upstream_down(cluster: &str) -> Result<(), String> {
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
    thread::sleep(Duration::from_secs(5));
    let ready = kubectl(
        cluster,
        ["get", "deployment/praxis", "-o=jsonpath={.status.readyReplicas}"],
    )?;
    if ready != "2" {
        return Err(format!(
            "proxy lost readiness with test upstream down: {ready} ready replicas"
        ));
    }
    kubectl(cluster, ["scale", "deployment/backend", "--replicas=2"])?;
    wait_for_rollout(cluster, "deployment/backend")
}

/// Runs `kubectl` in the rollout cluster and returns stdout.
fn kubectl<I, S>(cluster: &str, args: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new("kubectl");
    command
        .arg("--context")
        .arg(format!("kind-{cluster}"))
        .arg("--namespace")
        .arg("praxis");
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
    let mut command = Command::new("kubectl");
    command
        .arg("--context")
        .arg(format!("kind-{cluster}"))
        .arg("--namespace")
        .arg("praxis")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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

/// Waits for a Deployment rollout.
fn wait_for_rollout(cluster: &str, resource: &str) -> Result<(), String> {
    kubectl(cluster, ["rollout", "status", resource, "--timeout=240s"]).map(|output| println!("{}", output.trim_end()))
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
mod tests {
    use super::*;

    #[test]
    fn all_rollout_scenarios_are_selected_by_default() {
        assert_eq!(
            Scenario::value_variants().len(),
            7,
            "every acceptance scenario must be represented"
        );
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

    /// A deleted pod whose observed exit precedes its Kubernetes deadline.
    fn deleted_pod_event() -> serde_json::Value {
        serde_json::json!({
            "type": "DELETED",
            "object": {
                "metadata": { "uid": "old-proxy", "deletionTimestamp": "2026-11-03T12:00:30Z" },
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
            .unwrap() = "2026-11-03T12:00:31Z".into();
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
}
