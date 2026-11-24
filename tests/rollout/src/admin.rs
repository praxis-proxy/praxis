// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Acceptance checks for the dedicated health and metrics listener.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use serde_json::Value;

use super::{kubectl, pod_http_body, proxy_pod_names, proxy_pods};

/// Dedicated listener used by the operator's probes and scrapers.
const METRICS_PORT: u64 = 9902;

/// Minimum observation window for delayed readiness failures.
const MIN_READINESS_OBSERVATION_SECONDS: u64 = 15;

/// Checks the actual probe/config wiring and scrapes both proxy replicas.
pub(super) fn check(cluster: &str) -> Result<(), String> {
    let pods = proxy_pods(cluster)?;
    let names = proxy_pod_names(&pods)?;
    for pod in pod_items(&pods)? {
        let container = proxy_container(pod)?;
        check_probes(container)?;
        check_config_mount(container)?;
        let configmap = configmap_name(pod)?;
        let config = kubectl(
            cluster,
            ["get", "configmap", configmap, "-o=jsonpath={.data.config\\.yaml}"],
        )?;
        check_config(&config)?;
    }
    for name in names {
        check_health_status(&metrics_body(cluster, &name, "/healthy")?)
            .map_err(|error| format!("proxy {name} metrics health: {error}"))?;
        check_request_counter(cluster, &name).map_err(|error| format!("proxy {name}: {error}"))?;
    }
    println!("==> admin probes, configuration, and metrics passed on both replicas (port {METRICS_PORT})");
    Ok(())
}

/// Requires a replica's request counters to advance after a data-plane request.
fn check_request_counter(cluster: &str, pod: &str) -> Result<(), String> {
    let before = check_metrics(&metrics_body(cluster, pod, "/metrics")?)?.unwrap_or(0.0);
    if pod_http_body(cluster, pod, "/healthy")?.trim() != "ok" {
        return Err("proxy did not serve the healthy backend fixture".to_owned());
    }
    wait_for_counter_increase(before, 20, Duration::from_millis(250), || {
        check_metrics(&metrics_body(cluster, pod, "/metrics")?)
    })
}

/// Allows asynchronous request completion while rejecting a frozen counter.
fn wait_for_counter_increase(
    before: f64,
    samples: u64,
    interval: Duration,
    mut read: impl FnMut() -> Result<Option<f64>, String>,
) -> Result<(), String> {
    for index in 0..samples {
        if read()?.is_some_and(|total| total > before) {
            return Ok(());
        }
        if index < samples.saturating_sub(1) {
            thread::sleep(interval);
        }
    }
    Err(format!(
        "praxis_http_requests_total did not advance beyond {before} after the seeded request"
    ))
}

/// Samples both replicas' readiness until the caller stops it.
pub(super) struct ReadinessMonitor {
    /// Shared stop flag for the sampling loop.
    stop: Arc<AtomicBool>,
    /// Sampling loop; joins to the first readiness failure.
    handle: thread::JoinHandle<Result<(), String>>,
}

impl ReadinessMonitor {
    /// Starts sampling before the outage begins.
    ///
    /// Returns the monitor and the minimum outage window that must follow, so
    /// callers can keep sampling from before the disruption through the whole
    /// window instead of starting only after it completes.
    pub(super) fn start(cluster: &str) -> Result<(Self, u64), String> {
        let seconds = readiness_window(&proxy_pods(cluster)?)?;
        println!("==> observing both replicas' readiness for at least {seconds} seconds with upstream down");
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let cluster = cluster.to_owned();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            let mut first = true;
            run_readiness_samples(&thread_stop, Duration::from_secs(1), || {
                let pods = proxy_pods(&cluster)?;
                for name in ready_pod_names(&pods)? {
                    let body = metrics_body(&cluster, &name, "/ready")?;
                    check_health_status(&body).map_err(|error| format!("proxy {name} lost readiness: {error}"))?;
                }
                if first {
                    let _first_sample = ready_tx.send(());
                    first = false;
                }
                Ok(())
            })
        });
        if ready_rx.recv().is_err() {
            // The worker stopped before its first sample; surface its error.
            let error = match handle
                .join()
                .map_err(|payload| format!("readiness monitor panicked: {payload:?}"))?
            {
                Ok(()) => "readiness monitor stopped before its first sample".to_owned(),
                Err(error) => error,
            };
            return Err(error);
        }
        Ok((Self { stop, handle }, seconds))
    }

    /// Stops sampling and reports the first readiness failure.
    pub(super) fn finish(self) -> Result<(), String> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle
            .join()
            .map_err(|payload| format!("readiness monitor panicked: {payload:?}"))?
    }
}

/// Samples until stopped, returning the first failure.
fn run_readiness_samples(
    stop: &AtomicBool,
    interval: Duration,
    mut check: impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    while !stop.load(Ordering::Relaxed) {
        check()?;
        thread::sleep(interval);
    }
    Ok(())
}

/// Holds the outage for at least two configured readiness failure windows.
fn readiness_window(pods: &Value) -> Result<u64, String> {
    proxy_pod_names(pods)?;
    let mut seconds = MIN_READINESS_OBSERVATION_SECONDS;
    for pod in pod_items(pods)? {
        let container = proxy_container(pod)?;
        check_probes(container)?;
        let period = container
            .pointer("/readinessProbe/periodSeconds")
            .and_then(Value::as_u64)
            .unwrap_or(10);
        let failures = container
            .pointer("/readinessProbe/failureThreshold")
            .and_then(Value::as_u64)
            .unwrap_or(3);
        seconds = seconds.max(period.saturating_mul(failures).saturating_mul(2));
    }
    Ok(seconds)
}

/// Requires both Running replicas to retain the Kubernetes Ready condition.
fn ready_pod_names(pods: &Value) -> Result<Vec<String>, String> {
    let names = proxy_pod_names(pods)?;
    for pod in pod_items(pods)? {
        let ready = pod
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .is_some_and(|conditions| {
                conditions.iter().any(|condition| {
                    condition.get("type").and_then(Value::as_str) == Some("Ready")
                        && condition.get("status").and_then(Value::as_str) == Some("True")
                })
            });
        if !ready {
            return Err(format!("proxy lost its Pod Ready condition: {pod}"));
        }
    }
    Ok(names)
}

/// Verifies every health probe targets the dedicated listener and expected path.
fn check_probes(container: &Value) -> Result<(), String> {
    for (kind, path) in [
        ("livenessProbe", "/healthy"),
        ("readinessProbe", "/ready"),
        ("startupProbe", "/healthy"),
    ] {
        let http = container.get(kind).and_then(|probe| probe.get("httpGet"));
        let valid = http.is_some_and(|http| {
            http.get("path").and_then(Value::as_str) == Some(path)
                && probe_port(container, http) == Some(METRICS_PORT)
                && http.get("host").and_then(Value::as_str).is_none_or(str::is_empty)
        });
        if !valid {
            return Err(format!(
                "{kind} must use {path} on the pod's metrics port {METRICS_PORT}"
            ));
        }
    }
    Ok(())
}

/// Verifies the operator's explicit config argument reads the projected file.
fn check_config_mount(container: &Value) -> Result<(), String> {
    let args = serde_json::json!(["--config", "/etc/praxis/config.yaml"]);
    let mounted = container
        .get("volumeMounts")
        .and_then(Value::as_array)
        .is_some_and(|mounts| {
            mounts.iter().any(|mount| {
                mount.get("name").and_then(Value::as_str) == Some("config")
                    && mount.get("mountPath").and_then(Value::as_str) == Some("/etc/praxis")
                    && mount.get("subPath").is_none()
                    && mount.get("subPathExpr").is_none()
            })
        });
    if container.get("args") != Some(&args) || !mounted {
        return Err("proxy must load --config /etc/praxis/config.yaml from its config directory mount".to_owned());
    }
    Ok(())
}

/// Resolves numeric and named probe ports against the proxy container.
fn probe_port(container: &Value, http: &Value) -> Option<u64> {
    let port = http.get("port")?;
    port.as_u64().or_else(|| {
        let name = port.as_str()?;
        container
            .get("ports")?
            .as_array()?
            .iter()
            .find(|candidate| candidate.get("name").and_then(Value::as_str) == Some(name))?
            .get("containerPort")?
            .as_u64()
    })
}

/// Checks the generated YAML leaves the public admin override unset.
fn check_config(yaml: &str) -> Result<(), String> {
    let config: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|error| format!("parse proxy config: {error}"))?;
    if config
        .get("admin")
        .and_then(|admin| admin.get("metrics_address"))
        .and_then(serde_yaml::Value::as_str)
        != Some("0.0.0.0:9902")
    {
        return Err("proxy config must bind admin.metrics_address to 0.0.0.0:9902".to_owned());
    }
    if config
        .get("insecure_options")
        .and_then(|options| options.get("allow_public_admin"))
        .is_some()
    {
        return Err("proxy config must leave insecure_options.allow_public_admin unset".to_owned());
    }
    Ok(())
}

/// Requires the dedicated listener's JSON health status to be healthy.
fn check_health_status(body: &str) -> Result<(), String> {
    let health: Value = serde_json::from_str(body).map_err(|error| error.to_string())?;
    if health.get("status").and_then(Value::as_str) != Some("ok") {
        return Err(format!("health response was not ok: {body}"));
    }
    Ok(())
}

/// Sums finite request counters across label sets; absent samples precede use.
fn check_metrics(body: &str) -> Result<Option<f64>, String> {
    let mut total = None;
    for suffix in body.lines().filter_map(|line| {
        line.strip_prefix("praxis_http_requests_total")
            .filter(|suffix| suffix.starts_with('{') || suffix.starts_with(char::is_whitespace))
    }) {
        let value = request_counter_value(suffix)
            .ok_or_else(|| "metrics scrape contained a malformed praxis_http_requests_total sample".to_owned())?;
        let sum = total.unwrap_or(0.0) + value;
        if !sum.is_finite() {
            return Err("metrics request counter sum overflowed".to_owned());
        }
        total = Some(sum);
    }
    Ok(total)
}

/// Reads the sample value after optional labels and before an optional timestamp.
fn request_counter_value(suffix: &str) -> Option<f64> {
    let fields = if suffix.starts_with('{') {
        suffix.rsplit_once('}')?.1
    } else {
        suffix
    };
    fields
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value >= 0.0)
}

/// Reads from the metrics port through the Kubernetes pod proxy.
fn metrics_body(cluster: &str, pod: &str, path: &str) -> Result<String, String> {
    let proxy_path = format!("/api/v1/namespaces/praxis/pods/{pod}:{METRICS_PORT}/proxy{path}");
    kubectl(cluster, ["get", "--raw", &proxy_path]).map_err(|error| format!("proxy {pod} metrics-port {path}: {error}"))
}

/// Reads the `ConfigMap` actually referenced by the proxy's config volume.
fn configmap_name(pod: &Value) -> Result<&str, String> {
    pod.pointer("/spec/volumes")
        .and_then(Value::as_array)
        .and_then(|volumes| {
            volumes
                .iter()
                .find(|volume| volume.get("name").and_then(Value::as_str) == Some("config"))
        })
        .filter(|volume| volume.pointer("/configMap/items").is_none())
        .and_then(|volume| volume.pointer("/configMap/name"))
        .and_then(Value::as_str)
        .ok_or_else(|| "proxy config volume must project the complete ConfigMap without key remapping".to_owned())
}

/// Selects the proxy container independently of sidecar ordering.
fn proxy_container(pod: &Value) -> Result<&Value, String> {
    pod.pointer("/spec/containers")
        .and_then(Value::as_array)
        .and_then(|containers| {
            containers
                .iter()
                .find(|container| container.get("name").and_then(Value::as_str) == Some("praxis"))
        })
        .ok_or_else(|| "proxy pod omitted its praxis container".to_owned())
}

/// Reads the items of the Kubernetes pod list.
fn pod_items(pods: &Value) -> Result<&Vec<Value>, String> {
    pods.get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| "proxy pod list omitted items".to_owned())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "fixture mutations must address existing fields")]
mod tests {
    use super::*;

    /// Two ready proxies with the operator's health probe configuration.
    fn healthy_pods() -> Value {
        let items = (0..2)
            .map(|index| {
                serde_json::json!({
                    "metadata": {"name": format!("proxy-{index}")},
                    "spec": {
                        "volumes": [{"name": "config", "configMap": {"name": "praxis-rollout"}}],
                        "containers": [{
                            "name": "praxis",
                            "args": ["--config", "/etc/praxis/config.yaml"],
                            "volumeMounts": [{"name":"config", "mountPath":"/etc/praxis"}],
                            "ports": [{"name": "admin", "containerPort": 9902}],
                            "livenessProbe": {"httpGet": {"path": "/healthy", "port": 9902}},
                            "startupProbe": {"httpGet": {"path": "/healthy", "port": 9902}},
                            "readinessProbe": {
                                "httpGet": {"path": "/ready", "port": 9902},
                                "periodSeconds": 3,
                                "failureThreshold": 2
                            }
                        }]
                    },
                    "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({"items": items})
    }

    #[test]
    fn probes_must_use_the_dedicated_metrics_port() {
        let pods = healthy_pods();
        let original = proxy_container(pod_items(&pods).unwrap().first().unwrap()).unwrap();
        check_probes(original).unwrap();
        let mut named = original.clone();
        *named.pointer_mut("/readinessProbe/httpGet/port").unwrap() = "admin".into();
        check_probes(&named).unwrap();
        for (path, value) in [
            ("/readinessProbe/httpGet/port", serde_json::json!(9901)),
            ("/livenessProbe/httpGet/path", serde_json::json!("/api/stats")),
            ("/startupProbe/httpGet", serde_json::json!({"path": "/healthy"})),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(path).unwrap() = value;
            assert!(
                check_probes(&invalid).is_err(),
                "invalid probe {path} must fail acceptance"
            );
        }
        named
            .pointer_mut("/readinessProbe/httpGet")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("host".to_owned(), "another-host".into());
        assert!(check_probes(&named).is_err(), "probes must reach this pod");
    }

    #[test]
    fn validated_config_must_be_loaded_by_the_proxy_container() {
        let pods = healthy_pods();
        let original = proxy_container(pod_items(&pods).unwrap().first().unwrap()).unwrap();
        check_config_mount(original).unwrap();
        for (path, value) in [
            ("/volumeMounts", serde_json::json!([])),
            ("/volumeMounts/0/mountPath", serde_json::json!("/unused")),
            ("/volumeMounts/0/name", serde_json::json!("another-volume")),
            ("/volumeMounts/0/subPath", serde_json::json!("config.yaml")),
            ("/args", serde_json::json!(["--config", "/another/config.yaml"])),
            ("/args", serde_json::json!([])),
        ] {
            let mut invalid = original.clone();
            if path.ends_with("subPath") {
                invalid
                    .pointer_mut("/volumeMounts/0")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert("subPath".to_owned(), value);
            } else {
                *invalid.pointer_mut(path).unwrap() = value;
            }
            assert!(
                check_config_mount(&invalid).is_err(),
                "unused or misdirected config must fail: {path}"
            );
        }
        let mut remapped = pod_items(&pods).unwrap().first().unwrap().clone();
        remapped
            .pointer_mut("/spec/volumes/0/configMap")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "items".to_owned(),
                serde_json::json!([{"key":"config.yaml", "path":"unused.yaml"}]),
            );
        assert!(
            configmap_name(&remapped).is_err(),
            "the validated key must be projected at its expected filename"
        );
    }

    #[test]
    fn public_admin_override_must_remain_unset() {
        let base = "admin:\n  metrics_address: 0.0.0.0:9902\n";
        check_config(base).unwrap();
        for config in [
            "admin:\n  address: 0.0.0.0:9901\n".to_owned(),
            base.replace("9902", "9901"),
            format!("{base}insecure_options:\n  allow_public_admin: true\n"),
            format!("{base}insecure_options:\n  allow_public_admin: false\n"),
        ] {
            assert!(
                check_config(&config).is_err(),
                "unexpected admin configuration must fail: {config}"
            );
        }
    }

    #[test]
    fn health_checks_require_the_metrics_listener_json_response() {
        check_health_status(r#"{"status":"ok"}"#).unwrap();
        for body in ["ok", "", r#"{"status":"degraded"}"#, r#"{"other":"ok"}"#] {
            assert!(
                check_health_status(body).is_err(),
                "invalid health response must fail: {body}"
            );
        }
    }

    #[test]
    fn scrape_requires_proxy_request_metric_samples() {
        assert_eq!(
            check_metrics(
                "# TYPE praxis_http_requests_total counter\npraxis_http_requests_total{listener=\"http\"} 1\n"
            )
            .unwrap(),
            Some(1.0),
            "the sample value must be retained"
        );
        assert_eq!(check_metrics("praxis_http_requests_total 2.0\n").unwrap(), Some(2.0));
        assert_eq!(
            check_metrics("praxis_http_requests_total{route=\"/with spaces\"} 1e3 12345\n").unwrap(),
            Some(1000.0),
            "labels and timestamps must not affect the value"
        );
        for body in [
            "praxis_http_requests_total not-a-number\n",
            "praxis_http_requests_total{listener=\"http\"} not-a-number 12345\n",
            "praxis_http_requests_total NaN\n",
            "praxis_http_requests_total -1\n",
            "praxis_http_requests_total 1\npraxis_http_requests_total{listener=\"http\"} not-a-number\n",
            "praxis_http_requests_total{listener=\"one\"} 1e308\npraxis_http_requests_total{listener=\"two\"} 1e308\n",
        ] {
            assert!(
                check_metrics(body).is_err(),
                "empty or unrelated scrape must fail: {body}"
            );
        }
    }

    #[test]
    fn counter_progress_sums_labels_and_waits_for_completion() {
        let before = check_metrics("praxis_http_requests_total{route=\"old\"} 4\n")
            .unwrap()
            .unwrap();
        let mut scrapes = [
            "praxis_http_requests_total{route=\"old\"} 4\n",
            "praxis_http_requests_total{route=\"old\"} 4\npraxis_http_requests_total{route=\"new\"} 1\n",
        ]
        .into_iter();
        let mut samples = 0_u64;
        wait_for_counter_increase(before, 2, Duration::ZERO, || {
            samples = samples.saturating_add(1);
            check_metrics(scrapes.next().unwrap())
        })
        .unwrap();
        assert_eq!(samples, 2, "a delayed increment in a new label set must pass");
    }

    #[test]
    fn counter_progress_rejects_missing_frozen_and_decreasing_samples() {
        for (before, body) in [
            (0.0, ""),
            (0.0, "ok"),
            (0.0, "# TYPE praxis_http_requests_total counter\n"),
            (0.0, "praxis_http_requests_total_other 1\n"),
            (0.0, "praxis_http_requests_total 0\n"),
            (5.0, "praxis_http_requests_total 5\n"),
            (5.0, "praxis_http_requests_total 4\n"),
        ] {
            assert!(
                wait_for_counter_increase(before, 2, Duration::ZERO, || check_metrics(body)).is_err(),
                "absent or stalled metrics must fail even with an old positive sample: {body}"
            );
        }
        let mut scrapes = ["", "praxis_http_requests_total 1\n"].into_iter();
        wait_for_counter_increase(0.0, 2, Duration::ZERO, || check_metrics(scrapes.next().unwrap())).unwrap();
        assert!(
            wait_for_counter_increase(0.0, 2, Duration::ZERO, || check_metrics(
                "praxis_http_requests_total NaN\n"
            ))
            .is_err(),
            "malformed samples must fail rather than be retried"
        );
    }

    #[test]
    fn outage_window_covers_multiple_probe_failure_cycles() {
        let mut pods = healthy_pods();
        assert_eq!(
            readiness_window(&pods).unwrap(),
            15,
            "the short probes need at least fifteen seconds"
        );
        *pods
            .pointer_mut("/items/1/spec/containers/0/readinessProbe/periodSeconds")
            .unwrap() = 10.into();
        *pods
            .pointer_mut("/items/1/spec/containers/0/readinessProbe/failureThreshold")
            .unwrap() = 3.into();
        assert_eq!(
            readiness_window(&pods).unwrap(),
            60,
            "the slowest replica determines two failure windows"
        );
    }

    #[test]
    fn running_replicas_must_each_keep_their_ready_condition() {
        let mut pods = healthy_pods();
        ready_pod_names(&pods).unwrap();
        *pods.pointer_mut("/items/1/status/conditions/0/status").unwrap() = "False".into();
        assert!(
            ready_pod_names(&pods).is_err(),
            "one unready replica must fail despite both pods Running"
        );
    }

    #[test]
    fn the_readiness_monitor_surfaces_a_worker_failure_and_keeps_sampling() {
        let stop = AtomicBool::new(false);
        let mut samples = 0_u64;
        let outcome = run_readiness_samples(&stop, Duration::ZERO, || {
            samples = samples.saturating_add(1);
            if samples == 3 {
                return Err("proxy lost readiness".to_owned());
            }
            Ok(())
        });
        assert_eq!(samples, 3, "the monitor must sample until the failure, not skip it");
        assert!(
            outcome.unwrap_err().contains("lost readiness"),
            "the worker error must reach the caller"
        );
    }

    #[test]
    fn a_readiness_failure_after_the_original_window_is_rejected() {
        let stop = AtomicBool::new(false);
        let mut samples = 0_u64;
        let outcome = run_readiness_samples(&stop, Duration::ZERO, || {
            samples = samples.saturating_add(1);
            if samples == 7 {
                return Err("proxy returned HTTP 503".to_owned());
            }
            Ok(())
        });
        assert_eq!(
            samples, 7,
            "readiness must still be sampled after the old five-second cutoff"
        );
        assert!(
            outcome.unwrap_err().contains("503"),
            "a delayed failure must not be hidden by later recovery"
        );

        let healthy_stop = AtomicBool::new(false);
        let mut successful_samples = 0_u64;
        run_readiness_samples(&healthy_stop, Duration::ZERO, || {
            successful_samples = successful_samples.saturating_add(1);
            if successful_samples == 16 {
                healthy_stop.store(true, Ordering::Relaxed);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(
            successful_samples, 16,
            "healthy observations must span the complete window"
        );
    }
}
