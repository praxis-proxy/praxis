// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Hook-specific activity and streaming recorder lifetime regressions.

use std::{
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Method};
use metrics::{Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit};
use metrics_exporter_prometheus::{PrometheusHandle, PrometheusRecorder};
use praxis_core::config::FailureMode;

use super::make_pipeline;
use crate::{
    BodyAccess, BodyRequirement, FilterAction, FilterError, HttpFilter, HttpFilterContext,
    any_filter::AnyFilter,
    pipeline::{filter::PipelineFilter, http_utils::run_request_head_filter},
    tcp_filter::{TcpFilter, TcpFilterContext},
};

#[test]
fn response_body_activity_reuses_handles_within_each_request_and_recorder() {
    assert_body_activity_uses_request_recorders(false);
}

#[test]
fn request_body_activity_reuses_handles_within_each_request_and_recorder() {
    assert_body_activity_uses_request_recorders(true);
}

/// Reuse one pipeline across requests without reusing their recorder handles.
fn assert_body_activity_uses_request_recorders(request_body: bool) {
    let recorders = [recorder(), recorder()];
    let pipeline = make_pipeline(vec![Box::new(HookProbe {
        filter: "body_activity_probe",
        handle: recorders[0].1.clone(),
    })]);
    for (recorder, handle) in &recorders {
        let request = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&request);
        ctx.extensions.insert(handle.clone());
        metrics::with_local_recorder(recorder, || {
            for chunk in [b"first".as_slice(), b"second".as_slice()] {
                let mut body = Some(Bytes::copy_from_slice(chunk));
                if request_body {
                    drop(run_ready(pipeline.execute_http_request_body(&mut ctx, &mut body, false)).unwrap());
                } else {
                    drop(pipeline.execute_http_response_body(&mut ctx, &mut body, false).unwrap());
                }
                assert!(sample(handle, "body_activity_probe").abs() < f64::EPSILON);
            }
        });
        assert_eq!(
            recorder.registrations.load(Ordering::Relaxed),
            1,
            "both chunks must reuse one handle from this request's recorder"
        );
    }
    for (_, handle) in &recorders {
        assert!(sample(handle, "body_activity_probe").abs() < f64::EPSILON);
    }
}

#[test]
fn request_head_activity_is_visible_inside_the_hook_and_cleared_afterward() {
    let (recorder, handle) = recorder();
    let probe = HookProbe {
        filter: "head_activity_probe",
        handle: handle.clone(),
    };
    let request = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&request);
    metrics::with_local_recorder(&recorder, || {
        assert!(
            run_ready(run_request_head_filter(&probe, &mut ctx, FailureMode::Closed, false))
                .unwrap()
                .is_none()
        );
        assert!(sample(&handle, probe.filter).abs() < f64::EPSILON);
    });
}

#[test]
fn response_trailer_activity_is_visible_inside_the_hook_and_cleared_afterward() {
    let (recorder, handle) = recorder();
    let mut pipeline = make_pipeline(vec![Box::new(HookProbe {
        filter: "trailer_activity_probe",
        handle: handle.clone(),
    })]);
    pipeline.response_trailer_filter_indices =
        crate::pipeline::body::response_trailer_filter_indices(&pipeline.filters);
    let request = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&request);
    metrics::with_local_recorder(&recorder, || {
        assert!(
            pipeline
                .execute_http_response_trailers(&mut ctx, &mut HeaderMap::new())
                .unwrap()
                .is_none()
        );
        assert!(sample(&handle, "trailer_activity_probe").abs() < f64::EPSILON);
    });
}

#[test]
fn tcp_connect_activity_is_visible_inside_the_hook_and_cleared_afterward() {
    let (recorder, handle) = recorder();
    let pipeline = tcp_pipeline(HookProbe {
        filter: "connect_activity_probe",
        handle: handle.clone(),
    });
    metrics::with_local_recorder(&recorder, || {
        drop(run_ready(pipeline.execute_tcp_connect(&mut tcp_context())).unwrap());
        assert!(sample(&handle, "connect_activity_probe").abs() < f64::EPSILON);
    });
}

#[test]
fn tcp_disconnect_activity_is_visible_inside_the_hook_and_cleared_afterward() {
    let (recorder, handle) = recorder();
    let pipeline = tcp_pipeline(HookProbe {
        filter: "disconnect_activity_probe",
        handle: handle.clone(),
    });
    metrics::with_local_recorder(&recorder, || {
        run_ready(pipeline.execute_tcp_disconnect(&mut tcp_context())).unwrap();
        assert!(sample(&handle, "disconnect_activity_probe").abs() < f64::EPSILON);
    });
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Filter that checks the active gauge from inside each instrumented hook.
struct HookProbe {
    /// Registered type label for this test's isolated metric series.
    filter: &'static str,
    /// Recorder handle independent of ambient recorder lookup.
    handle: PrometheusHandle,
}

impl HookProbe {
    /// Body hooks inspect the recorder owned by the current request.
    fn assert_body_active(&self, ctx: &HttpFilterContext<'_>) {
        let handle = ctx.extensions.get::<PrometheusHandle>().unwrap();
        assert!((sample(handle, self.filter) - 1.0).abs() < f64::EPSILON);
    }

    /// Require exactly one active invocation while this hook executes.
    fn assert_active(&self) {
        assert!(
            (sample(&self.handle, self.filter) - 1.0).abs() < f64::EPSILON,
            "{} must be active inside its hook",
            self.filter
        );
    }
}

#[async_trait]
impl HttpFilter for HookProbe {
    fn name(&self) -> &'static str {
        self.filter
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_head(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.assert_active();
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.assert_body_active(ctx);
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.assert_body_active(ctx);
        Ok(FilterAction::Continue)
    }

    fn on_response_trailers(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _trailers: &mut HeaderMap,
    ) -> Result<Option<Bytes>, FilterError> {
        self.assert_active();
        Ok(None)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Optional)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Optional)
    }

    fn response_trailer_access(&self) -> bool {
        true
    }
}

#[async_trait]
impl TcpFilter for HookProbe {
    fn name(&self) -> &'static str {
        self.filter
    }

    async fn on_connect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.assert_active();
        Ok(FilterAction::Continue)
    }

    async fn on_disconnect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<(), FilterError> {
        self.assert_active();
        Ok(())
    }
}

/// Prometheus recorder that counts activity-handle registrations.
struct CountingRecorder {
    /// Delegate for metric values and exposition.
    inner: PrometheusRecorder,
    /// Number of activity registrations, independent of updates.
    registrations: AtomicUsize,
}

impl Recorder for CountingRecorder {
    fn describe_counter(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.inner.describe_counter(key, unit, description);
    }

    fn describe_gauge(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.inner.describe_gauge(key, unit, description);
    }

    fn describe_histogram(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.inner.describe_histogram(key, unit, description);
    }

    fn register_counter(&self, key: &Key, metadata: &Metadata<'_>) -> Counter {
        self.inner.register_counter(key, metadata)
    }

    fn register_gauge(&self, key: &Key, metadata: &Metadata<'_>) -> Gauge {
        if key.name() == "praxis_filter_active" {
            self.registrations.fetch_add(1, Ordering::Relaxed);
        }
        self.inner.register_gauge(key, metadata)
    }

    fn register_histogram(&self, key: &Key, metadata: &Metadata<'_>) -> Histogram {
        self.inner.register_histogram(key, metadata)
    }
}

/// Installable isolated recorder and a handle for checking live hook state.
fn recorder() -> (CountingRecorder, PrometheusHandle) {
    let inner = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = inner.handle();
    (
        CountingRecorder {
            inner,
            registrations: AtomicUsize::new(0),
        },
        handle,
    )
}

/// Parse exactly the requested activity series rather than matching a prefix value.
fn sample(handle: &PrometheusHandle, filter: &str) -> f64 {
    let prefix = format!("praxis_filter_active{{filter=\"{filter}\"}} ");
    handle
        .render()
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .expect("the hook must register its activity gauge")
        .parse()
        .expect("activity gauge values must be numeric")
}

/// Poll hooks that intentionally complete synchronously without a runtime.
fn run_ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("activity probe must complete in one poll"),
    }
}

/// Reuse the normal pipeline fixture while replacing its HTTP filter with TCP.
fn tcp_pipeline(probe: HookProbe) -> crate::FilterPipeline {
    let mut pipeline = make_pipeline(vec![]);
    pipeline.filters = vec![PipelineFilter::new(0, AnyFilter::Tcp(Box::new(probe)), vec![], vec![])];
    pipeline
}

/// Context independent of transport I/O for connect and disconnect hooks.
fn tcp_context() -> TcpFilterContext<'static> {
    TcpFilterContext {
        remote_addr: "127.0.0.1:12345",
        local_addr: "127.0.0.1:8080",
        sni: None,
        upstream_addr: None,
        cluster: None,
        health_registry: None,
        kv_stores: None,
        connect_time: std::time::Instant::now(),
        bytes_in: 0,
        bytes_out: 0,
    }
}
