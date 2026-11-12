// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Build the request metadata passed to the policy engine.

use std::sync::Arc;

use chrono::{DateTime, SecondsFormat, Utc};
use ppe::praxis_policy_core::extensions::RequestExtension;

use crate::{filter::HttpFilterContext, trace_context::TraceContext};

/// Build request metadata from the existing request ID, trace ID and clock.
/// The caller keeps this record so response checks use the same IDs and timestamp.
pub(super) fn get_request_context(ctx: &HttpFilterContext<'_>) -> Option<Arc<RequestExtension>> {
    let Some(trace) = ctx.extensions.get::<TraceContext>() else {
        tracing::debug!(target: "policy.filter", "no trace context; request IDs and timestamp will not be supplied");
        return None;
    };
    let now = ctx.time_source.now();
    let timestamp = i64::try_from(now.as_secs())
        .ok()
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, now.subsec_nanos()))
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true));
    Some(Arc::new(RequestExtension {
        request_id: Some(trace.request_id().to_owned()),
        trace_id: Some(trace.trace_id().to_owned()),
        timestamp,
        ..Default::default()
    }))
}

/// Add this policy filter's environment label, even when request IDs and the
/// timestamp are absent, so policy rules can still check the environment.
pub(super) fn with_environment(
    captured: Option<&Arc<RequestExtension>>,
    environment: Option<&str>,
) -> Option<Arc<RequestExtension>> {
    environment.map_or_else(
        || captured.cloned(),
        |environment| {
            let mut request = captured.map(|request| request.as_ref().clone()).unwrap_or_default();
            request.environment = Some(environment.to_owned());
            Some(Arc::new(request))
        },
    )
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use http::Method;
    use praxis_core::time::FixedTimeSource;
    use tracing_subscriber::prelude::*;

    use super::{get_request_context, with_environment};
    use crate::{
        test_utils::{make_filter_context, make_request},
        trace_context::TraceContext,
    };

    #[test]
    fn missing_trace_context_is_debug_logged_and_environment_still_works() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Capture(Arc::clone(&events)));
        tracing::subscriber::with_default(subscriber, || {
            let req = make_request(Method::GET, "/");
            let captured = get_request_context(&make_filter_context(&req));
            assert!(captured.is_none());
            assert!(with_environment(captured.as_ref(), None).is_none());
            let environment = with_environment(captured.as_ref(), Some("staging")).expect("environment-only context");
            assert_eq!(environment.environment.as_deref(), Some("staging"));
            assert!(environment.request_id.is_none());
            assert!(environment.trace_id.is_none());
            assert!(environment.timestamp.is_none());
            assert!(environment.span_id.is_none());
        });
        assert!(
            events
                .lock()
                .expect("events")
                .iter()
                .any(|(target, level)| *target == "policy.filter" && *level == tracing::Level::DEBUG)
        );
    }

    #[test]
    fn request_ids_are_preserved_when_the_clock_cannot_be_formatted() {
        let req = make_request(Method::GET, "/");
        for duration in [
            Duration::MAX,
            Duration::from_secs(u64::try_from(i64::MAX).expect("positive seconds")),
        ] {
            let clock = FixedTimeSource::new(duration);
            let mut ctx = make_filter_context(&req);
            ctx.extensions
                .insert(TraceContext::new("request".into(), "trace".into(), "01".into()));
            ctx.time_source = &clock;
            let captured = get_request_context(&ctx);
            let request = with_environment(captured.as_ref(), None).expect("request metadata");
            assert_eq!(request.request_id.as_deref(), Some("request"));
            assert_eq!(request.trace_id.as_deref(), Some("trace"));
            assert!(
                request.timestamp.is_none(),
                "an unrepresentable clock must not assert a timestamp"
            );
            assert!(request.environment.is_none());
            assert!(request.span_id.is_none());
        }
    }

    #[test]
    fn a_real_epoch_timestamp_is_preserved() {
        let req = make_request(Method::GET, "/");
        let mut ctx = make_filter_context(&req);
        ctx.extensions
            .insert(TraceContext::new("request".into(), "trace".into(), "01".into()));
        let clock = FixedTimeSource::new(Duration::ZERO);
        ctx.time_source = &clock;
        let request = get_request_context(&ctx).expect("request metadata");
        assert_eq!(request.timestamp.as_deref(), Some("1970-01-01T00:00:00.000Z"));
    }

    /// Records event metadata without installing a process-wide subscriber.
    struct Capture(Arc<Mutex<Events>>);

    /// Metadata retained by the test subscriber.
    type Events = Vec<(&'static str, tracing::Level)>;

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
            let metadata = event.metadata();
            self.0
                .lock()
                .expect("events")
                .push((metadata.target(), *metadata.level()));
        }
    }
}
