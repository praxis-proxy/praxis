// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! TCP pipeline execution: connect and disconnect filter phases.

use tracing::trace;

use super::{FilterPipeline, check_failure_mode};
use crate::{FilterError, actions::FilterAction, any_filter::AnyFilter, tcp_filter::TcpFilterContext};

// -----------------------------------------------------------------------------
// FilterPipeline TCP
// -----------------------------------------------------------------------------

impl FilterPipeline {
    /// Run all TCP connect filters in order.
    ///
    /// TCP filters do not participate in branch chain
    /// evaluation currently. TCP pipelines execute filters
    /// sequentially without conditional branching or rejoin logic.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any filter rejects or fails.
    pub async fn execute_tcp_connect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        for pf in &self.filters {
            let tcp_filter = match &pf.filter {
                AnyFilter::Tcp(f) => f.as_ref(),
                AnyFilter::Http(_) => continue,
            };
            trace!(filter = tcp_filter.name(), "on_connect");
            match tcp_filter.on_connect(ctx).await {
                Ok(FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone) => {},
                Ok(FilterAction::Reject(r)) => return Ok(FilterAction::Reject(r)),
                Err(e) => {
                    check_failure_mode(tcp_filter.name(), e, "tcp connect", pf.failure_mode)?;
                },
            }
        }

        Ok(FilterAction::Continue)
    }

    /// Run all TCP disconnect filters in reverse order.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any filter fails.
    pub async fn execute_tcp_disconnect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<(), FilterError> {
        for pf in self.filters.iter().rev() {
            let tcp_filter = match &pf.filter {
                AnyFilter::Tcp(f) => f.as_ref(),
                AnyFilter::Http(_) => continue,
            };
            trace!(filter = tcp_filter.name(), "on_disconnect");
            if let Err(e) = tcp_filter.on_disconnect(ctx).await {
                check_failure_mode(tcp_filter.name(), e, "tcp disconnect", pf.failure_mode)?;
            }
        }

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use praxis_core::config::FailureMode;

    use super::*;
    use crate::{FilterError, FilterRegistry, Rejection, body::BodyCapabilities, tcp_filter::TcpFilter};
    #[tokio::test]
    async fn empty_pipeline_connect_continues() {
        let registry = FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let mut ctx = make_ctx();
        let action = pipeline.execute_tcp_connect(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
    }

    #[tokio::test]
    async fn empty_pipeline_disconnect_succeeds() {
        let registry = FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let mut ctx = make_ctx();
        pipeline.execute_tcp_disconnect(&mut ctx).await.unwrap();
    }

    #[tokio::test]
    async fn connect_runs_all_filters() {
        let connects = Arc::new(AtomicUsize::new(0));
        let disconnects = Arc::new(AtomicUsize::new(0));
        let pipeline = make_tcp_pipeline(vec![
            Box::new(CountingTcpFilter {
                connects: Arc::clone(&connects),
                disconnects: Arc::clone(&disconnects),
            }),
            Box::new(CountingTcpFilter {
                connects: Arc::clone(&connects),
                disconnects: Arc::clone(&disconnects),
            }),
        ]);
        let mut ctx = make_ctx();
        drop(pipeline.execute_tcp_connect(&mut ctx).await.unwrap());
        assert_eq!(connects.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn connect_stops_on_reject() {
        let connects = Arc::new(AtomicUsize::new(0));
        let disconnects = Arc::new(AtomicUsize::new(0));
        let pipeline = make_tcp_pipeline(vec![
            Box::new(RejectTcpFilter { status: 403 }),
            Box::new(CountingTcpFilter {
                connects: Arc::clone(&connects),
                disconnects: Arc::clone(&disconnects),
            }),
        ]);
        let mut ctx = make_ctx();
        let action = pipeline.execute_tcp_connect(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Reject(r) if r.status == 403));
        assert_eq!(connects.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn connect_propagates_error() {
        let pipeline = make_tcp_pipeline(vec![Box::new(ErrorTcpFilter)]);
        let mut ctx = make_ctx();
        let result = pipeline.execute_tcp_connect(&mut ctx).await;
        assert!(result.is_err(), "error filter should propagate error");
        assert!(
            result.unwrap_err().to_string().contains("tcp filter error"),
            "error message should contain filter error text"
        );
    }

    #[tokio::test]
    async fn connect_runs_in_forward_order() {
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pipeline = make_tcp_pipeline(vec![
            Box::new(OrderTcpFilter {
                label: "first",
                log: Arc::clone(&log),
            }),
            Box::new(OrderTcpFilter {
                label: "second",
                log: Arc::clone(&log),
            }),
            Box::new(OrderTcpFilter {
                label: "third",
                log: Arc::clone(&log),
            }),
        ]);
        let mut ctx = make_ctx();
        drop(pipeline.execute_tcp_connect(&mut ctx).await.unwrap());
        let recorded = log.lock().unwrap().clone();
        assert_eq!(recorded, vec!["first", "second", "third"]);
    }

    #[tokio::test]
    async fn disconnect_runs_in_reverse_order() {
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pipeline = make_tcp_pipeline(vec![
            Box::new(OrderTcpFilter {
                label: "first",
                log: Arc::clone(&log),
            }),
            Box::new(OrderTcpFilter {
                label: "second",
                log: Arc::clone(&log),
            }),
            Box::new(OrderTcpFilter {
                label: "third",
                log: Arc::clone(&log),
            }),
        ]);
        let mut ctx = make_ctx();
        pipeline.execute_tcp_disconnect(&mut ctx).await.unwrap();
        let recorded = log.lock().unwrap().clone();
        assert_eq!(recorded, vec!["third", "second", "first"]);
    }

    #[tokio::test]
    async fn disconnect_all_filters_called() {
        let connects = Arc::new(AtomicUsize::new(0));
        let disconnects = Arc::new(AtomicUsize::new(0));
        let pipeline = make_tcp_pipeline(vec![
            Box::new(CountingTcpFilter {
                connects: Arc::clone(&connects),
                disconnects: Arc::clone(&disconnects),
            }),
            Box::new(CountingTcpFilter {
                connects: Arc::clone(&connects),
                disconnects: Arc::clone(&disconnects),
            }),
        ]);
        let mut ctx = make_ctx();
        pipeline.execute_tcp_disconnect(&mut ctx).await.unwrap();
        assert_eq!(disconnects.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn connect_failure_mode_open_continues() {
        let connects = Arc::new(AtomicUsize::new(0));
        let disconnects = Arc::new(AtomicUsize::new(0));
        let mut pipeline = make_tcp_pipeline(vec![
            Box::new(ErrorTcpFilter),
            Box::new(CountingTcpFilter {
                connects: Arc::clone(&connects),
                disconnects: Arc::clone(&disconnects),
            }),
        ]);
        pipeline.filters[0].failure_mode = FailureMode::Open;
        let mut ctx = make_ctx();

        let action = pipeline.execute_tcp_connect(&mut ctx).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "open failure_mode should continue past error"
        );
        assert_eq!(
            connects.load(Ordering::SeqCst),
            1,
            "second filter should still run after open error"
        );
    }

    #[tokio::test]
    async fn connect_failure_mode_closed_propagates() {
        let pipeline = make_tcp_pipeline(vec![Box::new(ErrorTcpFilter)]);
        let mut ctx = make_ctx();

        let result = pipeline.execute_tcp_connect(&mut ctx).await;

        assert!(result.is_err(), "closed (default) failure_mode should propagate error");
    }

    #[tokio::test]
    async fn disconnect_failure_mode_open_continues() {
        let connects = Arc::new(AtomicUsize::new(0));
        let disconnects = Arc::new(AtomicUsize::new(0));
        let mut pipeline = make_tcp_pipeline(vec![
            Box::new(CountingTcpFilter {
                connects: Arc::clone(&connects),
                disconnects: Arc::clone(&disconnects),
            }),
            Box::new(ErrorDisconnectTcpFilter),
        ]);
        pipeline.filters[1].failure_mode = FailureMode::Open;
        let mut ctx = make_ctx();

        pipeline.execute_tcp_disconnect(&mut ctx).await.unwrap();

        assert_eq!(
            disconnects.load(Ordering::SeqCst),
            1,
            "first filter disconnect should still run"
        );
    }

    #[tokio::test]
    async fn disconnect_failure_mode_closed_propagates() {
        let pipeline = make_tcp_pipeline(vec![Box::new(ErrorDisconnectTcpFilter)]);
        let mut ctx = make_ctx();

        let result = pipeline.execute_tcp_disconnect(&mut ctx).await;

        assert!(
            result.is_err(),
            "closed (default) failure_mode should propagate disconnect error"
        );
    }

    #[tokio::test]
    async fn connect_mixed_chain_open_skipped_closed_blocks() {
        let connects = Arc::new(AtomicUsize::new(0));
        let disconnects = Arc::new(AtomicUsize::new(0));
        let mut pipeline = make_tcp_pipeline(vec![
            Box::new(ErrorTcpFilter),
            Box::new(ErrorTcpFilter),
            Box::new(CountingTcpFilter {
                connects: Arc::clone(&connects),
                disconnects: Arc::clone(&disconnects),
            }),
        ]);
        pipeline.filters[0].failure_mode = FailureMode::Open;
        let mut ctx = make_ctx();

        let result = pipeline.execute_tcp_connect(&mut ctx).await;

        assert!(
            result.is_err(),
            "open filter should be skipped but closed filter should block"
        );
        assert_eq!(
            connects.load(Ordering::SeqCst),
            0,
            "third filter should not run after closed error"
        );
    }

    #[tokio::test]
    async fn http_filters_skipped_in_tcp_execution() {
        let registry = FilterRegistry::with_builtins();
        let mut entries = vec![crate::FilterEntry {
            branch_chains: None,
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes: []").unwrap(),
            conditions: vec![],
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        }];
        let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
        let mut ctx = make_ctx();

        let action = pipeline.execute_tcp_connect(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "TCP connect should skip HTTP filters"
        );
        pipeline.execute_tcp_disconnect(&mut ctx).await.unwrap();
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// TCP filter that counts connect and disconnect calls.
    struct CountingTcpFilter {
        connects: Arc<AtomicUsize>,
        disconnects: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl TcpFilter for CountingTcpFilter {
        fn name(&self) -> &'static str {
            "counting_tcp"
        }

        async fn on_connect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            self.connects.fetch_add(1, Ordering::SeqCst);
            Ok(FilterAction::Continue)
        }

        async fn on_disconnect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<(), FilterError> {
            self.disconnects.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// TCP filter that rejects connections with a given status.
    struct RejectTcpFilter {
        status: u16,
    }

    #[async_trait]
    impl TcpFilter for RejectTcpFilter {
        fn name(&self) -> &'static str {
            "reject_tcp"
        }

        async fn on_connect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Reject(Rejection::status(self.status)))
        }
    }

    /// TCP filter that always returns an error on connect.
    struct ErrorTcpFilter;

    #[async_trait]
    impl TcpFilter for ErrorTcpFilter {
        fn name(&self) -> &'static str {
            "error_tcp"
        }

        async fn on_connect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Err("tcp filter error".into())
        }
    }

    /// TCP filter that always errors on disconnect.
    struct ErrorDisconnectTcpFilter;

    #[async_trait]
    impl TcpFilter for ErrorDisconnectTcpFilter {
        fn name(&self) -> &'static str {
            "error_disconnect_tcp"
        }

        async fn on_disconnect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<(), FilterError> {
            Err("tcp disconnect error".into())
        }
    }

    /// TCP filter that records its label to a shared log.
    struct OrderTcpFilter {
        label: &'static str,
        log: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
    impl TcpFilter for OrderTcpFilter {
        fn name(&self) -> &'static str {
            self.label
        }

        async fn on_connect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            self.log.lock().unwrap().push(self.label);
            Ok(FilterAction::Continue)
        }

        async fn on_disconnect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<(), FilterError> {
            self.log.lock().unwrap().push(self.label);
            Ok(())
        }
    }

    /// Build a [`FilterPipeline`] wrapping the given TCP filters.
    fn make_tcp_pipeline(filters: Vec<Box<dyn TcpFilter>>) -> FilterPipeline {
        let filters: Vec<_> = filters
            .into_iter()
            .map(|f| crate::pipeline::filter::PipelineFilter::new(AnyFilter::Tcp(f), vec![], vec![]))
            .collect();
        FilterPipeline {
            body_capabilities: BodyCapabilities::default(),
            compression: None,
            filters,
            health_registry: None,
        }
    }

    /// Build a default [`TcpFilterContext`] for testing.
    fn make_ctx() -> TcpFilterContext<'static> {
        TcpFilterContext {
            remote_addr: "127.0.0.1:12345",
            local_addr: "0.0.0.0:8080",
            sni: None,
            upstream_addr: Some(std::borrow::Cow::Borrowed("10.0.0.1:80")),
            cluster: None,
            health_registry: None,
            connect_time: std::time::Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        }
    }
}
