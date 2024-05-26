//! TCP pipeline execution: connect and disconnect filter phases.

use super::FilterPipeline;
use crate::{FilterError, actions::FilterAction, any_filter::AnyFilter, tcp_filter::TcpFilterContext};

// -----------------------------------------------------------------------------
// FilterPipeline TCP
// -----------------------------------------------------------------------------

impl FilterPipeline {
    /// Run all TCP connect filters in order.
    pub async fn execute_tcp_connect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        for (filter, _conditions, _resp_conditions) in &self.filters {
            let tcp_filter = match filter {
                AnyFilter::Tcp(f) => f.as_ref(),
                AnyFilter::Http(_) => continue,
            };
            match tcp_filter.on_connect(ctx).await {
                Ok(FilterAction::Continue | FilterAction::Release) => {},
                Ok(FilterAction::Reject(r)) => return Ok(FilterAction::Reject(r)),
                Err(e) => return Err(e),
            }
        }

        Ok(FilterAction::Continue)
    }

    /// Run all TCP disconnect filters in reverse order.
    pub async fn execute_tcp_disconnect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<(), FilterError> {
        for (filter, _conditions, _resp_conditions) in self.filters.iter().rev() {
            let tcp_filter = match filter {
                AnyFilter::Tcp(f) => f.as_ref(),
                AnyFilter::Http(_) => continue,
            };
            tcp_filter.on_disconnect(ctx).await?;
        }

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;

    use super::*;
    use crate::{FilterError, FilterRegistry, Rejection, body::BodyCapabilities, tcp_filter::TcpFilter};

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

    #[tokio::test]
    async fn empty_pipeline_connect_continues() {
        let registry = FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&[], &registry).unwrap();
        let mut ctx = make_ctx();
        let action = pipeline.execute_tcp_connect(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
    }

    #[tokio::test]
    async fn empty_pipeline_disconnect_succeeds() {
        let registry = FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&[], &registry).unwrap();
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
        pipeline.execute_tcp_connect(&mut ctx).await.unwrap();
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
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tcp filter error"));
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
        pipeline.execute_tcp_connect(&mut ctx).await.unwrap();
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
    async fn http_filters_skipped_in_tcp_execution() {
        let registry = FilterRegistry::with_builtins();
        let entries = vec![crate::FilterEntry {
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes: []").unwrap(),
            conditions: vec![],
            response_conditions: vec![],
        }];
        let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
        let mut ctx = make_ctx();

        let action = pipeline.execute_tcp_connect(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "TCP connect should skip HTTP filters"
        );
        pipeline.execute_tcp_disconnect(&mut ctx).await.unwrap();
    }

    fn make_tcp_pipeline(filters: Vec<Box<dyn TcpFilter>>) -> FilterPipeline {
        let filters: Vec<_> = filters
            .into_iter()
            .map(|f| (AnyFilter::Tcp(f), vec![], vec![]))
            .collect();
        FilterPipeline {
            body_capabilities: BodyCapabilities::default(),
            compression: None,
            filters,
            health_registry: None,
        }
    }

    fn make_ctx() -> TcpFilterContext<'static> {
        TcpFilterContext {
            remote_addr: "127.0.0.1:12345",
            local_addr: "0.0.0.0:8080",
            upstream_addr: "10.0.0.1:80",
            connect_time: std::time::Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        }
    }
}
