// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared overload policy at the transport boundary.

#[cfg(any(feature = "pingora", feature = "hyper", test))]
use std::sync::Arc;

/// Reject before the expensive TLS handshake; management listeners never install it.
#[cfg(feature = "pingora")]
#[derive(Debug)]
pub(crate) struct AdmissionFilter(pub Arc<praxis_core::overload::Signal>);

#[cfg(feature = "pingora")]
#[async_trait::async_trait]
impl pingora_core::listeners::ConnectionFilter for AdmissionFilter {
    async fn should_accept(&self, _addr: Option<&std::net::SocketAddr>) -> bool {
        let accept = !self.0.is_saturated();
        if !accept {
            crate::http::metrics::record_overload_reject("pre_tls_pressure");
        }
        accept
    }
}

/// Scale transport establishment and idle retention, leaving body deadlines alone.
#[cfg(any(feature = "pingora", feature = "hyper", test))]
pub(crate) fn scale_connection(
    options: &mut Arc<praxis_core::connectivity::ConnectionOptions>,
    signal: &praxis_core::overload::Signal,
) {
    if !signal.is_enabled() && !signal.is_scaling() {
        return;
    }
    let options = Arc::make_mut(options);
    options.connection_timeout = options.connection_timeout.map(|value| signal.scale_timeout(value));
    options.total_connection_timeout = options
        .total_connection_timeout
        .map(|value| signal.scale_timeout(value));
    if signal.is_enabled() {
        options.idle_timeout =
            Some(signal.scale_timeout(options.idle_timeout.unwrap_or(std::time::Duration::from_secs(60))));
    }
}

/// Wrap the backend without changing its parser, pool, or streaming lifecycle.
#[cfg(feature = "pingora")]
pub(crate) fn http_app<T>(
    inner: T,
    listener: &praxis_core::config::Listener,
    signal: Arc<praxis_core::overload::Signal>,
) -> InitialHeader<HttpApp<T>> {
    let header_timeout = listener
        .downstream_keepalive_timeout_ms
        .map_or(std::time::Duration::from_secs(60), |millis| {
            std::time::Duration::from_secs(millis.div_ceil(1_000))
        });
    let initial_deadlines = Arc::default();
    let app = HttpApp {
        inner: Arc::new(inner),
        signal: Arc::clone(&signal),
        header_timeout,
        initial_deadlines: Arc::clone(&initial_deadlines),
    };
    InitialHeader {
        inner: Arc::new(app),
        signal,
        header_timeout,
        initial_deadlines,
    }
}

/// Initial HTTP header deadlines survive the backend's protocol probe.
#[cfg(feature = "pingora")]
type HeaderDeadlines = Arc<
    std::sync::Mutex<std::collections::HashMap<pingora_core::protocols::UniqueIDType, (tokio::time::Instant, u64)>>,
>;

/// Disambiguate recycled socket IDs during asynchronous connection cleanup.
#[cfg(feature = "pingora")]
static HEADER_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Marker passed through Pingora's connection context after parsing the header.
#[cfg(feature = "pingora")]
pub(crate) struct HeaderParsed(pub Arc<tokio::sync::Notify>);

/// Remove a probe deadline even if its connection future is cancelled.
#[cfg(feature = "pingora")]
struct InitialDeadline(HeaderDeadlines, pingora_core::protocols::UniqueIDType, u64);

#[cfg(feature = "pingora")]
impl Drop for InitialDeadline {
    fn drop(&mut self) {
        let mut deadlines = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if deadlines
            .get(&self.1)
            .is_some_and(|(_, generation)| *generation == self.2)
        {
            deadlines.remove(&self.1);
        }
    }
}

/// Delegates HTTP serving after setting only the next HTTP/1 header deadline.
#[cfg(feature = "pingora")]
pub(crate) struct HttpApp<T> {
    /// Backend proxy responsible for parsing, framing, and streaming.
    pub inner: Arc<T>,
    /// Controller shared by listeners belonging to this server.
    pub signal: Arc<praxis_core::overload::Signal>,
    /// Original listener header/idle budget, never the last scaled value.
    pub header_timeout: std::time::Duration,
    /// Budgets started before the initial protocol probe.
    initial_deadlines: HeaderDeadlines,
}

#[cfg(feature = "pingora")]
#[async_trait::async_trait]
impl<T> pingora_core::apps::HttpServerApp for HttpApp<T>
where
    T: pingora_core::apps::HttpServerApp + Send + Sync + 'static,
{
    async fn process_new_http(
        self: &Arc<Self>,
        mut session: pingora_core::protocols::http::ServerSession,
        shutdown: &pingora_core::server::ShutdownWatch,
    ) -> Option<pingora_core::apps::ReusedHttpStream> {
        if session.is_http2() || !self.signal.is_enabled() {
            return self.inner.process_new_http(session, shutdown).await;
        }
        let initial = session.stream().and_then(|stream| {
            self.initial_deadlines
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&stream.id())
                .map(|(deadline, _)| deadline)
        });
        let deadline =
            initial.unwrap_or_else(|| tokio::time::Instant::now() + self.signal.scale_timeout(self.header_timeout));
        session.set_keepalive(None);
        session.set_read_timeout(None);
        let parsed = Arc::new(tokio::sync::Notify::new());
        session.set_connection_user_context(Some(Box::new(HeaderParsed(Arc::clone(&parsed)))));
        let serving = self.inner.process_new_http(session, shutdown);
        tokio::pin!(serving);
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => None,
            result = &mut serving => result,
            _ = parsed.notified() => serving.await,
        }
    }

    fn server_options(&self) -> Option<&pingora_core::apps::HttpServerOptions> {
        self.inner.server_options()
    }

    fn h2_options(&self) -> Option<pingora_core::protocols::http::v2::server::H2Options> {
        self.inner.h2_options()
    }

    async fn http_cleanup(&self) {
        self.inner.http_cleanup().await;
    }
}

/// Bound the initial cleartext protocol probe before Pingora's h2c detection.
/// Peeking rewinds bytes and leaves framing entirely to the backend.
#[cfg(feature = "pingora")]
pub(crate) struct InitialHeader<T> {
    /// HTTP application retaining the backend's normal connection lifecycle.
    pub inner: Arc<T>,
    /// Same controller and original header budget as the HTTP wrapper.
    pub signal: Arc<praxis_core::overload::Signal>,
    /// Baseline header wait before pressure scaling.
    pub header_timeout: std::time::Duration,
    /// Per-connection budgets transferred into the HTTP/1 parser wrapper.
    initial_deadlines: HeaderDeadlines,
}

#[cfg(feature = "pingora")]
#[async_trait::async_trait]
impl<T: pingora_core::apps::ServerApp + Send + Sync + 'static> pingora_core::apps::ServerApp for InitialHeader<T> {
    async fn process_new(
        self: &Arc<Self>,
        mut session: pingora_core::protocols::Stream,
        shutdown: &pingora_core::server::ShutdownWatch,
    ) -> Option<pingora_core::protocols::Stream> {
        let mut initial = None;
        if self.signal.is_enabled() {
            let deadline = tokio::time::Instant::now() + self.signal.scale_timeout(self.header_timeout);
            // The backend's cleartext probe reads and rewinds the full 24-byte H2 preface.
            // TLS streams may not support peeking and return immediately in that case.
            tokio::time::timeout_at(deadline, session.try_peek(&mut [0_u8; 24]))
                .await
                .ok()?
                .ok()?;
            let id = session.id();
            let generation = HEADER_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.initial_deadlines
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(id, (deadline, generation));
            initial = Some(InitialDeadline(Arc::clone(&self.initial_deadlines), id, generation));
        }
        let result = self.inner.process_new(session, shutdown).await;
        drop(initial);
        result
    }

    async fn cleanup(&self) {
        self.inner.cleanup().await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use praxis_core::{
        connectivity::ConnectionOptions,
        overload::{EngagedActions, Signal},
    };

    /// Report whether Pingora's parser accepted a delayed complete request.
    #[cfg(feature = "pingora")]
    struct HeaderReader(std::sync::atomic::AtomicBool);

    #[cfg(feature = "pingora")]
    #[async_trait::async_trait]
    impl pingora_core::apps::HttpServerApp for HeaderReader {
        async fn process_new_http(
            self: &std::sync::Arc<Self>,
            mut session: pingora_core::protocols::http::ServerSession,
            _shutdown: &pingora_core::server::ShutdownWatch,
        ) -> Option<pingora_core::apps::ReusedHttpStream> {
            self.0.store(
                matches!(session.read_request().await, Ok(true)),
                std::sync::atomic::Ordering::Relaxed,
            );
            None
        }
    }

    #[cfg(feature = "pingora")]
    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::unwrap_used,
        clippy::too_many_lines,
        reason = "real socket fixture and paused-clock parser regression"
    )]
    async fn configured_header_budget_can_exceed_pingora_native_read_default() {
        use pingora_core::apps::HttpServerApp as _;
        use tokio::io::AsyncWriteExt as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, accepted) = tokio::join!(
            tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let mut client = client.unwrap();
        let (server, _) = accepted.unwrap();
        let session = pingora_core::protocols::http::ServerSession::new_http1(Box::new(
            pingora_core::protocols::l4::stream::Stream::from(server),
        ));
        let signal = std::sync::Arc::new(Signal::default());
        signal.update(EngagedActions::default(), 0.0);
        let reader = std::sync::Arc::new(HeaderReader(std::sync::atomic::AtomicBool::new(false)));
        let app = std::sync::Arc::new(super::HttpApp {
            inner: std::sync::Arc::clone(&reader),
            signal,
            header_timeout: Duration::from_secs(120),
            initial_deadlines: std::sync::Arc::default(),
        });
        let (_shutdown, watching) = tokio::sync::watch::channel(false);
        let serving = tokio::spawn(async move {
            app.process_new_http(session, &watching).await;
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(75)).await;
        tokio::task::yield_now().await;
        let _sent = client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        serving.await.unwrap();
        assert!(
            reader.0.load(std::sync::atomic::Ordering::Relaxed),
            "the configured 120-second header budget must accept a request after the native 60-second default"
        );
    }

    #[test]
    #[cfg(feature = "pingora")]
    fn old_header_cleanup_preserves_a_recycled_socket_deadline() {
        let deadlines = super::HeaderDeadlines::default();
        let now = tokio::time::Instant::now();
        deadlines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(7, (now, 1));
        let old = super::InitialDeadline(std::sync::Arc::clone(&deadlines), 7, 1);
        deadlines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(7, (now, 2));
        drop(old);
        assert_eq!(
            deadlines
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&7),
            Some(&(now, 2)),
            "dropping the old guard must preserve the replacement deadline for a reused socket ID"
        );
    }

    #[test]
    fn scales_establishment_and_idle_retention_without_touching_bodies() {
        let signal = Signal::default();
        signal.update(EngagedActions::default(), 0.5);
        let mut options = std::sync::Arc::new(ConnectionOptions {
            connection_timeout: Some(Duration::from_secs(10)),
            total_connection_timeout: Some(Duration::from_secs(20)),
            idle_timeout: Some(Duration::from_secs(30)),
            read_timeout: Some(Duration::from_secs(80)),
            write_timeout: Some(Duration::from_secs(90)),
            ..Default::default()
        });
        super::scale_connection(&mut options, &signal);
        assert_eq!(options.connection_timeout, Some(Duration::from_millis(5500)));
        assert_eq!(options.total_connection_timeout, Some(Duration::from_secs(11)));
        assert_eq!(options.idle_timeout, Some(Duration::from_millis(16500)));
        assert_eq!(options.read_timeout, Some(Duration::from_secs(80)));
        assert_eq!(options.write_timeout, Some(Duration::from_secs(90)));
    }

    #[test]
    fn only_enabled_actions_bound_an_unconfigured_pool_lifetime() {
        let signal = Signal::default();
        let mut options = std::sync::Arc::new(ConnectionOptions::default());
        let original = std::sync::Arc::clone(&options);
        super::scale_connection(&mut options, &signal);
        assert_eq!(options.idle_timeout, None);
        assert!(std::sync::Arc::ptr_eq(&options, &original));
        signal.update(EngagedActions::default(), 0.0);
        super::scale_connection(&mut options, &signal);
        assert_eq!(options.idle_timeout, Some(Duration::from_secs(60)));
        signal.update(EngagedActions::default(), 1.0);
        super::scale_connection(&mut options, &signal);
        assert_eq!(options.idle_timeout, Some(Duration::from_secs(6)));
    }

    #[cfg(feature = "pingora")]
    #[tokio::test]
    async fn pre_tls_filter_is_scoped_and_recovers() {
        use pingora_core::listeners::ConnectionFilter as _;
        let signal = std::sync::Arc::new(Signal::default());
        let gate = super::AdmissionFilter(std::sync::Arc::clone(&signal));
        assert!(gate.should_accept(None).await);
        signal.update(
            EngagedActions {
                fail_readiness: true,
                ..Default::default()
            },
            1.0,
        );
        assert!(!gate.should_accept(None).await);
        assert!(
            super::AdmissionFilter(std::sync::Arc::default())
                .should_accept(None)
                .await
        );
        signal.clear();
        assert!(gate.should_accept(None).await);
    }
}
