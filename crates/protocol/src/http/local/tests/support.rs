// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Instrumented bounded I/O, handlers, policies, and upstream dispatch spies.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterEntry, FilterError, FilterFactory, FilterPipeline, FilterRegistry,
    HttpFilter, HttpFilterContext, Request, Response, StreamingResponseBody, StreamingTerminalResponse, local_http::*,
};

use super::super::{LocalCompletion, LocalExchange, LocalTransport};

#[derive(Clone, Default)]
pub(super) struct State {
    pub(super) inner: Arc<Mutex<Observations>>,
}
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(super) enum WriteMode {
    #[default]
    Ready,
    Disconnected,
    Blocked,
}
#[derive(Default)]
pub(super) struct Observations {
    pub(super) events: Vec<String>,
    pub(super) pipeline: Option<std::sync::Weak<FilterPipeline>>,
    pub(super) upstream_connections: usize,
    pub(super) forwarded_bytes: u64,
    pub(super) completions: usize,
    pub(super) finalizations: Vec<LocalOutcome>,
    pub(super) source_cancels: usize,
    pub(super) suppressed: usize,
    pub(super) max_chunk: usize,
    pub(super) reusable: Option<bool>,
    pub(super) head: Option<(u16, http::HeaderMap)>,
    pub(super) write_mode: WriteMode,
    pub(super) fail_read: bool,
    pub(super) cancel_on_write: Option<LocalCancellation>,
}
impl State {
    pub(super) fn event(&self, event: impl Into<String>) {
        self.inner.lock().unwrap().events.push(event.into());
    }

    fn reclaim(&self, ctx: &mut HttpFilterContext<'_>) {
        let pipeline = self.inner.lock().unwrap().pipeline.as_ref().unwrap().upgrade().unwrap();
        assert!(pipeline.claim_local_http(ctx).is_some());
    }

    pub(super) fn events(&self) -> Vec<String> {
        self.inner.lock().unwrap().events.clone()
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Behavior {
    Pass,
    RejectHead,
    RejectRequest,
    ErrorRequest,
    TerminalRequest,
    RejectResponse,
    ExpandBody,
    DropBody,
    TerminalBody,
    PromoteHead,
    ReclaimRequest,
    ReclaimResponse,
    ReclaimBody,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HandlerKind {
    Consume,
    Early,
    Error,
    FactoryError,
    SourceErrorBefore,
    SourceErrorAfter,
    SuppressWait,
    Wait,
    SwallowRead,
    Reclaim,
}

#[derive(Clone)]
pub(super) struct Fixture {
    pub(super) name: &'static str,
    pub(super) routes: Vec<LocalRoute>,
    pub(super) state: State,
    pub(super) behavior: Behavior,
    pub(super) handler: HandlerKind,
    pub(super) response_bytes: u64,
    pub(super) response_status: u16,
    pub(super) response_headers: http::HeaderMap,
    pub(super) compatibility: LocalCompatibility,
    pub(super) request_access: BodyAccess,
    pub(super) selected_access: BodyAccess,
    pub(super) response_mode: BodyMode,
}
impl Fixture {
    pub(super) fn policy(name: &'static str, state: State) -> Self {
        Self {
            name,
            routes: vec![],
            state,
            behavior: Behavior::Pass,
            handler: HandlerKind::Consume,
            response_bytes: 4,
            response_status: 200,
            response_headers: http::HeaderMap::new(),
            compatibility: LocalCompatibility::Policy,
            request_access: BodyAccess::None,
            selected_access: BodyAccess::None,
            response_mode: BodyMode::Stream,
        }
    }

    pub(super) fn owner(state: State) -> Self {
        let mut owner = Self::policy("owner", state);
        owner.routes.push(LocalRoute {
            id: "files".into(),
            methods: LocalMethods::All,
            path: LocalPath::SegmentPrefix("/files".into()),
            body: LocalBodyOwnership::Exclusive,
            request_limit: 536_870_912,
            response_limit: 536_870_912,
        });
        owner
    }

    pub(super) fn routing(state: State) -> Self {
        let mut routing = Self::policy("routing", state);
        routing.compatibility = LocalCompatibility::UpstreamRoutingOnly;
        routing
    }
}
#[async_trait]
impl HttpFilter for Fixture {
    fn name(&self) -> &'static str {
        self.name
    }

    fn local_http_routes(&self) -> &[LocalRoute] {
        &self.routes
    }

    fn local_http_compatibility(&self) -> LocalCompatibility {
        self.compatibility
    }

    fn request_body_access(&self) -> BodyAccess {
        self.request_access
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        self.selected_access
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn response_body_mode(&self) -> BodyMode {
        self.response_mode
    }

    fn runs_request_head(&self) -> bool {
        true
    }

    fn create_local_http_handler(&self, _route: &str) -> Result<Box<dyn LocalHttpHandler>, FilterError> {
        self.state.event("factory");
        if self.handler == HandlerKind::FactoryError {
            return Err("factory failed".into());
        }
        Ok(Box::new(Handler {
            state: self.state.clone(),
            kind: self.handler,
            response_bytes: self.response_bytes,
            response_status: self.response_status,
            response_headers: self.response_headers.clone(),
        }))
    }

    async fn on_request_head(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.state.event(format!("head:{}", self.name));
        if matches!(self.behavior, Behavior::PromoteHead) {
            ctx.request_headers_to_set.push((
                http::header::HeaderName::from_static("x-praxis-approved"),
                http::HeaderValue::from_static("yes"),
            ));
        }
        Ok(if matches!(self.behavior, Behavior::RejectHead) {
            FilterAction::Reject(praxis_filter::Rejection::status(403))
        } else {
            FilterAction::Continue
        })
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.state.event(format!("request:{}", self.name));
        if self.compatibility == LocalCompatibility::UpstreamRoutingOnly {
            let mut inner = self.state.inner.lock().unwrap();
            inner.upstream_connections += 1;
            inner.forwarded_bytes += 4;
        }
        match self.behavior {
            Behavior::RejectRequest => Ok(FilterAction::Reject(praxis_filter::Rejection::status(403))),
            Behavior::ReclaimRequest => {
                self.state.reclaim(ctx);
                Ok(FilterAction::Continue)
            },
            Behavior::ErrorRequest => Err("policy failed".into()),
            Behavior::TerminalRequest => Ok(FilterAction::TerminalResponse(Box::new(
                praxis_filter::TerminalResponse::new(200),
            ))),
            Behavior::Pass
            | Behavior::RejectHead
            | Behavior::RejectResponse
            | Behavior::ExpandBody
            | Behavior::DropBody
            | Behavior::TerminalBody
            | Behavior::ReclaimResponse
            | Behavior::ReclaimBody
            | Behavior::PromoteHead => Ok(FilterAction::Continue),
        }
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.state.event(format!("response:{}", self.name));
        if matches!(self.behavior, Behavior::ReclaimResponse) {
            self.state.reclaim(ctx);
        }
        if let Some(head) = ctx.response_header.as_deref_mut() {
            head.headers.insert(
                http::header::HeaderName::try_from(format!("x-{}", self.name)).unwrap(),
                http::HeaderValue::from_static("yes"),
            );
        }
        Ok(if matches!(self.behavior, Behavior::RejectResponse) {
            FilterAction::Reject(praxis_filter::Rejection::status(451))
        } else {
            FilterAction::Continue
        })
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _eof: bool,
    ) -> Result<FilterAction, FilterError> {
        self.state.event(format!("chunk:{}", self.name));
        if matches!(self.behavior, Behavior::ReclaimBody) {
            self.state.reclaim(ctx);
        }
        if matches!(self.behavior, Behavior::TerminalBody) && ctx.response_body_bytes > 65_536 {
            return Ok(FilterAction::TerminalResponse(Box::new(
                praxis_filter::TerminalResponse::new(200),
            )));
        }
        if body.is_some() && matches!(self.behavior, Behavior::ExpandBody) {
            *body = Some(Bytes::from_static(b"expanded"));
        }
        if matches!(self.behavior, Behavior::DropBody) {
            *body = None;
        }
        Ok(FilterAction::Continue)
    }
}
struct Handler {
    state: State,
    kind: HandlerKind,
    response_bytes: u64,
    response_status: u16,
    response_headers: http::HeaderMap,
}
#[async_trait]
impl LocalHttpHandler for Handler {
    async fn execute(
        &mut self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut dyn LocalRequestBody,
        _cancel: &LocalCancellation,
    ) -> Result<LocalResponse, FilterError> {
        self.state.event("handler");
        if self.kind == HandlerKind::Reclaim {
            self.state.reclaim(ctx);
        }
        if self.kind == HandlerKind::Wait {
            std::future::pending::<()>().await;
        }
        if self.kind == HandlerKind::Error {
            return Err("handler failed".into());
        }
        if self.kind == HandlerKind::SwallowRead {
            let _ignored = body.next_chunk().await;
        } else if self.kind != HandlerKind::Early {
            while body.next_chunk().await?.is_some() {}
        }
        let mut response = StreamingTerminalResponse::new(
            self.response_status,
            Box::new(Source {
                state: self.state.clone(),
                kind: self.kind,
                remaining: self.response_bytes,
                pulled: false,
            }),
        );
        response.headers = self.response_headers.clone();
        Ok(LocalResponse::Streamed(response))
    }

    async fn finalize(&mut self, outcome: LocalOutcome) {
        self.state.event("finalize");
        self.state.inner.lock().unwrap().finalizations.push(outcome);
    }
}
struct Source {
    state: State,
    kind: HandlerKind,
    remaining: u64,
    pulled: bool,
}
#[async_trait]
impl StreamingResponseBody for Source {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
        self.state.event("source");
        if self.kind == HandlerKind::SourceErrorBefore || (self.kind == HandlerKind::SourceErrorAfter && self.pulled) {
            return Err("source failed".into());
        }
        self.pulled = true;
        Ok(generated(&mut self.remaining))
    }

    async fn suppress(&mut self) -> Result<(), FilterError> {
        self.state.inner.lock().unwrap().suppressed += 1;
        if self.kind == HandlerKind::SuppressWait {
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn cancel(&mut self) {
        self.state.inner.lock().unwrap().source_cancels += 1;
    }
}

pub(super) struct Input {
    remaining: u64,
    chunk_size: u64,
}
impl Input {
    pub(super) fn bytes(bytes: u64) -> Self {
        Self {
            remaining: bytes,
            chunk_size: bytes.max(1),
        }
    }

    pub(super) fn generated(bytes: u64) -> Self {
        Self {
            remaining: bytes,
            chunk_size: 65_536,
        }
    }
}
pub(super) struct Transport {
    pub(super) state: State,
    pub(super) input: Input,
}
#[async_trait]
impl LocalTransport for Transport {
    async fn accept_body(&mut self) -> Result<(), FilterError> {
        self.state.event("accept");
        Ok(())
    }

    async fn read_body(&mut self) -> Result<Option<Bytes>, FilterError> {
        self.state.event("read");
        if self.state.inner.lock().unwrap().fail_read {
            return Err("request read failed".into());
        }
        let bytes = self.input.remaining.min(self.input.chunk_size);
        let mut remaining = bytes;
        let chunk = generated(&mut remaining);
        self.input.remaining = self.input.remaining.saturating_sub(bytes);
        Ok(chunk)
    }

    async fn write_head(&mut self, head: &Response) -> Result<(), FilterError> {
        self.state.event("headers");
        self.state.inner.lock().unwrap().head = Some((head.status.as_u16(), head.headers.clone()));
        Ok(())
    }

    async fn write_body(&mut self, chunk: Bytes) -> Result<(), FilterError> {
        self.state.event("write");
        let block_write = {
            let mut inner = self.state.inner.lock().unwrap();
            inner.max_chunk = inner.max_chunk.max(chunk.len());
            if let Some(cancellation) = &inner.cancel_on_write {
                cancellation.cancel();
            }
            if inner.write_mode == WriteMode::Disconnected {
                return Err("disconnected".into());
            }
            inner.write_mode == WriteMode::Blocked
        };
        if block_write {
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn finish(&mut self, request_eof: bool) -> Result<(), FilterError> {
        self.state.event("finish");
        self.state.inner.lock().unwrap().reusable = Some(request_eof);
        Ok(())
    }

    async fn abort(&mut self) {
        self.state.event("abort");
    }

    fn complete(&mut self, _completion: LocalCompletion, _ctx: &HttpFilterContext<'_>) {
        self.state.event("complete");
        self.state.inner.lock().unwrap().completions += 1;
    }
}
fn generated(remaining: &mut u64) -> Option<Bytes> {
    static CHUNK: [u8; 65_536] = [0; 65_536];
    if *remaining == 0 {
        return None;
    }
    let bytes = (*remaining).min(65_536);
    *remaining = remaining.saturating_sub(bytes);
    Some(Bytes::from_static(&CHUNK).slice(..usize::try_from(bytes).unwrap()))
}
pub(super) fn registry(fixtures: Vec<Fixture>) -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    for fixture in fixtures {
        registry
            .register(
                fixture.name,
                FilterFactory::Http(Arc::new(move |_| Ok(Box::new(fixture.clone())))),
            )
            .unwrap();
    }
    registry
}
pub(super) fn entries(names: &[&str]) -> Vec<FilterEntry> {
    names
        .iter()
        .map(|name| serde_yaml::from_str(&format!("filter: {name}")).unwrap())
        .collect()
}
pub(super) fn build(fixtures: Vec<Fixture>) -> FilterPipeline {
    let mut entries = entries(&fixtures.iter().map(|fixture| fixture.name).collect::<Vec<_>>());
    FilterPipeline::build(&mut entries, &registry(fixtures)).unwrap()
}
pub(super) fn pipeline(fixtures: Vec<Fixture>) -> Arc<FilterPipeline> {
    Arc::new(build(fixtures))
}
pub(super) async fn run(
    pipeline: &Arc<FilterPipeline>,
    state: &State,
    input: Input,
    path: &str,
    method: http::Method,
) -> LocalCompletion {
    let request = Request {
        method,
        uri: path.parse().unwrap(),
        headers: http::HeaderMap::new(),
    };
    let mut head = Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
    };
    let mut ctx = super::context::context(&request, pipeline);
    ctx.response_header = Some(&mut head);
    let exchange = LocalExchange::claim(pipeline, &mut ctx).unwrap();
    assert!(state.events().is_empty(), "claim performs no body or service work");
    let result = exchange
        .run(
            &mut ctx,
            &mut Transport {
                state: state.clone(),
                input,
            },
        )
        .await;
    assert!(
        praxis_filter::access_record_already_emitted(&ctx),
        "coordinator owns fallback eligibility"
    );
    result
}
pub(super) fn assert_complete(state: &State, finalizations: usize) {
    let inner = state.inner.lock().unwrap();
    assert_eq!(inner.upstream_connections, 0, "claimed exits cannot connect upstream");
    assert_eq!(inner.forwarded_bytes, 0, "claimed exits cannot forward bytes");
    assert_eq!(inner.completions, 1, "request metrics and completion are emitted once");
    assert_eq!(
        inner.finalizations.len(),
        finalizations,
        "managed handlers finalize exactly once"
    );
}
