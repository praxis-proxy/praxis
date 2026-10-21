// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Test utilities for the hyper adapter's unit tests: pipelines with a
//! scripted filter, scripted streaming terminal response bodies, client
//! requests served by hyper, and upstream sessions to local sockets.

use std::{
    collections::VecDeque,
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response};
use hyper::{
    body::Incoming,
    server::conn::{http1, http2},
    service::Service,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use praxis_core::{
    config::Listener,
    egress::{
        Connector as _, PeerSpec, RequestHead, Session as _,
        hyper::{HyperConnector, HyperSession},
    },
};
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterEntry, FilterError, FilterFactory, FilterPipeline, FilterRegistry,
    HttpFilter, HttpFilterContext, StreamingResponseBody,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
};

use super::{
    body::ProxyBody,
    downstream::{DownstreamBody, DownstreamFrame},
    listener::ListenerShared,
    service::Flight,
    upload::Upload,
};
use crate::http::pingora::context::PingoraRequestCtx;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Registry name of the [`Scripted`] filter.
const SCRIPTED: &str = "scripted";

/// Bytes the in-memory client connection buffers each way.
const CLIENT_BUFFER: usize = 1_048_576; // 1 MiB

/// Bytes per chunk of a request body an upstream leaves unread.
const UNREAD_CHUNK_BYTES: usize = 65_536; // 64 KiB

/// Chunks of an unread request body: more than the socket buffers of an
/// upstream that stopped reading can absorb.
const UNREAD_CHUNKS: usize = 256; // 16 MiB in all

// -----------------------------------------------------------------------------
// Pipelines
// -----------------------------------------------------------------------------

/// What a [`Scripted`] filter answers with; called on every invocation.
pub(super) type Action = Arc<dyn Fn() -> Result<FilterAction, FilterError> + Send + Sync>;

/// What a [`Scripted`] filter does with one body chunk and whether it is the
/// last; called on every invocation.
pub(super) type BodyHook = Arc<dyn Fn(&mut Option<Bytes>, bool) -> Result<FilterAction, FilterError> + Send + Sync>;

/// What a [`Scripted`] filter does at each hook; an unset hook continues
/// and an unset body hook means no access to that body.
#[derive(Clone, Default)]
pub(super) struct Script {
    /// The request phase.
    pub(super) request: Option<Action>,

    /// The request body mode and hook.
    pub(super) request_body: Option<(BodyMode, BodyHook)>,

    /// The request-head phase; the filter opts into it when set.
    pub(super) request_head: Option<Action>,

    /// The response phase.
    pub(super) response: Option<Action>,

    /// The response body mode and hook.
    pub(super) response_body: Option<(BodyMode, BodyHook)>,
}

/// A pipeline with no filters.
pub(super) fn empty_pipeline() -> FilterPipeline {
    FilterPipeline::build(&mut [], &FilterRegistry::with_builtins()).unwrap()
}

/// A pipeline of one filter that follows `script` and whose response hooks
/// only apply to a response with `status`.
pub(super) fn conditional_pipeline(script: Script, status: u16) -> FilterPipeline {
    build_scripted(
        script,
        &format!("\n  response_conditions:\n    - when:\n        status: [{status}]"),
    )
}

/// A pipeline of one filter that follows `script`.
pub(super) fn scripted_pipeline(script: Script) -> FilterPipeline {
    build_scripted(script, "")
}

/// A pipeline of one filter that follows `script`, with `settings` added to
/// its entry.
fn build_scripted(script: Script, settings: &str) -> FilterPipeline {
    let mut registry = FilterRegistry::with_builtins();
    let factory = FilterFactory::Http(Arc::new(move |_config| {
        Ok(Box::new(Scripted { script: script.clone() }))
    }));
    registry.register(SCRIPTED, factory).unwrap();
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(&format!("- filter: {SCRIPTED}{settings}")).unwrap();
    FilterPipeline::build(&mut entries, &registry).unwrap()
}

/// A filter whose every hook does what its [`Script`] says.
struct Scripted {
    /// What each hook does.
    script: Script,
}

#[async_trait::async_trait]
impl HttpFilter for Scripted {
    fn name(&self) -> &'static str {
        SCRIPTED
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        act(self.script.request.as_ref())
    }

    async fn on_request_head(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        act(self.script.request_head.as_ref())
    }

    fn runs_request_head(&self) -> bool {
        self.script.request_head.is_some()
    }

    async fn on_response(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        act(self.script.response.as_ref())
    }

    fn request_body_access(&self) -> BodyAccess {
        access(self.script.request_body.as_ref())
    }

    fn response_body_access(&self) -> BodyAccess {
        access(self.script.response_body.as_ref())
    }

    fn request_body_mode(&self) -> BodyMode {
        mode(self.script.request_body.as_ref())
    }

    fn response_body_mode(&self) -> BodyMode {
        mode(self.script.response_body.as_ref())
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        hook(self.script.request_body.as_ref(), body, end_of_stream)
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        hook(self.script.response_body.as_ref(), body, end_of_stream)
    }
}

/// Run `action`, continuing when there is none.
fn act(action: Option<&Action>) -> Result<FilterAction, FilterError> {
    action.map_or(Ok(FilterAction::Continue), |action| action())
}

/// The body access a body hook needs.
fn access(body: Option<&(BodyMode, BodyHook)>) -> BodyAccess {
    body.map_or(BodyAccess::None, |_body| BodyAccess::ReadWrite)
}

/// The body mode a body hook asks for.
fn mode(body: Option<&(BodyMode, BodyHook)>) -> BodyMode {
    body.map_or(BodyMode::Stream, |(mode, _hook)| *mode)
}

/// Run a body hook, continuing when there is none.
fn hook(
    body_hook: Option<&(BodyMode, BodyHook)>,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
) -> Result<FilterAction, FilterError> {
    body_hook.map_or(Ok(FilterAction::Continue), |(_mode, hook)| hook(body, end_of_stream))
}

// -----------------------------------------------------------------------------
// Streaming Sources
// -----------------------------------------------------------------------------

/// One pull of a [`Source`].
#[derive(Clone, Copy, Debug)]
pub(super) enum Pull {
    /// A chunk of the body.
    Chunk(&'static str),

    /// The end of the body.
    End,

    /// A failed pull.
    Fail,

    /// A pull that never resolves.
    Hang,
}

/// A streaming terminal response body that yields scripted pulls and
/// records what it was asked to do: `"pull"`, `"suppress"`, `"cancel"`.
pub(super) struct Source {
    /// What it was asked to do, in order.
    calls: Arc<Mutex<Vec<&'static str>>>,

    /// The pulls still to yield; the end of the body once none are left.
    pulls: VecDeque<Pull>,

    /// Whether suppressing the body fails.
    suppress_fails: bool,
}

impl Source {
    /// A source yielding `pulls`, and the record of what it is asked.
    pub(super) fn new(pulls: &[Pull]) -> (Self, Arc<Mutex<Vec<&'static str>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let source = Self {
            calls: Arc::clone(&calls),
            pulls: pulls.iter().copied().collect(),
            suppress_fails: false,
        };
        (source, calls)
    }

    /// The same source, but one whose suppression fails.
    pub(super) fn failing_suppression(mut self) -> Self {
        self.suppress_fails = true;
        self
    }

    /// Note that the source was asked to `call`.
    fn record(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }
}

#[async_trait::async_trait]
impl StreamingResponseBody for Source {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
        self.record("pull");
        match self.pulls.pop_front() {
            Some(Pull::Chunk(chunk)) => Ok(Some(Bytes::from_static(chunk.as_bytes()))),
            Some(Pull::End) | None => Ok(None),
            Some(Pull::Fail) => Err("the source failed".into()),
            Some(Pull::Hang) => std::future::pending().await,
        }
    }

    async fn suppress(&mut self) -> Result<(), FilterError> {
        self.record("suppress");
        if self.suppress_fails {
            return Err("suppression failed".into());
        }
        Ok(())
    }

    async fn cancel(&mut self) {
        self.record("cancel");
    }
}

// -----------------------------------------------------------------------------
// Client Requests
// -----------------------------------------------------------------------------

/// The client side of a request served by [`client_request`] or
/// [`client_request_h2`].
pub(super) struct Client {
    /// The client's HTTP/2 request body, open until it is ended or reset.
    pub(super) h2_body: Option<h2::SendStream<Bytes>>,

    /// The client's end of an HTTP/1.1 connection: writing to it feeds the
    /// body, dropping it hangs up.
    pub(super) stream: Option<DuplexStream>,
}

/// Serve `raw`, HTTP/1.1 bytes from a client, with hyper and hand back the
/// request hyper parsed, its body still streaming, with the client side.
pub(super) async fn client_request(raw: &[u8]) -> (Request<Incoming>, Client) {
    let (mut stream, server) = tokio::io::duplex(CLIENT_BUFFER);
    let (service, mut received) = Forwarding::new();
    let connection = http1::Builder::new().serve_connection(TokioIo::new(server), service);
    drop(tokio::spawn(connection));

    stream.write_all(raw).await.unwrap();
    let request = received.recv().await.expect("hyper parses the client's request head");
    let client = Client {
        h2_body: None,
        stream: Some(stream),
    };
    (request, client)
}

/// Send a `POST` with an open body over HTTP/2 to hyper and hand back the
/// request hyper parsed, with the client side.
pub(super) async fn client_request_h2() -> (Request<Incoming>, Client) {
    let (stream, server) = tokio::io::duplex(CLIENT_BUFFER);
    let (service, mut received) = Forwarding::new();
    let connection = http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(server), service);
    drop(tokio::spawn(connection));

    let (mut sender, driver) = h2::client::handshake(stream).await.unwrap();
    drop(tokio::spawn(driver));
    let request = Request::post("http://upstream.test/").body(()).unwrap();
    let (_response, body) = sender.send_request(request, false).unwrap();
    let request = received.recv().await.expect("hyper parses the client's request head");
    let client = Client {
        h2_body: Some(body),
        stream: None,
    };
    (request, client)
}

/// A hyper service that hands every request it receives to a channel and
/// never answers it.
#[derive(Clone)]
struct Forwarding(mpsc::Sender<Request<Incoming>>);

impl Forwarding {
    /// The service and the channel its requests arrive on.
    fn new() -> (Self, mpsc::Receiver<Request<Incoming>>) {
        let (requests, received) = mpsc::channel(1);
        (Self(requests), received)
    }
}

impl Service<Request<Incoming>> for Forwarding {
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = Response<ProxyBody>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let requests = self.0.clone();
        Box::pin(async move {
            requests.send(req).await.unwrap();
            std::future::pending().await
        })
    }
}

/// The upload of a `POST` whose body the client is still sending, for a
/// request whose phase left `ctx`, with the client side.
pub(super) async fn streaming_upload(ctx: &PingoraRequestCtx) -> (Upload, Client) {
    let (request, client) = client_request(b"POST / HTTP/1.1\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\n").await;
    let body = DownstreamBody::new(request.into_body(), None);
    (Upload::new(body, ctx), client)
}

/// A streaming upload that already took more of the client's body than a
/// retry could replay, with the client side.
pub(super) async fn truncated_upload(flight: &mut Flight) -> (Upload, Client) {
    let (mut upload, client) = streaming_upload(&flight.ctx).await;
    let oversized = Bytes::from(vec![0_u8; 65_537]); // 64 KiB and a byte
    let accepted = upload.accept(flight, Ok(DownstreamFrame::Data(oversized)), false).await;
    assert!(accepted.is_ok(), "an unfiltered chunk is queued");
    assert!(upload.is_truncated(), "a body past the replay limit truncates the copy");
    (upload, client)
}

/// Queue more of the client's body on `upload` than an upstream that
/// stopped reading can absorb, so its next send stays blocked.
pub(super) async fn queue_unread_body(upload: &mut Upload, flight: &mut Flight) {
    for _chunk in 0..UNREAD_CHUNKS {
        let frame = DownstreamFrame::Data(Bytes::from(vec![b'x'; UNREAD_CHUNK_BYTES]));
        let accepted = Box::pin(upload.accept(flight, Ok(frame), false)).await;
        assert!(matches!(accepted, Ok(())), "the chunk is queued");
    }
}

// -----------------------------------------------------------------------------
// Upstreams
// -----------------------------------------------------------------------------

/// A local upstream that serves the connections it accepts one way.
pub(super) struct Upstream {
    /// Where it listens.
    pub(super) address: SocketAddr,

    /// The accept loop.
    task: JoinHandle<()>,
}

impl Upstream {
    /// An upstream that reads each request head, answers with `reply`, and
    /// then reads whatever else arrives until the client closes.
    pub(super) async fn answering(reply: &'static [u8]) -> Self {
        Self::listen(move |stream| answer(stream, reply)).await
    }

    /// An upstream that answers each request with `reply` as soon as its
    /// head arrives and then stops reading, as one that answers before the
    /// body is done does.
    pub(super) async fn answering_early(reply: &'static [u8]) -> Self {
        Self::listen(move |stream| answer_early(stream, reply)).await
    }

    /// An upstream that reads each request head, answers with `reply`, and
    /// closes the connection, cutting short a body `reply` promised.
    pub(super) async fn answering_then_closing(reply: &'static [u8]) -> Self {
        Self::listen(move |stream| answer_and_close(stream, reply)).await
    }

    /// Accept connections and hand each to `serve`.
    async fn listen<S, F>(serve: S) -> Self
    where
        S: Fn(TcpStream) -> F + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((stream, _peer)) = listener.accept().await {
                drop(tokio::spawn(serve(stream)));
            }
        });
        Self { address, task }
    }

    /// A plain HTTP/1 peer for this upstream.
    pub(super) fn peer(&self) -> PeerSpec {
        PeerSpec::plain(self.address)
    }

    /// An upstream that reads each request head and then neither answers
    /// nor reads again, as a stalled one does.
    pub(super) async fn stalled() -> Self {
        Self::listen(stall).await
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The shared state of a plain HTTP listener named `test`, with an empty
/// pipeline and a connector of its own.
pub(super) fn listener_shared() -> ListenerShared {
    let listener: Listener = serde_yaml::from_str("name: test\naddress: \"127.0.0.1:0\"\n").unwrap();
    let pipeline = Arc::new(ArcSwap::from_pointee(empty_pipeline()));
    ListenerShared::new(&listener, pipeline, HyperConnector::new(4), None)
}

/// A session to `upstream` with the request head of `method` to `/` sent.
pub(super) async fn session_to(upstream: &Upstream, method: Method) -> (HyperConnector, HyperSession) {
    let connector = HyperConnector::new(4);
    let mut session = connector
        .connect(&upstream.peer(), Duration::from_secs(5))
        .await
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("upstream.test"));
    session
        .send_request_head(RequestHead {
            headers,
            method,
            target: "/".to_owned(),
        })
        .await
        .unwrap();
    (connector, session)
}

/// A bodiless `GET` sent to an upstream answering `reply`, with the first
/// response head read.
pub(super) async fn answered(reply: &'static [u8]) -> (Upstream, HyperConnector, HyperSession) {
    let upstream = Upstream::answering(reply).await;
    let (connector, mut session) = session_to(&upstream, Method::GET).await;
    session.finish_request().await.unwrap();
    session.read_response_head().await.unwrap();
    (upstream, connector, session)
}

/// Read a request head from `stream`; `false` when the client closed first.
async fn read_head(stream: &mut TcpStream) -> bool {
    let mut head = Vec::with_capacity(1024);
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        if stream.read_buf(&mut head).await.unwrap_or(0) == 0 {
            return false;
        }
    }
    true
}

/// Answer the request on `stream` with `reply`, then read until it closes.
async fn answer(mut stream: TcpStream, reply: &'static [u8]) {
    if !read_head(&mut stream).await || stream.write_all(reply).await.is_err() {
        return;
    }
    let mut sink = vec![0_u8; 65_536]; // 64 KiB
    while stream.read(&mut sink).await.unwrap_or(0) > 0 {}
}

/// Answer the request on `stream` with `reply`, then close it.
async fn answer_and_close(mut stream: TcpStream, reply: &'static [u8]) {
    if read_head(&mut stream).await && stream.write_all(reply).await.is_ok() {
        drop(stream.shutdown().await);
    }
}

/// Answer the request on `stream` with `reply` once its head arrived, then
/// hold the connection without reading the body.
async fn answer_early(mut stream: TcpStream, reply: &'static [u8]) {
    if read_head(&mut stream).await && stream.write_all(reply).await.is_ok() {
        std::future::pending::<()>().await;
    }
}

/// Read the request head on `stream`, then hold it without reading.
async fn stall(mut stream: TcpStream) {
    if read_head(&mut stream).await {
        std::future::pending::<()>().await;
    }
}
