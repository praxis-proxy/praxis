// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! One HTTP exchange on a pooled hyper connection.

use std::{
    fmt, mem,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, Request, Response, StatusCode, Uri, Version,
    header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING},
    uri::{Authority, Scheme},
};
use http_body_util::BodyExt as _;
use hyper::body::{Body as _, Incoming};
use tokio::sync::mpsc;
use tokio_rustls::rustls::ProtocolVersion;
use tracing::debug;

use super::{
    body::{BodyFrame, BodySender, RequestBody},
    connection::{Connection, Exchange, Protocol, ResponseFuture},
    describe,
    pool::PoolKey,
};
use crate::egress::{Completion, EgressError, PeerSpec, RequestHead, ResponseHead, Session};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Interim (`1xx`) heads buffered per exchange; later ones are dropped. One
/// above the 32 a caller accepts before failing the exchange, so a flood
/// surfaces there as that error rather than as a stall, while a hostile
/// upstream can park at most 33 heads per exchange.
const INTERIM_CAPACITY: usize = 33; // interim heads

/// How long a released HTTP/1 connection may take to be ready for its next
/// request before it is closed instead of pooled.
const RELEASE_READY_TIMEOUT: Duration = Duration::from_millis(500); // 500 ms

// -----------------------------------------------------------------------------
// HyperSession
// -----------------------------------------------------------------------------

/// One HTTP exchange on a connection from a [`HyperConnector`].
///
/// Driven through [`Session`]. The inherent methods give the proxy data path
/// what it needs beyond that contract: the HTTP and TLS versions actually
/// spoken, the peer address, response trailers, and request trailers on
/// HTTP/2.
///
/// The request goes out once its body framing is known: a single body chunk
/// marked as the last, or [`finish_request`] with no body, sends a request
/// of known length; anything else streams the body through a small bounded
/// buffer, so a slow upstream holds back the producer. Interim (`1xx`)
/// responses on HTTP/1 come back from [`read_response_head`] ahead of the
/// final one, as the contract describes.
///
/// ```
/// use std::time::Duration;
///
/// use praxis_core::egress::{
///     Connector as _, PeerSpec, RequestHead, Session as _, hyper::HyperConnector,
/// };
/// use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
///
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
/// let peer = PeerSpec::plain(listener.local_addr().unwrap());
/// tokio::spawn(async move {
///     let (mut socket, _) = listener.accept().await.unwrap();
///     let mut request = [0_u8; 1024];
///     let _read = socket.read(&mut request).await.unwrap();
///     socket
///         .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
///         .await
///         .unwrap();
/// });
///
/// let connector = HyperConnector::new(8);
/// let mut session = connector
///     .connect(&peer, Duration::from_secs(5))
///     .await
///     .unwrap();
/// let mut headers = http::HeaderMap::new();
/// headers.insert(
///     http::header::HOST,
///     peer.address.to_string().parse().unwrap(),
/// );
/// session
///     .send_request_head(RequestHead {
///         headers,
///         method: http::Method::GET,
///         target: "/".to_owned(),
///     })
///     .await
///     .unwrap();
/// session.finish_request().await.unwrap();
/// session.read_response_head().await.unwrap();
///
/// assert_eq!(session.response_head().unwrap().status, 200);
/// assert_eq!(session.negotiated_version(), http::Version::HTTP_11);
/// assert!(session.tls_protocol_version().is_none());
/// assert_eq!(session.read_response_body().await.unwrap().unwrap(), "ok");
/// assert!(session.response_body_ended());
/// connector.release(session, true).await;
/// # });
/// ```
///
/// [`HyperConnector`]: super::HyperConnector
/// [`finish_request`]: Session::finish_request
/// [`read_response_head`]: Session::read_response_head
/// [`Session`]: Session
pub struct HyperSession {
    /// The connection the exchange runs on.
    connection: Connection,

    /// Keeps the exchange open on its connection while the session lives.
    exchange: Exchange,

    /// The most recently read response head, interim or final.
    head: Option<StoredHead>,

    /// How far the response got.
    inbound: Inbound,

    /// Interim heads hyper reported ahead of the final one (HTTP/1 only).
    interim: Option<mpsc::Receiver<StoredHead>>,

    /// The pool slot the connection goes back to.
    key: PoolKey,

    /// How far the request got.
    outbound: Outbound,

    /// Per-read limit, until the caller takes over pacing.
    read_timeout: Option<Duration>,

    /// The server name, the `:authority` fallback on HTTP/2.
    sni: Arc<str>,

    /// Trailers that ended the response body.
    trailers: Option<HeaderMap>,

    /// Per-send limit.
    write_timeout: Option<Duration>,
}

impl HyperSession {
    /// Start an exchange on `connection` for `peer`, to return to `key`.
    pub(super) fn new(connection: Connection, key: PoolKey, peer: &PeerSpec) -> Self {
        let exchange = connection.begin_exchange(peer.connection.idle_timeout);
        Self {
            connection,
            exchange,
            head: None,
            inbound: Inbound::Unsent,
            interim: None,
            key,
            outbound: Outbound::Unsent,
            read_timeout: peer.connection.read_timeout,
            sni: Arc::clone(&peer.sni),
            trailers: None,
            write_timeout: peer.connection.write_timeout,
        }
    }

    /// Drop the in-flight request and response, which on HTTP/2 resets the
    /// stream and on HTTP/1 leaves the connection to hyper to close unless
    /// the exchange had finished.
    fn abandon(&mut self) {
        self.outbound = Outbound::Done;
        self.inbound = Inbound::Closed;
        self.interim = None;
    }

    /// Take `response` as the final response, unless interim heads that
    /// arrived before it are still unread: then the next of those is the
    /// current head and the final one waits its turn.
    fn accept_final(&mut self, response: Response<Incoming>) {
        let queued = self.interim.as_mut().and_then(|heads| heads.try_recv().ok());
        if let Some(head) = queued {
            self.head = Some(head);
            self.inbound = Inbound::Arrived(Box::new(response));
            return;
        }

        let (parts, body) = response.into_parts();
        self.head = Some(StoredHead {
            headers: parts.headers,
            status: parts.status,
            version: parts.version,
        });
        self.inbound = Inbound::Body(body);
        self.interim = None;
    }

    /// The HTTP/2 `:authority`: the `Host` header when the caller set one,
    /// else the server name, else the peer address.
    fn authority(&self, host: Option<&HeaderValue>) -> Result<Authority, EgressError> {
        if let Some(host) = host {
            return Authority::try_from(host.as_bytes()).map_err(|err| invalid_target(&err));
        }
        if let Ok(authority) = Authority::try_from(&*self.sni) {
            return Ok(authority);
        }
        Authority::try_from(self.connection.peer_address().to_string()).map_err(|err| invalid_target(&err))
    }

    /// The hyper request for `head` on this connection. HTTP/1 sends the
    /// origin-form target and the headers as given; HTTP/2 also needs the
    /// scheme and authority, and carries `Host` as `:authority` instead.
    fn build_request(&self, head: RequestHead) -> Result<Request<()>, EgressError> {
        let RequestHead {
            mut headers,
            method,
            target,
        } = head;
        let protocol = self.connection.protocol();
        let uri = match protocol {
            Protocol::Http1 => Uri::try_from(target).map_err(|err| invalid_target(&err))?,
            Protocol::Http2 => {
                let authority = self.authority(headers.get(HOST))?;
                headers.remove(HOST);
                let scheme = if self.connection.tls_version().is_some() {
                    Scheme::HTTPS
                } else {
                    Scheme::HTTP
                };
                Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(target)
                    .build()
                    .map_err(|err| invalid_target(&err))?
            },
        };

        let mut request = Request::new(());
        *request.method_mut() = method;
        *request.uri_mut() = uri;
        *request.version_mut() = protocol.version();
        *request.headers_mut() = headers;
        Ok(request)
    }

    /// Send the waiting request head with `body`.
    fn dispatch(&mut self, body: RequestBody) -> Result<(), EgressError> {
        let request = match mem::replace(&mut self.outbound, Outbound::Done) {
            Outbound::Head(request) => *request,
            other @ (Outbound::Unsent | Outbound::Streaming(_) | Outbound::Done) => {
                self.outbound = other;
                return Err(EgressError::InvalidRequest(
                    "no request head is waiting to be sent".to_owned(),
                ));
            },
        };

        let mut request = request.map(|()| body);
        if self.connection.protocol() == Protocol::Http1 {
            self.interim = Some(watch_interim(&mut request));
        }
        self.inbound = Inbound::Awaiting(self.connection.send(request));
        Ok(())
    }

    /// Send the waiting request head with a body streamed through the session.
    ///
    /// On HTTP/1 a body of unknown length goes out chunked, whatever the
    /// method, unless the caller already framed it.
    fn dispatch_streaming(&mut self) -> Result<(), EgressError> {
        if self.connection.protocol() == Protocol::Http1
            && let Outbound::Head(request) = &mut self.outbound
        {
            frame_as_chunked(request.headers_mut());
        }

        let (sender, body) = RequestBody::channel();
        self.dispatch(body)?;
        self.outbound = Outbound::Streaming(sender);
        Ok(())
    }

    /// Record `err` as the end of the exchange and return it as an error.
    fn fail(&mut self, err: &hyper::Error) -> EgressError {
        let message = describe(err);
        self.inbound = Inbound::Failed(message.clone());
        EgressError::Io(message)
    }

    /// Finish with the session and hand back its connection when it can
    /// serve another exchange: with `keepalive`, an HTTP/1 connection once
    /// hyper reports it ready, and a still-open HTTP/2 connection. Without
    /// `keepalive` an HTTP/1 connection is closed and an HTTP/2 stream is
    /// reset, leaving the connection to its other streams.
    pub(super) async fn into_reusable(mut self, keepalive: bool) -> Option<(PoolKey, Connection)> {
        self.abandon();
        let reusable = match self.connection.protocol() {
            Protocol::Http1 if keepalive => {
                let ready = tokio::time::timeout(RELEASE_READY_TIMEOUT, self.connection.ready()).await;
                matches!(ready, Ok(Ok(())))
            },
            Protocol::Http1 => false,
            Protocol::Http2 => keepalive && self.connection.is_usable(),
        };

        if !reusable {
            debug!(peer = %self.connection.peer_address(), keepalive, "not pooling an upstream connection");
            if self.connection.protocol() == Protocol::Http1 {
                self.connection.close();
            }
            return None;
        }
        let Self { connection, key, .. } = self;
        Some((key, connection))
    }

    /// The HTTP version spoken on the connection: HTTP/1.1 or HTTP/2.
    ///
    /// ```
    /// # use praxis_core::egress::hyper::HyperSession;
    /// fn is_multiplexed(session: &HyperSession) -> bool {
    ///     session.negotiated_version() == http::Version::HTTP_2
    /// }
    /// ```
    #[must_use]
    pub fn negotiated_version(&self) -> Version {
        self.connection.protocol().version()
    }

    /// The next non-empty body chunk, keeping trailers aside.
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, EgressError> {
        loop {
            let body = match &mut self.inbound {
                Inbound::Body(body) => body,
                Inbound::Ended => return Ok(None),
                Inbound::Failed(message) => return Err(EgressError::Io(message.clone())),
                Inbound::Closed => return Err(EgressError::Io("the session was shut down".to_owned())),
                Inbound::Unsent | Inbound::Awaiting(_) | Inbound::Arrived(_) => {
                    return Err(EgressError::Io("no final response head has been read".to_owned()));
                },
            };

            match body.frame().await {
                None => {
                    self.inbound = Inbound::Ended;
                    return Ok(None);
                },
                Some(Err(err)) => return Err(self.fail(&err)),
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(chunk) if chunk.is_empty() => {},
                    Ok(chunk) => return Ok(Some(chunk)),
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            self.trailers = Some(trailers);
                        }
                    },
                },
            }
        }
    }

    /// Read the next response head: a queued interim head, else whatever
    /// hyper delivers next.
    async fn next_head(&mut self) -> Result<(), EgressError> {
        let next = match &mut self.inbound {
            Inbound::Awaiting(pending) => {
                let interim = &mut self.interim;
                std::future::poll_fn(|cx| poll_next_head(interim.as_mut(), pending, cx)).await
            },
            Inbound::Arrived(_) => NextHead::Queued,
            Inbound::Unsent => return Err(EgressError::Io("no request was sent".to_owned())),
            Inbound::Failed(message) => return Err(EgressError::Io(message.clone())),
            Inbound::Body(_) | Inbound::Ended | Inbound::Closed => {
                return Err(EgressError::Io("no further response head is coming".to_owned()));
            },
        };

        match next {
            NextHead::Interim(head) => self.head = Some(head),
            NextHead::Final(Ok(response)) => self.accept_final(response),
            NextHead::Final(Err(err)) => return Err(self.fail(&err)),
            NextHead::Queued => {
                if let Inbound::Arrived(response) = mem::replace(&mut self.inbound, Inbound::Closed) {
                    self.accept_final(*response);
                }
            },
        }
        Ok(())
    }

    /// The address the connection reached.
    #[must_use]
    pub fn peer_address(&self) -> SocketAddr {
        self.connection.peer_address()
    }

    /// Feed `frame` to the streamed request body.
    async fn push(&mut self, frame: BodyFrame) -> Result<(), EgressError> {
        let ends = frame.ends_body();
        let sender = match &self.outbound {
            Outbound::Streaming(sender) => sender,
            Outbound::Unsent => return Err(no_request_head()),
            Outbound::Head(_) | Outbound::Done => {
                return Err(EgressError::InvalidRequest("no request body is open".to_owned()));
            },
        };

        if !matches!(&frame, BodyFrame::Data(chunk) if chunk.is_empty()) {
            within(self.write_timeout, Phase::Write, sender.send(frame))
                .await?
                .map_err(|_closed| {
                    EgressError::Io("the upstream connection stopped taking the request body".to_owned())
                })?;
        }
        if ends {
            self.outbound = Outbound::Done;
        }
        Ok(())
    }

    /// Whether the response body reported its end, cleanly. This is what
    /// [`Session::completion`] reports as [`Completion::Finished`].
    ///
    /// [`Completion::Finished`]: Completion::Finished
    /// [`Session::completion`]: Session::completion
    #[must_use]
    pub fn response_body_ended(&self) -> bool {
        match &self.inbound {
            Inbound::Ended => true,
            Inbound::Body(body) => body.is_end_stream(),
            Inbound::Unsent | Inbound::Awaiting(_) | Inbound::Arrived(_) | Inbound::Failed(_) | Inbound::Closed => {
                false
            },
        }
    }

    /// Send request trailers, which end the request body.
    ///
    /// # Errors
    ///
    /// [`EgressError::InvalidRequest`] on an HTTP/1 connection, before the
    /// request head, or after the body ended; [`EgressError::Io`] when the
    /// write timeout expires or the connection stops taking the body.
    ///
    /// [`EgressError::InvalidRequest`]: EgressError::InvalidRequest
    /// [`EgressError::Io`]: EgressError::Io
    pub async fn send_request_trailers(&mut self, trailers: HeaderMap) -> Result<(), EgressError> {
        if self.connection.protocol() == Protocol::Http1 {
            return Err(EgressError::InvalidRequest(
                "request trailers need an HTTP/2 connection".to_owned(),
            ));
        }
        if matches!(self.outbound, Outbound::Head(_)) {
            self.dispatch_streaming()?;
        }
        self.push(BodyFrame::Trailers(trailers)).await
    }

    /// The response trailers, once the body ended with some. gRPC carries
    /// its status here.
    pub fn take_trailers(&mut self) -> Option<HeaderMap> {
        self.trailers.take()
    }

    /// The TLS version of the connection; `None` over plain TCP.
    #[must_use]
    pub fn tls_protocol_version(&self) -> Option<ProtocolVersion> {
        self.connection.tls_version()
    }
}

impl Session for HyperSession {
    fn reused(&self) -> bool {
        self.exchange.reused()
    }

    async fn send_request_head(&mut self, head: RequestHead) -> Result<(), EgressError> {
        if !matches!(self.outbound, Outbound::Unsent) {
            return Err(EgressError::InvalidRequest(
                "the request head was already sent".to_owned(),
            ));
        }

        let request = self.build_request(head)?;
        within(self.write_timeout, Phase::Write, self.connection.ready())
            .await?
            .map_err(|err| EgressError::Io(describe(&err)))?;
        self.outbound = Outbound::Head(Box::new(request));
        Ok(())
    }

    async fn send_request_body(&mut self, chunk: Bytes, end_of_stream: bool) -> Result<(), EgressError> {
        if matches!(self.outbound, Outbound::Head(_)) {
            if end_of_stream {
                return self.dispatch(RequestBody::full(chunk));
            }
            self.dispatch_streaming()?;
        }

        let frame = if end_of_stream {
            BodyFrame::Last(chunk)
        } else {
            BodyFrame::Data(chunk)
        };
        self.push(frame).await
    }

    async fn finish_request(&mut self) -> Result<(), EgressError> {
        match self.outbound {
            Outbound::Head(_) => self.dispatch(RequestBody::empty()),
            Outbound::Streaming(_) => self.push(BodyFrame::Last(Bytes::new())).await,
            Outbound::Done => Ok(()),
            Outbound::Unsent => Err(no_request_head()),
        }
    }

    async fn read_response_head(&mut self) -> Result<(), EgressError> {
        if matches!(self.outbound, Outbound::Head(_)) {
            self.dispatch_streaming()?;
        }
        within(self.read_timeout, Phase::Read, self.next_head()).await?
    }

    fn response_head(&self) -> Result<ResponseHead<'_>, EgressError> {
        let head = self
            .head
            .as_ref()
            .ok_or_else(|| EgressError::Io("no response header received".to_owned()))?;

        Ok(ResponseHead {
            headers: &head.headers,
            status: head.status.as_u16(),
            version: head.version,
        })
    }

    fn response_done(&mut self) -> bool {
        match &self.inbound {
            Inbound::Body(body) => body.is_end_stream(),
            Inbound::Ended | Inbound::Failed(_) | Inbound::Closed => true,
            Inbound::Unsent | Inbound::Awaiting(_) | Inbound::Arrived(_) => false,
        }
    }

    async fn read_response_body(&mut self) -> Result<Option<Bytes>, EgressError> {
        within(self.read_timeout, Phase::Read, self.next_chunk()).await?
    }

    fn completion(&mut self) -> Result<Completion, EgressError> {
        if let Inbound::Failed(message) = &self.inbound {
            return Err(EgressError::Io(message.clone()));
        }

        Ok(if self.response_body_ended() {
            Completion::Finished
        } else {
            Completion::Incomplete
        })
    }

    fn clear_read_timeout(&mut self) {
        self.read_timeout = None;
    }

    async fn shutdown(&mut self) {
        self.abandon();
        if self.connection.protocol() == Protocol::Http1 {
            self.connection.close();
        }
    }
}

impl fmt::Debug for HyperSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HyperSession")
            .field("peer", &self.connection.peer_address())
            .field("protocol", &self.connection.protocol())
            .field("request", &self.outbound.stage())
            .field("response", &self.inbound.stage())
            .field("reused", &self.exchange.reused())
            .finish_non_exhaustive()
    }
}

/// How far the request got.
enum Outbound {
    /// No head sent yet.
    Unsent,

    /// The head, held until the body framing is known.
    Head(Box<Request<()>>),

    /// Sent with a streamed body that is still open.
    Streaming(BodySender),

    /// Handed to hyper in full, or abandoned.
    Done,
}

impl Outbound {
    /// A name for the stage, for diagnostics.
    const fn stage(&self) -> &'static str {
        match self {
            Self::Unsent => "unsent",
            Self::Head(_) => "head",
            Self::Streaming(_) => "streaming",
            Self::Done => "done",
        }
    }
}

/// How far the response got.
enum Inbound {
    /// Nothing sent yet.
    Unsent,

    /// Sent; waiting for the final head.
    Awaiting(ResponseFuture),

    /// The final head arrived while interim heads were still unread.
    Arrived(Box<Response<Incoming>>),

    /// Reading the final response's body.
    Body(Incoming),

    /// The body ended cleanly.
    Ended,

    /// The exchange failed; later reads repeat the message.
    Failed(String),

    /// Torn down.
    Closed,
}

impl Inbound {
    /// A name for the stage, for diagnostics.
    const fn stage(&self) -> &'static str {
        match self {
            Self::Unsent => "unsent",
            Self::Awaiting(_) => "awaiting",
            Self::Arrived(_) => "arrived",
            Self::Body(_) => "body",
            Self::Ended => "ended",
            Self::Failed(_) => "failed",
            Self::Closed => "closed",
        }
    }
}

/// What the next head read produced.
enum NextHead {
    /// An interim head.
    Interim(StoredHead),

    /// hyper's final answer.
    Final(hyper::Result<Response<Incoming>>),

    /// The final head is already here, queued behind interim heads.
    Queued,
}

/// A response head the session keeps for [`Session::response_head`].
///
/// [`Session::response_head`]: Session::response_head
#[derive(Debug)]
struct StoredHead {
    /// The header fields as received.
    headers: HeaderMap,

    /// The status code.
    status: StatusCode,

    /// The protocol version the peer answered with.
    version: Version,
}

/// Which side of the exchange a timer bounds.
#[derive(Clone, Copy, Debug)]
enum Phase {
    /// Reading the response.
    Read,

    /// Sending the request.
    Write,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::Write => "write",
        })
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Declare a body of unknown length as chunked, unless `headers` already
/// frame it. hyper's HTTP/1 client sends an unframed `GET` or `HEAD` body of
/// unknown length as no body at all, and the caller strips the client's own
/// `Transfer-Encoding` as hop-by-hop, so the session reframes it.
fn frame_as_chunked(headers: &mut HeaderMap) {
    if !headers.contains_key(CONTENT_LENGTH) && !headers.contains_key(TRANSFER_ENCODING) {
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    }
}

/// A target or authority hyper cannot carry, as a request error.
fn invalid_target(err: &dyn std::error::Error) -> EgressError {
    EgressError::InvalidRequest(format!("invalid request target: {err}"))
}

/// The error for a body call before any request head.
fn no_request_head() -> EgressError {
    EgressError::InvalidRequest("no request head was sent".to_owned())
}

/// Poll for the next head: queued interim heads first, then the response.
fn poll_next_head(
    interim: Option<&mut mpsc::Receiver<StoredHead>>,
    pending: &mut ResponseFuture,
    cx: &mut Context<'_>,
) -> Poll<NextHead> {
    if let Some(heads) = interim
        && let Poll::Ready(Some(head)) = heads.poll_recv(cx)
    {
        return Poll::Ready(NextHead::Interim(head));
    }
    pending.as_mut().poll(cx).map(NextHead::Final)
}

/// Route the interim heads hyper reports for `request` into a channel.
fn watch_interim(request: &mut Request<RequestBody>) -> mpsc::Receiver<StoredHead> {
    let (sender, receiver) = mpsc::channel(INTERIM_CAPACITY);
    hyper::ext::on_informational(request, move |response| {
        // hyper only lends the head to the callback, so it is copied out.
        let head = StoredHead {
            headers: response.headers().clone(),
            status: response.status(),
            version: response.version(),
        };
        if sender.try_send(head).is_err() {
            debug!(status = %response.status(), "dropping an upstream interim response past the buffered limit");
        }
    });
    receiver
}

/// Run `work`, failing with a timeout named after `phase` when `limit` passes.
async fn within<F: Future>(limit: Option<Duration>, phase: Phase, work: F) -> Result<F::Output, EgressError> {
    let Some(limit) = limit else {
        return Ok(work.await);
    };

    tokio::time::timeout(limit, work)
        .await
        .map_err(|_elapsed| EgressError::Io(format!("upstream {phase} timeout ({} ms) expired", limit.as_millis())))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use http::Method;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
        task::JoinHandle,
    };

    use super::*;
    use crate::{
        config::UpstreamHttpVersion,
        egress::hyper::{
            connection::{SetupTimeouts, dial},
            tls::TlsConfigs,
        },
    };

    #[tokio::test]
    async fn within_without_a_limit_runs_the_work() {
        let result = within(None, Phase::Read, std::future::ready(7)).await;

        assert!(
            matches!(result, Ok(7)),
            "no limit hands back the work's output: {result:?}"
        );
    }

    #[tokio::test]
    async fn within_hands_back_work_that_finishes_in_time() {
        let result = within(Some(Duration::from_secs(5)), Phase::Write, std::future::ready(7)).await;

        assert!(
            matches!(result, Ok(7)),
            "work done inside the limit is not a timeout: {result:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn expired_read_names_the_read_timeout() {
        let result = within(
            Some(Duration::from_millis(50)),
            Phase::Read,
            std::future::pending::<()>(),
        )
        .await;

        assert!(
            matches!(&result, Err(EgressError::Io(message)) if message == "upstream read timeout (50 ms) expired"),
            "an expired read names its phase and limit: {result:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn expired_write_names_the_write_timeout() {
        let result = within(
            Some(Duration::from_millis(75)),
            Phase::Write,
            std::future::pending::<()>(),
        )
        .await;

        assert!(
            matches!(&result, Err(EgressError::Io(message)) if message == "upstream write timeout (75 ms) expired"),
            "an expired write names its phase and limit: {result:?}"
        );
    }

    #[test]
    fn invalid_target_is_a_request_error_naming_its_cause() {
        let cause = Uri::try_from("/a b").unwrap_err();

        let error = invalid_target(&cause);

        assert!(
            matches!(&error, EgressError::InvalidRequest(message)
                if message.starts_with("invalid request target: ") && message.len() > "invalid request target: ".len()),
            "the caller's target is at fault, and the cause is kept: {error:?}"
        );
    }

    #[test]
    fn no_request_head_is_a_request_error() {
        let error = no_request_head();

        assert!(
            matches!(&error, EgressError::InvalidRequest(message) if message == "no request head was sent"),
            "a body call before any head is the caller's mistake: {error:?}"
        );
    }

    #[tokio::test]
    async fn queued_interim_head_comes_before_the_pending_response() {
        let (sender, mut interim) = mpsc::channel(INTERIM_CAPACITY);
        sender.try_send(stored_head(StatusCode::EARLY_HINTS)).unwrap();
        let mut pending = never_answered();

        let first = poll_head_once(Some(&mut interim), &mut pending).await;
        let second = poll_head_once(Some(&mut interim), &mut pending).await;

        assert!(
            matches!(&first, Poll::Ready(NextHead::Interim(head)) if head.status == StatusCode::EARLY_HINTS),
            "a queued interim head is handed out first"
        );
        assert!(second.is_pending(), "with the queue drained, the response is waited on");
    }

    #[tokio::test]
    async fn without_interim_heads_the_response_is_waited_on() {
        let (_sender, mut interim) = mpsc::channel(INTERIM_CAPACITY);
        let mut pending = never_answered();

        let empty_queue = poll_head_once(Some(&mut interim), &mut pending).await;
        let no_queue = poll_head_once(None, &mut pending).await;

        assert!(empty_queue.is_pending(), "an empty queue leaves the response to answer");
        assert!(no_queue.is_pending(), "an HTTP/2 exchange has no queue at all");
    }

    #[tokio::test]
    async fn interim_heads_past_the_buffer_are_dropped() {
        let mut response = b"HTTP/1.1 103 Early Hints\r\nlink: </a.css>\r\n\r\n".repeat(40);
        response.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
        let peer = answering(Bytes::from(response), After::Hold).await;
        let mut session = open(&peer).await;
        send_get(&mut session).await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut interim = 0_usize;
        session.read_response_head().await.unwrap();
        while session.response_head().unwrap().status == 103 {
            interim = interim.saturating_add(1);
            session.read_response_head().await.unwrap();
        }

        assert_eq!(interim, INTERIM_CAPACITY, "only the buffered interim heads come back");
        assert_eq!(
            session.response_head().unwrap().status,
            204,
            "the final head follows the buffered interim heads"
        );
    }

    #[tokio::test]
    async fn trailers_are_handed_out_once_the_body_ended() {
        let peer = http2_upstream("api.test").await;
        let mut session = open(&peer).await;
        send_get(&mut session).await;
        session.read_response_head().await.unwrap();

        let before = session.take_trailers();
        let body = read_body(&mut session).await;
        let after = session.take_trailers();

        assert!(before.is_none(), "no trailers before the body is read");
        assert_eq!(body, b"hi", "the body comes before its trailers");
        assert_eq!(
            after.unwrap().get("grpc-status").unwrap(),
            "0",
            "the trailers that ended the body are kept"
        );
        assert!(session.take_trailers().is_none(), "trailers are handed out once");
    }

    #[tokio::test]
    async fn exchange_before_its_final_head_is_not_done() {
        let peer = answering(Bytes::from_static(OK), After::Hold).await;
        let mut session = open(&peer).await;

        let fresh = (session.response_done(), session.completion().unwrap());
        send_get(&mut session).await;
        let sent = (session.response_done(), session.completion().unwrap());

        assert_eq!(
            fresh,
            (false, Completion::Incomplete),
            "nothing is done before a request goes out"
        );
        assert_eq!(
            sent,
            (false, Completion::Incomplete),
            "a sent request waits for its response"
        );
    }

    #[tokio::test]
    async fn head_with_an_unread_body_is_incomplete() {
        let peer = answering(Bytes::from_static(OK), After::Hold).await;
        let mut session = open(&peer).await;
        send_get(&mut session).await;
        session.read_response_head().await.unwrap();

        assert!(!session.response_done(), "the body is still to read");
        assert!(!session.response_body_ended(), "the body has not ended");
        assert_eq!(
            session.completion().unwrap(),
            Completion::Incomplete,
            "an exchange with an unread body is incomplete"
        );
    }

    #[tokio::test]
    async fn body_read_to_its_end_finishes_the_exchange() {
        let peer = answering(Bytes::from_static(OK), After::Hold).await;
        let mut session = open(&peer).await;
        send_get(&mut session).await;
        session.read_response_head().await.unwrap();

        let body = read_body(&mut session).await;

        assert_eq!(body, b"ok", "the declared body comes through");
        assert!(session.response_done(), "nothing is left to read");
        assert_eq!(
            session.completion().unwrap(),
            Completion::Finished,
            "a body read to its end finishes the exchange"
        );
    }

    #[tokio::test]
    async fn body_cut_off_by_the_upstream_fails_the_exchange() {
        let response = b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nabc";
        let peer = answering(Bytes::from_static(response), After::Close).await;
        let mut session = open(&peer).await;
        send_get(&mut session).await;
        session.read_response_head().await.unwrap();

        let mut result = session.read_response_body().await;
        while matches!(result, Ok(Some(_))) {
            result = session.read_response_body().await;
        }

        assert!(
            matches!(result, Err(EgressError::Io(_))),
            "a body shorter than declared fails: {result:?}"
        );
        assert!(session.response_done(), "a failed exchange has nothing more to read");
        assert!(
            matches!(session.completion(), Err(EgressError::Io(_))),
            "the failure is what the exchange completes with"
        );
        assert!(
            matches!(session.read_response_body().await, Err(EgressError::Io(_))),
            "later reads repeat the failure"
        );
    }

    #[tokio::test]
    async fn shut_down_session_refuses_further_reads() {
        let peer = answering(Bytes::from_static(OK), After::Hold).await;
        let mut session = open(&peer).await;
        send_get(&mut session).await;
        session.read_response_head().await.unwrap();

        session.shutdown().await;
        let read = session.read_response_body().await;

        assert!(session.response_done(), "a torn-down exchange has nothing more to read");
        assert_eq!(
            session.completion().unwrap(),
            Completion::Incomplete,
            "a torn-down body did not finish"
        );
        assert!(
            matches!(&read, Err(EgressError::Io(message)) if message == "the session was shut down"),
            "reads after a shutdown say so: {read:?}"
        );
    }

    #[tokio::test]
    async fn cleared_read_timeout_no_longer_bounds_reads() {
        let mut peer = answering(Bytes::new(), After::Hold).await;
        Arc::make_mut(&mut peer.connection).read_timeout = Some(Duration::from_millis(50));
        let mut session = open(&peer).await;
        send_get(&mut session).await;

        session.clear_read_timeout();
        let read = tokio::time::timeout(Duration::from_millis(300), session.read_response_head()).await;

        assert!(
            read.is_err(),
            "once the caller paces reads, the session's own read timeout no longer fires"
        );
    }

    #[tokio::test]
    async fn http2_authority_comes_from_host() {
        let peer = http2_upstream("api.test").await;
        let session = open(&peer).await;

        let request = session.build_request(head(Some("upstream.test"), "/a?b=1")).unwrap();

        assert_eq!(
            request.uri().authority().map(Authority::as_str),
            Some("upstream.test"),
            "the Host header becomes the :authority"
        );
        assert!(
            request.headers().get(HOST).is_none(),
            "HTTP/2 carries Host as :authority instead of a header"
        );
    }

    #[tokio::test]
    async fn http2_target_over_plain_tcp_uses_the_http_scheme() {
        let peer = http2_upstream("api.test").await;
        let session = open(&peer).await;

        let request = session.build_request(head(Some("upstream.test"), "/a?b=1")).unwrap();

        assert_eq!(request.uri().scheme(), Some(&Scheme::HTTP), "plain TCP is http");
        assert_eq!(
            request.uri().path_and_query().map(http::uri::PathAndQuery::as_str),
            Some("/a?b=1"),
            "the origin-form target becomes the :path"
        );
        assert_eq!(request.version(), Version::HTTP_2, "the request speaks HTTP/2");
    }

    #[tokio::test]
    async fn http2_authority_falls_back_to_the_server_name() {
        let peer = http2_upstream("api.test").await;
        let session = open(&peer).await;

        let request = session.build_request(head(None, "/")).unwrap();

        assert_eq!(
            request.uri().authority().map(Authority::as_str),
            Some("api.test"),
            "without Host, the server name is the :authority"
        );
    }

    #[tokio::test]
    async fn http2_authority_falls_back_to_the_peer_address() {
        let peer = http2_upstream("").await;
        let session = open(&peer).await;

        let request = session.build_request(head(None, "/")).unwrap();

        assert_eq!(
            request.uri().authority().map(Authority::as_str),
            Some(peer.address.to_string().as_str()),
            "without Host or a server name, the peer address is the :authority"
        );
    }

    #[tokio::test]
    async fn http2_host_that_is_no_authority_is_refused() {
        let peer = http2_upstream("api.test").await;
        let session = open(&peer).await;

        let result = session.build_request(head(Some("bad host"), "/"));

        assert!(
            matches!(result, Err(EgressError::InvalidRequest(_))),
            "a Host that cannot be an :authority is the caller's error: {result:?}"
        );
    }

    #[tokio::test]
    async fn http1_request_keeps_its_origin_form_and_host() {
        let peer = answering(Bytes::from_static(OK), After::Hold).await;
        let session = open(&peer).await;

        let request = session.build_request(head(Some("upstream.test"), "/a?b=1")).unwrap();

        assert_eq!(request.uri(), "/a?b=1", "HTTP/1 sends the origin-form target as given");
        assert_eq!(
            request.headers().get(HOST).unwrap(),
            "upstream.test",
            "HTTP/1 keeps Host as a header"
        );
        assert_eq!(request.version(), Version::HTTP_11, "the request speaks HTTP/1.1");
    }

    #[tokio::test]
    async fn http1_target_that_is_no_uri_is_refused() {
        let peer = answering(Bytes::from_static(OK), After::Hold).await;
        let session = open(&peer).await;

        let result = session.build_request(head(Some("upstream.test"), "/a b"));

        assert!(
            matches!(result, Err(EgressError::InvalidRequest(_))),
            "a target hyper cannot carry is the caller's error: {result:?}"
        );
    }

    #[tokio::test]
    async fn request_head_is_sent_only_once() {
        let peer = answering(Bytes::from_static(OK), After::Hold).await;
        let mut session = open(&peer).await;
        session
            .send_request_head(head(Some("upstream.test"), "/"))
            .await
            .unwrap();

        let again = session.send_request_head(head(Some("upstream.test"), "/")).await;

        assert!(
            matches!(again, Err(EgressError::InvalidRequest(_))),
            "a second head is refused: {again:?}"
        );
    }

    #[tokio::test]
    async fn body_calls_before_a_head_are_refused() {
        let peer = answering(Bytes::from_static(OK), After::Hold).await;
        let mut session = open(&peer).await;

        let finished = session.finish_request().await;
        let sent = session.send_request_body(Bytes::from_static(b"x"), false).await;

        assert!(
            matches!(&finished, Err(EgressError::InvalidRequest(message)) if message == "no request head was sent"),
            "finishing before a head is refused: {finished:?}"
        );
        assert!(
            matches!(&sent, Err(EgressError::InvalidRequest(message)) if message == "no request head was sent"),
            "a body chunk before a head is refused: {sent:?}"
        );
    }

    #[tokio::test]
    async fn reading_a_head_before_any_request_fails() {
        let peer = answering(Bytes::from_static(OK), After::Hold).await;
        let mut session = open(&peer).await;

        let result = session.read_response_head().await;

        assert!(
            matches!(&result, Err(EgressError::Io(message)) if message == "no request was sent"),
            "there is no response to a request never sent: {result:?}"
        );
    }

    #[tokio::test]
    async fn reading_the_body_before_the_final_head_fails() {
        let peer = answering(Bytes::from_static(OK), After::Hold).await;
        let mut session = open(&peer).await;
        send_get(&mut session).await;

        let result = session.read_response_body().await;

        assert!(
            matches!(&result, Err(EgressError::Io(message)) if message == "no final response head has been read"),
            "the body follows the final head: {result:?}"
        );
    }

    #[tokio::test]
    async fn http2_trailers_before_a_head_are_refused() {
        let peer = http2_upstream("api.test").await;
        let mut session = open(&peer).await;

        let result = session.send_request_trailers(HeaderMap::new()).await;

        assert!(
            matches!(&result, Err(EgressError::InvalidRequest(message)) if message == "no request head was sent"),
            "trailers need a request to end: {result:?}"
        );
    }

    #[tokio::test]
    async fn http2_trailers_after_the_body_ended_are_refused() {
        let peer = http2_upstream("api.test").await;
        let mut session = open(&peer).await;
        session
            .send_request_head(head(Some("upstream.test"), "/"))
            .await
            .unwrap();
        session
            .send_request_body(Bytes::from_static(b"done"), true)
            .await
            .unwrap();

        let result = session.send_request_trailers(HeaderMap::new()).await;

        assert!(
            matches!(&result, Err(EgressError::InvalidRequest(message)) if message == "no request body is open"),
            "a body that already ended takes no trailers: {result:?}"
        );
    }

    #[tokio::test]
    async fn single_final_chunk_goes_out_with_its_length() {
        let (peer, recorded) = recording().await;
        let mut session = open(&peer).await;
        session.send_request_head(post()).await.unwrap();

        session
            .send_request_body(Bytes::from_static(b"hello"), true)
            .await
            .unwrap();
        session.read_response_head().await.unwrap();
        let request = String::from_utf8(recorded.await.unwrap()).unwrap();

        assert!(
            request.contains("content-length: 5\r\n"),
            "a body known in full is sent with its length: {request}"
        );
        assert!(
            !request.contains("transfer-encoding"),
            "a body of known length is not chunked: {request}"
        );
        assert!(request.ends_with("hello"), "the body follows the head: {request}");
    }

    #[tokio::test]
    async fn body_sent_in_pieces_is_streamed_chunked() {
        let (peer, recorded) = recording().await;
        let mut session = open(&peer).await;
        session.send_request_head(post()).await.unwrap();

        session
            .send_request_body(Bytes::from_static(b"hel"), false)
            .await
            .unwrap();
        session
            .send_request_body(Bytes::from_static(b"lo"), true)
            .await
            .unwrap();
        session.read_response_head().await.unwrap();
        let request = String::from_utf8(recorded.await.unwrap()).unwrap();

        assert!(
            request.contains("transfer-encoding: chunked\r\n"),
            "a body of unknown length is streamed chunked: {request}"
        );
        assert!(
            !request.contains("content-length"),
            "a streamed body declares no length: {request}"
        );
    }

    #[tokio::test]
    async fn get_body_sent_in_pieces_reaches_the_upstream() {
        let (peer, recorded) = recording().await;
        let mut session = open(&peer).await;
        session
            .send_request_head(head(Some("upstream.test"), "/"))
            .await
            .unwrap();

        session
            .send_request_body(Bytes::from_static(b"hel"), false)
            .await
            .unwrap();
        session
            .send_request_body(Bytes::from_static(b"lo"), true)
            .await
            .unwrap();
        session.read_response_head().await.unwrap();
        let request = String::from_utf8(recorded.await.unwrap()).unwrap();

        assert!(
            request.contains("transfer-encoding: chunked\r\n") && request.contains("hel"),
            "a streamed GET body must reach the upstream, as Pingora forwards it: {request}"
        );
    }

    #[tokio::test]
    async fn get_body_in_one_chunk_goes_out_with_its_length() {
        let (peer, recorded) = recording().await;
        let mut session = open(&peer).await;
        session
            .send_request_head(head(Some("upstream.test"), "/"))
            .await
            .unwrap();

        session
            .send_request_body(Bytes::from_static(b"hello"), true)
            .await
            .unwrap();
        session.read_response_head().await.unwrap();
        let request = String::from_utf8(recorded.await.unwrap()).unwrap();

        assert!(
            request.contains("content-length: 5\r\n"),
            "a GET body known in full is sent with its length: {request}"
        );
        assert!(
            !request.contains("transfer-encoding"),
            "a GET body of known length is not chunked: {request}"
        );
        assert!(request.ends_with("hello"), "the body follows the head: {request}");
    }

    #[tokio::test]
    async fn streamed_body_keeps_the_length_the_caller_declared() {
        let (peer, recorded) = recording().await;
        let mut session = open(&peer).await;
        let mut request_head = head(Some("upstream.test"), "/");
        request_head
            .headers
            .insert(CONTENT_LENGTH, HeaderValue::from_static("5"));
        session.send_request_head(request_head).await.unwrap();

        session
            .send_request_body(Bytes::from_static(b"hel"), false)
            .await
            .unwrap();
        session
            .send_request_body(Bytes::from_static(b"lo"), true)
            .await
            .unwrap();
        session.read_response_head().await.unwrap();
        let request = String::from_utf8(recorded.await.unwrap()).unwrap();

        assert!(
            request.contains("content-length: 5\r\n"),
            "a declared length is kept: {request}"
        );
        assert!(
            !request.contains("transfer-encoding"),
            "a body with a declared length is not reframed as chunked: {request}"
        );
        assert!(request.ends_with("hello"), "the body follows the head: {request}");
    }

    #[tokio::test]
    async fn empty_get_goes_out_without_framing_headers() {
        let (peer, recorded) = recording().await;
        let mut session = open(&peer).await;

        send_get(&mut session).await;
        session.read_response_head().await.unwrap();
        let request = String::from_utf8(recorded.await.unwrap()).unwrap();

        assert!(
            !request.contains("transfer-encoding") && !request.contains("content-length"),
            "a bodiless GET carries no framing headers: {request}"
        );
    }

    #[test]
    fn frame_as_chunked_leaves_framed_heads_alone() {
        let mut unframed = HeaderMap::new();
        let mut sized = HeaderMap::new();
        sized.insert(CONTENT_LENGTH, HeaderValue::from_static("3"));
        let mut encoded = HeaderMap::new();
        encoded.insert(TRANSFER_ENCODING, HeaderValue::from_static("gzip, chunked"));

        frame_as_chunked(&mut unframed);
        frame_as_chunked(&mut sized);
        frame_as_chunked(&mut encoded);

        assert_eq!(
            unframed.get(TRANSFER_ENCODING).unwrap(),
            "chunked",
            "an unframed head is declared chunked"
        );
        assert!(
            !sized.contains_key(TRANSFER_ENCODING),
            "a declared length is never paired with chunked"
        );
        assert_eq!(
            encoded.get(TRANSFER_ENCODING).unwrap(),
            "gzip, chunked",
            "a caller's own transfer coding is kept"
        );
    }

    #[tokio::test]
    async fn clean_http1_exchange_hands_back_its_connection() {
        let peer = answering(Bytes::from_static(OK), After::Hold).await;
        let mut session = open(&peer).await;
        send_get(&mut session).await;
        session.read_response_head().await.unwrap();
        read_body(&mut session).await;

        let (key, connection) = session
            .into_reusable(true)
            .await
            .expect("a finished exchange is reusable");

        assert_eq!(key, PoolKey::new(&peer), "the connection goes back to its own key");
        assert_eq!(
            connection.peer_address(),
            peer.address,
            "the handed-back connection reaches the peer"
        );
        assert!(
            connection.is_usable(),
            "the handed-back connection can take a new request"
        );
    }

    #[tokio::test]
    async fn http1_released_without_keepalive_is_not_reused() {
        let peer = answering(Bytes::from_static(OK), After::Hold).await;
        let mut session = open(&peer).await;
        send_get(&mut session).await;
        session.read_response_head().await.unwrap();
        read_body(&mut session).await;

        let reusable = session.into_reusable(false).await;

        assert!(reusable.is_none(), "without keepalive an HTTP/1 connection is closed");
    }

    #[tokio::test]
    async fn http2_connection_is_reusable_before_its_stream_ends() {
        let peer = http2_upstream("api.test").await;
        let mut session = open(&peer).await;
        send_get(&mut session).await;
        session.read_response_head().await.unwrap();

        let reusable = session.into_reusable(true).await;

        assert!(
            reusable.is_some_and(|(_, connection)| connection.protocol() == Protocol::Http2),
            "an HTTP/2 connection outlives the stream reset on release"
        );
    }

    #[tokio::test]
    async fn debug_names_the_request_and_response_stages() {
        let peer = answering(Bytes::from_static(OK), After::Hold).await;
        let mut session = open(&peer).await;

        let fresh = format!("{session:?}");
        session
            .send_request_head(head(Some("upstream.test"), "/"))
            .await
            .unwrap();
        let held = format!("{session:?}");
        session.finish_request().await.unwrap();
        let sent = format!("{session:?}");

        assert!(
            fresh.contains(r#"request: "unsent", response: "unsent", reused: false"#),
            "a fresh session has sent nothing: {fresh}"
        );
        assert!(
            held.contains(r#"request: "head""#),
            "the head waits for its body: {held}"
        );
        assert!(
            sent.contains(r#"request: "done", response: "awaiting""#),
            "a finished request waits for its response: {sent}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A plain `200 OK` with a two-byte body.
    const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";

    /// What a canned upstream does with its connection once it answered.
    #[derive(Clone, Copy, Debug)]
    enum After {
        /// Close it.
        Close,

        /// Keep it open until the client closes it.
        Hold,
    }

    /// Answer one HTTP/2 request: drain its body, then send `hi` and a
    /// `grpc-status: 0` trailer.
    async fn answer_h2(request: Request<h2::RecvStream>, mut respond: h2::server::SendResponse<Bytes>) {
        let mut body = request.into_body();
        while let Some(Ok(chunk)) = body.data().await {
            if body.flow_control().release_capacity(chunk.len()).is_err() {
                return;
            }
        }
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));

        let Ok(mut stream) = respond.send_response(Response::new(()), false) else {
            return;
        };
        if stream.send_data(Bytes::from_static(b"hi"), false).is_err() {
            return;
        }
        let _sent = stream.send_trailers(trailers);
    }

    /// An HTTP/1 upstream that writes `response` once the first request
    /// head arrives on its one connection, then does what `after` says.
    async fn answering(response: Bytes, after: After) -> PeerSpec {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = PeerSpec::plain(listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_head(&mut socket).await;
            socket.write_all(&response).await.unwrap();
            if matches!(after, After::Hold) {
                let mut sink = vec![0_u8; 1024];
                while socket.read(&mut sink).await.unwrap_or(0) > 0 {}
            }
        });
        peer
    }

    /// A request head for `target`, with `host` as its `Host` when given.
    fn head(host: Option<&'static str>, target: &str) -> RequestHead {
        let mut headers = HeaderMap::new();
        if let Some(host) = host {
            headers.insert(HOST, HeaderValue::from_static(host));
        }
        RequestHead {
            headers,
            method: Method::GET,
            target: target.to_owned(),
        }
    }

    /// A prior-knowledge HTTP/2 upstream, presenting `sni` as its server
    /// name, that answers every stream with [`answer_h2`].
    ///
    /// [`answer_h2`]: answer_h2
    async fn http2_upstream(sni: &str) -> PeerSpec {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = PeerSpec::new(listener.local_addr().unwrap(), false, sni);
        Arc::make_mut(&mut peer.connection).http_version = UpstreamHttpVersion::H2;
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(socket).await.unwrap();
            while let Some(Ok((request, respond))) = connection.accept().await {
                tokio::spawn(answer_h2(request, respond));
            }
        });
        peer
    }

    /// A response future that never resolves.
    fn never_answered() -> ResponseFuture {
        Box::pin(std::future::pending::<hyper::Result<Response<Incoming>>>())
    }

    /// A session on a fresh connection to `peer`.
    async fn open(peer: &PeerSpec) -> HyperSession {
        let timeouts = SetupTimeouts::new(&peer.connection, Duration::from_secs(5));
        let connection = Box::pin(dial(peer, &TlsConfigs::default(), timeouts)).await.unwrap();
        HyperSession::new(connection, PoolKey::new(peer), peer)
    }

    /// Poll [`poll_next_head`] once.
    ///
    /// [`poll_next_head`]: poll_next_head
    async fn poll_head_once(
        mut interim: Option<&mut mpsc::Receiver<StoredHead>>,
        pending: &mut ResponseFuture,
    ) -> Poll<NextHead> {
        std::future::poll_fn(|cx| Poll::Ready(poll_next_head(interim.as_deref_mut(), pending, cx))).await
    }

    /// A `POST` head for `/` with the `Host` the tests expect.
    fn post() -> RequestHead {
        let mut request = head(Some("upstream.test"), "/");
        request.method = Method::POST;
        request
    }

    /// Read the rest of the response body.
    async fn read_body(session: &mut HyperSession) -> Vec<u8> {
        let mut body = Vec::new();
        while let Some(chunk) = session.read_response_body().await.unwrap() {
            body.extend_from_slice(&chunk);
        }
        body
    }

    /// Read from `socket` until a request head has arrived.
    async fn read_head(socket: &mut TcpStream) {
        let mut request = Vec::with_capacity(1024);
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            if socket.read_buf(&mut request).await.unwrap_or(0) == 0 {
                return;
            }
        }
    }

    /// An HTTP/1 upstream that records everything its one connection sends
    /// until the client falls quiet, then answers with [`OK`]; the task
    /// resolves to the recorded bytes.
    ///
    /// [`OK`]: OK
    async fn recording() -> (PeerSpec, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = PeerSpec::plain(listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while let Ok(Ok(read)) =
                tokio::time::timeout(Duration::from_millis(200), socket.read_buf(&mut request)).await
                && read > 0
            {}
            socket.write_all(OK).await.unwrap();
            request
        });
        (peer, task)
    }

    /// Send a bodiless GET for `/`.
    async fn send_get(session: &mut HyperSession) {
        session
            .send_request_head(head(Some("upstream.test"), "/"))
            .await
            .unwrap();
        session.finish_request().await.unwrap();
    }

    /// A stored interim head with `status` and no headers.
    fn stored_head(status: StatusCode) -> StoredHead {
        StoredHead {
            headers: HeaderMap::new(),
            status,
            version: Version::HTTP_11,
        }
    }
}
