// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Persistent bidirectional `ext_proc` exchange state machine.
//!
//! Opens one [`ExternalProcessor.Process`] gRPC stream per HTTP
//! request and sends/receives multiple messages across request
//! and response phases.
//!
//! Sending and receiving are independent. Response envelopes are
//! classified into typed [`ExchangeEvent`] variants with
//! processor-output validation. Request and response directions
//! are tracked independently for both outbound and
//! processor-output phases.
//!
//! # State Domains
//!
//! The exchange tracks six orthogonal state domains:
//!
//! 1. **`terminal`** — shared terminal flag.
//! 2. **`request_send`** — outbound send phase for the request direction.
//! 3. **`response_send`** — outbound send phase for the response direction.
//! 4. **`request_output`** — processor-output phase for the request direction.
//! 5. **`response_output`** — processor-output phase for the response direction.
//! 6. **`active_processing`** — optional per-message processing state with deadline and override tracking.
//!
//! # Non-Full-Duplex vs Full-Duplex
//!
//! In non-full-duplex modes, every sent message (including every
//! body chunk) creates an [`ActiveProcessingState`] with a
//! deadline. At most one may be outstanding — a second send while
//! one is active fails with [`ExchangeError::OrderingViolation`].
//!
//! In full-duplex mode (`FULL_DUPLEX_STREAMED`), no messages in
//! the direction — headers, body chunks, or trailers — create
//! active processing state. The entire direction operates without
//! per-message timeouts.
//!
//! No background tasks are spawned. The bounded request channel
//! feeds tonic's h2 connection driver, which polls it lazily.
//!
//! [`ExternalProcessor.Process`]: praxis_proto::envoy::service::ext_proc::v3::external_processor_client::ExternalProcessorClient::process

use std::time::Duration;

use praxis_proto::envoy::service::ext_proc::v3::{
    BodyResponse, HeadersResponse, ImmediateResponse, ProcessingRequest, ProcessingResponse, ProtocolConfiguration,
    TrailersResponse, external_processor_client::ExternalProcessorClient, processing_request, processing_response,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

use crate::BodySendMode;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Bounded channel capacity for the request stream.
///
/// Capacity 1 provides tighter backpressure. No measured
/// performance benefit from capacity 2 was demonstrated.
pub(crate) const REQUEST_CHANNEL_CAPACITY: usize = 1;

/// Minimum valid override duration.
const MIN_OVERRIDE: Duration = Duration::from_millis(1);

// -----------------------------------------------------------------------------
// ExchangeConfig
// -----------------------------------------------------------------------------

/// Configuration for opening a duplex exchange.
#[derive(Debug, Clone)]
pub(crate) struct ExchangeConfig {
    /// Per-message timeout for non-full-duplex processing states.
    pub message_timeout: Duration,

    /// Upper bound for processor-requested timeout overrides.
    pub max_message_timeout: Option<Duration>,

    /// Body send mode for the request direction.
    pub request_body_mode: BodySendMode,

    /// Body send mode for the response direction.
    pub response_body_mode: BodySendMode,
}

// -----------------------------------------------------------------------------
// ExchangeError
// -----------------------------------------------------------------------------

/// Errors during a duplex exchange.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExchangeError {
    /// gRPC transport or protocol error.
    #[error("ext_proc gRPC error: {0}")]
    Grpc(#[from] tonic::Status),

    /// A processing-state deadline expired.
    #[error("ext_proc message timeout")]
    Timeout,

    /// The server closed the stream without a required response.
    #[error("ext_proc server closed stream without response")]
    EmptyStream,

    /// The request channel was closed or sending was finished.
    #[error("ext_proc request channel closed")]
    SendFailed,

    /// The exchange entered a terminal state.
    #[error("ext_proc exchange closed")]
    Closed,

    /// A processing deadline could not be represented.
    #[error("ext_proc deadline overflow")]
    DeadlineOverflow,

    /// A message violated within-direction ordering.
    #[error("ext_proc ordering violation: {0}")]
    OrderingViolation(String),
}

// -----------------------------------------------------------------------------
// ExchangeEvent
// -----------------------------------------------------------------------------

/// Typed exchange event classified from a processor response.
///
/// Each variant preserves the proto response payload and any
/// `dynamic_metadata` from the envelope.
#[derive(Debug)]
pub(crate) enum ExchangeEvent {
    /// Request headers response.
    RequestHeaders {
        /// Processor response payload.
        response: HeadersResponse,
        /// Structured dynamic metadata from the envelope.
        metadata: Option<prost_wkt_types::Struct>,
    },
    /// Request body response.
    RequestBody {
        /// Processor response payload.
        response: BodyResponse,
        /// Structured dynamic metadata from the envelope.
        metadata: Option<prost_wkt_types::Struct>,
    },
    /// Request trailers response.
    #[expect(
        dead_code,
        reason = "classified by receive; consumed in follow-up response lifecycle PR"
    )]
    RequestTrailers {
        /// Processor response payload.
        response: TrailersResponse,
        /// Structured dynamic metadata from the envelope.
        metadata: Option<prost_wkt_types::Struct>,
    },
    /// Response headers response.
    #[expect(
        dead_code,
        reason = "classified by receive; consumed in follow-up response lifecycle PR"
    )]
    ResponseHeaders {
        /// Processor response payload.
        response: HeadersResponse,
        /// Structured dynamic metadata from the envelope.
        metadata: Option<prost_wkt_types::Struct>,
    },
    /// Response body response.
    #[expect(
        dead_code,
        reason = "classified by receive; consumed in follow-up response lifecycle PR"
    )]
    ResponseBody {
        /// Processor response payload.
        response: BodyResponse,
        /// Structured dynamic metadata from the envelope.
        metadata: Option<prost_wkt_types::Struct>,
    },
    /// Response trailers response.
    #[expect(
        dead_code,
        reason = "classified by receive; consumed in follow-up response lifecycle PR"
    )]
    ResponseTrailers {
        /// Processor response payload.
        response: TrailersResponse,
        /// Structured dynamic metadata from the envelope.
        metadata: Option<prost_wkt_types::Struct>,
    },
    /// Immediate response — terminal event.
    Immediate {
        /// Processor immediate response payload.
        response: ImmediateResponse,
        /// Structured dynamic metadata from the envelope.
        metadata: Option<prost_wkt_types::Struct>,
    },
}

// -----------------------------------------------------------------------------
// Phase Types
// -----------------------------------------------------------------------------

/// Outbound send phase for a direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendPhase {
    /// No messages sent.
    NotStarted,
    /// Headers committed.
    Headers,
    /// Body chunks flowing.
    BodyOpen,
    /// Terminal body chunk committed (`end_of_stream`).
    BodyEos,
    /// Trailers committed.
    Trailers,
}

/// Per-direction outbound send state combining phase with
/// body-commitment tracking.
#[derive(Debug, Clone, Copy)]
struct DirectionSendState {
    /// Current send phase for the direction.
    phase: SendPhase,
    /// Whether at least one body message has been committed.
    body_ever_committed: bool,
}

impl DirectionSendState {
    /// Create a new send state at the initial phase.
    fn new() -> Self {
        Self {
            phase: SendPhase::NotStarted,
            body_ever_committed: false,
        }
    }
}

/// Processor-output phase for a direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputPhase {
    /// No output received.
    None,
    /// Header response received.
    Headers,
    /// Body responses flowing.
    BodyOpen,
    /// Body output completed (EOS received).
    BodyDone,
    /// Trailer response received.
    Trailers,
}

// -----------------------------------------------------------------------------
// Active Processing State
// -----------------------------------------------------------------------------

/// Which response type is expected from the processor.
///
/// Each variant corresponds to one of the six directional
/// message types that require a response before the next
/// send is permitted (in non-full-duplex modes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedResponse {
    /// Awaiting a request headers response.
    RequestHeaders,
    /// Awaiting a request body response.
    RequestBody,
    /// Awaiting a request trailers response.
    RequestTrailers,
    /// Awaiting a response headers response.
    ResponseHeaders,
    /// Awaiting a response body response.
    ResponseBody,
    /// Awaiting a response trailers response.
    ResponseTrailers,
}

impl ExpectedResponse {
    /// Map an expected response type to its direction.
    fn direction(self) -> Direction {
        match self {
            Self::RequestHeaders | Self::RequestBody | Self::RequestTrailers => Direction::Request,
            Self::ResponseHeaders | Self::ResponseBody | Self::ResponseTrailers => Direction::Response,
        }
    }
}

/// Per-message processing state for non-full-duplex directions.
///
/// Tracks the expected response type, deadline, and whether the
/// processor has consumed its one allowed timeout override.
/// Full-duplex directions never create this state.
#[derive(Debug)]
struct ActiveProcessingState {
    /// Which response type will consume this state.
    expected: ExpectedResponse,
    /// Absolute deadline for the processor to respond.
    deadline: tokio::time::Instant,
    /// Whether the override has been consumed.
    override_consumed: bool,
}

// -----------------------------------------------------------------------------
// Direction
// -----------------------------------------------------------------------------

/// Which direction a message belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// Request direction.
    Request,
    /// Response direction.
    Response,
}

// -----------------------------------------------------------------------------
// SendTransition
// -----------------------------------------------------------------------------

/// Proposed state transition computed by [`ExtProcExchange::compute_send_transition`].
///
/// Pure value — applying it is the only mutation step.
struct SendTransition {
    /// Which direction to advance.
    direction: Direction,
    /// New send phase for the direction.
    new_phase: SendPhase,
    /// Optional expected response to install after commit.
    ///
    /// `Some` for messages that require a response before the next
    /// send (all non-full-duplex messages). `None` for all messages
    /// in full-duplex directions.
    active_state: Option<ExpectedResponse>,
}

// -----------------------------------------------------------------------------
// Bootstrap State
// -----------------------------------------------------------------------------

use std::{future::Future, pin::Pin};

/// Pinned boxed Process future, `Send + 'static` but not `Sync`.
type PinnedProcessFuture =
    Pin<Box<dyn Future<Output = Result<tonic::Response<tonic::Streaming<ProcessingResponse>>, tonic::Status>> + Send>>;

/// Bootstrap state for the Process RPC.
///
/// Wraps the pending non-`Sync` future in [`SyncWrapper`] so the
/// exchange satisfies `Send + Sync` for typed filter state.
/// Access/poll occurs only through `&mut` exchange methods.
///
/// [`SyncWrapper`]: sync_wrapper::SyncWrapper
enum BootstrapState {
    /// The Process RPC is pending. The wrapped future is polled
    /// inline by [`send`] and resolved by [`receive`].
    ///
    /// [`send`]: ExtProcExchange::send
    /// [`receive`]: ExtProcExchange::receive
    Pending(sync_wrapper::SyncWrapper<PinnedProcessFuture>),

    /// The Process RPC completed and the response stream is ready.
    Ready(Box<tonic::Streaming<ProcessingResponse>>),

    /// The Process RPC failed or the stream was consumed.
    Closed,
}

// -----------------------------------------------------------------------------
// ExtProcExchange
// -----------------------------------------------------------------------------

/// Persistent bidirectional exchange with an external processor.
///
/// Owns one [`Process`] gRPC stream. [`send`] validates
/// ordering, reserves channel capacity, commits the message,
/// then atomically updates phase and active processing state.
/// [`receive`] reads the next response, handles timeout
/// overrides, validates processor-output ordering, and returns
/// a typed [`ExchangeEvent`].
///
/// Timeout policy is derived internally from the active
/// processing state. Callers cannot select or override timeout
/// behavior.
///
/// No background tasks are spawned.
///
/// [`Process`]: ExternalProcessorClient::process
/// [`send`]: Self::send
/// [`receive`]: Self::receive
pub(crate) struct ExtProcExchange {
    /// Non-full-duplex response expectation with deadline.
    active_processing: Option<ActiveProcessingState>,

    /// Whether the first message has been sent.
    first_sent: bool,

    /// Upper bound for processor-requested timeout overrides.
    max_message_timeout: Option<Duration>,

    /// Per-message timeout (non-full-duplex modes).
    message_timeout: Duration,

    /// Protocol configuration for the first request.
    protocol_config: ProtocolConfiguration,

    /// Request direction body mode.
    request_body_mode: BodySendMode,

    /// Processor output phase for the request direction.
    request_output: OutputPhase,

    /// Request outbound send state.
    request_send: DirectionSendState,

    /// Send half of the bounded request channel.
    request_tx: Option<mpsc::Sender<ProcessingRequest>>,

    /// Response direction body mode.
    response_body_mode: BodySendMode,

    /// Processor output phase for the response direction.
    response_output: OutputPhase,

    /// Response outbound send state.
    response_send: DirectionSendState,

    /// Process RPC bootstrap and response stream state.
    bootstrap: BootstrapState,

    /// Terminal state.
    terminal: bool,
}

impl ExtProcExchange {
    /// Open a new exchange on the given channel.
    ///
    /// Synchronous — constructs the Process future without polling
    /// it. The gRPC stream is established when [`send`] or
    /// [`receive`] first drives the pending future.
    ///
    /// [`send`]: Self::send
    /// [`receive`]: Self::receive
    #[expect(clippy::unnecessary_wraps, reason = "follow-up PR adds preload that can fail")]
    pub(crate) fn open(channel: Channel, config: &ExchangeConfig) -> Result<Self, ExchangeError> {
        let (tx, rx) = mpsc::channel(REQUEST_CHANNEL_CAPACITY);
        let request_stream = ReceiverStream::new(rx);
        let mut client = ExternalProcessorClient::new(channel);
        let pending: PinnedProcessFuture = Box::pin(async move { client.process(request_stream).await });

        Ok(Self {
            active_processing: None,
            first_sent: false,
            max_message_timeout: config.max_message_timeout,
            message_timeout: config.message_timeout,
            protocol_config: ProtocolConfiguration {
                request_body_mode: config.request_body_mode.to_proto_i32(),
                response_body_mode: config.response_body_mode.to_proto_i32(),
                send_body_without_waiting_for_header_response: false,
            },
            request_body_mode: config.request_body_mode,
            request_output: OutputPhase::None,
            request_send: DirectionSendState::new(),
            request_tx: Some(tx),
            response_body_mode: config.response_body_mode,
            response_output: OutputPhase::None,
            response_send: DirectionSendState::new(),
            bootstrap: BootstrapState::Pending(sync_wrapper::SyncWrapper::new(pending)),
            terminal: false,
        })
    }

    /// Send a processing request with transactional state update.
    ///
    /// 1. Validates the proposed transition (pure, no mutation).
    /// 2. Reserves bounded channel capacity (cancellable).
    /// 3. Commits the message via `permit.send()`.
    /// 4. Atomically updates phase and active processing state (no await between commit steps).
    pub(crate) async fn send(&mut self, request: processing_request::Request) -> Result<(), ExchangeError> {
        if self.terminal {
            return Err(ExchangeError::Closed);
        }

        let transition = self.compute_send_transition(&request)?;

        let include_config = !self.first_sent;
        let mut msg = ProcessingRequest {
            request: Some(request),
            ..Default::default()
        };
        if include_config {
            msg.protocol_config = Some(self.protocol_config);
        }

        let timeout = transition.active_state.map(|_| self.message_timeout);
        // Clone the sender to avoid aliasing `&mut self` with the permit borrow.
        let tx = self.request_tx.clone().ok_or(ExchangeError::SendFailed)?;
        let permit = self.reserve_while_bootstrapping(&tx).await?;

        let checked_deadline = timeout
            .map(|dur| {
                tokio::time::Instant::now()
                    .checked_add(dur)
                    .ok_or(ExchangeError::DeadlineOverflow)
            })
            .transpose()?;

        permit.send(msg);

        // --- Atomic state commit (no await below) ---
        if include_config {
            self.first_sent = true;
        }
        self.apply_send_transition(&transition, checked_deadline);
        Ok(())
    }

    /// Read the next response, validate output ordering, and
    /// return a typed event.
    ///
    /// Timeout policy is derived internally: uses the deadline
    /// from [`ActiveProcessingState`] if present, or awaits
    /// without timeout otherwise. The override loop handles
    /// `override_message_timeout` envelopes before classification.
    ///
    /// Takes no arguments — timeout behavior is fully internal.
    pub(crate) async fn receive(&mut self) -> Result<ExchangeEvent, ExchangeError> {
        if self.terminal {
            return Err(ExchangeError::Closed);
        }

        let result = self.receive_inner().await;
        match result {
            Ok(event) => {
                if matches!(event, ExchangeEvent::Immediate { .. }) {
                    self.terminal = true;
                }
                Ok(event)
            },
            Err(e) => {
                self.terminal = true;
                Err(e)
            },
        }
    }

    /// Half-close the request stream. Direction-local, not
    /// terminal. Response events remain readable.
    pub(crate) fn finish_sending(&mut self) {
        self.request_tx.take();
    }

    /// Consume remaining response stream messages to allow clean
    /// h2 stream closure. Prevents `RST_STREAM` on exchange drop
    /// when the server has trailing data.
    ///
    /// Only drains when the bootstrap is [`Ready`]. If the
    /// bootstrap is still [`Pending`], this is a no-op — callers
    /// must ensure at least one successful [`receive`] before
    /// calling `drain_trailing` for clean closure.
    ///
    /// [`Ready`]: BootstrapState::Ready
    /// [`Pending`]: BootstrapState::Pending
    /// [`receive`]: Self::receive
    pub(crate) async fn drain_trailing(&mut self) {
        if let BootstrapState::Ready(ref mut stream) = self.bootstrap {
            while stream.message().await.is_ok_and(|m| m.is_some()) {}
        }
    }

    /// Whether the exchange has entered a terminal state.
    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Whether the outbound request channel has been closed.
    ///
    /// Outbound closure is direction-local: the bootstrap/response
    /// stream may still contain buffered responses.
    #[expect(dead_code, reason = "used by integration tests and follow-up PRs")]
    pub(crate) fn is_outbound_closed(&self) -> bool {
        self.request_tx.is_none()
    }

    /// Reserve bounded channel capacity while driving the pending
    /// Process future via [`tokio::select!`].
    ///
    /// When the bootstrap is [`Pending`], polls both the channel
    /// reserve and the Process future. If the Process future
    /// resolves first, stores the response stream as [`Ready`]
    /// and continues the same reserve attempt. If the channel
    /// reserve wins, the pending future is preserved.
    ///
    /// [`Pending`]: BootstrapState::Pending
    /// [`Ready`]: BootstrapState::Ready
    #[expect(clippy::too_many_lines, reason = "select! branches with state transitions")]
    async fn reserve_while_bootstrapping<'a>(
        &mut self,
        tx: &'a mpsc::Sender<ProcessingRequest>,
    ) -> Result<mpsc::Permit<'a, ProcessingRequest>, ExchangeError> {
        loop {
            match self.bootstrap {
                BootstrapState::Pending(ref mut wrapper) => {
                    let future = wrapper.get_mut();
                    tokio::select! {
                        biased;
                        permit = tx.reserve() => {
                            return permit.map_err(|_send_err| {
                                self.request_tx.take();
                                ExchangeError::SendFailed
                            });
                        },
                        result = future.as_mut() => {
                            match result {
                                Ok(response) => {
                                    self.bootstrap = BootstrapState::Ready(Box::new(response.into_inner()));
                                },
                                Err(status) => {
                                    self.bootstrap = BootstrapState::Closed;
                                    self.request_tx.take();
                                    self.terminal = true;
                                    return Err(ExchangeError::Grpc(status));
                                },
                            }
                        },
                    }
                },
                BootstrapState::Ready(_) | BootstrapState::Closed => {
                    return tx.reserve().await.map_err(|_send_err| {
                        self.request_tx.take();
                        ExchangeError::SendFailed
                    });
                },
            }
        }
    }

    /// Snapshot of output phases for transactional-validation
    /// testing.
    #[cfg(test)]
    pub(crate) fn output_phases(&self) -> (OutputPhase, OutputPhase) {
        (self.request_output, self.response_output)
    }
}

// -----------------------------------------------------------------------------
// Send Transition — Computation
// -----------------------------------------------------------------------------

#[expect(
    clippy::multiple_inherent_impl,
    reason = "sectioned state-machine implementation keeps domains reviewable"
)]
impl ExtProcExchange {
    /// Compute the proposed send transition without mutating state.
    ///
    /// Validates ordering, body-mode gating, and active processing
    /// exclusivity. Returns a pure [`SendTransition`] value.
    ///
    /// Full-duplex directions (`FULL_DUPLEX_STREAMED`) never create
    /// active processing state for any message type — headers, body,
    /// or trailers — because full-duplex processing has no
    /// per-message timeout.
    #[expect(
        clippy::too_many_lines,
        reason = "six direction×type variants with mode-aware active-state logic"
    )]
    fn compute_send_transition(&self, request: &processing_request::Request) -> Result<SendTransition, ExchangeError> {
        let transition = match request {
            processing_request::Request::RequestHeaders(_) => {
                require_phase(
                    self.request_send.phase,
                    SendPhase::NotStarted,
                    "request headers already sent",
                )?;
                let creates_active = !self.request_body_mode.is_full_duplex();
                if creates_active {
                    self.require_no_active_processing("request headers")?;
                }
                SendTransition {
                    direction: Direction::Request,
                    new_phase: SendPhase::Headers,
                    active_state: creates_active.then_some(ExpectedResponse::RequestHeaders),
                }
            },
            processing_request::Request::RequestBody(b) => {
                self.require_body_mode_enabled(Direction::Request)?;
                require_body_phase(self.request_send.phase, "request body")?;
                let full_duplex = self.request_body_mode.is_full_duplex();
                if !full_duplex {
                    self.require_no_active_processing("request body")?;
                }
                SendTransition {
                    direction: Direction::Request,
                    new_phase: if b.end_of_stream {
                        SendPhase::BodyEos
                    } else {
                        SendPhase::BodyOpen
                    },
                    active_state: if full_duplex {
                        None
                    } else {
                        Some(ExpectedResponse::RequestBody)
                    },
                }
            },
            processing_request::Request::RequestTrailers(_) => {
                require_trailer_phase(self.request_send.phase, "request trailers")?;
                let creates_active = !self.request_body_mode.is_full_duplex();
                if creates_active {
                    self.require_no_active_processing("request trailers")?;
                }
                SendTransition {
                    direction: Direction::Request,
                    new_phase: SendPhase::Trailers,
                    active_state: creates_active.then_some(ExpectedResponse::RequestTrailers),
                }
            },
            processing_request::Request::ResponseHeaders(_) => {
                require_phase(
                    self.response_send.phase,
                    SendPhase::NotStarted,
                    "response headers already sent",
                )?;
                let creates_active = !self.response_body_mode.is_full_duplex();
                if creates_active {
                    self.require_no_active_processing("response headers")?;
                }
                SendTransition {
                    direction: Direction::Response,
                    new_phase: SendPhase::Headers,
                    active_state: creates_active.then_some(ExpectedResponse::ResponseHeaders),
                }
            },
            processing_request::Request::ResponseBody(b) => {
                self.require_body_mode_enabled(Direction::Response)?;
                require_body_phase(self.response_send.phase, "response body")?;
                let full_duplex = self.response_body_mode.is_full_duplex();
                if !full_duplex {
                    self.require_no_active_processing("response body")?;
                }
                SendTransition {
                    direction: Direction::Response,
                    new_phase: if b.end_of_stream {
                        SendPhase::BodyEos
                    } else {
                        SendPhase::BodyOpen
                    },
                    active_state: if full_duplex {
                        None
                    } else {
                        Some(ExpectedResponse::ResponseBody)
                    },
                }
            },
            processing_request::Request::ResponseTrailers(_) => {
                require_trailer_phase(self.response_send.phase, "response trailers")?;
                let creates_active = !self.response_body_mode.is_full_duplex();
                if creates_active {
                    self.require_no_active_processing("response trailers")?;
                }
                SendTransition {
                    direction: Direction::Response,
                    new_phase: SendPhase::Trailers,
                    active_state: creates_active.then_some(ExpectedResponse::ResponseTrailers),
                }
            },
        };

        Ok(transition)
    }

    /// Reject sends when active processing state is outstanding.
    fn require_no_active_processing(&self, label: &str) -> Result<(), ExchangeError> {
        if self.active_processing.is_some() {
            return Err(ExchangeError::OrderingViolation(format!(
                "cannot send {label}: active processing state outstanding"
            )));
        }
        Ok(())
    }

    /// Reject body sends when the body mode is `None`.
    fn require_body_mode_enabled(&self, direction: Direction) -> Result<(), ExchangeError> {
        let mode = match direction {
            Direction::Request => self.request_body_mode,
            Direction::Response => self.response_body_mode,
        };
        if matches!(mode, BodySendMode::None) {
            let dir = match direction {
                Direction::Request => "request",
                Direction::Response => "response",
            };
            return Err(ExchangeError::OrderingViolation(format!(
                "{dir} body send rejected: body mode is none"
            )));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Send Transition — Application
// -----------------------------------------------------------------------------

#[expect(
    clippy::multiple_inherent_impl,
    reason = "sectioned state-machine implementation keeps domains reviewable"
)]
impl ExtProcExchange {
    /// Apply the committed transition atomically (no await).
    ///
    /// The deadline is created after `reserve().await` and before
    /// `permit.send()`, so producer backpressure is excluded from
    /// the processing deadline.
    fn apply_send_transition(&mut self, t: &SendTransition, checked_deadline: Option<tokio::time::Instant>) {
        let state = match t.direction {
            Direction::Request => &mut self.request_send,
            Direction::Response => &mut self.response_send,
        };
        let is_body = matches!(t.new_phase, SendPhase::BodyOpen | SendPhase::BodyEos);
        state.phase = t.new_phase;
        if is_body {
            state.body_ever_committed = true;
        }
        if let (Some(expected), Some(deadline)) = (t.active_state, checked_deadline) {
            self.active_processing = Some(ActiveProcessingState {
                expected,
                deadline,
                override_consumed: false,
            });
        }
    }
}

// -----------------------------------------------------------------------------
// Send Phase Validation Helpers
// -----------------------------------------------------------------------------

/// Require the current phase to be `expected`.
fn require_phase(current: SendPhase, expected: SendPhase, msg: &str) -> Result<(), ExchangeError> {
    if current != expected {
        return Err(ExchangeError::OrderingViolation(msg.to_owned()));
    }
    Ok(())
}

/// Require the current phase to accept a body message.
fn require_body_phase(current: SendPhase, label: &str) -> Result<(), ExchangeError> {
    if !matches!(current, SendPhase::Headers | SendPhase::BodyOpen) {
        return Err(ExchangeError::OrderingViolation(format!(
            "{label} requires headers sent and no EOS/trailers"
        )));
    }
    Ok(())
}

/// Require the current phase to accept trailers.
fn require_trailer_phase(current: SendPhase, label: &str) -> Result<(), ExchangeError> {
    if !matches!(current, SendPhase::Headers | SendPhase::BodyOpen) {
        return Err(ExchangeError::OrderingViolation(format!(
            "{label} requires headers sent and no EOS"
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Receive Implementation
// -----------------------------------------------------------------------------

#[expect(
    clippy::multiple_inherent_impl,
    reason = "sectioned state-machine implementation keeps domains reviewable"
)]
impl ExtProcExchange {
    /// Ensure the bootstrap has resolved to a ready response
    /// stream. Awaits the pending Process future if necessary.
    async fn ensure_response_stream(&mut self) -> Result<(), ExchangeError> {
        if let BootstrapState::Pending(ref mut wrapper) = self.bootstrap {
            let future = wrapper.get_mut();
            let response = future.await.map_err(|status| {
                self.bootstrap = BootstrapState::Closed;
                self.terminal = true;
                ExchangeError::Grpc(status)
            })?;
            self.bootstrap = BootstrapState::Ready(Box::new(response.into_inner()));
        }
        Ok(())
    }

    /// Internal receive with deferred stream resolution, override
    /// loop, and classification.
    ///
    /// 1. Resolves the deferred response stream if needed.
    /// 2. Reads a response with optional deadline from active processing.
    /// 3. Runs the override loop: if `override_message_timeout` is present on the envelope, it is an override envelope.
    ///    Valid overrides replace the deadline and continue reading. Invalid overrides are silently ignored (the entire
    ///    envelope is discarded, including any populated response oneof). Override envelopes never reach
    ///    [`classify_and_validate`].
    /// 4. Classifies the response against expected type and validates output ordering.
    ///
    /// [`classify_and_validate`]: Self::classify_and_validate
    async fn receive_inner(&mut self) -> Result<ExchangeEvent, ExchangeError> {
        self.ensure_response_stream().await?;
        loop {
            let deadline = self.active_processing.as_ref().map(|ap| ap.deadline);
            let stream = match self.bootstrap {
                BootstrapState::Ready(ref mut s) => s,
                BootstrapState::Closed => return Err(ExchangeError::Closed),
                BootstrapState::Pending(_) => {
                    return Err(ExchangeError::OrderingViolation(
                        "bootstrap still pending after ensure".to_owned(),
                    ));
                },
            };
            let resp = read_with_optional_deadline(stream, deadline).await?;

            // If override_message_timeout is present, this is an
            // override envelope — it never reaches classification.
            if resp.override_message_timeout.is_some() {
                // Try to apply it; whether accepted or rejected,
                // the envelope is consumed and we read the next one.
                self.try_accept_override(&resp);
                continue;
            }

            return self.classify_and_validate(resp);
        }
    }

    /// Try to accept an override from a response envelope.
    ///
    /// Returns `true` if the override was accepted and the active
    /// deadline was replaced. Returns `false` if the override is
    /// invalid or not applicable. In both cases, the caller
    /// consumes the entire envelope and continues reading —
    /// invalid override envelopes are never classified as
    /// ordinary responses.
    ///
    /// Conditions for acceptance:
    /// - `override_message_timeout` is present
    /// - Active processing state exists (a timer is running)
    /// - Override has not already been consumed for this state
    /// - `max_message_timeout` is configured
    /// - Duration passes strict protobuf validation
    /// - Duration is at least 1ms
    #[expect(
        clippy::too_many_lines,
        reason = "override validation with multiple early-return conditions"
    )]
    fn try_accept_override(&mut self, resp: &ProcessingResponse) -> bool {
        let Some(proto_dur) = resp.override_message_timeout.as_ref() else {
            return false;
        };

        if self.active_processing.as_ref().is_none_or(|ap| ap.override_consumed) {
            return false;
        }

        let Some(max) = self.max_message_timeout else {
            return false;
        };

        let Some(dur) = parse_override_duration(proto_dur) else {
            return false;
        };

        let clamped = dur.min(max);
        if clamped < dur {
            tracing::warn!(
                requested_ms = dur.as_millis(),
                clamped_ms = clamped.as_millis(),
                "ext_proc exchange: override clamped to max"
            );
        }

        tracing::debug!(
            override_ms = clamped.as_millis(),
            "ext_proc exchange: timeout override accepted"
        );

        // Compute the new deadline with overflow protection.
        let Some(deadline) = tokio::time::Instant::now().checked_add(clamped) else {
            return false;
        };

        // Mutate active processing state. The `is_none_or`
        // guard above ensures this branch is taken.
        if let Some(ap) = self.active_processing.as_mut() {
            ap.deadline = deadline;
            ap.override_consumed = true;
        }
        true
    }

    /// Classify a raw response and validate output ordering.
    ///
    /// Validation is transactional: output phase is advanced on a
    /// local copy first, then committed only after all checks pass.
    /// This prevents rejected responses from corrupting state.
    ///
    /// [`ImmediateResponse`] is terminal regardless of active state
    /// but requires at least one outbound message to have been sent.
    #[expect(
        clippy::too_many_lines,
        reason = "seven response variants with transactional output validation"
    )]
    fn classify_and_validate(&mut self, resp: ProcessingResponse) -> Result<ExchangeEvent, ExchangeError> {
        let metadata = resp.dynamic_metadata;

        let Some(response) = resp.response else {
            return Err(ExchangeError::OrderingViolation(
                "empty response with no override".to_owned(),
            ));
        };

        match response {
            processing_response::Response::ImmediateResponse(r) => {
                if !self.first_sent {
                    return Err(ExchangeError::OrderingViolation(
                        "immediate response before first send".to_owned(),
                    ));
                }
                self.active_processing = None;
                Ok(ExchangeEvent::Immediate { response: r, metadata })
            },
            processing_response::Response::RequestHeaders(r) => {
                let expected = ExpectedResponse::RequestHeaders;
                self.validate_response_solicited(expected)?;
                let mut local_output = self.request_output;
                validate_output_transition(&mut local_output, OutputPhase::Headers, "request headers")?;
                self.request_output = local_output;
                self.consume_active_if_matched(expected);
                Ok(ExchangeEvent::RequestHeaders { response: r, metadata })
            },
            processing_response::Response::RequestBody(r) => {
                let expected = ExpectedResponse::RequestBody;
                self.validate_response_solicited(expected)?;
                validate_body_mutation_mode(&r, self.request_body_mode, "request body")?;
                let mut local_output = self.request_output;
                validate_body_output(&mut local_output, &r, "request body")?;
                self.request_output = local_output;
                self.consume_active_if_matched(expected);
                Ok(ExchangeEvent::RequestBody { response: r, metadata })
            },
            processing_response::Response::RequestTrailers(r) => {
                let expected = ExpectedResponse::RequestTrailers;
                self.validate_response_solicited(expected)?;
                let mut local_output = self.request_output;
                validate_output_transition(&mut local_output, OutputPhase::Trailers, "request trailers")?;
                self.request_output = local_output;
                self.consume_active_if_matched(expected);
                Ok(ExchangeEvent::RequestTrailers { response: r, metadata })
            },
            processing_response::Response::ResponseHeaders(r) => {
                let expected = ExpectedResponse::ResponseHeaders;
                self.validate_response_solicited(expected)?;
                let mut local_output = self.response_output;
                validate_output_transition(&mut local_output, OutputPhase::Headers, "response headers")?;
                self.response_output = local_output;
                self.consume_active_if_matched(expected);
                Ok(ExchangeEvent::ResponseHeaders { response: r, metadata })
            },
            processing_response::Response::ResponseBody(r) => {
                let expected = ExpectedResponse::ResponseBody;
                self.validate_response_solicited(expected)?;
                validate_body_mutation_mode(&r, self.response_body_mode, "response body")?;
                let mut local_output = self.response_output;
                validate_body_output(&mut local_output, &r, "response body")?;
                self.response_output = local_output;
                self.consume_active_if_matched(expected);
                Ok(ExchangeEvent::ResponseBody { response: r, metadata })
            },
            processing_response::Response::ResponseTrailers(r) => {
                let expected = ExpectedResponse::ResponseTrailers;
                self.validate_response_solicited(expected)?;
                let mut local_output = self.response_output;
                validate_output_transition(&mut local_output, OutputPhase::Trailers, "response trailers")?;
                self.response_output = local_output;
                self.consume_active_if_matched(expected);
                Ok(ExchangeEvent::ResponseTrailers { response: r, metadata })
            },
        }
    }

    /// Get the body send mode for the given direction.
    fn body_mode(&self, direction: Direction) -> BodySendMode {
        match direction {
            Direction::Request => self.request_body_mode,
            Direction::Response => self.response_body_mode,
        }
    }

    /// Get the outbound send state for the given direction.
    fn send_state(&self, direction: Direction) -> DirectionSendState {
        match direction {
            Direction::Request => self.request_send,
            Direction::Response => self.response_send,
        }
    }

    /// Whether an outbound message matching `received` has been
    /// committed in the appropriate direction.
    fn committed_for(&self, received: ExpectedResponse) -> bool {
        let state = self.send_state(received.direction());
        match received {
            ExpectedResponse::RequestHeaders | ExpectedResponse::ResponseHeaders => {
                state.phase != SendPhase::NotStarted
            },
            ExpectedResponse::RequestBody | ExpectedResponse::ResponseBody => state.body_ever_committed,
            ExpectedResponse::RequestTrailers | ExpectedResponse::ResponseTrailers => {
                state.phase == SendPhase::Trailers
            },
        }
    }

    /// Validate that the server's response was solicited by a
    /// matching outbound commit.
    ///
    /// In full-duplex mode, checks that an outbound message of the
    /// corresponding type was committed at some point. In
    /// non-full-duplex mode, checks against the active processing
    /// state.
    fn validate_response_solicited(&self, received: ExpectedResponse) -> Result<(), ExchangeError> {
        let direction = received.direction();
        let mode = self.body_mode(direction);

        if mode.is_full_duplex() {
            if !self.committed_for(received) {
                return Err(ExchangeError::OrderingViolation(format!(
                    "unsolicited {received:?} (no matching outbound committed)"
                )));
            }
            return Ok(());
        }

        match &self.active_processing {
            Some(active) if active.expected == received => Ok(()),
            Some(active) => Err(ExchangeError::OrderingViolation(format!(
                "expected {:?}, received {received:?}",
                active.expected
            ))),
            None => Err(ExchangeError::OrderingViolation(format!(
                "unsolicited {received:?} (no active processing state)"
            ))),
        }
    }

    /// Consume active processing state if the response matches
    /// the expected type. Only applicable in non-full-duplex mode.
    fn consume_active_if_matched(&mut self, received: ExpectedResponse) {
        if self
            .active_processing
            .as_ref()
            .is_some_and(|ap| ap.expected == received)
        {
            self.active_processing = None;
        }
    }
}

// -----------------------------------------------------------------------------
// Duration Parsing
// -----------------------------------------------------------------------------

/// Parse a protobuf [`Duration`] into a [`std::time::Duration`]
/// with strict validation.
///
/// Returns `None` if the value is negative, out of protobuf range,
/// has invalid nanos, or is below the minimum override threshold.
///
/// [`Duration`]: prost_types::Duration
fn parse_override_duration(value: &prost_types::Duration) -> Option<Duration> {
    // Protobuf Duration: seconds in [-315_576_000_000, 315_576_000_000],
    // nanos in [-999_999_999, 999_999_999], same sign as seconds.
    if value.seconds < 0 || value.seconds > 315_576_000_000 {
        return None;
    }
    if value.nanos < 0 || value.nanos >= 1_000_000_000 {
        return None;
    }
    #[expect(clippy::cast_sign_loss, reason = "negative values rejected above")]
    let dur = Duration::new(value.seconds as u64, value.nanos as u32);
    if dur < MIN_OVERRIDE {
        return None;
    }
    Some(dur)
}

// -----------------------------------------------------------------------------
// Output Validation
// -----------------------------------------------------------------------------

/// Validate a non-body output phase transition.
fn validate_output_transition(
    output: &mut OutputPhase,
    expected: OutputPhase,
    label: &str,
) -> Result<(), ExchangeError> {
    let valid = match (output, expected) {
        (phase @ &mut OutputPhase::None, OutputPhase::Headers) => {
            *phase = OutputPhase::Headers;
            true
        },
        (phase @ &mut (OutputPhase::Headers | OutputPhase::BodyOpen), OutputPhase::Trailers) => {
            *phase = OutputPhase::Trailers;
            true
        },
        _ => false,
    };
    if !valid {
        return Err(ExchangeError::OrderingViolation(format!(
            "unexpected {label} in output phase"
        )));
    }
    Ok(())
}

/// Validate and advance body output phase, including EOS tracking.
///
/// Checks `StreamedBodyResponse.end_of_stream` to transition
/// to [`OutputPhase::BodyDone`]. Post-EOS and duplicate-EOS
/// body outputs are rejected.
fn validate_body_output(output: &mut OutputPhase, body_resp: &BodyResponse, label: &str) -> Result<(), ExchangeError> {
    if matches!(output, OutputPhase::BodyDone | OutputPhase::Trailers) {
        return Err(ExchangeError::OrderingViolation(format!("post-EOS {label} output")));
    }
    if !matches!(output, OutputPhase::Headers | OutputPhase::BodyOpen) {
        return Err(ExchangeError::OrderingViolation(format!(
            "{label} output before headers"
        )));
    }

    let is_eos = body_resp
        .response
        .as_ref()
        .and_then(|c| c.body_mutation.as_ref())
        .and_then(|bm| match &bm.mutation {
            Some(praxis_proto::envoy::service::ext_proc::v3::body_mutation::Mutation::StreamedResponse(sr)) => {
                Some(sr.end_of_stream)
            },
            _ => None,
        })
        .unwrap_or(false);

    *output = if is_eos {
        OutputPhase::BodyDone
    } else {
        OutputPhase::BodyOpen
    };
    Ok(())
}

/// Validate that the body response mutation type matches the
/// direction's body send mode.
///
/// - [`BodySendMode::FullDuplexStreamed`] requires a [`StreamedBodyResponse`] mutation.
/// - All other modes reject [`StreamedBodyResponse`] mutations.
///
/// [`StreamedBodyResponse`]: praxis_proto::envoy::service::ext_proc::v3::StreamedBodyResponse
fn validate_body_mutation_mode(
    body_resp: &BodyResponse,
    body_mode: BodySendMode,
    label: &str,
) -> Result<(), ExchangeError> {
    let has_streamed = body_resp
        .response
        .as_ref()
        .and_then(|c| c.body_mutation.as_ref())
        .is_some_and(|bm| {
            matches!(
                bm.mutation,
                Some(praxis_proto::envoy::service::ext_proc::v3::body_mutation::Mutation::StreamedResponse(_))
            )
        });

    if body_mode.is_full_duplex() && !has_streamed {
        return Err(ExchangeError::OrderingViolation(format!(
            "{label}: full-duplex mode requires StreamedBodyResponse mutation"
        )));
    }
    if !body_mode.is_full_duplex() && has_streamed {
        return Err(ExchangeError::OrderingViolation(format!(
            "{label}: StreamedBodyResponse mutation requires full-duplex mode"
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// I/O Utilities
// -----------------------------------------------------------------------------

/// Read the next message with an optional absolute deadline.
async fn read_with_optional_deadline(
    streaming: &mut tonic::Streaming<ProcessingResponse>,
    deadline: Option<tokio::time::Instant>,
) -> Result<ProcessingResponse, ExchangeError> {
    if let Some(dl) = deadline {
        tokio::time::timeout_at(dl, next_message(streaming))
            .await
            .map_err(|_elapsed| ExchangeError::Timeout)?
    } else {
        next_message(streaming).await
    }
}

/// Reserve capacity, compute checked deadline, and commit message.
///
/// Does not mutate exchange lifecycle state. The caller commits
/// `first_sent`, outbound phase, and active processing state
/// after this returns.
/// `timeout` is `Some(duration)` when the committed message
/// requires a processing deadline, `None` otherwise.
#[cfg(test)]
pub(crate) async fn commit_message(
    tx: &mpsc::Sender<ProcessingRequest>,
    msg: ProcessingRequest,
    timeout: Option<Duration>,
) -> Result<Option<tokio::time::Instant>, ExchangeError> {
    let permit = tx.reserve().await.map_err(|_send_err| ExchangeError::SendFailed)?;

    let deadline = if let Some(dur) = timeout {
        Some(
            tokio::time::Instant::now()
                .checked_add(dur)
                .ok_or(ExchangeError::DeadlineOverflow)?,
        )
    } else {
        None
    };

    permit.send(msg);
    Ok(deadline)
}

/// Read the next message from the response stream.
async fn next_message(
    streaming: &mut tonic::Streaming<ProcessingResponse>,
) -> Result<ProcessingResponse, ExchangeError> {
    streaming
        .message()
        .await
        .map_err(ExchangeError::Grpc)?
        .ok_or(ExchangeError::EmptyStream)
}
