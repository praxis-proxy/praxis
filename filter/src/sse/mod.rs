// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bounded, incremental Server-Sent Events (SSE) codec.
//!
//! Pingora owns transport streaming, backpressure, and H1/H2 framing; this
//! module adds only application-level SSE record framing on top of a byte
//! stream. Provider JSON typing, `[DONE]`, event budgets, lifecycle rules,
//! accumulation, and replay stay in the consumer.
//!
//! # Decode from a streamed body
//!
//! Feed each Pingora body chunk to the decoder:
//!
//! ```
//! use bytes::Bytes;
//! use praxis_filter::sse::{SseBatch, SseDecoder};
//!
//! let mut decoder = SseDecoder::new();
//! let SseBatch { records, error, .. } =
//!     decoder.push(&Bytes::from_static(b"data: {\"n\":1}\n\ndata: {"));
//! assert!(error.is_none());
//! assert_eq!(records.len(), 1);
//! assert_eq!(records[0].data().as_ref(), br#"{"n":1}"#);
//!
//! // the second record completes on a later chunk
//! let batch = decoder.push(&Bytes::from_static(b"\"n\":2}\n\n"));
//! assert_eq!(batch.records[0].data().as_ref(), br#"{"n":2}"#);
//!
//! // at end of stream: the stream ended on a blank line, so nothing is left over
//! let tail = decoder.finish();
//! assert!(tail.records.is_empty());
//! assert!(tail.trailing.is_none());
//! ```
//!
//! # Encode locally generated records
//!
//! Build records and serialize them to canonical bytes:
//!
//! ```
//! use praxis_filter::sse::{SseRecord, encode};
//!
//! let record = SseRecord::builder()
//!     .event("message")
//!     .data("hello")
//!     .build()
//!     .expect("valid record");
//! assert_eq!(encode(&record).as_ref(), b"event: message\ndata: hello\n\n");
//! ```
//!
//! # Decode inside a streaming filter
//!
//! Run the decoder from `on_response_body` under
//! [`BodyMode::Stream`](crate::BodyMode): forward each chunk unchanged and feed
//! it to a per-request decoder for inspection. The decoder is request-scoped
//! state, so it lives in the filter context, not in the shared filter.
//!
//! ```
//! use async_trait::async_trait;
//! use bytes::Bytes;
//! use praxis_filter::{
//!     BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext,
//!     sse::SseDecoder,
//! };
//!
//! // A private newtype keeps this decoder distinct from other filters' state.
//! struct SseState(SseDecoder);
//!
//! struct SseInspector;
//!
//! #[async_trait]
//! impl HttpFilter for SseInspector {
//!     fn name(&self) -> &'static str {
//!         "sse-inspector"
//!     }
//!
//!     async fn on_request(
//!         &self,
//!         _ctx: &mut HttpFilterContext<'_>,
//!     ) -> Result<FilterAction, FilterError> {
//!         Ok(FilterAction::Continue)
//!     }
//!
//!     // Receive body chunks read-only, streamed one at a time (the default).
//!     fn response_body_access(&self) -> BodyAccess {
//!         BodyAccess::ReadOnly
//!     }
//!
//!     fn response_body_mode(&self) -> BodyMode {
//!         BodyMode::Stream
//!     }
//!
//!     fn on_response_body(
//!         &self,
//!         ctx: &mut HttpFilterContext<'_>,
//!         body: &mut Option<Bytes>,
//!         end_of_stream: bool,
//!     ) -> Result<FilterAction, FilterError> {
//!         if ctx.get_filter_state::<SseState>().is_none() {
//!             ctx.insert_filter_state(SseState(SseDecoder::new()));
//!         }
//!         let SseState(decoder) = ctx
//!             .get_filter_state_mut::<SseState>()
//!             .expect("just inserted the decoder state");
//!
//!         // Inspect by reference; `body` is left untouched and forwarded as is.
//!         if let Some(chunk) = body.as_ref() {
//!             let batch = decoder.push(chunk);
//!             if let Some(err) = batch.error {
//!                 return Err(err.into()); // a limit violation poisons the decoder
//!             }
//!             // Provider-neutral inspection, e.g. events completed by this chunk.
//!             let _event_count = batch.records.iter().filter(|r| r.is_event()).count();
//!         }
//!         if end_of_stream {
//!             let tail = decoder.finish();
//!             if let Some(err) = tail.error {
//!                 return Err(err.into()); // finish re-reports a poisoned decoder
//!             }
//!             // WHATWG discards an incomplete event at EOF; a truncated tail, if
//!             // any, surfaces in `tail.trailing` to ignore or deliberately salvage.
//!             let _truncated = tail.trailing.filter(|r| r.is_event());
//!         }
//!         Ok(FilterAction::Continue)
//!     }
//! }
//!
//! // The hook runs inside Pingora with a real context; construct the filter
//! // here to type-check the integration.
//! let filter = SseInspector;
//! assert_eq!(filter.name(), "sse-inspector");
//! ```
//!
//! # Encode for a streaming response body
//!
//! Serialize locally generated records as canonical SSE bytes from a
//! [`StreamingResponseBody`](crate::StreamingResponseBody), e.g. replaying a stored response:
//!
//! ```
//! use async_trait::async_trait;
//! use bytes::Bytes;
//! use praxis_filter::{
//!     FilterError, StreamingResponseBody,
//!     sse::{SseRecord, encode},
//! };
//!
//! struct ReplayBody {
//!     records: std::vec::IntoIter<SseRecord>,
//! }
//!
//! #[async_trait]
//! impl StreamingResponseBody for ReplayBody {
//!     async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
//!         Ok(self.records.next().as_ref().map(encode))
//!     }
//!
//!     async fn suppress(&mut self) -> Result<(), FilterError> {
//!         self.records = Vec::new().into_iter();
//!         Ok(())
//!     }
//!
//!     async fn cancel(&mut self) {
//!         self.records = Vec::new().into_iter();
//!     }
//! }
//!
//! let records = vec![
//!     SseRecord::builder()
//!         .data("hello")
//!         .build()
//!         .expect("valid record"),
//!     SseRecord::builder()
//!         .event("done")
//!         .data("bye")
//!         .build()
//!         .expect("valid record"),
//! ];
//! let mut body = ReplayBody {
//!     records: records.into_iter(),
//! };
//!
//! tokio::runtime::Runtime::new()
//!     .expect("runtime")
//!     .block_on(async {
//!         let first = body.next_chunk().await.expect("chunk").expect("record");
//!         assert_eq!(first.as_ref(), b"data: hello\n\n");
//!         let second = body.next_chunk().await.expect("chunk").expect("record");
//!         assert_eq!(second.as_ref(), b"event: done\ndata: bye\n\n");
//!         assert!(body.next_chunk().await.expect("chunk").is_none());
//!     });
//! ```

mod decoder;
mod encoder;
mod record;

pub use decoder::{SseBatch, SseDecodeError, SseDecoder, SseLimits};
pub use encoder::{encode, encode_into};
pub use record::{SseBuildError, SseField, SseRecord, SseRecordBuilder};
