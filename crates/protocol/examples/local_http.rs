// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Run with `cargo run -p praxis-proxy-protocol --example local-http --features local-http`.

#[path = "local_http/context.rs"]
mod context;
#[path = "local_http/handler.rs"]
mod handler;

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use praxis_filter::{FilterEntry, FilterError, FilterFactory, FilterPipeline, FilterRegistry, Request, Response};
use praxis_protocol::http::local::{LocalCompletion, LocalExchange, LocalTransport};

/// Bounded fake I/O for the contract harness; never binds a network listener.
#[derive(Default)]
struct MemoryTransport {
    /// One bounded upload chunk.
    input: Option<Bytes>,
    /// Small byte-count response captured for verification.
    output: Vec<Bytes>,
}

#[async_trait]
impl LocalTransport for MemoryTransport {
    async fn accept_body(&mut self) -> Result<(), FilterError> {
        Ok(())
    }

    async fn read_body(&mut self) -> Result<Option<Bytes>, FilterError> {
        Ok(self.input.take())
    }

    async fn write_head(&mut self, _head: &Response) -> Result<(), FilterError> {
        Ok(())
    }

    async fn write_body(&mut self, chunk: Bytes) -> Result<(), FilterError> {
        self.output.push(chunk);
        Ok(())
    }

    async fn finish(&mut self, _request_eof: bool) -> Result<(), FilterError> {
        Ok(())
    }

    async fn abort(&mut self) {}

    fn complete(&mut self, _completion: LocalCompletion, _ctx: &praxis_filter::HttpFilterContext<'_>) {}
}

#[cfg(not(test))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), FilterError> {
    run_example().await
}

/// Exercise a minimal handler through the production coordinator and fake I/O.
pub(crate) async fn run_example() -> Result<(), FilterError> {
    let pipeline = pipeline()?;
    let request = Request {
        method: http::Method::POST,
        uri: "/count".parse()?,
        headers: http::HeaderMap::new(),
    };
    let mut response = Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
    };
    let mut ctx = context::context(&request, &pipeline);
    ctx.response_header = Some(&mut response);
    let exchange = LocalExchange::claim(&pipeline, &mut ctx).ok_or("example route was not claimed")?;
    let mut transport = MemoryTransport {
        input: Some(Bytes::from_static(b"upload")),
        output: Vec::new(),
    };
    let completion = exchange.run(&mut ctx, &mut transport).await;
    assert_eq!(completion.status, 200, "example must complete locally");
    assert!(completion.request_eof, "handler must consume the upload");
    assert_eq!(
        transport.output,
        vec![Bytes::from_static(b"6")],
        "response counts upload bytes"
    );
    Ok(())
}

/// Build the example through the same mandatory public construction path.
fn pipeline() -> Result<Arc<FilterPipeline>, FilterError> {
    let mut registry = FilterRegistry::with_builtins();
    registry.register(
        "upload_count",
        FilterFactory::Http(Arc::new(|_| Ok(Box::new(handler::UploadCount::default())))),
    )?;
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str("- filter: upload_count")?;
    Ok(Arc::new(FilterPipeline::build(&mut entries, &registry)?))
}
