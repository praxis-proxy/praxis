// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Buffered-step emissions must cross their own bandwidth boundary.

use std::{
    fmt::Write as _,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;

use crate::{FilterAction, FilterError, HttpFilter, HttpFilterContext};

/// Emits output during both successful and handled transport completion.
struct EmitCompletion;

#[async_trait::async_trait]
impl HttpFilter for EmitCompletion {
    fn name(&self) -> &'static str {
        "test_emit_completion"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadOnly(crate::BodyRequirement::Optional)
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream {
            ctx.emit_stream_chunk(Bytes::from(vec![b'e'; 100]))?;
            ctx.mark_stream_termination_handled();
        }
        Ok(FilterAction::Continue)
    }
}

fn filter(config: &str) -> Box<dyn HttpFilter> {
    let mut registry = super::test_registry();
    registry
        .register(
            "test_emit_completion",
            crate::FilterFactory::Http(Arc::new(|_| Ok(Box::new(EmitCompletion)))),
        )
        .unwrap();
    super::super::IterativeRequestRouterFilter::from_config_with_registry(
        &serde_yaml::from_str(config).unwrap(),
        &registry,
    )
    .unwrap()
}

fn emitting_step(address: std::net::SocketAddr, streaming: bool) -> String {
    format!(
        "
      - filter: bandwidth_limit
        mode: per_ip
        download_bytes_per_sec: 1000
        burst_bytes: 10
      - filter: test_emit_completion
{}
{}",
        if streaming {
            "      - filter: test_streaming_selector"
        } else {
            ""
        },
        super::routed_step_yaml(address),
    )
}

/// Later steps each fit their own timeout but outlive the producing step.
fn retained_router(
    address: std::net::SocketAddr,
    final_address: std::net::SocketAddr,
    terminal: bool,
    timeout_ms: u64,
    rate: u64,
) -> Box<dyn HttpFilter> {
    let mut waits = String::new();
    for (name, next) in [("wait1", "wait2"), ("wait2", "wait3"), ("wait3", "final")] {
        write!(
            waits,
            "
  - name: {name}
    filters:
      - filter: test_slow_request
{}
    on_result: [{{default: true, next: {next}}}]
",
            super::routed_step_yaml(address)
        )
        .unwrap();
    }
    filter(&format!(
        "
initial_step: buffered
step_timeout_ms: 900
timeout_ms: {timeout_ms}
steps:
  - name: buffered
    filters:
{}
    on_result: [{{default: true, next: wait1}}]
{waits}
  - name: final
    filters:
      - filter: test_streaming_selector
{}
{}
    on_result: [{{default: true, done: true}}]
",
        emitting_step(address, false).replace(
            "download_bytes_per_sec: 1000",
            &format!("download_bytes_per_sec: {rate}")
        ),
        if terminal {
            "      - filter: test_emit_completion"
        } else {
            ""
        },
        super::routed_step_yaml(final_address)
    ))
}

async fn retained_response(terminal: bool, timeout_ms: u64, rate: u64) -> Result<Vec<u8>, FilterError> {
    let (address, backend) = super::spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    let final_address = if terminal {
        super::closed_port_addr().await
    } else {
        address
    };
    let router = retained_router(address, final_address, terminal, timeout_ms, rate);
    let request = crate::test_utils::make_request(http::Method::GET, "/");
    let client = super::make_client();
    let mut ctx = super::make_iteration_context(&request, &client, b"");
    ctx.client_addr = Some("127.0.0.1".parse().unwrap());
    let result = async {
        match router.on_request(&mut ctx).await? {
            FilterAction::StreamingTerminalResponse(mut response) => {
                let mut output = Vec::new();
                while let Some(chunk) = response.body.next_chunk().await? {
                    output.extend_from_slice(&chunk);
                }
                Ok(output)
            },
            FilterAction::TerminalResponse(response) => Ok(response.body.unwrap_or_default().to_vec()),
            other => panic!("expected a terminal response, got {other:?}"),
        }
    }
    .await;
    backend.abort();
    result
}

#[tokio::test]
async fn retained_emissions_survive_the_producing_step_timeout_in_a_stream() {
    let output = retained_response(false, 5000, 1000).await.unwrap();
    assert_eq!(output, vec![b'e'; 100]);
}

#[tokio::test]
async fn retained_emissions_survive_the_producing_step_timeout_in_a_terminal_body() {
    let output = retained_response(true, 5000, 1000).await.unwrap();
    assert_eq!(output, vec![b'e'; 200]);
}

#[tokio::test]
async fn retained_emissions_still_obey_the_overall_deadline() {
    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(4), retained_response(false, 2200, 1)).await;
    assert!(
        result
            .is_ok_and(|result| result.is_err_and(|error| error.to_string().contains("bandwidth reservation exceeds")))
    );
    assert!(
        started.elapsed() >= Duration::from_millis(2100),
        "the request must not fail at the producing step's expired deadline"
    );
}

#[tokio::test]
async fn buffered_emissions_are_paced_before_and_after_stream_handoff() {
    let (address, backend) = super::spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    for resumed in [false, true] {
        let leading = format!(
            "
  - name: leading
    filters:
      - filter: test_streaming_selector
{}
    on_result: [{{default: true, next: buffered}}]
",
            super::routed_step_yaml(address)
        );
        let router = filter(&format!(
            "
initial_step: {}
steps:
{}
  - name: buffered
    filters:
{}
    on_result: [{{default: true, next: final}}]
  - name: final
    filters:
      - filter: test_streaming_selector
{}
    on_result: [{{default: true, done: true}}]
",
            if resumed { "leading" } else { "buffered" },
            if resumed { &leading } else { "" },
            emitting_step(address, false),
            super::routed_step_yaml(address)
        ));
        let request = crate::test_utils::make_request(http::Method::GET, "/");
        let client = super::make_client();
        let mut ctx = super::make_iteration_context(&request, &client, b"");
        ctx.client_addr = Some("127.0.0.1".parse().unwrap());
        let FilterAction::StreamingTerminalResponse(mut response) = router.on_request(&mut ctx).await.unwrap() else {
            panic!("expected a stream")
        };
        let started = Instant::now();
        let mut output = Vec::new();
        while let Some(chunk) = response.body.next_chunk().await.unwrap() {
            assert!(chunk.len() <= 10, "buffered emissions must release bounded prefixes");
            output.extend_from_slice(&chunk);
        }
        assert_eq!(output, vec![b'e'; 100]);
        assert!(
            started.elapsed() >= Duration::from_millis(70),
            "100 generated bytes must spend their 10-byte burst and refill"
        );
    }
    backend.abort();
}

#[tokio::test]
async fn abnormal_buffered_terminal_emissions_are_paced() {
    let address = super::closed_port_addr().await;
    let router = filter(&format!(
        "
initial_step: failed
steps:
  - name: failed
    filters:
{}
    on_result: [{{default: true, done: true}}]
",
        emitting_step(address, true)
    ));
    let request = crate::test_utils::make_request(http::Method::GET, "/");
    let client = super::make_client();
    let mut ctx = super::make_iteration_context(&request, &client, b"");
    ctx.client_addr = Some("127.0.0.1".parse().unwrap());
    let started = Instant::now();
    let FilterAction::TerminalResponse(response) = router.on_request(&mut ctx).await.unwrap() else {
        panic!("expected buffered abnormal completion")
    };
    assert_eq!(response.body.as_deref(), Some(vec![b'e'; 100].as_slice()));
    assert!(
        started.elapsed() >= Duration::from_millis(70),
        "handled terminal emissions must not bypass the download budget"
    );
}

#[tokio::test]
async fn ordinary_buffered_terminal_still_rejects_emitted_chunks() {
    let (address, backend) = super::spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    let router = filter(&format!(
        "
initial_step: buffered
steps:
  - name: buffered
    filters:
{}
    on_result: [{{default: true, done: true}}]
",
        emitting_step(address, false)
    ));
    let request = crate::test_utils::make_request(http::Method::GET, "/");
    let client = super::make_client();
    let mut ctx = super::make_iteration_context(&request, &client, b"");
    ctx.client_addr = Some("127.0.0.1".parse().unwrap());
    let result = router.on_request(&mut ctx).await;
    assert!(result.is_err_and(|error| {
        error
            .to_string()
            .contains("stream chunks were emitted without a streaming response")
    }));
    backend.abort();
}
