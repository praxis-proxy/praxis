#![no_main]

use libfuzzer_sys::fuzz_target;
use praxis_filter::{FailureMode, FilterEntry, FilterPipeline, FilterRegistry};

fuzz_target!(|data: &str| {
    let registry = FilterRegistry::with_builtins();

    let Ok(entries_yaml) = serde_yaml::from_str::<Vec<serde_yaml::Value>>(data) else {
        return;
    };

    let mut entries: Vec<FilterEntry> = entries_yaml
        .into_iter()
        .filter_map(|v| {
            let filter_type = v.get("filter")?.as_str()?.to_owned();
            Some(FilterEntry {
                branch_chains: None,
                filter_type,
                config: v,
                conditions: vec![],
                name: None,
                response_conditions: vec![],
                failure_mode: FailureMode::default(),
            })
        })
        .collect();

    if entries.is_empty() {
        return;
    }

    let Ok(pipeline) = FilterPipeline::build(&mut entries, &registry) else {
        return;
    };

    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(async {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, "fuzz.example.com".parse().unwrap());
        headers.insert(http::header::ACCEPT, "*/*".parse().unwrap());
        headers.insert(http::header::USER_AGENT, "praxis-fuzz/1.0".parse().unwrap());

        let request = praxis_filter::Request {
            method: http::Method::GET,
            uri: http::Uri::from_static("/fuzz"),
            headers,
        };

        let mut ctx = praxis_filter::HttpFilterContext {
            body_done_indices: Vec::new(),
            branch_iterations: std::collections::HashMap::new(),
            client_addr: None,
            cluster: None,
            executed_filter_indices: Vec::new(),
            extra_request_headers: Vec::new(),
            filter_metadata: std::collections::HashMap::new(),
            filter_results: std::collections::HashMap::new(),
            health_registry: None,
            request: &request,
            request_body_bytes: 0,
            request_body_mode: praxis_filter::BodyMode::Stream,
            request_start: std::time::Instant::now(),
            response_body_bytes: 0,
            response_body_mode: praxis_filter::BodyMode::Stream,
            response_header: None,
            response_headers_modified: false,
            rewritten_path: None,
            selected_endpoint_index: None,
            upstream: None,
        };

        let _ = pipeline.execute_http_request(&mut ctx).await;

        let mut resp = praxis_filter::Response {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
        };
        ctx.response_header = Some(&mut resp);
        let _ = pipeline.execute_http_response(&mut ctx).await;

        if pipeline.body_capabilities().needs_request_body {
            let mut body = Some(bytes::Bytes::from_static(b"fuzz-body"));
            let _ = pipeline.execute_http_request_body(&mut ctx, &mut body, true).await;
        }
    });
});
