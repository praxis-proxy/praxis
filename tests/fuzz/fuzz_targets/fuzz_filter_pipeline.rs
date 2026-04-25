#![no_main]

use libfuzzer_sys::fuzz_target;
use praxis_filter::{FilterEntry, FilterPipeline, FilterRegistry};

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
        let request = praxis_filter::Request {
            method: http::Method::GET,
            uri: http::Uri::from_static("/fuzz"),
            headers: http::HeaderMap::new(),
        };

        let mut ctx = praxis_filter::HttpFilterContext {
            branch_iterations: std::collections::HashMap::new(),
            client_addr: None,
            cluster: None,
            executed_filter_indices: Vec::new(),
            extra_request_headers: Vec::new(),
            filter_results: std::collections::HashMap::new(),
            health_registry: None,
            request: &request,
            request_body_bytes: 0,
            request_start: std::time::Instant::now(),
            response_body_bytes: 0,
            response_header: None,
            response_headers_modified: false,
            rewritten_path: None,
            upstream: None,
        };

        let _ = pipeline.execute_http_request(&mut ctx).await;
    });
});
