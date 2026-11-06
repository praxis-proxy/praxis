// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! One context table per request and filter instance, threaded through every
//! hook.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use http::{HeaderValue, Method};
use ppe::{
    praxis_policy_core::{
        http_hook::{HOOK_HTTP_REQUEST, HOOK_HTTP_RESPONSE, HttpHook, HttpPayload},
        identity::{HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload},
    },
    prelude::{
        AnyHookHandler, Extensions, HookHandler, Plugin, PluginConfig, PluginContext, PluginError, PluginFactory,
        PluginInstance, PluginResult, TypedHandlerAdapter,
    },
};
use tempfile::TempDir;

use super::{
    config::{BodyAccessMode, ContextMetaConfig, PolicyFilterConfig},
    filter::PolicyFilter,
    register_policy_plugin_factory,
    request_state::state_mut,
};
use crate::{
    FilterAction, FilterEntry, FilterPipeline, FilterRegistry,
    filter::HttpFilter as _,
    test_utils::{make_filter_context, make_request},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The `global_state` key the counter increments.
const COUNT: &str = "test/count";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn one_table_carries_state_from_identity_to_the_response_hook() {
    let (_dir, path, seen) = counter_policy("test/state-counter");
    let pipeline = pipeline(&[&path]);
    round_trip(&pipeline, "first").await;
    round_trip(&pipeline, "second").await;
    assert_eq!(
        counts(&seen, "first"),
        [1, 2, 3],
        "identity, request and response hooks share one table"
    );
    assert_eq!(counts(&seen, "second"), [1, 2, 3], "a new request starts a fresh table");
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_requests_keep_their_own_tables() {
    let (_dir, path, seen) = counter_policy("test/state-counter-concurrent");
    let pipeline = Arc::new(pipeline(&[&path]));
    let markers: Vec<String> = (0..16).map(|index| format!("request-{index}")).collect();
    let tasks: Vec<_> = markers
        .iter()
        .cloned()
        .map(|marker| {
            let pipeline = Arc::clone(&pipeline);
            tokio::spawn(async move { round_trip(&pipeline, &marker).await })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
    for marker in &markers {
        assert_eq!(counts(&seen, marker), [1, 2, 3], "{marker} saw another request's table");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_policy_instances_keep_separate_tables_and_admission() {
    let (_dir, path, seen) = counter_policy("test/state-counter-two");
    let (_other_dir, other_path, other_seen) = counter_policy("test/state-counter-two-b");
    let pipeline = pipeline(&[&path, &other_path]);
    round_trip(&pipeline, "both").await;
    assert_eq!(counts(&seen, "both"), [1, 2, 3], "the first instance");
    assert_eq!(
        counts(&other_seen, "both"),
        [1, 2, 3],
        "the second instance runs every hook on its own table, not skipping because the first admitted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lost_table_fails_later_hooks_instead_of_starting_fresh() {
    let (_dir, path, seen) = counter_policy("test/state-counter-lost");
    let filter = PolicyFilter::new(config(path), None).unwrap();
    let mut req = make_request(Method::GET, "/");
    req.headers.insert("x-marker", HeaderValue::from_static("lost"));
    let mut ctx = make_filter_context(&req);
    ctx.current_filter_id = Some(0);
    assert!(matches!(
        filter.on_request(&mut ctx).await.unwrap(),
        FilterAction::Continue
    ));

    state_mut(&mut ctx).take_table().unwrap();
    let mut response = crate::test_utils::make_response();
    ctx.response_header = Some(&mut response);
    let error = filter
        .on_response(&mut ctx)
        .await
        .expect_err("the response must fail under failure_mode");
    assert!(error.to_string().contains("context table was lost"), "got {error}");
    assert_eq!(counts(&seen, "lost"), [1, 2], "no response hook ran with a fresh table");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// `(marker, count after the hook)` for each counter invocation.
type Seen = Arc<Mutex<Vec<(String, u64)>>>;

/// Counts invocations in the context table's `global_state` and records each
/// value it saw, tagged with the request's marker header.
struct Counter {
    /// Plugin config.
    cfg: PluginConfig,
    /// `(marker, count after this hook)` per invocation.
    seen: Seen,
}

impl Counter {
    /// Increment the table's counter and record it.
    fn bump(&self, ctx: &mut PluginContext, marker: String) {
        let next = ctx.get_global(COUNT).and_then(serde_json::Value::as_u64).unwrap_or(0) + 1;
        ctx.set_global(COUNT, next.into());
        self.seen.lock().unwrap().push((marker, next));
    }
}

impl Plugin for Counter {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<IdentityHook> for Counter {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        _ext: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        let marker = payload.headers().get("x-marker").cloned().unwrap_or_default();
        self.bump(ctx, marker);
        PluginResult::modify_payload(payload.clone())
    }
}

impl HookHandler<HttpHook> for Counter {
    async fn handle(
        &self,
        _payload: &HttpPayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<HttpPayload> {
        let marker = extensions
            .http
            .as_ref()
            .and_then(|http| http.request_headers.get("x-marker").cloned())
            .unwrap_or_default();
        self.bump(ctx, marker);
        PluginResult::allow()
    }
}

/// Builds [`Counter`]s sharing one record.
///
/// [`Counter`]: Counter
struct CounterFactory(Seen);

impl PluginFactory for CounterFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(Counter {
            cfg: config.clone(),
            seen: Arc::clone(&self.0),
        });
        let identity: Arc<dyn AnyHookHandler> =
            Arc::new(TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(&plugin)));
        let http: Arc<dyn AnyHookHandler> = Arc::new(TypedHandlerAdapter::<HttpHook, _>::new(Arc::clone(&plugin)));
        Ok(PluginInstance {
            plugin,
            handlers: vec![
                (HOOK_IDENTITY_RESOLVE, identity),
                (HOOK_HTTP_REQUEST, Arc::clone(&http)),
                (HOOK_HTTP_RESPONSE, http),
            ],
        })
    }
}

/// A pure-L7 policy whose counter runs at identity, request and response, and
/// the record its counter writes. `kind` must be unique per test.
fn counter_policy(kind: &'static str) -> (TempDir, String, Seen) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    register_policy_plugin_factory(kind, Arc::new(move || Box::new(CounterFactory(Arc::clone(&record)))));
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("policy.yaml");
    std::fs::write(
        &path,
        format!(
            "engine_settings:\n  dispatch: hooks\nplugins:\n  - name: counter\n    kind: {kind}\n    \
             hooks: [identity.resolve, http.request, http.response]\n    mode: sequential\n    on_error: fail\n    \
             capabilities: [read_headers]\n"
        ),
    )
    .unwrap();
    (dir, path.to_str().unwrap().to_owned(), seen)
}

/// A filter config over `path`.
fn config(path: String) -> PolicyFilterConfig {
    PolicyFilterConfig {
        config_path: path,
        allow_private_idp: false,
        trusted_private_endpoints: vec![],
        trusted_proxies: vec![],
        body_access: BodyAccessMode::ReadOnly,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
        llm: super::config::LlmOptions::default(),
        context_headers: HashMap::default(),
        context_meta: ContextMetaConfig::default(),
    }
}

/// A pipeline of one `policy` filter per path.
fn pipeline(paths: &[&str]) -> FilterPipeline {
    let yaml: String = paths
        .iter()
        .map(|path| format!("- filter: policy\n  config_path: {path}\n"))
        .collect();
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(&yaml).unwrap();
    FilterPipeline::build(&mut entries, &FilterRegistry::with_builtins()).unwrap()
}

/// Run `marker`'s request and response through `pipeline`.
async fn round_trip(pipeline: &FilterPipeline, marker: &str) {
    let mut req = make_request(Method::GET, "/");
    req.headers.insert("x-marker", HeaderValue::from_str(marker).unwrap());
    let mut ctx = make_filter_context(&req);
    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "{marker}: got {action:?}");
    let mut response = crate::test_utils::make_response();
    ctx.response_header = Some(&mut response);
    let action = pipeline.execute_http_response(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "{marker}: got {action:?}");
}

/// The counts recorded for `marker`, in order.
fn counts(seen: &Mutex<Vec<(String, u64)>>, marker: &str) -> Vec<u64> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|(seen, _)| seen == marker)
        .map(|(_, count)| *count)
        .collect()
}
