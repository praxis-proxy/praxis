// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The two rate-limit stages: where they run, how often, and what a denial
//! puts on the wire.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use http::{HeaderValue, Method};
use ppe::{
    praxis_policy_core::{
        error::PluginViolation,
        extensions::SubjectExtension,
        http_hook::{HttpHook, HttpPayload},
        identity::{HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload},
        ratelimit_hook::{HOOK_RATELIMIT_POST_IDENTITY, HOOK_RATELIMIT_PRE_IDENTITY},
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
    FilterAction, FilterEntry, FilterPipeline, FilterRegistry, Rejection,
    filter::{HttpFilter as _, HttpFilterContext},
    test_utils::{make_filter_context, make_request},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// A tool route with a post-identity limiter keyed by subject.
const TOOL_SUBJECT_LIMIT: &str = "plugins:
  - name: who
    kind: {kind}
    hooks: [identity.resolve]
    capabilities: [read_headers]
  - name: per-user
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
    capabilities: [read_subject, read_headers]
    config:
      namespace: per-user
      bindings:
        subject_id: subject.id
      limits:
        - max: 1
          seconds: 60
          variables: [subject_id]
global:
  authentication: [who]
routes:
  - tool: echo
    rate_limits: [per-user]
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
";

/// An inference route with a post-identity limiter keyed by model.
const MODEL_LIMIT: &str = "plugins:
  - name: who
    kind: {kind}
    hooks: [identity.resolve]
    capabilities: [read_headers]
  - name: per-model
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
    capabilities: [read_subject]
    config:
      namespace: per-model
      bindings:
        model: llm.model_id
      limits:
        - max: 1
          seconds: 60
          variables: [model]
global:
  authentication: [who]
routes:
  - llm: \"*\"
    rate_limits: [per-model]
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
";

/// Pre- and post-identity host limiters around a host resolver; `{deny}` is
/// the pre limiter's extra config.
const HOST_LIMITERS: &str = "plugins:
  - name: who
    kind: {kind}
    hooks: [identity.resolve]
    capabilities: [read_headers]
  - name: pre
    kind: {kind}
    hooks: [ratelimit.pre_identity]
    capabilities: [read_headers]
    config: {deny}
  - name: post
    kind: {kind}
    hooks: [ratelimit.post_identity]
    capabilities: [read_headers, read_subject]
global:
  authentication: [who]
  rate_limits: [pre, post]
";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[expect(clippy::too_many_lines, reason = "one request sequence")]
async fn over_the_address_limit_is_429_with_retry_after_and_allowlisted_fields() {
    let (_dir, path, _calls) = l7_address_limit("test/rl-l7", 2);
    let filter = filter(path);
    assert_eq!(filter.limit_stages(), (true, false));
    for _ in 0..2 {
        assert!(matches!(
            header_phase(&filter, Some("alice"), 1).await,
            FilterAction::Continue
        ));
    }
    let denied = rejection(header_phase(&filter, Some("alice"), 1).await);
    assert_eq!(denied.status, 429);
    let retry: u64 = header(&denied, "Retry-After").unwrap().parse().unwrap();
    assert!(retry >= 1);
    let json = body(&denied);
    let mut keys: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "code",
            "limit",
            "message",
            "remaining",
            "retry_after_seconds",
            "window_seconds"
        ]
    );
    assert_eq!(json["limit"], 2);
    assert!(
        matches!(header_phase(&filter, Some("alice"), 2).await, FilterAction::Continue),
        "another address has its own counter"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pre_identity_denial_stops_before_identity_runs() {
    let (_dir, path, calls) = l7_address_limit("test/rl-before-identity", 1);
    let filter = filter(path);
    let _admitted = header_phase(&filter, Some("forged"), 9).await;
    assert_eq!(plugins(&calls), ["who"]);
    let denied = rejection(header_phase(&filter, Some("forged"), 9).await);
    assert_eq!(denied.status, 429);
    assert_eq!(plugins(&calls), ["who"], "the resolver never saw the limited request");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_trusted_hop_denies_an_address_limit_instead_of_sharing_a_bucket() {
    let (_dir, path, calls) = l7_address_limit("test/rl-malformed-hop", 1);
    let filter = filter_behind(path, vec!["203.0.113.0/24".to_owned()]);

    for forwarded in ["not-an-ip", "198.51.100.7, garbage"] {
        let denied = rejection(forwarded_phase(&filter, 9, forwarded).await);
        assert_eq!(
            denied.status, 400,
            "{forwarded}: no client address is a denial, not a skip"
        );
        assert_eq!(
            header(&denied, "X-Policy-Violation"),
            Some("ratelimit.missing_attribute"),
            "{forwarded}"
        );
    }
    assert!(
        plugins(&calls).is_empty(),
        "identity never ran for an unattributable request"
    );
    assert!(
        matches!(header_phase(&filter, Some("alice"), 9).await, FilterAction::Continue),
        "the proxy's own one-request budget was not spent by the malformed requests"
    );

    for client in ["198.51.100.7", "198.51.100.8"] {
        assert!(
            matches!(forwarded_phase(&filter, 9, client).await, FilterAction::Continue),
            "{client} has its own counter behind the proxy"
        );
    }
    let over = rejection(forwarded_phase(&filter, 9, "198.51.100.7").await);
    assert_eq!(over.status, 429, "the per-client limit still counts");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_route_counts_each_subject_separately_and_keeps_the_json_rpc_id() {
    let (_dir, path, _calls) = recorded_policy("test/rl-tool", TOOL_SUBJECT_LIMIT);
    let filter = filter(path);
    assert!(matches!(tool_call(&filter, "alice").await, FilterAction::BodyDone));
    let denied = rejection(tool_call(&filter, "alice").await);
    assert_eq!(denied.status, 429, "a JSON-RPC limit denial keeps its real status");
    let json = body(&denied);
    assert_eq!(json["id"], "call-7");
    assert_eq!(json["error"]["data"]["violation"], "ratelimit.exceeded");
    assert!(matches!(tool_call(&filter, "bob").await, FilterAction::BodyDone));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_identity_limit_binds_the_inference_model() {
    let (_dir, path, _calls) = recorded_policy("test/rl-model", MODEL_LIMIT);
    let filter = filter(path);
    assert!(matches!(inference_call(&filter, "m1").await, FilterAction::BodyDone));
    let denied = rejection(inference_call(&filter, "m1").await);
    assert_eq!(denied.status, 429, "the second call on one model is over the limit");
    assert!(
        matches!(inference_call(&filter, "m2").await, FilterAction::BodyDone),
        "another model has its own counter"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stages_wrap_identity_on_http_coordinates_with_the_resolved_subject() {
    let (_dir, path, calls) = recorded_policy("test/rl-order", &HOST_LIMITERS.replace("{deny}", "{}"));
    let filter = filter(path);
    assert!(matches!(
        header_phase(&filter, Some("alice"), 1).await,
        FilterAction::Continue
    ));
    let seen = calls.lock().unwrap().clone();
    let expected: Vec<(String, String, String)> =
        [("pre", "http", ""), ("who", "http", "alice"), ("post", "http", "alice")]
            .iter()
            .map(|(a, b, c)| ((*a).to_owned(), (*b).to_owned(), (*c).to_owned()))
            .collect();
    assert_eq!(seen, expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_limiter_denial_never_echoes_its_reason_or_details() {
    let deny = "{deny: ratelimit.exceeded}";
    let (_dir, path, calls) = recorded_policy("test/rl-sentinel", &HOST_LIMITERS.replace("{deny}", deny));
    let filter = filter(path);
    let denied = rejection(header_phase(&filter, Some("alice"), 1).await);
    assert_eq!(denied.status, 429, "an unlisted status falls back to the code's");
    assert_eq!(header(&denied, "Retry-After"), Some("5"));
    let wire = format!("{:?} {}", denied.headers, body(&denied));
    assert!(!wire.contains("SENTINEL"), "plugin text leaked: {wire}");
    assert_eq!(plugins(&calls), ["pre"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_host_limiter_code_gets_a_generic_503() {
    let deny = "{deny: SENTINEL-CODE}";
    let (_dir, path, _calls) = recorded_policy("test/rl-unknown", &HOST_LIMITERS.replace("{deny}", deny));
    let denied = rejection(header_phase(&filter(path), Some("alice"), 1).await);
    assert_eq!(denied.status, 503);
    assert_eq!(header(&denied, "X-Policy-Violation"), Some("ratelimit.denied"));
    assert!(!format!("{:?} {:?}", denied.headers, denied.body).contains("SENTINEL"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_subject_keyed_limit_without_a_subject_is_401() {
    let yaml = TOOL_SUBJECT_LIMIT.replace(
        "routes:\n  - tool: echo\n    rate_limits: [per-user]\n",
        "  rate_limits: [per-user]\nroutes:\n  - tool: echo\n",
    );
    let (_dir, path, _calls) = recorded_policy("test/rl-anonymous", &yaml);
    let filter = filter(path);
    let req = request(None);
    let mut ctx = context(&req, 1);
    let _admitted = filter.on_request(&mut ctx).await.unwrap();
    let mut body = Some(Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#));
    ctx.set_metadata("mcp.method", "ping");
    let denied = rejection(filter.on_request_body(&mut ctx, &mut body, true).await.unwrap());
    assert_eq!(denied.status, 401);
    assert_eq!(header(&denied, "X-Policy-Violation"), Some("ratelimit.no_identity"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_without_rate_limits_runs_no_stage() {
    let (_dir, path, calls) = recorded_policy(
        "test/rl-none",
        "plugins:
  - name: who
    kind: {kind}
    hooks: [identity.resolve]
    capabilities: [read_headers]
global:
  authentication: [who]
",
    );
    let filter = filter(path);
    assert_eq!(filter.limit_stages(), (false, false));
    let _admitted = header_phase(&filter, Some("alice"), 1).await;
    assert_eq!(plugins(&calls), ["who"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn body_first_runs_each_stage_once() {
    let (_dir, path, calls) = recorded_policy("test/rl-body-first", &HOST_LIMITERS.replace("{deny}", "{}"));
    let filter = filter(path);
    let req = request(Some("alice"));
    let mut ctx = context(&req, 1);
    let mut body = Some(Bytes::from_static(b"{}"));
    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone), "got {action:?}");
    assert!(matches!(
        filter.on_request(&mut ctx).await.unwrap(),
        FilterAction::Continue
    ));
    assert_eq!(plugins(&calls), ["pre", "who", "post"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_instances_each_run_both_stages_once() {
    let (_dir, path, calls) = recorded_policy("test/rl-two-a", &HOST_LIMITERS.replace("{deny}", "{}"));
    let (_other_dir, other_path, other_calls) =
        recorded_policy("test/rl-two-b", &HOST_LIMITERS.replace("{deny}", "{}"));
    let yaml = format!("- filter: policy\n  config_path: {path}\n- filter: policy\n  config_path: {other_path}\n");
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(&yaml).unwrap();
    let pipeline = FilterPipeline::build(&mut entries, &FilterRegistry::with_builtins()).unwrap();
    let req = request(Some("alice"));
    let mut ctx = make_filter_context(&req);
    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "got {action:?}");
    assert_eq!(plugins(&calls), ["pre", "who", "post"]);
    assert_eq!(plugins(&other_calls), ["pre", "who", "post"]);
}

#[tokio::test(flavor = "current_thread")]
async fn threading_the_table_raises_no_skipped_stage_alarm() {
    let (_dir, path, _calls) = l7_address_limit("test/rl-no-alarm", 10);
    let filter = filter(path);
    let sink = Sink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let _admitted = header_phase(&filter, Some("alice"), 1).await;
    let threaded = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();

    let req = request(Some("alice"));
    let mut ctx = context(&req, 2);
    state_mut(&mut ctx).limits.pre_identity = true;
    let _admitted = filter.on_request(&mut ctx).await.unwrap();
    drop(guard);
    let skipped = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
    assert!(!threaded.contains("rate_limit_stage_skipped"), "{threaded}");
    assert!(
        skipped.contains("rate_limit_stage_skipped"),
        "the capture sees the alarm: {skipped}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// What the host plugins saw: `(plugin, entity_type, subject)` per call.
type Calls = Arc<Mutex<Vec<(String, String, String)>>>;

/// A host identity resolver that takes the subject from `x-user`, and a host
/// limiter that records each call and denies with sentinel text when its
/// config sets `deny`.
struct Recorder {
    /// Plugin config.
    cfg: PluginConfig,
    /// Shared call record.
    calls: Calls,
}

impl Recorder {
    /// Record one call.
    fn record(&self, ext: &Extensions, subject: Option<String>) {
        let entity = ext
            .meta
            .as_ref()
            .and_then(|meta| meta.entity_type.clone())
            .unwrap_or_default();
        self.calls
            .lock()
            .unwrap()
            .push((self.cfg.name.clone(), entity, subject.unwrap_or_default()));
    }
}

impl Plugin for Recorder {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<IdentityHook> for Recorder {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        let user = payload.headers().get("x-user").cloned();
        self.record(extensions, user.clone());
        let mut resolved = payload.clone();
        resolved.subject = user.map(|id| SubjectExtension {
            id: Some(id),
            ..Default::default()
        });
        PluginResult::modify_payload(resolved)
    }
}

impl HookHandler<HttpHook> for Recorder {
    async fn handle(
        &self,
        _payload: &HttpPayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<HttpPayload> {
        let subject = extensions
            .security
            .as_ref()
            .and_then(|security| security.subject.as_ref())
            .and_then(|subject| subject.id.clone());
        self.record(extensions, subject);
        let deny = self
            .cfg
            .config
            .as_ref()
            .and_then(|config| config.get("deny"))
            .and_then(serde_json::Value::as_str);
        let Some(code) = deny else {
            return PluginResult::allow();
        };
        let details = HashMap::from([
            ("http.status".to_owned(), serde_json::json!(418)),
            ("retry_after_seconds".to_owned(), serde_json::json!(5)),
            ("operator".to_owned(), serde_json::json!("SENTINEL-DETAIL")),
        ]);
        PluginResult::deny(PluginViolation::new(code, "SENTINEL-REASON").with_details(details))
    }
}

/// Builds [`Recorder`]s sharing one record.
///
/// [`Recorder`]: Recorder
struct RecorderFactory(Calls);

impl PluginFactory for RecorderFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(Recorder {
            cfg: config.clone(),
            calls: Arc::clone(&self.0),
        });
        let identity: Arc<dyn AnyHookHandler> =
            Arc::new(TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(&plugin)));
        let http: Arc<dyn AnyHookHandler> = Arc::new(TypedHandlerAdapter::<HttpHook, _>::new(Arc::clone(&plugin)));
        let handlers = [
            (HOOK_IDENTITY_RESOLVE, identity),
            (HOOK_RATELIMIT_PRE_IDENTITY, Arc::clone(&http)),
            (HOOK_RATELIMIT_POST_IDENTITY, http),
        ]
        .into_iter()
        .filter(|(hook, _)| config.hooks.iter().any(|declared| declared == hook))
        .collect();
        Ok(PluginInstance { plugin, handlers })
    }
}

/// Register a recorder under `kind` and write `yaml` with `{kind}` filled in.
fn recorded_policy(kind: &'static str, yaml: &str) -> (TempDir, String, Calls) {
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&calls);
    register_policy_plugin_factory(kind, Arc::new(move || Box::new(RecorderFactory(Arc::clone(&record)))));
    let (dir, path) = write_policy(&yaml.replace("{kind}", kind));
    (dir, path, calls)
}

/// Write `yaml` as a policy document.
fn write_policy(yaml: &str) -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, yaml).unwrap();
    (dir, path.to_str().unwrap().to_owned())
}

/// A filter over `path`.
fn filter(path: String) -> PolicyFilter {
    filter_behind(path, vec![])
}

/// A filter over `path` that trusts `X-Forwarded-For` from `trusted_proxies`.
fn filter_behind(path: String, trusted_proxies: Vec<String>) -> PolicyFilter {
    PolicyFilter::new(
        PolicyFilterConfig {
            config_path: path,
            allow_private_idp: false,
            trusted_private_endpoints: vec![],
            trusted_proxies,
            body_access: BodyAccessMode::ReadOnly,
            require_protocol_metadata: true,
            init_timeout_secs: 30,
            max_buffer_bytes: 10_485_760,
            llm: super::config::LlmOptions::default(),
            context_headers: HashMap::default(),
            context_meta: ContextMetaConfig::default(),
        },
        None,
    )
    .unwrap()
}

/// A request from `peer` as `user`.
fn request(user: Option<&str>) -> crate::Request {
    let mut req = make_request(Method::POST, "/tools");
    if let Some(user) = user {
        req.headers.insert("x-user", HeaderValue::from_str(user).unwrap());
    }
    req
}

/// A context for `req` from `peer`, as filter instance 0.
fn context(req: &crate::Request, peer: u8) -> HttpFilterContext<'_> {
    let mut ctx = make_filter_context(req);
    ctx.client_addr = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, peer)));
    ctx.current_filter_id = Some(0);
    ctx
}

/// Run the header phase for `user` from `peer`.
async fn header_phase(filter: &PolicyFilter, user: Option<&str>, peer: u8) -> FilterAction {
    let req = request(user);
    let mut ctx = context(&req, peer);
    filter.on_request(&mut ctx).await.unwrap()
}

/// The rejection in `action`.
fn rejection(action: FilterAction) -> Rejection {
    match action {
        FilterAction::Reject(rejection) => rejection,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

/// The header `name` on `rejection`.
fn header<'r>(rejection: &'r Rejection, name: &str) -> Option<&'r str> {
    rejection
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// The rejection body as JSON.
fn body(rejection: &Rejection) -> serde_json::Value {
    serde_json::from_slice(rejection.body.as_ref().unwrap()).unwrap()
}

/// The plugins `calls` recorded, in order.
fn plugins(calls: &Calls) -> Vec<String> {
    calls.lock().unwrap().iter().map(|(name, ..)| name.clone()).collect()
}

/// An L7 policy: host identity, `max` requests per client address before
/// identity, and an authenticated-only global rule.
fn l7_address_limit(kind: &'static str, max: u32) -> (TempDir, String, Calls) {
    recorded_policy(
        kind,
        &format!(
            "plugins:
  - name: who
    kind: {{kind}}
    hooks: [identity.resolve]
    capabilities: [read_headers]
  - name: edge
    kind: ratelimit/limitador
    hooks: [ratelimit.pre_identity]
    capabilities: [read_headers]
    config:
      namespace: edge
      bindings:
        client: http.client_address
      limits:
        - max: {max}
          seconds: 60
          variables: [client]
global:
  authentication: [who]
  rate_limits: [edge]
  authorization:
    pre_invocation:
      - \"require(authenticated)\"
"
        ),
    )
}

/// Run the header phase from trusted proxy `peer` carrying `forwarded`.
async fn forwarded_phase(filter: &PolicyFilter, peer: u8, forwarded: &str) -> FilterAction {
    let mut req = request(Some("alice"));
    req.headers
        .insert("x-forwarded-for", HeaderValue::from_str(forwarded).unwrap());
    let mut ctx = context(&req, peer);
    filter.on_request(&mut ctx).await.unwrap()
}

/// Run a classified `tools/call` for `user` through both phases.
async fn tool_call(filter: &PolicyFilter, user: &str) -> FilterAction {
    let req = request(Some(user));
    let mut ctx = context(&req, 1);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "gate: {action:?}");
    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", "echo");
    let mut body = Some(Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":"call-7","method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
    ));
    filter.on_request_body(&mut ctx, &mut body, true).await.unwrap()
}

/// Run an inference request for `model` through both phases.
async fn inference_call(filter: &PolicyFilter, model: &str) -> FilterAction {
    let mut req = request(Some("alice"));
    req.uri = "/v1/chat/completions".parse().unwrap();
    let mut ctx = context(&req, 1);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "gate: {action:?}");
    let mut body = Some(Bytes::from(format!(r#"{{"model":"{model}","messages":[]}}"#)));
    filter.on_request_body(&mut ctx, &mut body, true).await.unwrap()
}

/// Collects formatted log output.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
