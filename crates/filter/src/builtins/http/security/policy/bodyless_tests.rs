// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bodyless requests on inference policies, and entity-less assertions-only
//! policies: HTTP authorization, delegation and request assertions before
//! admission.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use http::{HeaderValue, Method};
use ppe::{
    praxis_policy_core::{
        extensions::SubjectExtension,
        identity::{HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload},
    },
    prelude::{
        AnyHookHandler, Extensions, HookHandler, Plugin, PluginConfig, PluginContext, PluginError, PluginFactory,
        PluginInstance, PluginResult, TypedHandlerAdapter,
    },
};
use tempfile::TempDir;

use super::{
    config::{BodyAccessMode, ContextMetaConfig, LlmOptions, PolicyFilterConfig},
    filter::{PolicyFilter, identity_only_fallback_warnings},
    register_policy_plugin_factory,
};
use crate::{
    FilterAction,
    filter::{HttpFilter as _, HttpFilterContext},
    test_utils::{make_filter_context, make_request},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The identity plugin every policy here authenticates with.
const WHO: &str = "plugins:
  - name: who
    kind: {kind}
    hooks: [identity.resolve]
    capabilities: [read_headers]
global:
  authentication: [who]
";

/// Global rule admitting only `alice`, beside an inference route.
const ALICE_ONLY: &str = "  authorization:
    pre_invocation:
      - \"require(subject.id == 'alice')\"
routes:
  - llm: \"*\"
    authorization:
      pre_invocation:
        - \"allow\"
";

/// Request assertions alone, with no entity routes.
const L7_ASSERTIONS: &str = "  assertions:
    request:
      headers:
        - name: x-auth-user-id
          from: subject.id
      strip:
        - authorization
";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn every_bodyless_method_runs_the_global_http_rules() {
    let (_dir, path, _count) = policy("test/bodyless-methods", ALICE_ONLY);
    let filter = filter(path);
    for method in [
        Method::GET,
        Method::HEAD,
        Method::OPTIONS,
        Method::TRACE,
        Method::CONNECT,
    ] {
        let req = request(method.clone(), "/v1/models", "bob");
        assert_eq!(
            status(&body_phase(&filter, &mut context(&req)).await),
            Some(403),
            "{method}"
        );
        let req = request(method.clone(), "/v1/models", "alice");
        assert_eq!(status(&body_phase(&filter, &mut context(&req)).await), None, "{method}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn header_first_reuses_the_gate_identity_and_enforces_at_the_body() {
    let (_dir, path, count) = policy("test/bodyless-header-first", ALICE_ONLY);
    let filter = filter(path);
    for (user, expected) in [("bob", Some(403)), ("alice", None)] {
        *count.lock().unwrap() = 0;
        let req = request(Method::GET, "/v1/models", user);
        let mut ctx = context(&req);
        assert!(matches!(
            filter.on_request(&mut ctx).await.unwrap(),
            FilterAction::Continue
        ));
        assert_eq!(status(&body_phase(&filter, &mut ctx).await), expected, "{user}");
        assert_eq!(*count.lock().unwrap(), 1, "{user}: the gate identity is reused");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn body_first_admission_makes_the_header_phase_a_no_op() {
    let (_dir, path, count) = policy("test/bodyless-body-first", ALICE_ONLY);
    let filter = filter(path);
    let req = request(Method::GET, "/v1/models", "alice");
    let mut ctx = context(&req);
    assert_eq!(status(&body_phase(&filter, &mut ctx).await), None);
    assert!(matches!(
        filter.on_request(&mut ctx).await.unwrap(),
        FilterAction::Continue
    ));
    assert!(matches!(body_phase(&filter, &mut ctx).await, FilterAction::BodyDone));
    assert_eq!(*count.lock().unwrap(), 1, "one resolution, one enforcement");
}

#[expect(clippy::too_many_lines, reason = "one fixture and its cases")]
#[tokio::test(flavor = "multi_thread")]
async fn an_http_route_governs_its_path_and_global_rules_the_rest() {
    let (_dir, path, _count) = policy(
        "test/bodyless-http-route",
        "  authorization:
    pre_invocation:
      - \"require(authenticated)\"
routes:
  - http:
      path_prefix: /v1/admin
    authorization:
      pre_invocation:
        - \"require(subject.id == 'alice')\"
  - llm: \"*\"
    authorization:
      pre_invocation:
        - \"allow\"
",
    );
    let filter = filter(path);
    assert_eq!(filter.derived_shape(), (true, true));
    for (target, user, expected) in [
        ("/v1/models", "bob", None),
        ("/v1/admin/keys", "bob", Some(403)),
        ("/v1/admin/keys", "alice", None),
    ] {
        let req = request(Method::GET, target, user);
        assert_eq!(
            status(&body_phase(&filter, &mut context(&req)).await),
            expected,
            "{user} {target}"
        );
    }
}

#[expect(clippy::too_many_lines, reason = "one fixture and its cases")]
#[tokio::test(flavor = "multi_thread")]
async fn an_assertions_only_policy_applies_its_contract() {
    let (_dir, path, _count) = policy(
        "test/bodyless-assertions",
        "  assertions:
    request:
      headers:
        - name: x-auth-user-id
          from: subject.id
      strip:
        - authorization
        - x-api-key
routes:
  - llm: \"*\"
    authorization:
      pre_invocation:
        - \"allow\"
",
    );
    let filter = filter(path);
    let mut req = request(Method::GET, "/v1/models", "alice");
    req.headers
        .insert("authorization", HeaderValue::from_static("Bearer inbound"));
    req.headers.insert("x-api-key", HeaderValue::from_static("inbound"));
    req.headers.insert("x-auth-user-id", HeaderValue::from_static("root"));
    let mut ctx = context(&req);
    assert_eq!(status(&body_phase(&filter, &mut ctx).await), None);
    let set: Vec<(String, String)> = ctx
        .request_headers_to_set
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap().to_owned()))
        .collect();
    assert!(
        set.contains(&("x-auth-user-id".to_owned(), "alice".to_owned())),
        "{set:?}"
    );
    let removed: Vec<&str> = ctx
        .request_headers_to_remove
        .iter()
        .map(http::HeaderName::as_str)
        .collect();
    assert!(
        removed.contains(&"authorization") && removed.contains(&"x-api-key"),
        "{removed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_assertions_only_l7_policy_applies_its_contract_in_both_phases() {
    let (_dir, path, _count) = policy("test/l7-assertions", L7_ASSERTIONS);
    let filter = filter(path);
    assert_eq!(filter.derived_shape(), (true, false));
    let mut req = request(Method::GET, "/anything", "alice");
    req.headers
        .insert("authorization", HeaderValue::from_static("Bearer inbound"));
    for header_first in [true, false] {
        let mut ctx = context(&req);
        let action = if header_first {
            filter.on_request(&mut ctx).await.unwrap()
        } else {
            body_phase(&filter, &mut ctx).await
        };
        assert!(
            matches!(action, FilterAction::Continue | FilterAction::BodyDone),
            "header first: {header_first}, got {action:?}"
        );
        assert!(
            ctx.request_headers_to_remove
                .iter()
                .any(|name| name.as_str() == "authorization"),
            "header first: {header_first}: the inbound credential is stripped"
        );
        assert!(
            ctx.request_headers_to_set
                .iter()
                .any(|(name, value)| name.as_str() == "x-auth-user-id" && value == "alice"),
            "header first: {header_first}: the subject header is set"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_global_rule_requiring_the_inference_request_denies_discovery() {
    let (_dir, path, _count) = policy(
        "test/bodyless-llm-request",
        "  pdp:
    - kind: cel
  authorization:
    pre_invocation:
      - cel: { expr: \"has(llm.request)\" }
routes:
  - llm: \"*\"
    authorization:
      pre_invocation:
        - \"allow\"
",
    );
    let filter = filter(path);
    let req = request(Method::GET, "/v1/models", "alice");
    let action = body_phase(&filter, &mut context(&req)).await;
    assert!(
        matches!(&action, FilterAction::Reject(rejection) if rejection.status != 401),
        "an authorization denial, not an identity failure; got {action:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_inference_policy_without_http_rules_admits_on_identity() {
    let (_dir, path, count) = policy(
        "test/bodyless-identity-only",
        "routes:
  - llm: \"*\"
    authorization:
      pre_invocation:
        - \"deny('no', 'denied')\"
",
    );
    let filter = filter(path);
    let req = request(Method::GET, "/v1/models", "bob");
    assert_eq!(status(&body_phase(&filter, &mut context(&req)).await), None);
    assert_eq!(*count.lock().unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fallback_without_a_model_still_admits_on_identity() {
    let (_dir, path, _count) = policy("test/bodyless-no-model-fallback", ALICE_ONLY);
    let filter = filter_with(
        path,
        LlmOptions {
            require_model: false,
            ..Default::default()
        },
    );
    let req = request(Method::POST, "/v1/chat/completions", "bob");
    let mut ctx = context(&req);
    let mut body = Some(bytes::Bytes::from_static(br#"{"messages":[]}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone), "got {action:?}");
}

#[expect(clippy::too_many_lines, reason = "one fixture and its cases")]
#[test]
fn identity_only_fallbacks_beside_http_rules_warn_at_startup() {
    let base = PolicyFilterConfig {
        config_path: String::new(),
        allow_private_idp: false,
        trusted_private_endpoints: vec![],
        trusted_proxies: vec![],
        body_access: BodyAccessMode::ReadOnly,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
        llm: LlmOptions::default(),
        context_headers: HashMap::default(),
        context_meta: ContextMetaConfig::default(),
    };
    assert!(identity_only_fallback_warnings(&base, true, true).is_empty());
    let no_model = PolicyFilterConfig {
        llm: LlmOptions {
            require_model: false,
            ..Default::default()
        },
        ..base.clone()
    };
    let warned = identity_only_fallback_warnings(&no_model, true, true);
    assert!(
        warned.len() == 1 && warned.iter().all(|w| w.contains("llm.require_model")),
        "{warned:?}"
    );
    assert!(identity_only_fallback_warnings(&no_model, true, false).is_empty());
    let unclassified = PolicyFilterConfig {
        require_protocol_metadata: false,
        ..base
    };
    let warned = identity_only_fallback_warnings(&unclassified, true, true);
    assert!(
        warned.len() == 1 && warned.iter().all(|w| w.contains("require_protocol_metadata")),
        "{warned:?}"
    );
    assert!(identity_only_fallback_warnings(&unclassified, false, true).is_empty());
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Number of identity resolutions.
type Resolutions = Arc<Mutex<usize>>;

/// A host identity resolver taking the subject from `x-user`.
struct Who {
    /// Plugin config.
    cfg: PluginConfig,
    /// Shared resolution count.
    resolutions: Resolutions,
}

impl Plugin for Who {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<IdentityHook> for Who {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        *self.resolutions.lock().unwrap() += 1;
        let mut resolved = payload.clone();
        resolved.subject = payload.headers().get("x-user").map(|id| SubjectExtension {
            id: Some(id.clone()),
            ..Default::default()
        });
        PluginResult::modify_payload(resolved)
    }
}

/// Builds [`Who`]s sharing one count.
///
/// [`Who`]: Who
struct WhoFactory(Resolutions);

impl PluginFactory for WhoFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(Who {
            cfg: config.clone(),
            resolutions: Arc::clone(&self.0),
        });
        let identity: Arc<dyn AnyHookHandler> =
            Arc::new(TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(&plugin)));
        Ok(PluginInstance {
            plugin,
            handlers: vec![(HOOK_IDENTITY_RESOLVE, identity)],
        })
    }
}

/// A policy of [`WHO`] plus `rest`, with a fresh `kind`, and its count.
///
/// [`WHO`]: WHO
fn policy(kind: &'static str, rest: &str) -> (TempDir, String, Resolutions) {
    let resolutions: Resolutions = Arc::new(Mutex::new(0));
    let count = Arc::clone(&resolutions);
    register_policy_plugin_factory(kind, Arc::new(move || Box::new(WhoFactory(Arc::clone(&count)))));
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, format!("{}{rest}", WHO.replace("{kind}", kind))).unwrap();
    (dir, path.to_str().unwrap().to_owned(), resolutions)
}

/// A filter over `path` with `llm` options.
fn filter_with(path: String, llm: LlmOptions) -> PolicyFilter {
    PolicyFilter::new(
        PolicyFilterConfig {
            config_path: path,
            allow_private_idp: false,
            trusted_private_endpoints: vec![],
            trusted_proxies: vec![],
            body_access: BodyAccessMode::ReadOnly,
            require_protocol_metadata: true,
            init_timeout_secs: 30,
            max_buffer_bytes: 10_485_760,
            llm,
            context_headers: HashMap::default(),
            context_meta: ContextMetaConfig::default(),
        },
        None,
    )
    .unwrap()
}

/// A filter over `path` with default options.
fn filter(path: String) -> PolicyFilter {
    filter_with(path, LlmOptions::default())
}

/// A `method` request to `path` as `user`.
fn request(method: Method, path: &str, user: &str) -> crate::Request {
    let mut req = make_request(method, path);
    req.headers.insert("x-user", HeaderValue::from_str(user).unwrap());
    req
}

/// A context for `req` as filter instance 0.
fn context(req: &crate::Request) -> HttpFilterContext<'_> {
    let mut ctx = make_filter_context(req);
    ctx.current_filter_id = Some(0);
    ctx
}

/// Run the bodyless body phase.
async fn body_phase(filter: &PolicyFilter, ctx: &mut HttpFilterContext<'_>) -> FilterAction {
    filter.on_request_body(ctx, &mut None, true).await.unwrap()
}

/// The status of a rejection, or `None` when admitted.
fn status(action: &FilterAction) -> Option<u16> {
    match action {
        FilterAction::Reject(rejection) => Some(rejection.status),
        FilterAction::BodyDone => None,
        other => panic!("unexpected action {other:?}"),
    }
}
