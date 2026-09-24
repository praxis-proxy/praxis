// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Type-safe, request-scoped extension container.
//!
//! [`RequestExtensions`] is a type-map keyed by [`TypeId`]. Filters
//! store and retrieve arbitrary typed values that persist across all
//! Pingora lifecycle phases (request, request body, response,
//! response body, logging).
//!
//! The framework has no knowledge of what filters store in it; when
//! unused it holds an empty [`HashMap`].
//!
//! Only one value per concrete type can be stored. Filters must use
//! private newtypes for their state, not bare types like
//! [`serde_json::Value`] or `Vec<String>`, to avoid overwriting
//! each other's data.
//!
//! [`TypeId`]: std::any::TypeId

use std::{
    any::Any,
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};

#[cfg(feature = "bound-upstream-request-body")]
use bytes::Bytes;

// -----------------------------------------------------------------------------
// AuthenticatedIdentity
// -----------------------------------------------------------------------------

/// Raw-credential-free identity established by a trusted authentication filter.
///
/// This is the stable, request-scoped identity contract for filters that need
/// to consume an authenticated principal without accessing the credential or
/// depending on an authentication provider's payload types. Presence means
/// authentication succeeded and produced a non-empty subject identifier; it
/// does not by itself mean that every subsequent operation was authorized.
///
/// The fields are intentionally read-only outside this crate. Only trusted
/// built-in producers can construct the value, while external filters can
/// inspect it through the getters below. The type deliberately does not
/// implement serialization so wire adapters must choose an explicit output
/// format rather than serializing authentication state wholesale.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedIdentity {
    /// Stable identifier of the authenticated subject.
    subject_id: String,
    /// Roles assigned to the authenticated subject.
    roles: BTreeSet<String>,
    /// Teams assigned to the authenticated subject.
    teams: BTreeSet<String>,
    /// Provider-mapped custom claims from the validated identity.
    custom_claims: BTreeMap<String, String>,
}

impl AuthenticatedIdentity {
    /// Construct a raw-credential-free identity from trusted, normalized parts.
    ///
    /// Returns `None` when authentication did not produce a subject ID.
    #[cfg(any(feature = "basic-auth-filter", feature = "policy-engine", test))]
    pub(crate) fn new(
        subject_id: String,
        roles: impl IntoIterator<Item = String>,
        teams: impl IntoIterator<Item = String>,
        custom_claims: impl IntoIterator<Item = (String, String)>,
    ) -> Option<Self> {
        (!subject_id.is_empty()).then(|| Self {
            subject_id,
            roles: roles.into_iter().collect(),
            teams: teams.into_iter().collect(),
            custom_claims: custom_claims.into_iter().collect(),
        })
    }

    /// Stable identifier of the authenticated subject.
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    /// Roles assigned to the authenticated subject.
    pub fn roles(&self) -> &BTreeSet<String> {
        &self.roles
    }

    /// Teams assigned to the authenticated subject.
    pub fn teams(&self) -> &BTreeSet<String> {
        &self.teams
    }

    /// Provider-mapped custom claims from the validated identity.
    ///
    /// Registered JWT claims and claims promoted to typed fields are excluded.
    /// Strings are preserved; other JSON values use their compact serialized
    /// form to maintain this type's string-valued contract.
    ///
    /// Wire adapters must explicitly allowlist and bound claims before
    /// serializing them outside Praxis.
    pub fn custom_claims(&self) -> &BTreeMap<String, String> {
        &self.custom_claims
    }
}

// -----------------------------------------------------------------------------
// SelectedClusterApplication
// -----------------------------------------------------------------------------

/// Opaque application metadata of the cluster the load balancer selected
/// for this exchange.
///
/// Published once by the trusted built-in load balancer after a successful
/// upstream selection and read-only thereafter, so request, response,
/// response-body, and logging filters all observe the same values for the
/// life of the exchange. Absent when no cluster was selected or the
/// selected cluster tagged neither field.
///
/// The identifiers are opaque to Praxis core: consuming filters interpret
/// them; Praxis defines no enum of known protocols or providers. The type
/// is deliberately crate-private with read-only getters: only the load
/// balancer constructs it (via
/// [`HttpFilterContext::publish_selected_application`]), and external
/// filters read it through
/// [`HttpFilterContext::selected_application_protocol`] and
/// [`HttpFilterContext::selected_application_provider`] rather than naming
/// the type. The identifiers come straight from the resolved cluster entry.
///
/// [`HttpFilterContext::publish_selected_application`]: crate::HttpFilterContext::publish_selected_application
/// [`HttpFilterContext::selected_application_protocol`]: crate::HttpFilterContext::selected_application_protocol
/// [`HttpFilterContext::selected_application_provider`]: crate::HttpFilterContext::selected_application_provider
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SelectedClusterApplication {
    /// Opaque application protocol of the selected cluster, if tagged.
    protocol: Option<Arc<str>>,
    /// Opaque application provider of the selected cluster, if tagged.
    provider: Option<Arc<str>>,
}

impl SelectedClusterApplication {
    /// Build selected-application metadata from a resolved cluster's
    /// identifiers, or `None` when the cluster tagged neither field, so the
    /// extension is inserted only when there is something to read.
    pub(crate) fn new(protocol: Option<Arc<str>>, provider: Option<Arc<str>>) -> Option<Self> {
        (protocol.is_some() || provider.is_some()).then_some(Self { protocol, provider })
    }

    /// Opaque application protocol of the selected cluster, if tagged.
    pub(crate) fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    /// Opaque application provider of the selected cluster, if tagged.
    pub(crate) fn provider(&self) -> Option<&str> {
        self.provider.as_deref()
    }
}

// -----------------------------------------------------------------------------
// BoundUpstream
// -----------------------------------------------------------------------------

/// Logical upstream cluster bound once for the whole downstream request.
///
/// Published by the trusted built-in `router` after it matches a route in a
/// pipeline that reads the binding somewhere. Ordinary router pipelines never
/// create this extension. Unlike [`SelectedClusterApplication`], which is
/// exchange-local and cleared between IRR rounds, `BoundUpstream` stays put
/// for the entire downstream request and survives every IRR iteration, so
/// request, bound-body, response, and logging filters all see the same
/// binding.
///
/// The identifiers are opaque to Praxis core: consuming filters interpret
/// them, and Praxis defines no list of known protocols or providers. The type
/// is crate-private with read-only getters. Only the router constructs it
/// (through [`HttpFilterContext::publish_bound_upstream`]); filters read it
/// through [`HttpFilterContext::bound_cluster`],
/// [`HttpFilterContext::bound_application_protocol`], and
/// [`HttpFilterContext::bound_application_provider`]. The metadata comes from
/// the pipeline's cluster catalog, keyed by the cluster name.
///
/// The executor freezes the binding right after the first router publishes
/// it, before that router's branches run. Until then a later binding router
/// would replace it; after it, republishing the same cluster is a no-op and a
/// different cluster fails closed. Validation rejects branch publishers,
/// IRR-step publishers, and `ReEnter` paths that could run a binding router
/// again, so only the no-op case happens in a valid config.
///
/// [`HttpFilterContext::publish_bound_upstream`]: crate::HttpFilterContext::publish_bound_upstream
/// [`HttpFilterContext::bound_cluster`]: crate::HttpFilterContext::bound_cluster
/// [`HttpFilterContext::bound_application_protocol`]: crate::HttpFilterContext::bound_application_protocol
/// [`HttpFilterContext::bound_application_provider`]: crate::HttpFilterContext::bound_application_provider
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundUpstream {
    /// Logical cluster name selected by the router.
    cluster: Arc<str>,
    /// Opaque application protocol of the bound cluster, if tagged.
    application_protocol: Option<Arc<str>>,
    /// Opaque application provider of the bound cluster, if tagged.
    application_provider: Option<Arc<str>>,
}

/// The request body a bound-upstream read-write participant produced at the
/// binding barrier.
///
/// Recorded only when a writer actually ran, so the transport forwards and
/// replays the barrier's output even if a later request filter takes or
/// replaces the buffered body. Crate-private so no filter can forge it; the
/// transport reads it through
/// [`HttpFilterContext::take_bound_request_body_rewrite`].
///
/// [`HttpFilterContext::take_bound_request_body_rewrite`]: crate::HttpFilterContext::take_bound_request_body_rewrite
#[cfg(feature = "bound-upstream-request-body")]
#[derive(Clone, Debug)]
pub(crate) struct BoundRequestBodyRewrite(pub(crate) Bytes);

/// Request-scoped marker that freezes [`BoundUpstream`] and records that the
/// once-per-request bound-body barrier has run.
#[cfg(feature = "upstream-binding")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct BoundUpstreamFrozen;

impl BoundUpstream {
    /// Build a binding for `cluster` with its catalog-resolved application
    /// metadata. The cluster name is mandatory (a route always names a
    /// cluster); protocol and provider are present only when the cluster
    /// declaration tagged them.
    #[cfg(feature = "upstream-binding")]
    pub(crate) fn new(
        cluster: Arc<str>,
        application_protocol: Option<Arc<str>>,
        application_provider: Option<Arc<str>>,
    ) -> Self {
        Self {
            cluster,
            application_protocol,
            application_provider,
        }
    }

    /// Logical cluster name selected by the router.
    pub(crate) fn cluster(&self) -> &str {
        &self.cluster
    }

    /// Opaque application protocol of the bound cluster, if tagged.
    pub(crate) fn application_protocol(&self) -> Option<&str> {
        self.application_protocol.as_deref()
    }

    /// Opaque application provider of the bound cluster, if tagged.
    pub(crate) fn application_provider(&self) -> Option<&str> {
        self.application_provider.as_deref()
    }
}

// -----------------------------------------------------------------------------
// RequestExtensions
// -----------------------------------------------------------------------------

/// Type-safe, request-scoped extension container.
///
/// Keyed by [`TypeId`], so only one value per concrete type is
/// stored. Use private newtypes to avoid collisions between
/// independent filters.
///
/// [`TypeId`]: std::any::TypeId
#[derive(Default)]
pub struct RequestExtensions(HashMap<std::any::TypeId, Box<dyn Any + Send + Sync>>);

impl RequestExtensions {
    /// Create an empty extension container.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a typed value, replacing any previous value of the same type.
    pub fn insert<T: Send + Sync + 'static>(&mut self, val: T) {
        self.0.insert(std::any::TypeId::of::<T>(), Box::new(val));
    }

    /// Get a shared reference to a stored value by type.
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.0
            .get(&std::any::TypeId::of::<T>())
            .and_then(|boxed| boxed.downcast_ref())
    }

    /// Get an exclusive reference to a stored value by type.
    pub fn get_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.0
            .get_mut(&std::any::TypeId::of::<T>())
            .and_then(|boxed| boxed.downcast_mut())
    }

    /// Get an exclusive reference to a stored value, inserting a
    /// default computed by `f` if absent.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice: the value was just inserted with
    /// the correct type.
    pub fn get_or_insert_with<T: Send + Sync + 'static>(&mut self, f: impl FnOnce() -> T) -> &mut T {
        #[expect(clippy::expect_used, reason = "downcast cannot fail after typed insert")]
        self.0
            .entry(std::any::TypeId::of::<T>())
            .or_insert_with(|| Box::new(f()))
            .downcast_mut()
            .expect("type mismatch after insert")
    }

    /// Remove a stored value by type, returning it if present.
    pub fn remove<T: Send + Sync + 'static>(&mut self) -> Option<T> {
        self.0
            .remove(&std::any::TypeId::of::<T>())
            .and_then(|boxed| boxed.downcast().ok())
            .map(|boxed| *boxed)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn authenticated_identity_exposes_stable_collections_and_getters() {
        let identity = AuthenticatedIdentity::new(
            "alice".to_owned(),
            ["writer".to_owned(), "admin".to_owned(), "admin".to_owned()],
            ["platform".to_owned()],
            [("tenant".to_owned(), "acme".to_owned())],
        )
        .expect("non-empty subject");

        assert_eq!(identity.subject_id(), "alice");
        assert_eq!(
            identity.roles().iter().map(String::as_str).collect::<Vec<_>>(),
            ["admin", "writer"],
        );
        assert_eq!(
            identity.teams().iter().map(String::as_str).collect::<Vec<_>>(),
            ["platform"]
        );
        assert_eq!(identity.custom_claims().get("tenant").map(String::as_str), Some("acme"));
    }

    #[test]
    fn authenticated_identity_rejects_empty_subject() {
        assert!(
            AuthenticatedIdentity::new(
                String::new(),
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
            )
            .is_none(),
        );
    }

    #[test]
    fn default_is_empty() {
        let ext = RequestExtensions::default();
        assert!(ext.get::<String>().is_none(), "default should contain no values");
    }

    // -------------------------------------------------------------------------
    // SelectedClusterApplication Tests
    // -------------------------------------------------------------------------

    #[test]
    fn selected_cluster_application_absent_when_both_fields_absent() {
        assert!(
            SelectedClusterApplication::new(None, None).is_none(),
            "an untagged cluster must not produce a metadata value"
        );
    }

    #[test]
    fn selected_cluster_application_present_with_protocol_only() {
        let app = SelectedClusterApplication::new(Some(Arc::from("openai_chat_completions")), None)
            .expect("a protocol-only cluster should produce a value");
        assert_eq!(
            app.protocol(),
            Some("openai_chat_completions"),
            "protocol should read back"
        );
        assert!(app.provider().is_none(), "an absent provider should read back as None");
    }

    #[test]
    fn selected_cluster_application_present_with_provider_only() {
        let app = SelectedClusterApplication::new(None, Some(Arc::from("vllm")))
            .expect("a provider-only cluster should produce a value");
        assert!(app.protocol().is_none(), "an absent protocol should read back as None");
        assert_eq!(app.provider(), Some("vllm"), "provider should read back");
    }

    #[test]
    fn selected_cluster_application_exposes_both_fields() {
        let app = SelectedClusterApplication::new(Some(Arc::from("openai_responses")), Some(Arc::from("openai")))
            .expect("a fully tagged cluster should produce a value");
        assert_eq!(app.protocol(), Some("openai_responses"), "protocol should read back");
        assert_eq!(app.provider(), Some("openai"), "provider should read back");
    }

    // -------------------------------------------------------------------------
    // BoundUpstream Tests
    // -------------------------------------------------------------------------

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn bound_upstream_exposes_cluster_and_metadata() {
        let bound = BoundUpstream::new(
            Arc::from("inference-backend"),
            Some(Arc::from("openai_responses")),
            Some(Arc::from("openai")),
        );
        assert_eq!(bound.cluster(), "inference-backend", "cluster name should read back");
        assert_eq!(
            bound.application_protocol(),
            Some("openai_responses"),
            "protocol should read back"
        );
        assert_eq!(
            bound.application_provider(),
            Some("openai"),
            "provider should read back"
        );
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn bound_upstream_allows_untagged_cluster() {
        let bound = BoundUpstream::new(Arc::from("backend"), None, None);
        assert_eq!(
            bound.cluster(),
            "backend",
            "an untagged cluster still produces a binding (the cluster name is mandatory)"
        );
        assert!(
            bound.application_protocol().is_none(),
            "absent protocol reads back as None"
        );
        assert!(
            bound.application_provider().is_none(),
            "absent provider reads back as None"
        );
    }

    #[test]
    fn insert_and_get() {
        let mut ext = RequestExtensions::new();
        ext.insert(42_u32);
        assert_eq!(ext.get::<u32>(), Some(&42), "should retrieve inserted value");
    }

    #[test]
    fn insert_and_get_mut() {
        let mut ext = RequestExtensions::new();
        ext.insert("hello".to_owned());
        if let Some(val) = ext.get_mut::<String>() {
            val.push_str(" world");
        }
        assert_eq!(
            ext.get::<String>().map(String::as_str),
            Some("hello world"),
            "get_mut should allow mutation"
        );
    }

    #[test]
    fn multiple_types_coexist() {
        let mut ext = RequestExtensions::new();
        ext.insert(1_u32);
        ext.insert("text".to_owned());
        ext.insert(1.5_f64);
        assert_eq!(ext.get::<u32>(), Some(&1), "u32 should be present");
        assert_eq!(
            ext.get::<String>().map(String::as_str),
            Some("text"),
            "String should be present"
        );
        assert_eq!(ext.get::<f64>(), Some(&1.5), "f64 should be present");
    }

    #[test]
    fn insert_same_type_overwrites() {
        let mut ext = RequestExtensions::new();
        ext.insert(1_u32);
        ext.insert(2_u32);
        assert_eq!(ext.get::<u32>(), Some(&2), "second insert should overwrite first");
    }

    #[test]
    fn remove_returns_owned_value() {
        let mut ext = RequestExtensions::new();
        ext.insert(99_u32);
        let removed = ext.remove::<u32>();
        assert_eq!(removed, Some(99), "remove should return the stored value");
        assert!(ext.get::<u32>().is_none(), "value should be gone after remove");
    }

    #[test]
    fn remove_absent_returns_none() {
        let mut ext = RequestExtensions::new();
        assert!(ext.remove::<u32>().is_none(), "removing absent type should return None");
    }

    #[test]
    fn get_or_insert_with_creates_when_absent() {
        let mut ext = RequestExtensions::new();
        let val = ext.get_or_insert_with(|| 42_u32);
        assert_eq!(*val, 42, "should create value when absent");
    }

    #[test]
    fn get_or_insert_with_returns_existing() {
        let mut ext = RequestExtensions::new();
        ext.insert(10_u32);
        let val = ext.get_or_insert_with(|| 42_u32);
        assert_eq!(*val, 10, "should return existing value without calling factory");
    }

    #[test]
    fn get_wrong_type_returns_none() {
        let mut ext = RequestExtensions::new();
        ext.insert(42_u32);
        assert!(ext.get::<String>().is_none(), "wrong type should return None");
    }

    #[test]
    fn newtypes_are_independent() {
        struct FilterAState(u32);
        struct FilterBState(u32);

        let mut ext = RequestExtensions::new();
        ext.insert(FilterAState(1));
        ext.insert(FilterBState(2));

        assert_eq!(
            ext.get::<FilterAState>().map(|s| s.0),
            Some(1),
            "FilterAState should be 1"
        );
        assert_eq!(
            ext.get::<FilterBState>().map(|s| s.0),
            Some(2),
            "FilterBState should be 2"
        );
    }
}
