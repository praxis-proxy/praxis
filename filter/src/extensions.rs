// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Type-safe, request-scoped extension container.
//!
//! [`RequestExtensions`] is a type-map keyed by [`TypeId`]. Filters
//! store and retrieve arbitrary typed values that persist across all
//! Pingora lifecycle phases (request, request body, response,
//! response body, logging).
//!
//! The framework has no knowledge of what filters store in it. The
//! cost when unused is an empty [`HashMap`] (zero allocations, no
//! overhead on existing filter chains).
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
};

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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    #[cfg(any(feature = "policy-engine", test))]
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
    /// Registered JWT claims and claims promoted to the typed fields above are
    /// excluded by the policy engine claim mapper. Values use the policy
    /// engine's normalized string representation rather than exposing the raw
    /// decoded JWT claim set: string-typed JWT claims are passed through
    /// as-is, while non-string values (objects, arrays, numbers, booleans)
    /// are JSON-serialized into their compact string form (e.g.
    /// `{"tier":"gold"}` for a nested object).
    /// Wire adapters must explicitly allowlist and bound claims before
    /// serializing them outside Praxis.
    pub fn custom_claims(&self) -> &BTreeMap<String, String> {
        &self.custom_claims
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
    /// the correct type. The `expect` guards against impossible
    /// `TypeId` collisions in the standard library.
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
