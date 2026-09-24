// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pipeline-scoped catalog of cluster application metadata.
//!
//! A binding `router` records only a cluster name in [`BoundUpstream`].
//! To publish that cluster's opaque application protocol and provider
//! alongside the name, the router resolves the name through this catalog.
//! Pipeline construction builds it once from every reachable cluster
//! declaration and hands it to the pipeline's binding routers, so the
//! catalog never travels with the request.
//!
//! The catalog is metadata-only: it stores cluster name, protocol, and
//! provider. Endpoint and load-balancing state remain owned by each
//! `load_balancer`.
//!
//! [`BoundUpstream`]: crate::extensions

use std::{collections::HashMap, sync::Arc};

// -----------------------------------------------------------------------------
// ClusterApplicationMetadata
// -----------------------------------------------------------------------------

/// Opaque application protocol/provider tags declared on a cluster.
///
/// Both fields are optional: a cluster may be tagged with a protocol, a
/// provider, both, or neither. The values are opaque identifiers matched
/// verbatim by `bound_upstream` conditions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClusterApplicationMetadata {
    /// Opaque application protocol, if the cluster declares one.
    protocol: Option<Arc<str>>,

    /// Opaque application provider, if the cluster declares one.
    provider: Option<Arc<str>>,
}

impl ClusterApplicationMetadata {
    /// Create metadata from optional protocol and provider tags.
    #[must_use]
    pub fn new(protocol: Option<Arc<str>>, provider: Option<Arc<str>>) -> Self {
        Self { protocol, provider }
    }

    /// The opaque application protocol, if declared.
    #[must_use]
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    /// The opaque application provider, if declared.
    #[must_use]
    pub fn provider(&self) -> Option<&str> {
        self.provider.as_deref()
    }

    /// Clone the protocol tag as a shared handle for republishing.
    pub(crate) fn protocol_arc(&self) -> Option<Arc<str>> {
        self.protocol.clone()
    }

    /// Clone the provider tag as a shared handle for republishing.
    pub(crate) fn provider_arc(&self) -> Option<Arc<str>> {
        self.provider.clone()
    }
}

// -----------------------------------------------------------------------------
// ClusterMetadataDeclaration
// -----------------------------------------------------------------------------

/// One cluster's application-metadata declaration, as reported by a
/// load-balancing filter through
/// [`declared_cluster_metadata`](crate::HttpFilter::declared_cluster_metadata).
///
/// The catalog builder folds every declaration into a single metadata map,
/// treating disagreeing declarations of the same name as a configuration
/// error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterMetadataDeclaration {
    /// Cluster name; matches an entry in
    /// [`load_balancer_clusters`](crate::HttpFilter::load_balancer_clusters).
    pub name: Arc<str>,

    /// The cluster's opaque application metadata.
    pub metadata: ClusterApplicationMetadata,
}

// -----------------------------------------------------------------------------
// ClusterApplicationCatalog
// -----------------------------------------------------------------------------

/// Metadata-only catalog keyed by cluster name.
///
/// Opaque outside this crate. Pipeline construction builds one per
/// binding-enabled pipeline and hands it to the pipeline's binding router, so
/// the router resolves a matched cluster's application metadata without owning
/// any endpoint state. Routers inside branches receive it too, but only so
/// validation can see and reject them as branch publishers. A nested pipeline
/// (an IRR step or outbound chain) builds its own catalog from its own
/// declarations.
#[derive(Debug, Default)]
pub struct ClusterApplicationCatalog {
    /// Cluster name -> resolved application metadata.
    map: HashMap<Arc<str>, ClusterApplicationMetadata>,
}

impl ClusterApplicationCatalog {
    /// Look up a cluster's application metadata by name.
    pub(crate) fn lookup(&self, cluster: &str) -> Option<&ClusterApplicationMetadata> {
        self.map.get(cluster)
    }

    /// Whether the catalog holds no cluster declarations.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// -----------------------------------------------------------------------------
// CatalogConflict
// -----------------------------------------------------------------------------

/// Two declarations of the same cluster name disagree on metadata.
///
/// Surfaced by pipeline validation as a configuration error, because a
/// binding cannot resolve a single protocol/provider for the cluster.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CatalogConflict {
    /// The cluster name that was declared more than once with differing tags.
    pub(crate) cluster: Arc<str>,

    /// The first-seen metadata retained in the catalog.
    pub(crate) first: ClusterApplicationMetadata,

    /// The later, conflicting metadata.
    pub(crate) second: ClusterApplicationMetadata,
}

/// Build a catalog from cluster declarations, collecting any conflicts.
///
/// The first declaration of each name wins in the returned map, and every
/// later declaration that disagrees is reported as a [`CatalogConflict`], so
/// callers must pass declarations in a stable order.
/// Identical re-declarations are accepted silently: the same cluster is
/// commonly declared by several load balancers (for example one per IRR
/// round) and agreement is the normal case.
///
/// Pipeline validation turns the reported conflicts into configuration
/// errors before the pipeline serves traffic, so the map is only consulted
/// once no conflicts remain.
pub(crate) fn build_catalog(
    declarations: impl IntoIterator<Item = ClusterMetadataDeclaration>,
) -> (ClusterApplicationCatalog, Vec<CatalogConflict>) {
    let mut map: HashMap<Arc<str>, ClusterApplicationMetadata> = HashMap::new();
    let mut conflicts = Vec::new();
    for decl in declarations {
        match map.get(&decl.name) {
            Some(existing) if *existing != decl.metadata => conflicts.push(CatalogConflict {
                cluster: Arc::clone(&decl.name),
                first: existing.clone(),
                second: decl.metadata,
            }),
            Some(_) => {},
            None => {
                map.insert(decl.name, decl.metadata);
            },
        }
    }
    (ClusterApplicationCatalog { map }, conflicts)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    fn decl(name: &str, protocol: Option<&str>, provider: Option<&str>) -> ClusterMetadataDeclaration {
        ClusterMetadataDeclaration {
            name: Arc::from(name),
            metadata: ClusterApplicationMetadata::new(protocol.map(Arc::from), provider.map(Arc::from)),
        }
    }

    #[test]
    fn empty_catalog_reports_empty_and_misses_lookups() {
        let (catalog, conflicts) = build_catalog(std::iter::empty());
        assert!(catalog.is_empty(), "no declarations should yield an empty catalog");
        assert!(conflicts.is_empty(), "no declarations cannot conflict");
        assert!(catalog.lookup("web").is_none(), "an empty catalog resolves nothing");
    }

    #[test]
    fn single_declaration_resolves_metadata() {
        let (catalog, conflicts) = build_catalog([decl("inference", Some("openai_responses"), Some("openai"))]);

        assert!(conflicts.is_empty(), "a lone declaration cannot conflict");
        let meta = catalog.lookup("inference").expect("cluster present");
        assert_eq!(meta.protocol(), Some("openai_responses"), "protocol must round-trip");
        assert_eq!(meta.provider(), Some("openai"), "provider must round-trip");
    }

    #[test]
    fn untagged_declaration_resolves_to_none() {
        let (catalog, conflicts) = build_catalog([decl("web", None, None)]);

        assert!(conflicts.is_empty(), "an untagged declaration cannot conflict");
        let meta = catalog.lookup("web").expect("cluster present even when untagged");
        assert_eq!(meta.protocol(), None, "untagged cluster has no protocol");
        assert_eq!(meta.provider(), None, "untagged cluster has no provider");
    }

    #[test]
    fn identical_redeclarations_do_not_conflict() {
        let (catalog, conflicts) = build_catalog([
            decl("inference", Some("openai_responses"), Some("openai")),
            decl("inference", Some("openai_responses"), Some("openai")),
        ]);

        assert!(
            conflicts.is_empty(),
            "agreeing re-declarations are the normal multi-LB case, not a conflict"
        );
        assert_eq!(
            catalog.lookup("inference").unwrap().provider(),
            Some("openai"),
            "the agreed metadata must resolve"
        );
    }

    #[test]
    fn conflicting_provider_is_reported_and_first_wins() {
        let (catalog, conflicts) = build_catalog([
            decl("inference", Some("openai_responses"), Some("openai")),
            decl("inference", Some("openai_responses"), Some("azure")),
        ]);

        assert_eq!(conflicts.len(), 1, "the disagreeing declaration must be reported");
        let conflict = conflicts.first().expect("one conflict reported");
        assert_eq!(&*conflict.cluster, "inference", "conflict names the cluster");
        assert_eq!(
            conflict.first.provider(),
            Some("openai"),
            "first-seen metadata retained"
        );
        assert_eq!(
            conflict.second.provider(),
            Some("azure"),
            "conflicting metadata recorded"
        );
        assert_eq!(
            catalog.lookup("inference").unwrap().provider(),
            Some("openai"),
            "first declaration wins in the runtime map for determinism"
        );
    }

    #[test]
    fn conflicting_protocol_is_reported() {
        let (_, conflicts) = build_catalog([
            decl("inference", Some("openai_responses"), None),
            decl("inference", Some("openai_chat"), None),
        ]);

        assert_eq!(conflicts.len(), 1, "protocol disagreement is a conflict");
    }

    #[test]
    fn tag_presence_disagreement_is_a_conflict() {
        let (_, conflicts) = build_catalog([
            decl("inference", Some("openai_responses"), None),
            decl("inference", None, None),
        ]);

        assert_eq!(
            conflicts.len(),
            1,
            "a tagged declaration disagrees with an untagged one of the same name"
        );
    }

    #[test]
    fn distinct_clusters_coexist_without_conflict() {
        let (catalog, conflicts) = build_catalog([
            decl("web", None, None),
            decl("inference", Some("openai_responses"), Some("openai")),
        ]);

        assert!(conflicts.is_empty(), "different names never conflict");
        assert_eq!(
            catalog.lookup("web").unwrap().protocol(),
            None,
            "the untagged web cluster should keep no protocol"
        );
        assert_eq!(
            catalog.lookup("inference").unwrap().protocol(),
            Some("openai_responses"),
            "the tagged inference cluster should keep its own protocol"
        );
    }
}
