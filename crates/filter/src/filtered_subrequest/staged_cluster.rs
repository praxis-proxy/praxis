// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Seeding and re-pinning a callout staged at a named cluster.

use praxis_core::connectivity::Upstream;

use super::types::StagedCluster;
use crate::{
    ClusterRef, FilterError, HttpFilterContext, cluster_ref::ClusterLease, credentials::QueuedCredentialClusters,
};

/// The cluster a callout was staged at and the endpoint it holds.
pub(super) struct PinnedCluster {
    /// The staged cluster.
    pub(super) cluster: ClusterRef,

    /// The selected endpoint; dropping it releases the selection.
    pub(super) lease: ClusterLease,
}

/// Drain a staged cluster, select its endpoint, and seed `ctx` with it.
///
/// Returns the selected upstream to pin alongside the cluster. Fails closed
/// when a [`StagedUpstream`](super::StagedUpstream) was staged as well
/// (`conflicting`).
///
/// # Errors
///
/// Returns [`FilterError`] on a conflicting staged destination, when the
/// cluster is at its `max_connections`, or when it has no endpoint to offer.
pub(super) fn stage_cluster(
    ctx: &mut HttpFilterContext<'_>,
    conflicting: bool,
) -> Result<Option<(Upstream, PinnedCluster)>, FilterError> {
    let Some(StagedCluster(cluster)) = ctx.extensions.remove::<StagedCluster>() else {
        return Ok(None);
    };
    if conflicting {
        return Err("filtered_subrequest: both StagedCluster and StagedUpstream were staged".into());
    }
    let admission = cluster.admit()?;
    let (upstream, lease) = cluster.select(ctx, &[], &admission)?;
    ctx.upstream = Some(upstream.clone());
    let pinned = PinnedCluster { cluster, lease };
    repin_cluster(ctx, Some(&pinned));
    Ok(Some((upstream, pinned)))
}

/// Fail the callout when a chain filter pointed `ctx.cluster` away from the
/// staged cluster, or queued a credential for another cluster.
///
/// Silently re-pinning is not enough here: a filter that runs after the
/// change, such as `credential_injection`, has already queued headers chosen
/// for the other cluster, and they would reach the staged cluster's endpoint.
/// Checking `ctx.cluster` alone is not enough either: a chain can point it
/// elsewhere, let a credential be queued, and point it back.
///
/// # Errors
///
/// Returns [`FilterError`] naming both clusters when they differ.
pub(super) fn ensure_cluster_unchanged(
    ctx: &HttpFilterContext<'_>,
    pinned: Option<&PinnedCluster>,
) -> Result<(), FilterError> {
    let Some(pinned) = pinned else {
        return Ok(());
    };
    let staged = pinned.cluster.name();
    if let Some(other) = ctx
        .extensions
        .get::<QueuedCredentialClusters>()
        .and_then(|queued| queued.other_than(staged))
    {
        return Err(format!(
            "filtered_subrequest: a chain filter queued a credential for cluster '{other}' on the callout staged at cluster '{staged}'"
        )
        .into());
    }
    match ctx.cluster.as_deref() {
        Some(current) if current == staged => Ok(()),
        current => Err(format!(
            "filtered_subrequest: a chain filter rerouted the callout staged at cluster '{staged}' to {}",
            current.map_or_else(|| "no cluster".to_owned(), |name| format!("cluster '{name}'"))
        )
        .into()),
    }
}

/// Reassert the staged cluster and its application metadata on `ctx`.
///
/// Runs right after the staged upstream is re-pinned, which clears any
/// selection metadata a chain filter published.
pub(super) fn repin_cluster(ctx: &mut HttpFilterContext<'_>, pinned: Option<&PinnedCluster>) {
    let Some(pinned) = pinned else {
        return;
    };
    ctx.cluster = Some(std::sync::Arc::clone(pinned.cluster.name_arc()));
    pinned.cluster.entry().publish_application(ctx);
}
