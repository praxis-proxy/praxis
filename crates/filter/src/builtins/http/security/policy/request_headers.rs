// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Policy header writes across grouped queues and ordered pre-read replay.

use http::{HeaderName, HeaderValue};

use crate::{HttpFilterContext, TrustedHeaderMutation};

/// Names touched by earlier pre-read passes and the current ordered producer.
pub(super) fn pending_names<'ctx>(ctx: &'ctx HttpFilterContext<'_>) -> impl Iterator<Item = &'ctx HeaderName> {
    ctx.prior_pre_read_mutations
        .iter()
        .chain(&ctx.pre_read_mutations)
        .map(|mutation| match mutation {
            TrustedHeaderMutation::Remove(name)
            | TrustedHeaderMutation::Set(name, _)
            | TrustedHeaderMutation::Add(name, _) => name,
        })
}

/// Remove conflicting grouped writes, reporting whether either representation
/// mentioned the header. Ordered writes remain until a later policy operation
/// overrides them; the prior-pass log is read-only.
pub(super) fn purge_pending(ctx: &mut HttpFilterContext<'_>, lowercase: &str) -> bool {
    let mut pending = pending_names(ctx).any(|name| name.as_str() == lowercase);
    ctx.request_headers_to_set.retain(|(name, _)| {
        let hit = name.as_str() == lowercase;
        pending |= hit;
        !hit
    });
    ctx.extra_request_headers.retain(|(name, _)| {
        let hit = name.eq_ignore_ascii_case(lowercase);
        pending |= hit;
        !hit
    });
    pending
}

/// Replace a header in the active mutation representation and grouped state.
pub(super) fn set(ctx: &mut HttpFilterContext<'_>, name: HeaderName, value: HeaderValue) {
    purge_pending(ctx, name.as_str());
    if !ctx.pre_read_mutations.is_empty() {
        ctx.pre_read_mutations
            .push(TrustedHeaderMutation::Set(name.clone(), value.clone()));
    }
    ctx.request_headers_to_set.push((name, value));
}

/// Remove a header without allowing a preceding grouped add/set to revive it.
pub(super) fn remove(ctx: &mut HttpFilterContext<'_>, name: HeaderName) {
    purge_pending(ctx, name.as_str());
    if !ctx.pre_read_mutations.is_empty() {
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Remove(name.clone()));
    }
    ctx.request_headers_to_remove.push(name);
}
