// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Input item pagination for the `OpenAI` Responses API.

use crate::builtins::http::ai::store::{ResponseRecord, StoreError};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default page size for input item list operations (matches `OpenAI` default).
const DEFAULT_PAGE_LIMIT: u32 = 20;

/// Maximum page size for input item list operations (matches `OpenAI` maximum).
const MAX_PAGE_LIMIT: u32 = 100;

// -----------------------------------------------------------------------------
// Order
// -----------------------------------------------------------------------------

/// Sort order for input item listing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// Oldest first (natural input order).
    Ascending,

    /// Newest first (reversed input order).
    #[default]
    Descending,
}

// -----------------------------------------------------------------------------
// ListParams
// -----------------------------------------------------------------------------

/// Cursor-based pagination parameters for input item listing.
#[derive(Debug, Clone)]
pub struct ListParams {
    /// Opaque cursor for the next page. `None` starts from the
    /// beginning.
    pub cursor: Option<String>,

    /// Maximum number of items to return (clamped to
    /// `1..=[MAX_PAGE_LIMIT]`).
    pub limit: u32,

    /// Sort order.
    pub order: Order,
}

impl Default for ListParams {
    fn default() -> Self {
        Self {
            cursor: None,
            limit: DEFAULT_PAGE_LIMIT,
            order: Order::default(),
        }
    }
}

impl ListParams {
    /// Return the effective limit, clamped to `1..=[MAX_PAGE_LIMIT]`.
    fn effective_limit(&self) -> u32 {
        self.limit.clamp(1, MAX_PAGE_LIMIT)
    }
}

// -----------------------------------------------------------------------------
// InputItemPage
// -----------------------------------------------------------------------------

/// A page of input items from an `OpenAI` Responses API response.
pub struct InputItemPage {
    /// Input items as JSON values (heterogeneous types).
    pub data: Vec<serde_json::Value>,

    /// Cursor for the next page (`None` when no more pages).
    pub next_cursor: Option<String>,

    /// Whether more pages exist beyond this one.
    pub has_more: bool,
}

// -----------------------------------------------------------------------------
// Input Item Pagination
// -----------------------------------------------------------------------------

/// Extract and paginate input items from a [`ResponseRecord`].
///
/// Items are extracted from the stored `input` JSON column and
/// paginated in memory using an offset-based cursor. This is
/// specific to the `OpenAI` Responses API `/v1/responses/{id}/input_items`
/// endpoint.
///
/// # Errors
///
/// Returns [`StoreError::Database`] if the cursor is malformed
/// or overflows while calculating the page window. Uses the
/// `Database` variant as a pragmatic fit until a dedicated
/// input-validation variant is added to [`StoreError`].
pub fn list_input_items(record: &ResponseRecord, params: &ListParams) -> Result<InputItemPage, StoreError> {
    let mut items = match &record.input {
        serde_json::Value::Array(arr) => arr.clone(),
        other => vec![other.clone()],
    };
    if params.order == Order::Descending {
        items.reverse();
    }

    let offset = params
        .cursor
        .as_deref()
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|e| StoreError::Database(format!("invalid input_items cursor: {e}")))?
        .unwrap_or(0);

    let limit = usize::try_from(params.effective_limit()).map_err(|e| StoreError::Database(e.to_string()))?;
    let end = offset
        .checked_add(limit)
        .ok_or_else(|| StoreError::Database("input_items cursor offset overflow".to_owned()))?
        .min(items.len());
    let has_more = end < items.len();

    let data: Vec<serde_json::Value> = items.into_iter().skip(offset).take(limit).collect();

    let next_cursor = if has_more { Some(end.to_string()) } else { None };

    Ok(InputItemPage {
        data,
        next_cursor,
        has_more,
    })
}
