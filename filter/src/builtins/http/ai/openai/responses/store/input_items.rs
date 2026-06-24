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
    #[expect(clippy::allow_attributes, reason = "dead_code expect unfulfilled on struct fields")]
    #[allow(dead_code, reason = "pagination cursor for upcoming list endpoint")]
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
/// paginated in memory using item ID cursors when available. Numeric
/// offset cursors remain supported for stored inputs without item IDs.
///
/// # Errors
///
/// Returns [`StoreError::InvalidInput`] if the cursor is malformed
/// or overflows while calculating the page window.
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
        .map(|cursor| cursor_offset(&items, cursor))
        .transpose()?
        .unwrap_or(0);

    let limit = usize::try_from(params.effective_limit()).map_err(|e| StoreError::InvalidInput(e.to_string()))?;
    let end = offset
        .checked_add(limit)
        .ok_or_else(|| StoreError::InvalidInput("input_items cursor offset overflow".to_owned()))?
        .min(items.len());
    let has_more = end < items.len();

    let data: Vec<serde_json::Value> = items.iter().skip(offset).take(limit).cloned().collect();

    let next_cursor = page_next_cursor(&data, end, has_more);

    Ok(InputItemPage {
        data,
        next_cursor,
        has_more,
    })
}

/// Resolve an `after` cursor to the offset where the next page starts.
/// ID-based lookup takes precedence: if an item's `id` field matches
/// the cursor string, the offset is the position after that item.
/// Numeric parsing is a fallback for inputs without item IDs.
fn cursor_offset(items: &[serde_json::Value], cursor: &str) -> Result<usize, StoreError> {
    if let Some(offset) = cursor_id_offset(items, cursor) {
        return Ok(offset);
    }

    cursor
        .parse::<usize>()
        .map_err(|e| StoreError::InvalidInput(format!("invalid input_items cursor: {e}")))
}

/// Return the offset after the item whose `id` matches the cursor.
fn cursor_id_offset(items: &[serde_json::Value], cursor: &str) -> Option<usize> {
    items
        .iter()
        .position(|item| item_id(item) == Some(cursor))
        .map(|index| index + 1)
}

/// Return the public item ID when the input item has one.
fn item_id(item: &serde_json::Value) -> Option<&str> {
    item.get("id").and_then(serde_json::Value::as_str)
}

/// Return the cursor clients should use to fetch the next page.
fn page_next_cursor(data: &[serde_json::Value], end: usize, has_more: bool) -> Option<String> {
    if !has_more {
        return None;
    }

    data.last()
        .and_then(item_id)
        .map(str::to_owned)
        .or_else(|| Some(end.to_string()))
}
