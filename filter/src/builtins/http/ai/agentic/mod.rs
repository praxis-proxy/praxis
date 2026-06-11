// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Agentic protocol filters: JSON-RPC 2.0 extraction, MCP and A2A classification.
//!
//! These filters extract JSON-RPC and MCP metadata for routing and handle
//! MCP static catalog behavior inside the built-in HTTP AI filter family.

mod a2a;
pub(crate) mod json_rpc;
mod mcp;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum length for dynamic values promoted to headers or metadata.
pub(crate) const MAX_DYNAMIC_VALUE_LEN: usize = 256;

pub use a2a::A2aFilter;
pub use json_rpc::JsonRpcFilter;
pub use mcp::McpFilter;
