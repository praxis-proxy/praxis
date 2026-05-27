// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! HTTP AI and agentic protocol filters.
//!
//! These filters extract JSON-RPC and MCP metadata for routing and handle
//! MCP static catalog behavior inside the built-in HTTP AI filter family.

pub(crate) mod json_rpc;
mod mcp;

pub use json_rpc::JsonRpcFilter;
pub use mcp::McpFilter;
