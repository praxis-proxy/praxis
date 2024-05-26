//! AI filters for HTTP workloads. Two sub-themes covering AI proxy functionality:
//!
//! - [`agentic`]: filters for AI agent workloads (MCP, A2A, agent orchestration, tool-use, etc)
//! - [`inference`]: filters for AI inference workloads (model routing, token counting, prompt inspection, etc)

mod agentic;
mod inference;

pub use inference::ModelToHeaderFilter;
