//! AI filters for HTTP workloads.
//!
//! Two sub-themes covering AI proxy functionality:
//!
//! - [`agentic`]: filters for AI agent workloads (MCP, A2A,
//!   agent orchestration, tool-use proxying)
//! - [`inference`]: filters for AI inference workloads (model
//!   routing, token counting, prompt inspection,
//!   inference-aware load balancing)

mod agentic;
mod inference;

pub use inference::ModelToHeaderFilter;
