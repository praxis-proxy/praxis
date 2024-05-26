//! AI inference proxy filters.
//!
//! Extends the Praxis proxy with filters tailored for AI inference
//! workloads: model routing, token counting, prompt inspection,
//! and inference-aware load balancing, etc.

mod model_to_header;

pub use model_to_header::ModelToHeaderFilter;
