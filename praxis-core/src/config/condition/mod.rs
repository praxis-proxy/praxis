//! Condition predicates that gate filter execution.
//!
//! Used in [`PipelineEntry`] to conditionally run
//! filters based on request or response attributes.
//!
//! [`PipelineEntry`]: super::PipelineEntry

mod request;
mod response;

pub use request::{Condition, ConditionMatch};
pub use response::{ResponseCondition, ResponseConditionMatch};
