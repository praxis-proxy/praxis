//! Condition evaluation for gating filter execution on request/response attributes.

mod request;
mod response;

pub use request::should_execute;
pub use response::should_execute_response;
