//! Integration test suite for Praxis.

mod body;
mod body_pipeline;
mod common;
mod compression;
mod conditions;
mod downstream_read_timeout;
mod filter_composition;
mod guardrails;
mod health_check;
mod ip_acl;
mod json_body_field;
mod payload_processing;
mod per_listener_pipeline;
mod rate_limit;
mod retry;
mod routing;
mod security;
mod tcp_access_log;
mod tls;
mod wildcard_routing;
