//! Security test suite for Praxis.
//!
//! Adversarial tests verifying that security filters
//! correctly reject, sanitize, or neutralize malicious
//! input. Each module focuses on one security boundary.

mod common;
mod filter_leakage;
mod forwarded_headers;
mod header_injection;
mod host_header;
mod info_leakage;
mod ip_acl;
mod request_smuggling;
