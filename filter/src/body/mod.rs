// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Body access declarations, buffering, and capability computation.

mod access;
mod buffer;
mod builder;
mod limits;
mod mode;

pub use access::BodyAccess;
pub use buffer::{BodyBuffer, BodyBufferOverflow};
pub use builder::BodyCapabilities;
pub use limits::{DEFAULT_JSON_BODY_MAX_BYTES, MAX_JSON_BODY_BYTES};
pub use mode::BodyMode;
