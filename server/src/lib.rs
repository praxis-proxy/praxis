// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

#![deny(unsafe_code)]

//! Server bootstrap for the Praxis proxy.

mod pipelines;
mod server;

pub use praxis_core::{config::load_config, logging::init_tracing};
pub use server::{check_root_privilege, fatal, run_server, run_server_with_registry};
