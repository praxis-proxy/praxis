// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Observability example configuration tests.

mod access_log_fields;
mod access_logging;
#[cfg(feature = "cloud-events-filter")]
mod cloud_events;
mod logging;
mod process_logging;
