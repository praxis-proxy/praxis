// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Network callout filters: external processing, remote auth, etc.

#[cfg(feature = "ext-proc")]
pub(crate) mod ext_proc;

#[cfg(feature = "ext-proc")]
pub use ext_proc::ExtProcFilter;
