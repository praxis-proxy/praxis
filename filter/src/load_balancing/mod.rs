// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Protocol-agnostic load-balancing strategies and endpoint types.

pub(crate) mod consistent_hash;
pub(crate) mod endpoint;
pub(crate) mod least_connections;
pub(crate) mod p2c;
pub(crate) mod round_robin;
pub(crate) mod strategy;
