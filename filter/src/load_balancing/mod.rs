// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Protocol-agnostic load-balancing strategies and endpoint types.

pub(crate) mod consistent_hash;
pub(crate) mod endpoint;
pub(crate) mod least_connections;
pub(crate) mod round_robin;
pub(crate) mod strategy;
