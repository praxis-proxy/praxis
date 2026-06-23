// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Origin matching for the CORS filter, delegating to the
//! shared [`OriginMatcher`].
//!
//! [`OriginMatcher`]: super::super::origin_matcher::OriginMatcher

pub(super) use super::super::origin_matcher::{
    OriginMatcher as OriginPolicy, build_origin_matcher as build_origin_policy,
};
