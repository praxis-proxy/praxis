// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! The process-wide connection limit, in its own binary.
//!
//! The limit is a process-wide `OnceLock`: once this test installs a ceiling
//! of two, every other test in the same process that opens connections
//! through the admission path is refused, so it cannot share a test binary
//! with them.

#![expect(
    clippy::tests_outside_test_module,
    clippy::expect_used,
    reason = "integration tests are in tests/ directory, not in src"
)]

use praxis_protocol::connections::{init_global_limit, try_acquire_global};

#[test]
fn global_limit_lifecycle() {
    let (uninitialized_exceeded, uninitialized_permit) = try_acquire_global();
    assert!(
        !uninitialized_exceeded,
        "uninitialized global should not report exceeded"
    );
    assert!(
        uninitialized_permit.is_none(),
        "uninitialized global should return no permit"
    );

    init_global_limit(2);

    let (first_exceeded, first) = try_acquire_global();
    assert!(!first_exceeded, "first acquire should not exceed limit");
    let first = first.expect("first acquire should return a permit");

    let (second_exceeded, second) = try_acquire_global();
    assert!(!second_exceeded, "second acquire should not exceed limit");
    let second = second.expect("second acquire should return a permit");

    let (third_exceeded, third) = try_acquire_global();
    assert!(third_exceeded, "third acquire should exceed limit of 2");
    assert!(third.is_none(), "exhausted limit should return no permit");

    init_global_limit(100);

    let (reinit_exceeded, still_none) = try_acquire_global();
    assert!(reinit_exceeded, "limit should still be 2 after re-init");
    assert!(still_none.is_none(), "re-init should be a no-op");

    drop(first);

    let (reclaimed_exceeded, reclaimed) = try_acquire_global();
    assert!(!reclaimed_exceeded, "acquire after drop should not exceed limit");
    assert!(reclaimed.is_some(), "released slot should yield a permit");

    drop(second);
}
