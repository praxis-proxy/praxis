# Bandwidth scheduler crate evaluation

Evaluated Governor **0.10.4** and async-speed-limit **0.4.2** for
[the accepted bandwidth proposal](https://github.com/praxis-proxy/enhancements/pull/29).
Connection/IP lookup and transport accepted-byte measurement remain Praxis responsibilities
with either library. The existing Governor benchmark measures admission performance;
it does not exercise refundable ownership across asynchronous writes.

## Results

- [Governor](https://docs.rs/governor/0.10.4/governor/struct.RateLimiter.html)
  admits batches with `check_n`/`until_n_ready`, but exposes no refund operation.
  Returning the unused part of a write would require additional accounting.
- [async-speed-limit](https://docs.rs/async-speed-limit/0.4.2/async_speed_limit/limiter/struct.Limiter.html)
  shares a bucket across clones and provides `unconsume`. The basic case **works**:
  reserve 16 KiB, accept 4 KiB, return 12 KiB, then a new request can immediately
  consume that 12 KiB. Refund support alone does not justify a custom scheduler.
- An **already waiting** `consume(12_288)` retains its original 750 ms sleep after
  the refund. Polling it again at the same clock time still returns `Pending`.
  `unconsume` changes the bucket but does not notify or recalculate existing
  `Consume` futures. This can turn an otherwise satisfiable deadline into a timeout.
- Outstanding writes also need a separate allowance ledger. Hold the initial
  16 KiB reservation until t=1 s. At t=1 s the shared clone can consume 4 KiB
  using refill; the first writer then accepts 4 KiB and returns 12 KiB.
  A further 16 KiB consumption succeeds immediately. The two writers can therefore
  accept **24 KiB at t=1 s**, exceeding the configured 16 KiB burst at settlement.
  Refunding unused bytes does not distinguish elapsed refill from capacity still
  owned by an unfinished write.

The comparison uses 16 KiB/s, a one-second refill period (16 KiB burst), and
`min_wait(Duration::ZERO)` to remove the crate's default extra wait. Its built-in
`ManualClock` makes all three results deterministic. These are public-API checks
against the published crate, not a reimplementation of its algorithm.

Praxis retains a separate accepted-write ledger, holds only outstanding prefix
allowance across a write, and notifies waiters when that allowance settles.
Its regressions exercise a real partial `AsyncWrite` followed by a broken pipe,
a sibling already waiting before the refund, and late partial settlement after
an idle refill. They check both prompt reuse and the remaining rate/burst debt.
Transport support still determines whether exact partial progress is observable;
the Pingora hooks in integration PR #1600 remain pending an upstream release.

A wrapper around async-speed-limit could add settlement ownership, a shared
notification mechanism and refund/re-admission of obsolete sleeps. Those are the
specific responsibilities the current scheduler supplies. This evaluation supports
retaining that primitive for these requirements; it does not compare every crate
or claim a performance advantage. A compatible upstream primitive could replace it.

## Reproduce against async-speed-limit 0.4.2

In a temporary directory outside the Praxis workspace, create this `Cargo.toml`
(and leave Praxis's manifest and lockfile unchanged):

```toml
[package]
name = "bandwidth-refund-evaluation"
version = "0.0.0"
edition = "2024"

[workspace]

[dependencies]
async-speed-limit = { version = "=0.4.2", default-features = false }
```

Save the following as `src/main.rs`, then run `cargo run`. It asserts the working
baseline and both limitations. The evaluated published archive has SHA-256
`97c1688bb8e4eb3dcd68a8b0e5a81deae887c67362bb482a902b785e83ac2edc`.

```rust
use async_speed_limit::{Limiter, clock::{ManualClock, Nanoseconds}};
use std::{future::Future, pin::Pin, task::{Context, Waker}, time::Duration};

fn limiter() -> Limiter<ManualClock> {
    Limiter::builder(16_384.0).refill(Duration::from_secs(1))
        .min_wait(Duration::ZERO).build()
}

fn main() {
    let first = limiter();
    let second = first.clone();
    assert!(first.consume_duration(16_384).is_zero());
    first.unconsume(12_288); // 4 KiB accepted, 12 KiB unused.
    assert!(second.consume_duration(12_288).is_zero());
    println!("PASS: a new second request uses the 12 KiB refund immediately");

    let first = limiter();
    let second = first.clone();
    assert!(first.consume_duration(16_384).is_zero());
    let mut pending = second.consume(12_288);
    let mut context = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut pending).poll(&mut context).is_pending());
    first.unconsume(12_288);
    assert!(Pin::new(&mut pending).poll(&mut context).is_pending());
    first.clock().set_time(Nanoseconds(749_999_999));
    assert!(Pin::new(&mut pending).poll(&mut context).is_pending());
    first.clock().set_time(Nanoseconds(750_000_000));
    assert!(Pin::new(&mut pending).poll(&mut context).is_ready());
    println!("LIMITATION: an existing second waiter keeps its 750 ms timer after refund");

    let first = limiter();
    let second = first.clone();
    assert!(first.consume_duration(16_384).is_zero());
    first.clock().set_time(Nanoseconds(1_000_000_000));
    assert!(second.consume_duration(4_096).is_zero());
    first.unconsume(12_288); // First writer accepts 4 KiB only now.
    assert!(second.consume_duration(16_384).is_zero());
    assert_eq!(first.total_bytes_consumed(), 24_576);
    println!("LIMITATION: delayed settlement allows 24 KiB at t=1s with a 16 KiB burst");
}
```
