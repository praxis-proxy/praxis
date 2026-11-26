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

## Seven-requirement thin-wrapper comparison

The [standalone harness](../../tests/benches/experiments/async_speed_limit_contract.rs)
imports the actual `schedule.rs` unchanged, so its existing 23 tests run alongside
14 crate observations. The wrapper only defers charging until activation, owns the
crate's `Consume` future, refunds on drop, and settles accepted bytes. It adds no
arrival-time ledger, generation tracking, notification queue, or timer rescheduling.
A passing observation test can reproduce a **contract failure**; it does not mean
the candidate meets the contract. Read the outcome column below.

| Requirement | Observed with async-speed-limit 0.4.2 and the thin wrapper |
| --- | --- |
| 1. Partial write/refund | Fresh sibling immediately reuses 12 KiB after 4 KiB is accepted; an already waiting sibling retains its 750 ms timer. |
| 2. Configured burst and pre-refill refund | A positive burst maps to `refill = burst / rate`. Normal refill works. Cancelling an old full-burst reservation after refill and a newer full-burst write admits another full burst at the same time. The earlier delayed-partial-settlement counterexample also reproduces. |
| 3. Zero burst, first byte and idle | Literal zero refill panics. A 1 ns refill plus matching `min_wait` paces the first byte and prevents idle credit at 1,000 B/s. At 2,000,000,000 B/s its initial bucket holds two bytes and the first byte is free. This workaround does not cover the configured `u64` rate range. |
| 4. Repeated resets on one key | With all writes cancelled, both the positive-burst and ordinary-rate zero-burst adapters recover without banked credit or debt, including resets across idle intervals. Cancellation while a newer write has committed is the failing case in row 2. |
| 5. Out-of-order cancellation | An earlier 500-byte cancellation leaves the later captured deadline at 1 s; cancelling both restores the next byte's ordinary-rate no-burst delay. The retained deadline is compatible with `schedule.rs`'s conservative outstanding-reservation test, so this probe is **not an independent failure**. Prompt dynamic waiter re-admission is tested separately in row 1. |
| 6. Prepared but never written | Passes with deferred activation: live plans debit nothing and do not block another full-burst reservation. Bare `consume` charges on creation, so the wrapper intentionally delays that call. |
| 7. Absolute release after DNS/connect | An owned future created at t=0 correctly completes at t=1 s after DNS uses 600 ms. Combined with row 6, activating the previously uncharged plan only at t=600 ms instead completes at t=1.6 s. Retaining plan age while respecting intervening shared debt needs additional accounting. |

These results support retaining the current scheduler rather than replacing it with
this wrapper. They do not rule out a more capable adapter or an upstream change:
those would need to implement and validate the missing ownership, re-admission,
zero-burst and plan-age behavior. Existing open runtime findings remain separate;
this comparison is not a correctness proof or their resolution.

## Reproduce against async-speed-limit 0.4.2

The harness is intentionally outside the production workspace's targets and
has no dependency changes in Praxis's `Cargo.toml` or `Cargo.lock`. Create a
**temporary directory** and this manifest, replacing the absolute `path` with
your checkout's harness path:

```toml
[package]
name = "praxis-limiter-contract-evaluation"
version = "0.0.0"
edition = "2024"

[workspace]

[lib]
path = "/absolute/path/to/praxis/tests/benches/experiments/async_speed_limit_contract.rs"

[dependencies]
async-speed-limit = { version = "=0.4.2", default-features = false }
tokio = { version = "1", features = ["sync"] }
```

Run `cargo test --manifest-path /path/to/temporary/Cargo.toml -- --test-threads=1`.
The relative source import reads `schedule.rs` directly from the checkout, without
copying its implementation or replacing its state. The evaluated published crate
archive has SHA-256
`97c1688bb8e4eb3dcd68a8b0e5a81deae887c67362bb482a902b785e83ac2edc`.
