# Subrequest response-header benchmark

This benchmark calls the public `SubRequestClient::execute` API against a
loopback responder in a separate process. Backend allocations are excluded
from the client's heap totals. Each response has a 64-byte body, 16 or 64
extra distinct headers with 32-byte values, a connection identifier, and
Content-Length. The client checks the status, body and sanitized header
count on every call.

Run unprofiled timing samples with a release benchmark build:

```console
cargo bench -p praxis-tests-benches --bench subrequest_headers -- \
  --mode timing --protocol h1 --headers 16 --attempts 1 \
  --iterations 1000 --samples 7
```

Measure client allocations with a separate DHAT build:

```console
cargo bench -p praxis-tests-benches --bench subrequest_headers \
  --features dhat-heap -- --mode allocations --protocol h2 \
  --headers 64 --attempts 2 --iterations 200
```

The binary rejects timing mode when built with `dhat-heap`, and rejects
allocation mode without it. DHAT timings are never reported or compared.

Supported workload values are `--protocol h1|h2`, `--headers 16|64` and
`--attempts 1|2`. Two attempts run concurrent executor calls through one
shared pool using `tokio::join!`; they do not exercise the full hedge
scheduler. Both client and responder use a current-thread Tokio runtime.
The responder accepts only the bodyless, non-pipelined GET workload on H1.

Before measuring, 101 warmup cycles establish and exercise the pool. Every
measured response must identify a connection used by the first warmup
cycle; a cold reconnection fails the run. Startup, warmup and result
serialization are outside heap accounting. The common cost of client
future boxing, validation, timeout handling and scheduling is included.
The responder exits when the parent's pipe closes, including after parent
termination, and is killed and reaped on ordinary client cleanup.

Each invocation prints one JSON record. Common fields identify the mode,
protocol, extra header count, attempts per cycle, cycles (`iterations`),
`total_calls` and `warmed_connections`. Timing records include
`calls_per_sample` and `sample_ns_per_call`: elapsed wall time divided by
completed calls in each sample, rather than individual request latency.
Allocation records include total `allocations` and `bytes` plus their
per-call values. They contain no timing result.

The CI driver [`subrequest-comparison.py`](subrequest-comparison.py) runs all
16 workload cells on pull requests: HTTP/1 and HTTP/2, 16 and 64 headers,
one and two attempts, and separate timing and allocation modes. Ordinary PRs
validate the current candidate without comparing it to historical snapshots
whose dependency versions may have drifted. Metadata and the summary identify
this as candidate validation, not comparative performance evidence.

Manual workflow runs compare three revisions on one runner. Select the workflow
branch or tag containing the candidate, then supply explicit `base_ref` and
`before_ref` commits. CI fetches missing comparison snapshots; the driver requires
all three revisions to use identical locked package versions and compiler
profiles. Raw JSON and a descriptive comparison summary are preserved. Locally,
omit both `--base` and `--before` for candidate validation, or supply both to
enable comparison; either mode requires `--candidate` to match the checkout.
Peer construction is adapted for the API before the backend seam;
`subrequest_peer.rs` keeps that setup outside the common workload.
The benchmark explicitly enables the Pingora backend. The comparison driver
omits that feature request only on the pre-seam revision, where Pingora was
unconditional and the feature did not exist.

The completion-guard investigation pins parent `3141d5b9` and verifies the
current harness head's tree is equivalent to the test-lint snapshot
`e6f006bc`, which retains the runtime guard from `45bc8af2`: only this
document, the comparison driver, its regression tests, and its workflow may
differ. Any other changed path fails the investigation. Metadata records the
harness SHA and its runtime-equivalent guard SHA separately. The existing
base/original/candidate matrix remains intact. An additional timing-only
comparison builds the parent once and reuses the candidate binary. It runs
four alternating ABBA/BAAB blocks per cell: parent, candidate, candidate,
parent, then candidate, parent, parent, candidate. This balances middle and
outer process positions between revisions, while cell order rotates between
blocks. Each fresh process performs the same 101 warmup
cycles and seven samples of 1000 cycles as the normal timing workload.

Raw process records and per-block ratios are retained separately. Each block
ratio divides the median of its two candidate process medians by the median
of its two parent process medians. The summary reports all four ratios and
their median and range; the seven contiguous samples within each process
are not independent replicates. This bounded comparison isolates the guard
commit more closely, but shared-runner interference and process order can
still affect results. It introduces no latency threshold or universal
performance claim and does not measure tail latency or the hedge scheduler.

The workflow retains the pinned three-revision and paired study automatically
only for PR 1407. Other PRs run candidate validation; manual workflow runs use
their explicit three-revision inputs. The optional `--completion-parent` CLI
flag remains available with `--base` and `--before` for the pinned investigation.
