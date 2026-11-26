# Subrequest response-header benchmark

This benchmark calls the public `SubRequestClient::execute` API against a
loopback responder in a separate process, so backend allocations stay out of
the client's heap totals. Each response has a 64-byte body, 16 or 64 extra
distinct headers with 32-byte values, a connection identifier, and
Content-Length. The client checks the status, body, and sanitized header count
on every call.

Timing samples, unprofiled, from a release benchmark build:

```console
cargo bench -p praxis-tests-benches --bench subrequest_headers -- \
  --mode timing --protocol h1 --headers 16 --attempts 1 \
  --iterations 1000 --samples 7
```

Client allocations, from a separate DHAT build:

```console
cargo bench -p praxis-tests-benches --bench subrequest_headers \
  --features dhat-heap -- --mode allocations --protocol h2 \
  --headers 64 --attempts 2 --iterations 200
```

Timing mode is rejected in a `dhat-heap` build and allocation mode without it.
DHAT timings are never reported or compared.

Workload values are `--protocol h1|h2`, `--headers 16|64`, and
`--attempts 1|2`. Two attempts run concurrent executor calls through one
shared pool with `tokio::join!`; they do not exercise the full hedge
scheduler. Client and responder both use a current-thread Tokio runtime. On
H1 the responder accepts only the bodyless, non-pipelined GET workload.

Before measuring, 101 warmup cycles establish and exercise the pool. Every
measured response must come from a connection used in the first warmup cycle; a
cold reconnection fails the run. Startup, warmup, and result serialization are
outside heap accounting. The shared cost of client future boxing, validation,
timeout handling, and scheduling is included. The responder exits when the
parent's pipe closes (including after parent termination), and is killed and
reaped on ordinary client cleanup.

Each invocation prints one JSON record. Common fields give the mode, protocol,
extra header count, attempts per cycle, cycles (`iterations`), `total_calls`,
and `warmed_connections`. Timing records add `calls_per_sample` and
`sample_ns_per_call`: elapsed wall time divided by completed calls in each
sample, not individual request latency. Allocation records add total
`allocations` and `bytes` and their per-call values, and contain no timing
result.

The CI driver [`subrequest-comparison.py`](subrequest-comparison.py) runs all
16 workload cells on pull requests: HTTP/1 and HTTP/2, 16 and 64 headers, one
and two attempts, in separate timing and allocation modes. Ordinary PRs
validate the current candidate only, without comparing against historical
snapshots whose dependency versions may have drifted; metadata and the summary
label the run as candidate validation, not comparative performance evidence.

Manual workflow runs compare three revisions on one runner. Select the workflow
branch or tag containing the candidate, then give explicit `base_ref` and
`before_ref` commits. CI fetches missing comparison snapshots, and the driver
requires all three revisions to use identical locked package versions and
compiler profiles. Raw JSON and a descriptive comparison summary are kept.
Locally, omit both `--base` and `--before` for candidate validation, or pass
both to compare; either way `--candidate` must match the checkout.

Peer construction is adapted to the API as it was before the backend seam;
`subrequest_peer.rs` keeps that setup out of the common workload. The benchmark
explicitly enables the Pingora backend feature. The driver omits that feature
only for the pre-seam revision, where Pingora was unconditional and the feature
did not exist.

## Completion-guard investigation (PR 1407)

The investigation pins parent `3141d5b9` and checks that the current harness
head's tree matches the test-lint snapshot `e6f006bc`, which keeps the runtime
guard from `45bc8af2`. Only this document, the comparison driver, its
regression tests, and its workflow may differ; any other changed path fails the
investigation. Metadata records the harness SHA and its runtime-equivalent
guard SHA separately.

The base/original/candidate matrix is unchanged. An extra timing-only
comparison builds the parent once and reuses the candidate binary. It runs four
alternating ABBA/BAAB blocks per cell (parent, candidate, candidate, parent,
then candidate, parent, parent, candidate), which balances middle and outer
process positions between revisions; cell order rotates between blocks. Each
fresh process runs the same 101 warmup cycles and seven samples of 1000 cycles
as the normal timing workload.

Raw process records and per-block ratios are kept separately. Each block ratio
is the median of its two candidate process medians divided by the median of its
two parent process medians. The summary reports all four ratios with their
median and range; the seven contiguous samples within a process are not
independent replicates. The comparison isolates the guard commit more closely,
but shared-runner interference and process order can still affect results. It
sets no latency threshold, makes no general performance claim, and does not
measure tail latency or the hedge scheduler.

The workflow runs the pinned three-revision and paired study automatically only
for PR 1407. Other PRs run candidate validation, and manual runs use their
explicit three-revision inputs. The optional `--completion-parent` CLI flag
still works with `--base` and `--before` for the pinned investigation.
