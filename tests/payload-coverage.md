# Payload-size coverage ledger

The [manifest](payload-coverage.json) maps the 102 families in the accepted
payload-size test plan and four generated campaigns. Final reconciliation records
394 passing case entries, nine proposed contract entries and one intentionally
unmeasured process-wide instrumentation scope. Entries can reuse a test when its
observations support several invariants; these are not 394 distinct tests.

Family disposition summarizes only its listed variants and observed builds:
`verified` means those cases passed, `verified_with_proposals` retains explicit
unadopted contracts, and `partial` identifies the remaining process-wide
allocation/task measurement scope. Platform qualifications are separate.
A unit test alone does not establish wire or process behavior.

Verification completed serially through the repository gates, with 96.84% line
coverage against the 96% threshold. A Hyper policy-order fixture failure was
corrected and its exact test passed on both adapters; earlier passing suites
were retained. Original failed runs and source revisions remain in the evidence.
All 17 scheduled selectors passed separately on Pingora and Hyper, and the heap
campaign passed 48 profiles and 64 warmed callback samples. Narrowly reviewed
source differences and unchanged benchmark dependencies justify retained evidence.

An additional broad Hyper/CloudEvents Clippy probe failed on an unchanged
`large_futures` expectation. The standard lint targets and the focused policy
lint passed; the extra probe remains explicitly recorded as failed.

## Case records

Each case is an object with these fields:

| Field | Meaning |
| --- | --- |
| `scenario` | The specific invariant and consumer, with any variant identifier. |
| `consumer` | The concrete filter, protocol, or workload variant. |
| `owner` | Primary owner or the owner of an additional consumer variant. |
| `source_basis` | Source paths and behavior supporting the expected result. |
| `contract` | `established`, `investigate`, or `proposed`, for this case. |
| `representations` | Input, buffered, rewritten and wire octets observed. |
| `parameters` | Sizes, seed, configuration and framing as applicable. |
| `adapter_features` | Intended adapter and feature scope; the observations identify the executed build and exact Cargo log. |
| `validated_adapters` | Adapters actually established by the case's individual observations. |
| `expected` | Exact expected observation, including completion or failure. |
| `lane` | PR, scheduled functional, scheduled resource, generated or platform. |
| `test_location` | Test path and name, including an existing test if reused. |
| `evidence` | Command, revision, selection count and actual outcome. |
| `result` | `passed`, `failed`, `not_run`, `unsupported`, or `proposed`. |

Case `validation_runs` references resolve to the manifest's shared run records,
which retain exact command, adapter, source revision, log, executable and source
provenance. `selected_test` identifies the individually passing test within that
run. The evidence archive retains full observations and earlier history under
each stable `case_id`, without repeating the same run metadata in every case.

Record an explicit reason and follow-up for `unsupported` or `proposed` cases.
Never use a passing status for an unrun case. Each test can support several
families only when its observations establish each invariant. Record each
case's owner and evidence rather than counting a duplicate implementation.
Where exact inputs have not been transcribed, `parameters` points to the named
fixture rather than asserting coverage of the whole family. A null
`test_location` with `not_run` may identify a missing fixture or an intentionally
unmeasured scope; its evidence explains which. Neither implies an unsupported
product feature. The same test can appear under different families as
complementary evidence, with each family retaining its own gap.

The `platform_matrix` records completed Hyper checks with the repository's
existing parity exclusions, plus unrun aarch64, Miri/sanitizer and
FIPS-approved-host configurations. FIPS-feature tests on this host do not
establish approved-mode host certification. Ignored 64 MiB and larger selectors
have explicit scheduled runs with nonzero selection; an ignored listing alone
is not a pass.

## Recent resource and lifecycle fixtures

The following cases have verified source implementations. Their manifest records
identify the exact selector, original source revision and observed outcome;
earlier observations are retained separately as history.
The [scheduled manifest](payload-scheduled.json) has 17 selectors, including
the CloudEvents and 16/32-download cases below; both adapters require matching
feature-built proxy binaries and separate results.

| Families | Current selector or workload | Observation |
| --- | --- | --- |
| N07 | `payload_metadata::huge_denied_headers_do_not_allocate_or_dispatch` | Huge declared request lengths, header-only denial, no backend dispatch, and child RSS/VmPeak. |
| N08 | `payload_metadata::huge_allowed_lengths_keep_only_a_tiny_prefix_on_close_and_timeout` | Tiny verified upstream prefix, client close or idle timeout, incomplete upstream request, and child RSS/VmPeak. |
| N11 | `payload_metadata::sustained_unbounded_sse_is_incremental_and_memory_bounded` | 4,097 ordered SSE events, delivery barriers, idle gaps, probes, and process memory observations. |
| N13 | `payload_resources::bodyless_huge_lengths_stay_bounded_and_preserve_connection_framing` | HEAD/304 and invalid 204 framing with independent probes, RSS and VmPeak. |
| A15 | `payload_resources::oversized_trailer_failures_preserve_resources_and_never_dispatch` | Oversized trailer metadata, no completed dispatch, healthy probe, RSS and VmPeak. |
| R01 | `examples::cloud_events::slow_process::scheduled_cloud_events_streaming_rss_plateau_through_one_gib` | CloudEvents response-completion profiling at 10/64/256 MiB and 1 GiB. |
| R02 | `json_body_heap` with `PRAXIS_HEAP_STRESS=1` | The actual guardrails callback and PII rules, including U+0130 lowercase expansion, alongside extraction, tokenizer and DOM profiles. |
| R07 | `payload_resources::small_probes_during_concurrent_downloads` and `payload_resources::scheduled_small_probes_during_16_and_32_downloads` | Paced 10 MiB H1 downloads at 1/4/16/32 concurrency with separate tenant-tagged probe baselines and latency samples. |
| R08 | `payload_metadata::repeated_request_cycles_drop_tracked_body_owners` | Test-owned request state and retained incoming body chunks drop after repeated success, rejection and cancellation. |
| R08 | `json_body_heap` with `PRAXIS_HEAP_CYCLES=1` | Warmed 1 MiB filter success and late-invalid cycles, with tracked current and peak allocations after each callback. |
| R08, R12 | `payload_lifecycle::repeated_failures_and_cancellation_leave_proxy_available` and `payload_lifecycle::repeated_slow_response_cancellations_leave_process_available` | Repeated process failure/cancellation cycles now include the active HTTP request gauge in addition to RSS and FD sampling. |
| R09 | `payload_lifecycle::reload_drains_old_response_hook_and_body_owner` | Watched reload with old/new response hooks and tracked old filter and incoming-chunk owner drops after drain. |

The G1 normal and pre-read models retain their separately documented passing
protocol-unit evidence for specific input-owner release. They are not a count
of all live allocations. Dhat tracks allocations made during its profile,
not fixture inputs allocated beforehand or the proxy's entire heap. The HTTP
active-request gauge is neither a Tokio task count nor a TCP connection count;
RSS and FD samples do not establish live-object counts. Runner memory and
latency envelopes are measurement containment, not universal product limits.

## Contract ledger

D1 separates incoming content, retained inspection bytes, filter-produced
content and encoded transport bytes. Incoming and effective buffer limits have
existing source-backed checks. Universal cumulative output limits and bounds on
filter-internal temporary allocation remain **proposed** per affected phase;
they are not proven by an input-limit assertion. Response compression and
`grpc_web` expansion require separate representation ledgers.

D2 requires explicit configuration for a protected route's missing selector,
invalid JSON and unsupported encodings. The extractor's continuation and
flag-mode behavior are existing configuration choices; mandatory decoding,
normalization or automatic rejection are **proposed**, not assumed. Record
inspection completion separately from a clean result.

D3 distinguishes per-request limits from process admission and total time.
The current `runtime.max_connections` and `runtime.max_memory_bytes` provide
optional connection and RSS-based request shedding; file-descriptor pressure
shedding is enabled by default. `runtime.overload_gauges` reports sampled
pressure and does not itself shed work. These controls are not a proven strict
aggregate allocation or total-upload deadline. Such bounds and their calibrated
budgets remain **proposed**, with isolated measurements needed before claims.
The runner's containment limits are distinct from proxy protections. R05 has
no configurable downstream response write deadline at this revision: Pingora
initializes that timeout to None, Praxis does not set it, and Hyper installs no
such deadline. Cluster write timeouts govern uploads to upstream. A downstream
write deadline remains proposed; pause/resume and cancellation have separate
regression tests.

## Shared fixtures

`praxis_test_utils::PayloadSpec` provides deterministic binary or padded
prefix/suffix payloads and generates bounded chunks. The one-request
`start_counting_backend` records acceptance, first content byte, request
headers, observed and verified body bytes, and completion independently; it
replies with success only after a complete matching request. Join or drop the
backend when it is unselected. `read_h1_response` streams binary bytes to a
sink and distinguishes fixed-length, chunked, close-delimited and incomplete
responses. Its caller sets socket deadlines. EOF for a close-delimited body
does not prove the sender produced its intended length.

```rust
use praxis_test_utils::{H1Completion, PayloadSpec, read_h1_response};
use std::io::{BufReader, Cursor};

let spec = PayloadSpec::binary(7, 42);
let bytes = spec.chunk(0, 7);
assert_eq!(spec.mismatch(0, &bytes), None);
let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na\0b";
let mut body = Vec::new();
let result = read_h1_response(&mut BufReader::new(Cursor::new(wire)), false, 3, |part| {
    body.extend_from_slice(part);
    Ok(())
});
assert_eq!(result.completion, Some(H1Completion::ContentLength));
assert_eq!(body, b"a\0b");
```

## File ownership for integration

- W1: core body-limit validation, filter body/pipeline and protocol body units.
- W2: JSON and JSON-RPC units; integration `json_body_field.rs`, `json_rpc.rs`,
  `payload_processing.rs`, `body_pipeline.rs` and relevant payload examples.
- W3: guardrails and policy units; integration `guardrails.rs` and their
  examples. New security modules require registration by W0.
- W4: integration `body.rs`, `body_release.rs`, `body_filter_failures.rs`,
  transport/header security and resilience `large_payload.rs`.
- W5: subrequest/history units; integration `selected_upstream_body.rs`,
  `selected_upstream_body_subrequests.rs`, `bound_upstream_body.rs`, and
  proposed resilience `payload_fanout.rs`.
- W6: gRPC-Web/codec units, compression/gRPC-Web/observability integration,
  their examples, and security `compression_bomb.rs`.
- W7: resilience `payload_resources.rs` and `payload_lifecycle.rs`, plus
  resource benchmark workloads. `payload_metadata.rs` adds request metadata,
  SSE and owner-lifetime fixtures.
- W0: `tests/utils/`, suite registrations, manifests, Makefile and CI wiring.

The manifest records actual source locations or identifies missing fixtures;
the ownership list describes the implementation work areas.
